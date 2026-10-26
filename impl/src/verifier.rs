//! Verification of a message's evidence against its plaintext
//! (05-evidence.md §2.2, §3.7, §7).
//!
//! Inputs are those of §7.1: the evidence package, the session log, the
//! `MLSMessage`, the application data, retained MLS state, and the EBW URL logs.
//! Retained state is loaded and used with mls-rs's public API only
//! ([`crate::dispute`]).
//! Each check yields OK, INCOMPLETE (an input is missing) or FAIL; the
//! verdict is the worst of them.

use crate::certs::TrustStore;
use crate::credential::{Credential, StatusListToken};
use crate::delivery::SessionLog;
use crate::registry::{self, RegistryDocument, HeadStatement, LogEntry};
use crate::dispute::{self, Join, Processed, Replay, RetainedKeyPackage, RetainedState};
use crate::endpoint::PrivateData;
use crate::evidence::{self, Artefact, ConsentDecision, DecryptionReport, EvidenceBody, Event, MessageEvidence, ReportResult};
use crate::mls::{self, AppMessage, MemberInfo, SccIdentityProvider, TrustContext};
use crate::util::{b64u, fmt_time, sha256};
use anyhow::{anyhow, bail, Context, Result};
use mls_rs::client_builder::MlsConfig;
use mls_rs::Group;
use mls_rs_codec::MlsEncode;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Incomplete,
    Fail,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "OK",
            Status::Incomplete => "INCOMPLETE",
            Status::Fail => "FAIL",
        })
    }
}

#[derive(Debug)]
pub struct Check {
    pub section: &'static str,
    pub name: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    pub summary: Vec<String>,
}

impl Report {
    fn add(&mut self, section: &'static str, name: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.checks.push(Check { section, name: name.into(), status, detail: detail.into() });
    }
    fn result(&mut self, section: &'static str, name: impl Into<String>, r: Result<String>) {
        match r {
            Ok(d) => self.add(section, name, Status::Ok, d),
            Err(e) => self.add(section, name, Status::Fail, format!("{e:#}")),
        }
    }
    pub fn verdict(&self) -> Status {
        self.checks.iter().map(|c| c.status).max().unwrap_or(Status::Incomplete)
    }
}

/// What a verifier is given.
pub struct Inputs {
    /// An evidence artefact holding an evidence package (§3.6).
    pub package: Vec<u8>,
    pub session_log: Option<SessionLog>,
    pub private: PrivateData,
    pub registry_logs: HashMap<String, Vec<LogEntry>>,
    /// The plaintext body the claim is about.
    pub plaintext: Option<Vec<u8>>,
    pub trust: TrustStore,
}

/// The registry document in force according to a head statement, from the EBW URL log.
fn state_for_head(inputs: &Inputs, head: &HeadStatement) -> Result<RegistryDocument> {
    let log = inputs.registry_logs.get(&head.body.owner).ok_or_else(|| anyhow!("no EBW URL log for {}", head.body.owner))?;
    let audited = registry::audit_log(&head.body.owner, log, &inputs.trust)?;
    registry::state_at_head(&audited, &head.body.head)
}

struct Item {
    art: Artefact,
    body: MessageEvidence,
    event: Event,
}

/// Verify an endpoint statement's credential at the statement's time
/// (§2.2 step 7), with the registry document named by the artefact's head
/// statements and the embedded status list tokens.
fn check_statement_credential(inputs: &Inputs, item: &Item, cred: &Credential, t: u64) -> Result<()> {
    check_credential(inputs, item, cred, t, true)
}

/// As [`check_statement_credential`]; without `require_status`, the status
/// is checked only if the artefact embeds a status list token for it.
fn check_credential(inputs: &Inputs, item: &Item, cred: &Credential, t: u64, require_status: bool) -> Result<()> {
    let head = item
        .body
        .heads
        .iter()
        .filter_map(|h| HeadStatement::parse(h).ok())
        .find(|h| h.body.owner == cred.claims.iss)
        .ok_or_else(|| anyhow!("no head statement for {}", cred.claims.iss))?;
    let state = state_for_head(inputs, &head)?;
    cred.verify_signature_and_time(&state, t)?;
    let tok = item.body.statuses.iter().flatten().filter_map(|s| StatusListToken::parse(s).ok()).find(|s| s.claims.sub == cred.claims.status_uri);
    match tok {
        Some(tok) => cred.check_status(&tok, &state, t),
        None if require_status => bail!("no embedded status list for {}", cred.claims.status_uri),
        None => Ok(()),
    }
}

/// What the session log gives for each epoch, indexed by epoch.
pub struct Replayed {
    pub contexts: Vec<Vec<u8>>,
    pub members: Vec<Vec<MemberInfo>>,
    /// The leaf index of the committer of the Commit that created the epoch.
    pub committers: Vec<Option<u32>>,
}

/// Recompute the GroupContext and members of every epoch from the
/// session log (doc 3 §6.2), as an RDS does.
pub fn replay_log(log: &SessionLog, states: HashMap<String, RegistryDocument>) -> Result<Replayed> {
    let ip = SccIdentityProvider::new(TrustContext { states, statuses: HashMap::new(), require_status: false, at: None });
    let obs = mls::observer_client(ip.clone());
    let first = log.commits.first().map(|c| c.accepted_at);
    ip.ctx.write().unwrap().at = first;
    let mut g = obs
        .observe_group(mls::parse_mls_message(&log.group_info)?, None, None)
        .map_err(|e| anyhow!("creation GroupInfo: {e:?}"))?;
    if g.group_context().epoch != 0 {
        bail!("creation GroupInfo is not for epoch 0");
    }
    mls::check_session_extensions(&g.group_context().extensions)?;
    let mut contexts = vec![g.group_context().mls_encode_to_vec()?];
    let mut members = vec![mls::members_of(&g.roster().members())?];
    let mut committers = vec![None];
    for e in &log.commits {
        ip.ctx.write().unwrap().at = Some(e.accepted_at);
        let msg = mls::parse_mls_message(&e.commit)?;
        if msg.wire_format() != mls_rs::WireFormat::PublicMessage {
            bail!("Commit for epoch {} is not a PublicMessage", e.epoch);
        }
        match g.process_incoming_message(msg).map_err(|err| anyhow!("Commit for epoch {}: {err:?}", e.epoch))? {
            mls_rs::external_client::ExternalReceivedMessage::Commit(d) => committers.push(Some(d.committer)),
            _ => bail!("log entry for epoch {} is not a Commit", e.epoch),
        }
        if g.group_context().epoch != e.epoch {
            bail!("log entry says epoch {}, Commit gives {}", e.epoch, g.group_context().epoch);
        }
        mls::check_session_extensions(&g.group_context().extensions)?;
        contexts.push(g.group_context().mls_encode_to_vec()?);
        members.push(mls::members_of(&g.roster().members())?);
    }
    Ok(Replayed { contexts, members, committers })
}

pub fn verify(inputs: &Inputs) -> Report {
    let mut r = Report::default();
    if let Err(e) = verify_inner(inputs, &mut r) {
        r.add("§7.2", "verification", Status::Fail, format!("{e:#}"));
    }
    r
}

fn verify_inner(inputs: &Inputs, r: &mut Report) -> Result<()> {
    // ---- The package (§3.6) ----
    let pkg_art = Artefact::parse(&inputs.package)?;
    r.result("§2.2", "package seal and timestamp", pkg_art.verify_seal(&inputs.trust).map(|t| format!("sealed by {}, timestamped {}", issuer_of(&pkg_art), fmt_time(t))));
    r.result("§2.2", "package matches CDDL", crate::schema::validate("evidence-artefact", &inputs.package).map(|_| "evidence-artefact".into()));
    let pkg = match &pkg_art.body {
        EvidenceBody::Package(p) => p.clone(),
        _ => bail!("the artefact does not hold an evidence package"),
    };
    // ---- Each artefact (§2.2) ----
    let mut items = Vec::new();
    for (i, (seal, ts)) in pkg.items.iter().enumerate() {
        let art = Artefact::from_parts(seal, ts)?;
        let body = art.message().cloned().ok_or_else(|| anyhow!("item {i} is not message evidence"))?;
        let event = body.event()?;
        let name = format!("{} {} by {}", event.code(), event.name(), body.issuer.rds);
        let mut problems = Vec::new();
        match art.verify_seal(&inputs.trust) {
            Ok(_) => {}
            Err(e) => problems.push(format!("seal: {e:#}")),
        }
        if let Err(e) = crate::schema::validate("evidence-artefact", &art.raw) {
            problems.push(format!("{e:#}"));
        }
        for h in &body.heads {
            match HeadStatement::parse(h).and_then(|hs| hs.verify(&inputs.trust, body.event_time).map(|_| hs)) {
                Ok(hs) if hs.body.status != crate::types::OwnerStatus::Active && !matches!(event, Event::A2 | Event::B2 | Event::D2) => {
                    problems.push(format!("head statement for {} shows {}", hs.body.owner, hs.body.status.as_str()))
                }
                Ok(_) => {}
                Err(e) => problems.push(format!("head statement: {e:#}")),
            }
        }
        for s in body.statuses.iter().flatten() {
            if let Err(e) = StatusListToken::parse(s) {
                problems.push(format!("status list token: {e:#}"));
            }
        }
        items.push(Item { art, body, event });
        let item = items.last().unwrap();
        for raw in item.body.reports.iter().flatten() {
            match evidence::parse_statement::<DecryptionReport>(raw) {
                Ok(st) => {
                    if let Err(e) = check_statement_credential(inputs, item, &st.credential, st.body.reported_at) {
                        problems.push(format!("decryption report of {}: {e:#}", st.body.subject));
                    }
                }
                Err(e) => problems.push(format!("decryption report: {e:#}")),
            }
        }
        for raw in item.body.decisions.iter().flatten() {
            match evidence::parse_statement::<ConsentDecision>(raw) {
                Ok(st) => {
                    if let Err(e) = check_statement_credential(inputs, item, &st.credential, st.body.decided_at) {
                        problems.push(format!("consent decision of {}: {e:#}", st.body.subject));
                    }
                }
                Err(e) => problems.push(format!("consent decision: {e:#}")),
            }
        }
        if problems.is_empty() {
            r.add("§2.2", name, Status::Ok, format!("issued {}; seal, timestamp, CDDL, head statements and endpoint statements verify", fmt_time(item.body.event_time)));
        } else {
            r.add("§2.2", name, Status::Fail, problems.join("; "));
        }
    }
    if items.is_empty() {
        bail!("empty evidence package");
    }
    // ---- §7.2 step 1: same message everywhere ----
    let msg = items[0].body.message.clone();
    let same = items.iter().all(|i| i.body.message == msg) && pkg.message_id == msg.message_id;
    r.add("§7.2", "same message in every artefact", if same { Status::Ok } else { Status::Fail }, format!("message {}", b64u(&msg.message_id)));
    // ---- §7.2 step 2: chain ----
    let chain: Vec<(Vec<u8>, Event, Vec<Vec<u8>>)> = items.iter().map(|i| (i.art.seal_hash(), i.event, i.body.prev_hashes())).collect();
    let terminal = match evidence::check_chain(&chain) {
        Ok(s) => {
            r.add("§3.7", "evidence chain", Status::Ok, s.order.iter().map(|e| e.code()).collect::<Vec<_>>().join(" -> "));
            Some(s.terminal)
        }
        Err(e) => {
            r.add("§3.7", "evidence chain", Status::Fail, format!("{e:#}"));
            None
        }
    };
    // ---- §7.2 step 4: envelope ----
    let envelope = inputs.private.mls_message.as_ref();
    let epoch = match envelope {
        Some(m) => {
            let ok = sha256(m) == msg.envelope_hash;
            r.add("§7.2", "envelope hash", if ok { Status::Ok } else { Status::Fail }, if ok { "SHA-256(MLSMessage) = envelope_hash".to_string() } else { "the MLSMessage does not match envelope_hash".into() });
            let parsed = mls::parse_mls_message(m).ok();
            if parsed.as_ref().and_then(|p| p.group_id()) != Some(&msg.session_id[..]) {
                r.add("§7.2", "session of the MLSMessage", Status::Fail, "group_id is not the session ID");
            }
            parsed.and_then(|p| p.epoch())
        }
        None => {
            r.add("§7.2", "envelope hash", Status::Incomplete, "no MLSMessage given");
            None
        }
    };
    // ---- §7.2 step 3: GroupContexts from the session log ----
    let mut states = HashMap::new();
    for i in &items {
        for h in &i.body.heads {
            if let Ok(hs) = HeadStatement::parse(h) {
                if let Ok(s) = state_for_head(inputs, &hs) {
                    states.insert(hs.body.owner.clone(), s);
                }
            }
        }
    }
    let mut replayed: Option<Replayed> = None;
    match &inputs.session_log {
        None => r.add("§7.2", "GroupContext from the session log", Status::Incomplete, "no session log given"),
        Some(log) => match replay_log(log, states.clone()) {
            Err(e) => r.add("§7.2", "GroupContext from the session log", Status::Fail, format!("{e:#}")),
            Ok(rep) => {
                let contexts = &rep.contexts;
                let mut bad = Vec::new();
                let mut checked = 0;
                for i in &items {
                    if let Some(m) = &i.body.mls {
                        let e = epoch.or_else(|| contexts.iter().position(|c| c == &m.group_context).map(|x| x as u64));
                        match e.and_then(|e| contexts.get(e as usize)) {
                            Some(c) if c == &m.group_context => checked += 1,
                            _ => bad.push(i.event.code()),
                        }
                    }
                }
                if bad.is_empty() {
                    r.add("§7.2", "GroupContext from the session log", Status::Ok, format!("replayed {} Commits; {checked} artefacts carry the recomputed GroupContext of epoch {}", log.commits.len(), epoch.map(|e| e.to_string()).unwrap_or("?".into())));
                } else {
                    r.add("§7.2", "GroupContext from the session log", Status::Fail, format!("group_context differs in {}", bad.join(", ")));
                }
                // The credential of each endpoint the evidence names is in
                // its leaf of the tree (§3.2), at the message's epoch.
                let leaves = epoch.and_then(|e| rep.members.get(e as usize));
                let mut problems = Vec::new();
                let mut found = 0;
                for i in &items {
                    let Some(ep) = &i.body.endpoint else { continue };
                    match leaves.and_then(|ls| ls.iter().find(|m| m.owner == ep.owner && m.subject == ep.subject)) {
                        Some(m) => {
                            found += 1;
                            if let Err(e) = Credential::parse(&m.credential).and_then(|c| check_credential(inputs, i, &c, i.body.event_time, true)) {
                                problems.push(format!("{} ({}): {e:#}", i.event.code(), ep.subject));
                            }
                        }
                        // A.2 may name an endpoint that is not a member.
                        None if i.event == Event::A2 => {}
                        None => problems.push(format!("{}: {} is not in the tree", i.event.code(), ep.subject)),
                    }
                }
                if problems.is_empty() {
                    r.add("§3.2", "credentials of named endpoints", Status::Ok, format!("{found} found in the tree; signatures, validity and status verify"));
                } else {
                    r.add("§3.2", "credentials of named endpoints", Status::Fail, problems.join("; "));
                }
                replayed = Some(rep);
            }
        },
    }
    // ---- Outcome (§7.3) ----
    let sender_mls = items.iter().find_map(|i| i.body.mls.clone());
    let a1 = items.iter().find(|i| i.event == Event::A1);
    r.summary.push(format!("message {} from {} to {}, sent {}", b64u(&msg.message_id), msg.from, msg.to, fmt_time(msg.sent_at)));
    let term = terminal.and_then(|t| items.iter().find(|i| i.event == t));
    // The results the recipient side reported, and who reported them.
    let mut results: Vec<ReportResult> = Vec::new();
    let mut reporters: Vec<(String, String)> = Vec::new();
    let mut n_reports = 0usize;
    match term {
        None => {}
        Some(t) => {
            let reports: Vec<_> = t.body.reports.iter().flatten().filter_map(|x| evidence::parse_statement::<DecryptionReport>(x).ok()).collect();
            n_reports = reports.len();
            for rep in &reports {
                results.push(rep.body.result);
                reporters.push((rep.body.owner.clone(), rep.body.subject.clone()));
            }
            match t.event {
                Event::E1 => {
                    let good = reports.iter().find(|rep| {
                        let b = &rep.body;
                        b.result == ReportResult::Match
                            && b.message_id == msg.message_id
                            && b.session_id == msg.session_id
                            && b.envelope_hash == msg.envelope_hash
                            && rep.credential.claims.iss == msg.to.owner
                            && rep.credential.claims.roles.contains(&msg.to.role)
                    });
                    match good {
                        Some(rep) => {
                            r.add("§7.3", "decryptable by the recipient", Status::Ok, format!("E.1 embeds a match report from {}/{}, which agrees with the sender", rep.body.owner, rep.body.subject));
                            r.summary.push(format!("outcome: DELIVERED (E.1 at {}) to endpoint {}", fmt_time(t.body.event_time), rep.body.subject));
                        }
                        None => r.add("§7.3", "decryptable by the recipient", Status::Fail, "E.1 does not embed a valid match report"),
                    }
                }
                Event::E2 => {
                    let why = t.body.reason.as_ref().and_then(|x| x.scc.clone()).unwrap_or_default();
                    r.summary.push(format!("outcome: HANDOVER FAILED (E.2, {why})"));
                    if reports.is_empty() {
                        r.add("§7.3", "recipient reports", Status::Incomplete, "E.2 without reports: decryptability cannot be shown (§8 Silence)");
                    } else {
                        let agree = reports.iter().any(|rep| agrees(rep.body.result));
                        r.add("§7.3", "dispute type", Status::Ok, if agree { "decrypt-failed or mismatch: message-key dispute (§7.4)" } else { "invalid-epoch or join-failure: group-state dispute (§7.5)" });
                    }
                }
                e => {
                    let why = t.body.reason.as_ref().map(|x| format!("{} {}", x.code, x.scc.clone().unwrap_or_default())).unwrap_or_default();
                    r.summary.push(format!("outcome: NOT DELIVERED ({} {}, {why})", e.code(), e.name()));
                }
            }
        }
    }
    // ---- Retained state and disputes (§7.4, §7.5, §8) ----
    let dispute = term.map(|t| t.event == Event::E2).unwrap_or(false) && n_reports > 0;
    let ctx = DisputeInputs {
        evidence_gc: sender_mls.as_ref().map(|m| m.group_context.clone()),
        sender_ea: sender_mls.as_ref().map(|m| m.epoch_authenticator.clone()),
        mismatch: term.and_then(|t| mismatch_commitment(t, &inputs.private)),
        envelope: envelope.map(|e| e.as_slice()),
        plaintext_hash: msg.plaintext_hash.clone(),
        a1_endpoint: a1.and_then(|a| a.body.endpoint.clone()),
    };
    let ip = SccIdentityProvider::new(TrustContext { states: states.clone(), statuses: HashMap::new(), require_status: false, at: None });
    let mut decrypted: Option<Vec<u8>> = None;
    // Every report other than invalid-epoch and join-failure says that the
    // recipient's epoch authenticator equals the sender's (§4).
    let agree = !results.is_empty() && results.iter().all(|x| agrees(*x));
    let recipient_agreed: Vec<(u64, Vec<u8>)> = match (&inputs.private.agreement, &replayed, &inputs.session_log) {
        (Some(raw), Some(rep), Some(_)) if dispute && !agree => match agreed_epoch(raw, &msg.session_id, rep, &inputs.trust) {
            Ok((k, ea)) => {
                r.add("§7.5", "agreement shown", Status::Ok, format!("an earlier message of the session in epoch {k} ended in E.1 with a match report"));
                vec![(k, ea)]
            }
            Err(e) => {
                r.add("§7.5", "agreement shown", Status::Fail, format!("{e:#}"));
                vec![]
            }
        },
        _ => vec![],
    };
    match (&inputs.private.state, epoch) {
        (Some(st), Some(n)) if st.epoch == n => {
            if dispute && !agree {
                r.add("§7.5", "anchor state", Status::Incomplete, "the presented state is of the message's epoch, whose authenticators the parties do not agree on");
            } else {
                decrypted = message_key_dispute(r, &ip, st, &ctx, dispute);
            }
        }
        (Some(st), Some(n)) if dispute && st.epoch < n => {
            decrypted = group_state_dispute(r, &ip, inputs, Some(st), &[], &ctx, replayed.as_ref(), &recipient_agreed, &reporters, n);
        }
        (None, Some(n)) if dispute && !agree && !inputs.private.key_packages.is_empty() => {
            decrypted = group_state_dispute(r, &ip, inputs, None, &inputs.private.key_packages, &ctx, replayed.as_ref(), &recipient_agreed, &reporters, n);
        }
        (Some(st), _) => r.add("§8", format!("presented MLS state of epoch {}", st.epoch), Status::Incomplete, "not of the message's epoch, and no group-state dispute to settle"),
        (None, _) if dispute => r.add(if agree { "§7.4" } else { "§7.5" }, "presented MLS state", Status::Incomplete, "a recipient reported a failure, but no retained MLS state was presented"),
        _ => {}
    }
    if decrypted.is_some() && dispute {
        r.summary.push("the recipient's claim that it could not decrypt the message fails: the message decrypts under the presented MLS state".into());
    }
    // ---- §7.2 step 5: plaintext ----
    let recovered = inputs.private.application_data.is_none() && decrypted.is_some();
    match inputs.private.application_data.as_ref().or(decrypted.as_ref()) {
        None => r.add("§7.2", "plaintext", Status::Incomplete, "no application data given"),
        Some(d) => {
            let hash_ok = sha256(d) == msg.plaintext_hash;
            let app = AppMessage::decode(d);
            let meta_ok = app
                .as_ref()
                .map(|a| {
                    a.message_id == msg.message_id && a.from == msg.from && a.to == msg.to && a.sent_at == msg.sent_at && a.expires_at == msg.expires_at && a.consignment == msg.consignment
                })
                .unwrap_or(false);
            let body_ok = match (&inputs.plaintext, &app) {
                (Some(p), Ok(a)) => Some(&a.body == p),
                _ => None,
            };
            let status = if !hash_ok || !meta_ok || body_ok == Some(false) {
                Status::Fail
            } else if body_ok.is_none() {
                Status::Incomplete
            } else {
                Status::Ok
            };
            let mut why = Vec::new();
            if recovered {
                why.push("application data recovered by processing the message under the presented state");
            }
            why.push(if hash_ok { "SHA-256(application data) = plaintext_hash" } else { "application data does not match plaintext_hash" });
            why.push(if meta_ok { "metadata equal" } else { "metadata differ" });
            why.push(match body_ok {
                Some(true) => "body equals the presented plaintext",
                Some(false) => "body differs from the presented plaintext",
                None => "no plaintext presented",
            });
            r.add("§7.2", "plaintext", status, why.join("; "));
            if let Ok(a) = &app {
                r.summary.push(format!("content: {} ({} bytes{})", a.content_type, a.body.len(), a.subject.as_ref().map(|s| format!(", subject {s:?}")).unwrap_or_default()));
            }
        }
    }
    Ok(())
}

/// Whether a report result says that the recipient's epoch authenticator
/// equals the sender's (§4).
fn agrees(r: ReportResult) -> bool {
    !matches!(r, ReportResult::InvalidEpoch | ReportResult::JoinFailure)
}

/// §7.5 step 1: the epoch and agreed epoch authenticator shown by the
/// evidence package of an earlier message of the session that ended in
/// E.1 with a match report.
fn agreed_epoch(raw: &[u8], session_id: &[u8], rep: &Replayed, trust: &TrustStore) -> Result<(u64, Vec<u8>)> {
    let pkg = Artefact::parse(raw)?;
    pkg.verify_seal(trust).context("agreement package seal")?;
    let EvidenceBody::Package(p) = &pkg.body else { bail!("the agreement artefact is not an evidence package") };
    for (seal, ts) in &p.items {
        let art = Artefact::from_parts(seal, ts)?;
        let Some(m) = art.message() else { continue };
        if m.event()? != Event::E1 {
            continue;
        }
        art.verify_seal(trust).context("E.1 seal")?;
        if m.message.session_id != session_id {
            bail!("the agreement E.1 is for another session");
        }
        let mls = m.mls.as_ref().ok_or_else(|| anyhow!("the agreement E.1 has no mls"))?;
        let k = rep.contexts.iter().position(|c| c == &mls.group_context).ok_or_else(|| anyhow!("the agreement E.1's group_context is not in the session log"))?;
        let matched = m.reports.iter().flatten().filter_map(|x| evidence::parse_statement::<DecryptionReport>(x).ok()).any(|x| x.body.result == ReportResult::Match);
        if !matched {
            bail!("the agreement E.1 embeds no match report");
        }
        return Ok((k as u64, mls.epoch_authenticator.clone()));
    }
    bail!("the agreement package has no E.1")
}

/// A `mismatch` report in the terminal event, with the salt and
/// application data the recipient presented for it (§7.4).
fn mismatch_commitment(t: &Item, private: &PrivateData) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let salt = private.report_salt.clone()?;
    let data = private.application_data.clone()?;
    let h = t.body.reports.iter().flatten().filter_map(|x| evidence::parse_statement::<DecryptionReport>(x).ok()).find(|x| x.body.result == ReportResult::Mismatch)?.body.plaintext_hash?;
    Some((h.to_vec(), salt, data))
}

/// What the evidence says about the message, for disputes.
struct DisputeInputs<'a> {
    evidence_gc: Option<Vec<u8>>,
    sender_ea: Option<Vec<u8>>,
    /// For a `mismatch` report: the report's `plaintext_hash` and the salt
    /// and application data the recipient presented.
    mismatch: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    envelope: Option<&'a [u8]>,
    plaintext_hash: Vec<u8>,
    a1_endpoint: Option<crate::types::EndpointRef>,
}

/// §7.4 (or, without a dispute, a check that the retained state matches,
/// §8). Returns the application data if the message decrypts.
fn message_key_dispute(r: &mut Report, ip: &SccIdentityProvider, st: &RetainedState, c: &DisputeInputs, dispute: bool) -> Option<Vec<u8>> {
    let sec = if dispute { "§7.4" } else { "§8" };
    let name = format!("presented MLS state of epoch {}", st.epoch);
    let mut g = match dispute::load_state(ip, st) {
        Ok(g) => g,
        Err(e) => {
            r.add(sec, name, Status::Fail, format!("{e:#}"));
            return None;
        }
    };
    // Step 1.
    let (gc, ea) = match dispute::group_values(&g) {
        Ok(v) => v,
        Err(e) => {
            r.add(sec, name, Status::Fail, format!("{e:#}"));
            return None;
        }
    };
    let mut bad = Vec::new();
    if c.evidence_gc.as_ref() != Some(&gc) {
        bad.push("its GroupContext is not the evidence group_context");
    }
    if c.sender_ea.as_ref() != Some(&ea) {
        bad.push("its epoch authenticator is not the sender's");
    }
    if !bad.is_empty() {
        r.add(sec, name, Status::Fail, bad.join("; "));
        return None;
    }
    r.add(
        sec,
        name,
        Status::Ok,
        format!(
            "loaded with mls-rs (member at leaf {}); GroupContext equals the evidence group_context; epoch authenticator equals the sender's",
            g.current_member_index(),
        ),
    );
    if !dispute {
        return None;
    }
    process_under(r, "§7.4", &mut g, c)
}

/// §7.4 steps 2 and 3: process the PrivateMessage under a loaded state.
fn process_under<C: MlsConfig>(r: &mut Report, sec: &'static str, g: &mut Group<C>, c: &DisputeInputs) -> Option<Vec<u8>> {
    let name = "message processed under the presented state";
    let Some(env) = c.envelope else {
        r.add(sec, name, Status::Incomplete, "no MLSMessage given");
        return None;
    };
    let me = g.current_member_index();
    let p = match dispute::process_message(g, env) {
        Ok(p) => p,
        Err(e) => {
            r.add(sec, name, Status::Fail, format!("{e:#}"));
            return None;
        }
    };
    match p {
        Processed::Rejected(e) => {
            r.add(sec, name, Status::Fail, format!("mls-rs rejects the message ({e}): the encryption is bogus, and the sender is at fault"));
            None
        }
        Processed::FromSelf => {
            r.add(
                sec,
                name,
                Status::Incomplete,
                format!("the presented state is the sender's own (leaf {me}); mls-rs does not process a member's own PrivateMessage, so the state of another member, such as the recipient, is needed (see NOTES.md)"),
            );
            None
        }
        Processed::Application { sender_index, data } => {
            let res = (|| -> Result<String> {
                let cred = dispute::member_credential(g, sender_index)?;
                let ep = c.a1_endpoint.as_ref().ok_or_else(|| anyhow!("no A.1 naming the sending endpoint"))?;
                if ep.owner != cred.claims.iss || ep.subject != cred.claims.sub {
                    bail!("the sender's leaf {sender_index} is {}/{}, not the sending endpoint named in A.1", cred.claims.iss, cred.claims.sub);
                }
                if sha256(&data) != c.plaintext_hash {
                    bail!("SHA-256 of the application data is not plaintext_hash");
                }
                Ok(format!(
                    "mls-rs decrypts it and verifies the signature of leaf {sender_index}, the sending endpoint {}; SHA-256(application data) = plaintext_hash",
                    cred.claims.sub
                ))
            })();
            if let Some((h, salt, presented)) = &c.mismatch {
                let n = "the recipient's mismatch commitment";
                if sha256(&[&salt[..], &presented[..]].concat()) != *h {
                    r.add(sec, n, Status::Fail, "the presented salt and application data do not give the report's plaintext_hash");
                } else if *presented != data {
                    r.add(sec, n, Status::Fail, "the recipient committed to application data other than what the message decrypts to");
                } else {
                    r.add(sec, n, Status::Ok, "the presented salt and application data give the report's plaintext_hash, and are what the message decrypts to");
                }
            }
            match res {
                Ok(d) => {
                    r.add(sec, name, Status::Ok, d);
                    Some(data)
                }
                Err(e) => {
                    r.add(sec, name, Status::Fail, format!("{e:#}: the sender is at fault"));
                    None
                }
            }
        }
    }
}

/// §7.5: from the recipient's anchor (its retained state of its last
/// agreed epoch, or the KeyPackage it joined with), replay the logged
/// Commits up to the message's epoch.
#[allow(clippy::too_many_arguments)]
fn group_state_dispute(
    r: &mut Report,
    ip: &SccIdentityProvider,
    inputs: &Inputs,
    st: Option<&RetainedState>,
    kps: &[RetainedKeyPackage],
    c: &DisputeInputs,
    replayed: Option<&Replayed>,
    agreed: &[(u64, Vec<u8>)],
    reporters: &[(String, String)],
    n: u64,
) -> Option<Vec<u8>> {
    let (Some(log), Some(rep)) = (&inputs.session_log, replayed) else {
        r.add("§7.5", "group-state dispute", Status::Incomplete, "the session log is needed");
        return None;
    };
    match st {
        Some(st) => {
            let name = format!("anchor: presented MLS state of epoch {}", st.epoch);
            let g = match dispute::load_state(ip, st) {
                Ok(g) => g,
                Err(e) => {
                    r.add("§7.5", name, Status::Fail, format!("{e:#}"));
                    return None;
                }
            };
            // The anchor is a last agreed epoch, or an epoch that a
            // reporting recipient endpoint created with its own Commit.
            let agreed_ea = agreed.iter().find(|(e, _)| *e == st.epoch).map(|(_, a)| a);
            let me = g.current_member_index();
            let own = rep.committers.get(st.epoch as usize).copied().flatten() == Some(me)
                && rep
                    .members
                    .get(st.epoch as usize)
                    .and_then(|ms| ms.iter().find(|m| m.index == me))
                    .map(|m| reporters.iter().any(|(o, s)| o == &m.owner && s == &m.subject))
                    .unwrap_or(false);
            if agreed_ea.is_none() && !own {
                r.add("§7.5", name, Status::Fail, "neither an epoch shown to be agreed nor an epoch the reporting endpoint created");
                return None;
            }
            let ok = match dispute::group_values(&g) {
                Ok((gc, ea)) => {
                    let mut bad: Vec<String> = Vec::new();
                    if rep.contexts.get(st.epoch as usize) != Some(&gc) {
                        bad.push("its GroupContext is not the one recomputed from the log".into());
                    }
                    if agreed_ea.is_some_and(|a| a != &ea) {
                        bad.push("its epoch authenticator is not the agreed value".into());
                    }
                    bad
                }
                Err(e) => vec![format!("{e:#}")],
            };
            if !ok.is_empty() {
                r.add("§7.5", name, Status::Fail, ok.join("; "));
                return None;
            }
            let why = if agreed_ea.is_some() {
                "epoch authenticator equals the agreed value".to_string()
            } else {
                format!("the epoch was created by the reporting endpoint's own Commit (leaf {me})")
            };
            r.add("§7.5", name, Status::Ok, format!("loaded with mls-rs; GroupContext equals the one recomputed from the log; {why}"));
            continue_from(r, ip, g, log, rep, c, n)
        }
        None => {
            let name = "anchor: join with a presented KeyPackage";
            match dispute::join_with_key_packages(ip, kps, log) {
                Err(e) => {
                    r.add("§7.5", name, Status::Fail, format!("{e:#}"));
                    None
                }
                Ok(Join::NoWelcome) => {
                    r.add("§7.5", name, Status::Incomplete, "no Welcome in the session log is for a presented KeyPackage");
                    None
                }
                Ok(Join::Rejected { epoch, error }) => {
                    r.add("§7.5", name, Status::Fail, format!("mls-rs rejects the Welcome for epoch {epoch} ({error}): {} is at fault", committer(rep, epoch)));
                    None
                }
                Ok(Join::Joined(g)) => {
                    let e = g.current_epoch();
                    let gc = dispute::group_values(&g).map(|v| v.0).ok();
                    if rep.contexts.get(e as usize) != gc.as_ref() {
                        r.add("§7.5", name, Status::Fail, format!("the joined GroupContext of epoch {e} is not the one recomputed from the log"));
                        return None;
                    }
                    r.add("§7.5", name, Status::Ok, format!("the KeyPackage's private keys match it; mls-rs processes the Welcome and joins at epoch {e}"));
                    continue_from(r, ip, g, log, rep, c, n)
                }
            }
        }
    }
}

fn committer(rep: &Replayed, epoch: u64) -> String {
    let idx = rep.committers.get(epoch as usize).copied().flatten();
    let m = idx.and_then(|i| rep.members.get(epoch.saturating_sub(1) as usize).and_then(|ms| ms.iter().find(|m| m.index == i)));
    match (idx, m) {
        (_, Some(m)) => format!("the committer (leaf {}, {}/{})", m.index, m.owner, m.subject),
        (Some(i), None) => format!("the committer (leaf {i})"),
        _ => "the committer".into(),
    }
}

/// §7.5 steps 3 and 4, then §7.4 steps 2 and 3 under the resulting state.
fn continue_from<C: MlsConfig>(r: &mut Report, ip: &SccIdentityProvider, mut g: Group<C>, log: &SessionLog, rep: &Replayed, c: &DisputeInputs, n: u64) -> Option<Vec<u8>> {
    let from = g.current_epoch();
    match dispute::replay_commits(ip, &mut g, log, n) {
        Err(e) => {
            r.add("§7.5", "replay of the logged Commits", Status::Incomplete, format!("{e:#}"));
            return None;
        }
        Ok(Replay::Rejected { epoch, error }) => {
            r.add("§7.5", "replay of the logged Commits", Status::Fail, format!("mls-rs rejects the Commit for epoch {epoch} ({error}): {} is at fault", committer(rep, epoch)));
            return None;
        }
        Ok(Replay::FromSelf { epoch }) => {
            r.add("§7.5", "replay of the logged Commits", Status::Incomplete, format!("the Commit for epoch {epoch} is the presenting member's own, which mls-rs does not process from a stored state"));
            return None;
        }
        Ok(Replay::Done) => {}
    }
    let ea = dispute::group_values(&g).map(|v| v.1).ok();
    if ea.is_none() || ea != c.sender_ea {
        r.add("§7.5", "replay of the logged Commits", Status::Fail, format!("after the Commits for epochs {} to {n}, the epoch authenticator is not the sender's", from + 1));
        return None;
    }
    r.add("§7.5", "replay of the logged Commits", Status::Ok, format!("mls-rs processes the Commits for epochs {} to {n}; the resulting epoch authenticator equals the sender's", from + 1));
    process_under(r, "§7.5", &mut g, c)
}

fn issuer_of(a: &Artefact) -> String {
    match &a.body {
        EvidenceBody::Message(m) => m.issuer.rds.clone(),
        EvidenceBody::CommitFailure(c) => c.issuer.rds.clone(),
        EvidenceBody::Package(_) => a.cose.x5chain().first().map(|c| crate::certs::cert_subject(c)).unwrap_or_default(),
    }
}
