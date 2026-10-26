//! Messages: submission, relay, consignment, handover, consent, expiry and
//! evidence (04-delivery.md §7, 05-evidence.md §3).

use super::{ep_key, ConsentState, EpKey, Msg, Rds, Report, Session, State};
use crate::delivery::{DeliverParams, EvidenceNotifyParams, MembershipMismatch, Meta};
use crate::evidence::{
    self, Artefact, Assurance, ConsentDecision, Decision, DecryptionReport, EvidenceBody, EvidencePackage, Event,
    Handover, MessageEvidence, MessageRef, MlsRef, Reason, ReportResult,
};
use crate::rpc::{self, RpcError, RpcResult};
use crate::types::{AcceptancePolicy, Address, Consignment, OwnerStatus, EndpointRef};
use crate::util::{now, random_bytes, sha256};
use serde_bytes::ByteBuf;
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;

/// Optional fields of an evidence body.
#[derive(Default)]
pub struct Extra {
    pub reason: Option<Reason>,
    pub endpoint: Option<EndpointRef>,
    pub statuses: Vec<Vec<u8>>,
    pub recipient_assurance: Option<Assurance>,
    pub handovers: bool,
    pub reports: Vec<Vec<u8>>,
    pub decisions: Vec<Vec<u8>>,
    pub eligible_holders: Option<u64>,
    pub peer: Option<String>,
    pub heads: Option<Vec<Vec<u8>>>,
}

/// A rejection reason: SCC reason and EN 319 522-2 codes for A.2 and B.2.
fn reason(scc: &str, a: bool, text: impl Into<String>) -> Reason {
    let code = match (scc, a) {
        ("malformed", true) => "RA02",
        ("malformed", false) => "RB02",
        (_, true) => "RA05",
        ("unknown-address" | "recipient-retired" | "recipient-merged", false) => "RB21",
        (_, false) => "RB06",
    };
    Reason::new(code, Some(scc), Some(text.into()))
}

fn message_ref(m: &Msg) -> MessageRef {
    MessageRef {
        message_id: m.meta.message_id.clone(),
        session_id: m.session_id.clone(),
        from: m.meta.from.clone(),
        to: m.meta.to.clone(),
        sent_at: m.meta.sent_at,
        expires_at: m.meta.expires_at,
        consignment: m.meta.consignment,
        plaintext_hash: m.plaintext_hash.clone(),
        envelope_hash: m.envelope_hash.clone(),
    }
}

/// A rejection carrying evidence in its error data.
fn evidenced(code: i64, message: &str, art: &Artefact, more: serde_json::Value) -> RpcError {
    let mut data = more;
    data["evidence"] = json!(crate::util::b64u(&art.raw));
    RpcError::with_data(code, message, data)
}

impl Rds {
    // ---- Evidence issuance ----

    /// Current head statements of both owners (doc 1 §5.4), and the first
    /// owner whose registry document is not active, if any.
    pub async fn heads(&self, m: &Meta) -> RpcResult<(Vec<Vec<u8>>, Option<(String, OwnerStatus)>)> {
        let mut heads = Vec::new();
        let mut inactive = None;
        for owner in [&m.from.owner, &m.to.owner] {
            let st = self.resolver.resolve(owner).await.map_err(RpcError::from)?;
            if st.document.status != OwnerStatus::Active && inactive.is_none() {
                inactive = Some((owner.clone(), st.document.status));
            }
            if !heads.contains(&st.head.raw) {
                heads.push(st.head.raw.clone());
            }
        }
        Ok((heads, inactive))
    }

    /// Issue an evidence artefact for a message and record it.
    pub async fn issue(&self, st: &mut State, mid: &[u8], event: Event, x: Extra) -> RpcResult<Artefact> {
        let meta = st.messages.get(mid).ok_or_else(|| RpcError::internal("unknown message"))?.meta.clone();
        let heads = match x.heads {
            Some(h) => h,
            None => self.heads(&meta).await?.0,
        };
        // The EDD status lists showing the head statements current (doc 1 §5.3).
        let mut statuses = Vec::new();
        for h in &heads {
            let uri = crate::registry::HeadStatement::parse(h).map_err(RpcError::from)?.body.status_list.uri;
            let tok = self.resolver.status(&uri).await.map_err(RpcError::from)?;
            if !statuses.contains(&tok.raw) {
                statuses.push(tok.raw);
            }
        }
        statuses.extend(x.statuses);
        let m = st.messages.get(mid).unwrap();
        let mls = st.sessions.get(&m.session_id).and_then(|s| s.contexts.get(m.epoch as usize)).map(|gc| MlsRef {
            group_context: gc.clone(),
            epoch_authenticator: m.epoch_authenticator.clone(),
        });
        let handovers = if x.handovers {
            let mut h: Vec<Handover> = m.handovers.values().cloned().collect();
            h.sort_by_key(|h| (h.transferred_at, h.subject.clone()));
            if h.is_empty() { None } else { Some(h) }
        } else {
            None
        };
        let t = now();
        let body = MessageEvidence {
            v: 1,
            evidence_id: random_bytes(16),
            event: event.uri(),
            issuer: self.issuer(),
            event_time: t,
            message: message_ref(m),
            mls,
            reason: x.reason,
            heads: heads.into_iter().map(ByteBuf::from).collect(),
            statuses: if statuses.is_empty() { None } else { Some(statuses.into_iter().map(ByteBuf::from).collect()) },
            sender_assurance: m.sender_assurance.clone(),
            recipient_assurance: x.recipient_assurance,
            peer: x.peer,
            prev: if matches!(event, Event::A1 | Event::A2) || m.last.is_empty() {
                None
            } else {
                Some(m.last.iter().cloned().map(ByteBuf::from).collect())
            },
            endpoint: x.endpoint,
            handovers,
            decisions: if x.decisions.is_empty() { None } else { Some(x.decisions.into_iter().map(ByteBuf::from).collect()) },
            reports: if x.reports.is_empty() { None } else { Some(x.reports.into_iter().map(ByteBuf::from).collect()) },
            eligible_holders: x.eligible_holders,
        };
        let art = self.sealer.seal(&body, t).map_err(RpcError::from)?;
        tracing::info!("evidence {} for message {}", event.code(), crate::util::b64u(mid));
        self.record(st, mid, art.clone());
        Ok(art)
    }

    /// Record an artefact (own or received) for a message.
    fn record(&self, st: &mut State, mid: &[u8], art: Artefact) {
        let m = st.messages.get_mut(mid).unwrap();
        if m.evidence.iter().any(|a| a.seal == art.seal) {
            return;
        }
        let ev = art.message().and_then(|b| b.event().ok());
        if let Some(e) = ev {
            m.last = vec![art.seal_hash()];
            if e.is_terminal() {
                m.terminal = Some(e);
            }
        }
        m.evidence.push(art);
    }

    /// Send evidence to the sender's endpoints and, if the sending RDS is a
    /// peer, to that RDS (doc 4 §7.7).
    fn distribute(self: &Arc<Self>, st: &mut State, mid: &[u8], art: &Artefact) {
        let m = st.messages.get(mid).unwrap();
        let event = art.message().and_then(|b| b.event().ok()).map(|e| e.code().to_string()).unwrap_or_default();
        let p = EvidenceNotifyParams {
            event: event.clone(),
            evidence: art.raw.clone(),
            message_id: Some(mid.to_vec()),
            session_id: None,
            seq: None,
        };
        if m.send_local {
            let from = m.meta.from.clone();
            let mut targets: Vec<EpKey> = st
                .sessions
                .get(&m.session_id)
                .and_then(|s| s.members.get(m.epoch as usize))
                .map(|ms| ms.iter().filter(|x| x.holds(&from)).map(|x| ep_key(&x.owner, &x.subject)).collect())
                .unwrap_or_default();
            if !targets.contains(&m.sender) {
                targets.push(m.sender.clone());
            }
            for k in targets {
                self.enqueue(st, &k, "wmp.evidence.notify", rpc::to_value(&p));
            }
        } else if let Some(peer) = st.sessions.get(&m.session_id).and_then(|s| s.peer.clone()) {
            let me = self.clone();
            tokio::spawn(async move {
                for attempt in 0..10u64 {
                    match me.call_peer(&peer, "wmp.evidence.notify", rpc::to_value(&p)).await {
                        Ok(_) => return,
                        Err(e) => {
                            tracing::warn!("evidence notify to {peer}: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(250 * (attempt + 1))).await;
                        }
                    }
                }
            });
        }
    }

    // ---- Checks shared by submission and relay (§7.1) ----

    /// Checks 2 to 5 of §7.1 against this RDS's view of the session. At
    /// relay (`a1` given), with the differences of §7.2: the message may be
    /// in the earlier epoch of A.1's GroupContext, membership
    /// is checked as of the message's epoch, and the recipient side's
    /// eligible endpoints may be those of any unexpired `scc.rds.subjects`
    /// answer this RDS gave (§9). A remote side whose RDS could not be
    /// reached (`None` in `remote`) is not checked here; the receiving RDS
    /// checks it at relay (doc 3 §5).
    /// Returns Err((code, message, scc reason, extra data)).
    async fn check_session_state(
        &self,
        st: &State,
        s: &Session,
        p: &DeliverParams,
        remote: &[Option<crate::delivery::SubjectsResult>],
        a1: Option<&MessageEvidence>,
    ) -> Result<u64, (i64, String, &'static str, serde_json::Value)> {
        let msg = crate::mls::parse_mls_message(&p.message).map_err(|e| (rpc::E_MLS, e.to_string(), "malformed", json!({})))?;
        // 2. PrivateMessage for this session and the current epoch.
        if msg.wire_format() != mls_rs::WireFormat::PrivateMessage || msg.group_id() != Some(&s.id[..]) {
            return Err((rpc::E_MLS, "not a PrivateMessage of this session".into(), "malformed", json!({})));
        }
        let epoch = msg.epoch().unwrap_or(u64::MAX);
        let earlier_ok = a1
            .map(|a| {
                // A.1 carries the GroupContext the sending RDS accepted the
                // message under; it must be this RDS's own GroupContext for
                // the message's epoch, which fixes that epoch too.
                let same_gc = a.mls.as_ref().map(|m| s.contexts.get(epoch as usize) == Some(&m.group_context)).unwrap_or(false);
                epoch < s.epoch && same_gc
            })
            .unwrap_or(false);
        if epoch != s.epoch && !earlier_ok {
            return Err((rpc::E_STALE_EPOCH, "Stale epoch".into(), "malformed", json!({"epoch": s.epoch})));
        }
        if s.closed {
            return Err((rpc::E_SESSION_CLOSED, "Session closed".into(), "malformed", json!({})));
        }
        // 3. from and to are the session's addresses.
        let fwd = p.meta.from == s.initiator && p.meta.to == s.responder;
        let back = p.meta.from == s.responder && p.meta.to == s.initiator;
        if !fwd && !back {
            return Err((rpc::E_INVALID_PARAMS, "from/to are not the session's addresses".into(), "malformed", json!({})));
        }
        // 4. Correctly formed (doc 3 §4.2, §5), as of the message's epoch.
        let cs = s.cipher_suite;
        let members = s.members.get(epoch as usize).cloned().unwrap_or_default();
        // Eligible subjects of each side: the other RDS's answer for a
        // remote side; this RDS's current list for a local side, and at
        // relay also each unexpired answer it gave for it.
        let mut fixed: Vec<(String, String)> = Vec::new();
        let mut no_kp: Vec<(String, String)> = Vec::new();
        let mut local: Vec<(Address, Vec<String>)> = Vec::new();
        let mut unchecked: Vec<String> = Vec::new();
        for a in s.addresses() {
            match remote.iter().zip([&s.initiator, &s.responder]).find(|(_, x)| *x == a) {
                Some((Some(r), _)) if !self.serves(&a.owner).await.unwrap_or(false) => {
                    fixed.extend(r.subjects.iter().map(|x| (a.owner.clone(), x.clone())));
                    no_kp.extend(r.no_key_packages.iter().map(|x| (a.owner.clone(), x.clone())));
                }
                Some((None, _)) if !self.serves(&a.owner).await.unwrap_or(false) => unchecked.push(a.owner.clone()),
                _ => {
                    let (subs, missing) = self.eligible_local(st, a, Some(cs)).await;
                    no_kp.extend(missing.into_iter().map(|x| (a.owner.clone(), x)));
                    local.push((a.clone(), subs));
                }
            }
        }
        // Candidate eligible sets: the current one first, then (at relay) one
        // per unexpired answer given for a local address.
        let current: Vec<(String, String)> = fixed.iter().cloned().chain(local.iter().flat_map(|(a, subs)| subs.iter().map(move |x| (a.owner.clone(), x.clone())))).collect();
        let mut candidates = vec![(current, true)];
        if a1.is_some() {
            for (a, _) in &local {
                for answer in self.answers_given(a) {
                    let mut c: Vec<(String, String)> = fixed.clone();
                    for (b, bsubs) in &local {
                        let use_subs = if b == a { &answer } else { bsubs };
                        c.extend(use_subs.iter().map(|x| (b.owner.clone(), x.clone())));
                    }
                    candidates.push((c, false));
                }
            }
        }
        let mut first: Option<(Vec<EndpointRef>, Vec<u32>)> = None;
        for (required, check_status) in candidates {
            let (add, remove) = self.membership_diff(s, &members, &required, &unchecked, check_status).await;
            if add.is_empty() && remove.is_empty() {
                return Ok(epoch);
            }
            first.get_or_insert((add, remove));
        }
        let (add, remove) = first.unwrap();
        // 5. Every missing endpoint must have a KeyPackage.
        let lacking: Vec<&EndpointRef> = add.iter().filter(|e| no_kp.contains(&(e.owner.clone(), e.subject.clone()))).collect();
        if !lacking.is_empty() {
            let subjects: Vec<String> = lacking.iter().map(|e| e.subject.clone()).collect();
            return Err((
                rpc::E_NO_KEYPACKAGE,
                format!("No KeyPackage for {}", subjects.join(", ")),
                "no-keypackage",
                json!({ "subjects": subjects }),
            ));
        }
        Err((
            rpc::E_MEMBERSHIP_MISMATCH,
            "Membership mismatch".into(),
            "membership-mismatch",
            rpc::to_value(&MembershipMismatch { add, remove }),
        ))
    }

    /// Endpoints to add and leaves to remove so that the members are
    /// exactly the `required` (EBW URL, subject) pairs. Members of the
    /// `unchecked` owners are left as they are. With `check_status`, a
    /// member's credential must also be valid now.
    async fn membership_diff(
        &self,
        s: &Session,
        members: &[crate::mls::MemberInfo],
        required: &[(String, String)],
        unchecked: &[String],
        check_status: bool,
    ) -> (Vec<EndpointRef>, Vec<u32>) {
        let t = now();
        let mut remove = Vec::new();
        let mut present = HashSet::new();
        for m in members {
            let id = (m.owner.clone(), m.subject.clone());
            if unchecked.contains(&m.owner) {
                continue;
            }
            let mut ok = required.contains(&id) && s.addresses().iter().any(|a| m.holds(a));
            if ok && check_status {
                // The leaf's own credential must be valid now.
                ok = t < m.exp
                    && match crate::credential::Credential::parse(&m.credential) {
                        Ok(c) => self.credential_status_ok(&c).await.is_ok(),
                        Err(_) => false,
                    };
            }
            if ok {
                present.insert(id);
            } else {
                remove.push(m.index);
            }
        }
        let add: Vec<EndpointRef> = required
            .iter()
            .filter(|id| !present.contains(*id) || members.iter().any(|m| remove.contains(&m.index) && m.owner == id.0 && m.subject == id.1))
            .map(|(d, s)| EndpointRef { owner: d.clone(), subject: s.clone() })
            .collect();
        (add, remove)
    }

    /// Checks 6 to 8 of §7.1. Returns Err((code, message, scc reason, data)).
    async fn check_policy(&self, p: &DeliverParams, peer_max_ttl: Option<u64>, peer_modes: Option<&[Consignment]>, skew_check: bool) -> Result<Vec<Vec<u8>>, (i64, String, &'static str, serde_json::Value)> {
        let t = now();
        let m = &p.meta;
        let max_ttl = peer_max_ttl.map(|x| x.min(self.cfg.max_ttl)).unwrap_or(self.cfg.max_ttl);
        let skew = m.sent_at.abs_diff(t);
        if (skew_check && skew > self.cfg.max_clock_skew) || m.expires_at <= m.sent_at || m.expires_at > m.sent_at + max_ttl || m.expires_at <= t {
            return Err((rpc::E_BAD_TIME, "Bad time".into(), "bad-time", json!({})));
        }
        let modes = peer_modes.map(|m| m.to_vec()).unwrap_or_else(|| self.cfg.consignment_modes.clone());
        if !modes.contains(&m.consignment) {
            return Err((rpc::E_CONSIGNMENT_UNSUPPORTED, "Consignment mode unsupported".into(), "consignment-unsupported", json!({})));
        }
        let (heads, inactive) = self.heads(m).await.map_err(|e| (e.code, e.message, "unknown-address", json!({})))?;
        if let Some((owner, status)) = inactive {
            let r = if owner == m.from.owner {
                "sender-not-active"
            } else {
                match status {
                    OwnerStatus::Retired | OwnerStatus::Closed => "recipient-retired",
                    OwnerStatus::Merged => "recipient-merged",
                    _ => "recipient-not-active",
                }
            };
            return Err((rpc::E_OWNER_NOT_ACTIVE, "Owner not active".into(), r, json!({"owner": owner, "status": status.as_str()})));
        }
        Ok(heads)
    }

    fn new_msg(&self, p: &DeliverParams, epoch: u64, sender: EpKey, assurance: Assurance, send_local: bool, recv_local: bool) -> Msg {
        Msg {
            meta: p.meta.clone(),
            session_id: p.session_id.clone(),
            envelope: p.message.clone(),
            envelope_hash: sha256(&p.message),
            plaintext_hash: p.plaintext_hash.clone(),
            epoch_authenticator: p.epoch_authenticator.clone(),
            epoch,
            send_local,
            recv_local,
            sender,
            sender_assurance: assurance,
            evidence: vec![],
            last: vec![],
            terminal: None,
            answer: None,
            recipients: vec![],
            handovers: Default::default(),
            reports: vec![],
            consigned: false,
            consent: None,
        }
    }

    // ---- Submission (§7.1) ----

    pub async fn submit(self: &Arc<Self>, caller: &EpKey, p: DeliverParams) -> RpcResult<Vec<u8>> {
        if p.meta.message_id.len() != 16 || p.plaintext_hash.len() != 32 {
            return Err(RpcError::params("bad message_id or plaintext_hash"));
        }
        if p.message.len() as u64 > self.cfg.max_message_size {
            return Err(RpcError::params("message too large"));
        }
        let mid = p.meta.message_id.clone();
        // Idempotent retry.
        let (session_peer, addrs, cs) = {
            let st = self.st.lock().await;
            if let Some(m) = st.messages.get(&mid) {
                if m.envelope == p.message {
                    if let Some(a) = &m.answer {
                        return Ok(a.clone());
                    }
                }
            }
            let s = st.sessions.get(&p.session_id).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
            (s.peer.clone(), [s.initiator.clone(), s.responder.clone()], s.cipher_suite)
        };
        // Eligible subjects of the other side, from its home RDS. If that
        // RDS cannot be reached, the other side is checked at relay, and the
        // message is held for relay meanwhile (§7.1, doc 3 §5).
        let mut remote = Vec::new();
        let peer_md = match &session_peer {
            Some(pr) => {
                for a in &addrs {
                    if !self.serves(&a.owner).await? {
                        match self.subjects(a, cs).await {
                            Ok(r) => remote.push(Some(r)),
                            Err(e) if e.code == rpc::E_PEER_UNREACHABLE => {
                                tracing::info!("{pr} unreachable; checking the sender's side only: {}", e.message);
                                remote.push(None);
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        remote.push(Some(crate::delivery::SubjectsResult { as_of: 0, expires_at: 0, subjects: vec![], no_key_packages: vec![] }));
                    }
                }
                Some(self.peer(pr)?.metadata)
            }
            None => None,
        };
        let mut st = self.st.lock().await;
        let s = st.sessions.get(&p.session_id).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
        // 1. The caller is a member on the from side.
        let members = s.members.last().cloned().unwrap_or_default();
        if !members.iter().any(|m| m.owner == caller.0 && m.subject == caller.1 && m.holds(&p.meta.from)) {
            return Err(RpcError::unauthorized("caller is not a member of the session on the from side"));
        }
        let auth_at = st.endpoints.get(caller).map(|e| e.auth_at).unwrap_or(0);
        let sender_cred = st.endpoints.get(caller).map(|e| e.credential.clone()).ok_or_else(|| RpcError::unauthorized("unknown endpoint"))?;
        let assurance = Assurance::scc(&self.cfg.identity_policy, auth_at);
        let recv_local = session_peer.is_none();
        let s = st.sessions.get(&p.session_id).unwrap();
        let checked = self.check_session_state(&st, s, &p, &remote, None).await;
        let epoch = match checked {
            Ok(e) => e,
            Err((rpc::E_NO_KEYPACKAGE, msg, r, data)) => {
                return Err(self.reject_a2(&mut st, caller, &p, assurance, reason(r, true, msg.clone()), rpc::E_NO_KEYPACKAGE, &msg, data).await);
            }
            Err((code, msg, _, data)) => return Err(RpcError::with_data(code, msg, data)),
        };
        // 6, 7, 8.
        let heads = match self
            .check_policy(&p, peer_md.as_ref().map(|m| m.max_ttl), peer_md.as_ref().map(|m| &m.consignment_modes[..]), true)
            .await
        {
            Ok(h) => h,
            Err((code, msg, r, data)) => {
                return Err(self.reject_a2(&mut st, caller, &p, assurance, reason(r, true, msg.clone()), code, &msg, data).await);
            }
        };
        // 9. New message ID.
        if st.messages.contains_key(&mid) {
            let r = reason("duplicate-message-id", true, "message ID already used");
            return Err(self.reject_a2(&mut st, caller, &p, assurance, r, rpc::E_DUPLICATE_MESSAGE_ID, "Duplicate message ID", json!({})).await);
        }
        let status = self.credential_status_ok(&sender_cred).await.map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        st.messages.insert(mid.clone(), self.new_msg(&p, epoch, caller.clone(), assurance, true, recv_local));
        let a1 = self
            .issue(&mut st, &mid, Event::A1, Extra { endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }), statuses: vec![status], heads: Some(heads), ..Default::default() })
            .await?;
        st.messages.get_mut(&mid).unwrap().answer = Some(a1.raw.clone());
        if let Some(s) = st.sessions.get_mut(&p.session_id) {
            s.last_activity = now();
        }
        // Queue for the other members on the sender's side.
        let from = p.meta.from.clone();
        let others: Vec<EpKey> = members
            .iter()
            .filter(|m| m.holds(&from) && !(m.owner == caller.0 && m.subject == caller.1))
            .map(|m| ep_key(&m.owner, &m.subject))
            .collect();
        for k in others {
            let mut q = p.clone();
            q.submission_evidence = None;
            self.enqueue(&mut st, &k, "wmp.message.deliver", rpc::to_value(&q));
        }
        drop(st);
        if recv_local {
            self.consign_start(mid.clone()).await;
        } else {
            let me = self.clone();
            let pr = session_peer.unwrap();
            let mut q = p.clone();
            q.submission_evidence = Some(a1.raw.clone());
            tokio::spawn(async move { me.relay(pr, mid, q).await });
        }
        Ok(a1.raw)
    }

    #[allow(clippy::too_many_arguments)]
    async fn reject_a2(&self, st: &mut State, caller: &EpKey, p: &DeliverParams, assurance: Assurance, r: Reason, code: i64, msg: &str, data: serde_json::Value) -> RpcError {
        let mid = p.meta.message_id.clone();
        if st.messages.contains_key(&mid) {
            // Reused ID: evidence the rejection under a fresh record is not
            // possible, so only report the error.
            return RpcError::with_data(code, msg, data);
        }
        st.messages.insert(mid.clone(), self.new_msg(p, header_epoch(p), caller.clone(), assurance, true, false));
        let heads = self.heads(&p.meta).await.map(|h| h.0).unwrap_or_default();
        // The status list relied on for the sender, if it could be checked (doc 5 §3.2).
        let mut statuses = Vec::new();
        if let Some(e) = st.endpoints.get(caller) {
            if let Ok(tok) = self.credential_status_ok(&e.credential).await {
                statuses.push(tok);
            }
        }
        match self
            .issue(st, &mid, Event::A2, Extra { reason: Some(r), endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }), statuses, heads: Some(heads), ..Default::default() })
            .await
        {
            Ok(a) => {
                st.messages.get_mut(&mid).unwrap().answer = Some(a.raw.clone());
                evidenced(code, msg, &a, data)
            }
            Err(e) => e,
        }
    }

    // ---- Relay, sending side (§7.2) ----

    async fn relay(self: Arc<Self>, peer: String, mid: Vec<u8>, p: DeliverParams) {
        let mut attempt = 0u64;
        loop {
            let mut q = p.clone();
            q.relayed_at = Some(now());
            let r = self.call_peer(&peer, "wmp.message.deliver", rpc::to_value(&q)).await;
            let art = match &r {
                Ok(v) => v.get("evidence").and_then(|e| e.as_str()).and_then(|s| crate::util::b64u_dec(s).ok()),
                Err(e) => e.evidence(),
            };
            if let Some(raw) = art {
                match self.accept_peer_evidence(&mid, &raw).await {
                    Ok(_) => return,
                    Err(e) => tracing::warn!("relay of {}: bad evidence from {peer}: {e}", crate::util::b64u(&mid)),
                }
            } else if let Err(e) = &r {
                tracing::warn!("relay of {} to {peer}: {e}", crate::util::b64u(&mid));
            }
            attempt += 1;
            let wait = std::time::Duration::from_millis((500 * attempt).min(5000));
            if now() + wait.as_secs() >= p.meta.expires_at {
                break;
            }
            tokio::time::sleep(wait).await;
        }
        // B.3: not reached before expiry.
        let mut st = self.st.lock().await;
        if st.messages.get(&mid).map(|m| m.terminal.is_none()).unwrap_or(false) {
            let x = Extra { reason: Some(Reason::new("RB09", Some("rds-unreachable"), None)), peer: Some(peer), ..Default::default() };
            if let Ok(a) = self.issue(&mut st, &mid, Event::B3, x).await {
                self.distribute(&mut st, &mid, &a);
            }
        }
    }

    /// Verify and store evidence from the peer RDS about one of our
    /// messages, and pass it to the sender's endpoints.
    pub async fn accept_peer_evidence(self: &Arc<Self>, mid: &[u8], raw: &[u8]) -> RpcResult<()> {
        let art = Artefact::parse(raw).map_err(RpcError::params)?;
        art.verify_seal(&self.trust).map_err(RpcError::params)?;
        let mut st = self.st.lock().await;
        let m = st.messages.get(mid).ok_or_else(|| RpcError::params("unknown message"))?;
        match &art.body {
            EvidenceBody::Message(b) => {
                if b.message != message_ref(m) {
                    return Err(RpcError::params("evidence is for a different message"));
                }
            }
            _ => return Err(RpcError::params("not message evidence")),
        }
        if m.evidence.iter().any(|a| a.seal == art.seal) {
            return Ok(());
        }
        self.record(&mut st, mid, art.clone());
        self.distribute(&mut st, mid, &art);
        Ok(())
    }

    // ---- Relay, receiving side (§7.2) ----

    pub async fn relay_in(self: &Arc<Self>, caller: &str, p: DeliverParams) -> RpcResult<Vec<u8>> {
        self.check_caller_serves(caller, &p.meta.from.owner).await?;
        if !self.serves(&p.meta.to.owner).await? {
            return Err(RpcError::new(rpc::E_WRONG_RDS, "recipient is not served here"));
        }
        let mid = p.meta.message_id.clone();
        let raw_a1 = p.submission_evidence.clone().ok_or_else(|| RpcError::params("relay without submission_evidence"))?;
        {
            let st = self.st.lock().await;
            if let Some(m) = st.messages.get(&mid) {
                if m.envelope == p.message {
                    if let Some(a) = &m.answer {
                        return Ok(a.clone());
                    }
                }
            }
        }
        // Verify A.1.
        let a1 = Artefact::parse(&raw_a1).map_err(RpcError::params)?;
        a1.verify_seal(&self.trust).map_err(|e| RpcError::params(format!("A.1: {e}")))?;
        let b = a1.message().ok_or_else(|| RpcError::params("A.1 is not message evidence"))?.clone();
        if b.event().ok() != Some(Event::A1) || b.issuer.rds != caller {
            return Err(RpcError::params("submission evidence is not A.1 from the caller"));
        }
        let expect = MessageRef {
            message_id: mid.clone(),
            session_id: p.session_id.clone(),
            from: p.meta.from.clone(),
            to: p.meta.to.clone(),
            sent_at: p.meta.sent_at,
            expires_at: p.meta.expires_at,
            consignment: p.meta.consignment,
            plaintext_hash: p.plaintext_hash.clone(),
            envelope_hash: sha256(&p.message),
        };
        if b.message != expect {
            return Err(RpcError::params("A.1 does not match the relayed message"));
        }
        if let Some(mls) = &b.mls {
            if mls.epoch_authenticator != p.epoch_authenticator {
                return Err(RpcError::params("A.1 epoch authenticator differs from the relayed one"));
            }
        }
        let (addrs, cs) = {
            let st = self.st.lock().await;
            let s = st.sessions.get(&p.session_id).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
            ([s.initiator.clone(), s.responder.clone()], s.cipher_suite)
        };
        let mut remote = Vec::new();
        for a in &addrs {
            if !self.serves(&a.owner).await? {
                remote.push(Some(self.subjects(a, cs).await?));
            } else {
                remote.push(Some(crate::delivery::SubjectsResult { as_of: 0, expires_at: 0, subjects: vec![], no_key_packages: vec![] }));
            }
        }
        let peer_md = self.peer(caller)?.metadata;
        let mut st = self.st.lock().await;
        let s = st.sessions.get(&p.session_id).unwrap();
        let mut m = self.new_msg(&p, 0, ep_key(&b.endpoint.as_ref().map(|e| e.owner.clone()).unwrap_or_default(), &b.endpoint.as_ref().map(|e| e.subject.clone()).unwrap_or_default()), b.sender_assurance.clone(), false, true);
        let checked = match self.check_session_state(&st, s, &p, &remote, Some(&b)).await {
            Ok(e) => self.check_policy(&p, Some(peer_md.max_ttl), None, false).await.map(|h| (e, h)),
            Err(e) => Err(e),
        };
        let fresh = !st.messages.contains_key(&mid);
        m.epoch = checked.as_ref().map(|c| c.0).unwrap_or_else(|_| header_epoch(&p));
        if fresh {
            st.messages.insert(mid.clone(), m);
            self.record(&mut st, &mid, a1.clone());
        }
        match checked {
            Ok((_, heads)) => {
                if !fresh {
                    return Err(RpcError::new(rpc::E_DUPLICATE_MESSAGE_ID, "Duplicate message ID"));
                }
                let b1 = self.issue(&mut st, &mid, Event::B1, Extra { peer: Some(caller.into()), heads: Some(heads), ..Default::default() }).await?;
                st.messages.get_mut(&mid).unwrap().answer = Some(b1.raw.clone());
                drop(st);
                let me = self.clone();
                let mid2 = mid.clone();
                tokio::spawn(async move {
                    // Let the B.1 answer reach the sending RDS first.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    me.consign_start(mid2).await;
                });
                Ok(b1.raw)
            }
            Err((code, msg, r, data)) => {
                if !fresh {
                    return Err(RpcError::with_data(code, msg, data));
                }
                let x = Extra { reason: Some(reason(r, false, msg.clone())), peer: Some(caller.into()), ..Default::default() };
                let b2 = self.issue(&mut st, &mid, Event::B2, x).await?;
                st.messages.get_mut(&mid).unwrap().answer = Some(b2.raw.clone());
                Err(evidenced(code, &msg, &b2, data))
            }
        }
    }

    // ---- Consignment (§7.3, §7.4) ----

    /// Recipient-side member endpoints served here, at the message's epoch.
    fn recipient_members(&self, st: &State, mid: &[u8]) -> Vec<(String, String)> {
        let m = st.messages.get(mid).unwrap();
        st.sessions
            .get(&m.session_id)
            .and_then(|s| s.members.get(m.epoch as usize))
            .map(|ms| ms.iter().filter(|x| x.holds(&m.meta.to)).map(|x| (x.subject.clone(), x.holder.clone())).collect())
            .unwrap_or_default()
    }

    pub async fn consign_start(self: &Arc<Self>, mid: Vec<u8>) {
        let mut st = self.st.lock().await;
        let Some(m) = st.messages.get(&mid) else { return };
        if m.terminal.is_some() {
            return;
        }
        let r = match m.meta.consignment {
            Consignment::Basic => self.consign(&mut st, &mid).await,
            Consignment::Consented => self.notify_for_acceptance(&mut st, &mid).await,
        };
        if let Err(e) = r {
            tracing::warn!("consignment of {}: {e}", crate::util::b64u(&mid));
        }
    }

    /// Make the message available: queue it for every recipient member and
    /// issue D.1.
    async fn consign(self: &Arc<Self>, st: &mut State, mid: &[u8]) -> RpcResult<()> {
        let recips = self.recipient_members(st, mid);
        let to_owner = st.messages[mid].meta.to.owner.clone();
        let d1 = self.issue(st, mid, Event::D1, Extra::default()).await?;
        let m = st.messages.get_mut(mid).unwrap();
        m.consigned = true;
        m.recipients = recips.iter().map(|r| r.0.clone()).collect();
        let p = DeliverParams {
            session_id: m.session_id.clone(),
            message: m.envelope.clone(),
            meta: m.meta.clone(),
            plaintext_hash: m.plaintext_hash.clone(),
            epoch_authenticator: m.epoch_authenticator.clone(),
            submission_evidence: None,
            relayed_at: None,
            seq: None,
        };
        for (sub, _) in recips {
            self.enqueue(st, &ep_key(&to_owner, &sub), "wmp.message.deliver", rpc::to_value(&p));
        }
        self.distribute(st, mid, &d1);
        Ok(())
    }

    async fn notify_for_acceptance(self: &Arc<Self>, st: &mut State, mid: &[u8]) -> RpcResult<()> {
        let recips = self.recipient_members(st, mid);
        let to = st.messages[mid].meta.to.clone();
        let (eligible, _) = self.eligible_local(st, &to, None).await;
        let holders: HashSet<String> = st
            .endpoints
            .values()
            .filter(|e| e.owner == to.owner && eligible.contains(&e.subject))
            .map(|e| e.credential.claims.holder_id())
            .collect();
        let c1 = self.issue(st, mid, Event::C1, Extra { eligible_holders: Some(holders.len() as u64), ..Default::default() }).await?;
        let m = st.messages.get_mut(mid).unwrap();
        m.consent = Some(ConsentState { notified: recips.iter().map(|r| r.0.clone()).collect(), eligible_holders: holders, ..Default::default() });
        let p = crate::delivery::ConsentRequestParams {
            seq: 0,
            session_id: m.session_id.clone(),
            meta: m.meta.clone(),
            envelope_hash: m.envelope_hash.clone(),
            size: m.envelope.len() as u64,
        };
        for (sub, _) in recips {
            self.enqueue(st, &ep_key(&to.owner, &sub), "scc.consent.request", rpc::to_value(&p));
        }
        self.distribute(st, mid, &c1);
        Ok(())
    }

    /// Queue items confirmed by an endpoint: transfers (§7.3) and consent
    /// request deliveries (§7.4 step 2).
    pub async fn on_queue_ack(self: &Arc<Self>, caller: &EpKey, removed: Vec<(String, serde_json::Value)>) {
        let mut st = self.st.lock().await;
        let t = now();
        for (method, params) in removed {
            let Some(mid) = params.get("meta").and_then(|m| m.get("message_id")).and_then(|v| v.as_str()).and_then(|s| crate::util::b64u_dec(s).ok()) else {
                continue;
            };
            let Some(m) = st.messages.get_mut(&mid) else { continue };
            if m.terminal.is_some() || !m.recv_local || m.meta.to.owner != caller.0 {
                continue;
            }
            match method.as_str() {
                "wmp.message.deliver" if m.recipients.contains(&caller.1) => {
                    m.handovers.entry(caller.1.clone()).or_insert(Handover {
                        subject: caller.1.clone(),
                        transferred_at: t,
                        acknowledged_at: None,
                        result: None,
                    });
                }
                "scc.consent.request" => {
                    let first = m.consent.as_ref().map(|c| !c.c6).unwrap_or(false);
                    if first {
                        m.consent.as_mut().unwrap().c6 = true;
                        let cred = st.endpoints.get(caller).map(|e| e.credential.clone());
                        let mut statuses = Vec::new();
                        if let Some(c) = &cred {
                            if let Ok(tok) = self.credential_status_ok(c).await {
                                statuses.push(tok);
                            }
                        }
                        let x = Extra { endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }), statuses, ..Default::default() };
                        if let Ok(a) = self.issue(&mut st, &mid, Event::C6, x).await {
                            self.distribute(&mut st, &mid, &a);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// `wmp.message.ack` from a recipient endpoint (§7.4, §7.5).
    pub async fn message_ack(self: &Arc<Self>, caller: &EpKey, p: crate::delivery::MessageAckParams) -> RpcResult<Option<Vec<u8>>> {
        use crate::delivery::AckStatus;
        match p.status {
            AckStatus::Processed | AckStatus::Failed => {
                let raw = p.report.ok_or_else(|| RpcError::params("report required"))?;
                self.on_report(caller, &p.message_id, raw).await
            }
            AckStatus::Accepted | AckStatus::Rejected => {
                let raw = p.decision.ok_or_else(|| RpcError::params("decision required"))?;
                self.on_decision(caller, &p.message_id, raw).await
            }
        }
    }

    async fn on_report(self: &Arc<Self>, caller: &EpKey, mid: &[u8], raw: Vec<u8>) -> RpcResult<Option<Vec<u8>>> {
        let stmt = evidence::parse_statement::<DecryptionReport>(&raw).map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        if stmt.body.owner != caller.0 || stmt.body.subject != caller.1 {
            return Err(RpcError::unauthorized("report is not from the caller"));
        }
        let status = self.credential_status_ok(&stmt.credential).await.map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        let mut st = self.st.lock().await;
        let auth_at = st.endpoints.get(caller).map(|e| e.auth_at).unwrap_or(0);
        let m = st.messages.get(mid).ok_or_else(|| RpcError::params("unknown message"))?;
        let r = &stmt.body;
        if r.message_id != mid || r.session_id != m.session_id || r.envelope_hash != m.envelope_hash || r.epoch != m.epoch {
            return Err(RpcError::params("report does not match the message"));
        }
        let member = st
            .sessions
            .get(&m.session_id)
            .and_then(|s| s.members.get(m.epoch as usize))
            .and_then(|ms| ms.iter().find(|x| x.owner == caller.0 && x.subject == caller.1).cloned())
            .ok_or_else(|| RpcError::unauthorized("reporter was not a member at the message's epoch"))?;
        // A match report agrees with the sender's epoch authenticator and
        // plaintext hash (doc 5 §4).
        let success = r.result == ReportResult::Match && member.holds(&m.meta.to);
        let t = now();
        let m = st.messages.get_mut(mid).unwrap();
        m.reports.push(Report { subject: caller.1.clone(), raw: raw.clone(), result: r.result, success, status_token: status.clone() });
        if m.terminal.is_some() {
            return Ok(None);
        }
        let h = m.handovers.entry(caller.1.clone()).or_insert(Handover { subject: caller.1.clone(), transferred_at: t, acknowledged_at: None, result: None });
        h.acknowledged_at = Some(t);
        h.result = Some(r.result.as_str().into());
        let art = if success {
            let x = Extra {
                endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }),
                statuses: vec![status],
                recipient_assurance: Some(Assurance::scc(&self.cfg.identity_policy, auth_at)),
                handovers: true,
                reports: vec![raw],
                ..Default::default()
            };
            Some(self.issue(&mut st, mid, Event::E1, x).await?)
        } else {
            let m = &st.messages[mid];
            let reported: HashSet<&String> = m.reports.iter().map(|r| &r.subject).collect();
            if m.recipients.iter().all(|s| reported.contains(s)) {
                Some(self.handover_failure(&mut st, mid, "decryption-failed").await?)
            } else {
                None
            }
        };
        if let Some(a) = &art {
            self.distribute(&mut st, mid, a);
        }
        Ok(art.map(|a| a.raw))
    }

    async fn handover_failure(&self, st: &mut State, mid: &[u8], why: &str) -> RpcResult<Artefact> {
        let m = &st.messages[mid];
        let reports: Vec<Vec<u8>> = m.reports.iter().filter(|r| !r.success).map(|r| r.raw.clone()).collect();
        let statuses: Vec<Vec<u8>> = {
            let mut v: Vec<Vec<u8>> = Vec::new();
            for r in m.reports.iter().filter(|r| !r.success) {
                if !v.contains(&r.status_token) {
                    v.push(r.status_token.clone());
                }
            }
            v
        };
        let code = match why {
            "decryption-failed" => "REXX",
            _ => "RE04",
        };
        let x = Extra { reason: Some(Reason::new(code, Some(why), None)), handovers: true, reports, statuses, ..Default::default() };
        self.issue(st, mid, Event::E2, x).await
    }

    async fn on_decision(self: &Arc<Self>, caller: &EpKey, mid: &[u8], raw: Vec<u8>) -> RpcResult<Option<Vec<u8>>> {
        let stmt = evidence::parse_statement::<ConsentDecision>(&raw).map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        if stmt.body.owner != caller.0 || stmt.body.subject != caller.1 {
            return Err(RpcError::unauthorized("decision is not from the caller"));
        }
        let status = self.credential_status_ok(&stmt.credential).await.map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        let mut st = self.st.lock().await;
        let auth_at = st.endpoints.get(caller).map(|e| e.auth_at).unwrap_or(0);
        let m = st.messages.get(mid).ok_or_else(|| RpcError::params("unknown message"))?;
        let d = &stmt.body;
        if d.message_id != mid || d.session_id != m.session_id || d.envelope_hash != m.envelope_hash {
            return Err(RpcError::params("decision does not match the message"));
        }
        if m.terminal.is_some() || m.consent.is_none() || m.consigned {
            return Ok(None);
        }
        let holds = stmt.credential.claims.roles.contains(&m.meta.to.role) && stmt.credential.claims.iss == m.meta.to.owner;
        if !holds {
            return Err(RpcError::unauthorized("endpoint does not hold the recipient role"));
        }
        let holder = stmt.credential.claims.holder_id();
        let accept = d.decision == Decision::Accept;
        // A decision before the consent request was confirmed implies C.6.
        if !m.consent.as_ref().unwrap().c6 {
            st.messages.get_mut(mid).unwrap().consent.as_mut().unwrap().c6 = true;
            let x = Extra { endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }), statuses: vec![status.clone()], ..Default::default() };
            let a = self.issue(&mut st, mid, Event::C6, x).await?;
            self.distribute(&mut st, mid, &a);
        }
        let m = st.messages.get_mut(mid).unwrap();
        let c = m.consent.as_mut().unwrap();
        if c.decisions.iter().any(|x| x.0 == caller.1) {
            return Ok(None);
        }
        c.decisions.push((caller.1.clone(), holder, raw.clone(), accept));
        if !c.statuses.contains(&status) {
            c.statuses.push(status.clone());
        }
        let ra = Some(Assurance::scc(&self.cfg.identity_policy, auth_at));
        if !accept {
            let x = Extra {
                endpoint: Some(EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() }),
                decisions: vec![raw],
                statuses: vec![status],
                reason: Some(Reason::new("RC08", Some("refused"), None)),
                recipient_assurance: ra,
                ..Default::default()
            };
            let a = self.issue(&mut st, mid, Event::C4, x).await?;
            self.distribute(&mut st, mid, &a);
            return Ok(Some(a.raw));
        }
        // Evaluate the acceptance policy with the registry document named in B.1.
        let to = m.meta.to.clone();
        let policy = self.resolver.resolve(&to.owner).await.map_err(RpcError::from)?.document.policy_for(&to.role);
        let m = st.messages.get(mid).unwrap();
        let c = m.consent.as_ref().unwrap();
        let accepted: HashSet<&String> = c.decisions.iter().filter(|d| d.3).map(|d| &d.1).collect();
        let met = match policy {
            AcceptancePolicy::Any => !accepted.is_empty(),
            AcceptancePolicy::All => c.eligible_holders.iter().all(|h| accepted.contains(h)),
            AcceptancePolicy::Quorum(n) => accepted.len() as u64 >= n,
        };
        if !met {
            return Ok(None);
        }
        let decisions: Vec<Vec<u8>> = c.decisions.iter().filter(|d| d.3).map(|d| d.2.clone()).collect();
        let statuses = c.statuses.clone();
        let x = Extra { decisions, statuses, recipient_assurance: ra, reason: Some(Reason::new("RC07", None, None)), ..Default::default() };
        let a = self.issue(&mut st, mid, Event::C3, x).await?;
        self.distribute(&mut st, mid, &a);
        self.consign(&mut st, mid).await?;
        Ok(Some(a.raw))
    }

    // ---- Expiry (§7.3, §7.4) ----

    pub async fn expire(self: &Arc<Self>) {
        let mut st = self.st.lock().await;
        let t = now();
        let due: Vec<Vec<u8>> = st
            .messages
            .iter()
            .filter(|(_, m)| m.recv_local && m.terminal.is_none() && m.meta.expires_at <= t && !m.evidence.is_empty())
            .map(|(k, _)| k.clone())
            .collect();
        for mid in due {
            let m = &st.messages[&mid];
            let r = if !m.consigned {
                match &m.consent {
                    Some(c) if c.c6 => self.issue(&mut st, &mid, Event::C5, Extra { reason: Some(Reason::new("RC09", Some("expired"), None)), ..Default::default() }).await,
                    Some(_) => self.issue(&mut st, &mid, Event::C2, Extra { reason: Some(Reason::new("RC05", Some("notification-failed"), None)), ..Default::default() }).await,
                    None => continue,
                }
            } else if m.handovers.is_empty() {
                self.handover_failure(&mut st, &mid, "expired").await
            } else if m.reports.is_empty() {
                self.handover_failure(&mut st, &mid, "not-acknowledged").await
            } else {
                self.handover_failure(&mut st, &mid, "decryption-failed").await
            };
            match r {
                Ok(a) => self.distribute(&mut st, &mid, &a),
                Err(e) => tracing::warn!("expiry of {}: {e}", crate::util::b64u(&mid)),
            }
        }
    }

    // ---- Evidence packages (05-evidence.md §3.6) ----

    pub async fn evidence_package(&self, caller: &EpKey, mid: &[u8]) -> RpcResult<Vec<u8>> {
        let st = self.st.lock().await;
        let m = st.messages.get(mid).ok_or_else(|| RpcError::params("unknown message"))?;
        if caller.0 != m.meta.from.owner && caller.0 != m.meta.to.owner {
            return Err(RpcError::unauthorized("not a party to this message"));
        }
        if m.terminal.is_none() {
            return Err(RpcError::new(rpc::E_EVIDENCE_INCOMPLETE, "Evidence incomplete: the message has not reached its terminal event"));
        }
        // Items in issue order: a topological order of the chain.
        let mut placed: Vec<&Artefact> = Vec::new();
        let mut placed_hashes: HashSet<Vec<u8>> = HashSet::new();
        let mut rest: Vec<&Artefact> = m.evidence.iter().collect();
        while !rest.is_empty() {
            let before = rest.len();
            rest.retain(|a| {
                let prev = a.message().map(|b| b.prev_hashes()).unwrap_or_default();
                if prev.iter().all(|p| placed_hashes.contains(p)) {
                    placed_hashes.insert(a.seal_hash());
                    placed.push(a);
                    false
                } else {
                    true
                }
            });
            if rest.len() == before {
                // Notifications can arrive out of order: some evidence the
                // chain refers to has not arrived yet (doc 4 §7.7).
                return Err(RpcError::new(rpc::E_EVIDENCE_INCOMPLETE, "Evidence incomplete: the RDS does not yet hold the whole chain"));
            }
        }
        let pkg = EvidencePackage {
            v: 1,
            st_type: "evidence-package".into(),
            message_id: mid.to_vec(),
            composed_at: now(),
            items: placed.iter().map(|a| a.as_items()).collect(),
        };
        Ok(self.sealer.seal(&pkg, now()).map_err(RpcError::from)?.raw)
    }
}

/// The epoch in the `PrivateMessage` header (0 if it cannot be parsed).
/// Evidence for a rejected message takes its GroupContext from this epoch
/// (doc 5 §3.2).
fn header_epoch(p: &DeliverParams) -> u64 {
    crate::mls::parse_mls_message(&p.message).ok().and_then(|m| m.epoch()).unwrap_or(0)
}
