//! Sessions, Commit checks and two-sided acceptance (03-mls.md §4, §6;
//! 04-delivery.md §8).

use super::{ep_key, KpState, PendingCommit, Rds, Session, State};
use crate::delivery::{LogEntry, RdsCommitResult};
use crate::mls::{self, MemberInfo};
use crate::rpc::{self, RpcError, RpcResult};
use crate::types::Address;
use crate::util::now;
use mls_rs::external_client::{ExternalReceivedMessage, ExternalSnapshot};
use mls_rs::group::CommitEffect;
use mls_rs::mls_rules::ProposalInfo;
use mls_rs::WireFormat;
use mls_rs_codec::MlsEncode;
use serde_json::json;
use std::collections::HashSet;

/// The result of checking a Commit: the next epoch's state.
#[derive(Clone)]
pub struct Provisional {
    pub epoch: u64,
    pub snapshot: Vec<u8>,
    pub context: Vec<u8>,
    pub members: Vec<MemberInfo>,
    /// KeyPackages added, by hash, with the endpoint they belong to.
    pub added: Vec<(String, String, Vec<u8>)>,
    pub added_members: Vec<u32>,
    pub committer: u32,
}

fn stale(epoch: u64) -> RpcError {
    RpcError::with_data(rpc::E_STALE_EPOCH, "Stale epoch", json!({ "epoch": epoch }))
}

impl Rds {
    /// Observe a creation GroupInfo (epoch 0) and check it (doc 3 §4.1).
    pub fn observe_group_info(&self, session_id: &[u8], gi: &[u8]) -> RpcResult<(Session, mls::SccSession)> {
        if !(16..=32).contains(&session_id.len()) {
            return Err(RpcError::params("session ID must be 16 to 32 bytes"));
        }
        let msg = mls::parse_mls_message(gi).map_err(RpcError::mls)?;
        let obs = mls::observer_client(self.ip.clone());
        let g = obs.observe_group(msg, None, None).map_err(|e| RpcError::mls(format!("GroupInfo: {e:?}")))?;
        let ctx = g.group_context();
        if ctx.group_id != session_id {
            return Err(RpcError::mls("GroupInfo group_id is not the session ID"));
        }
        if ctx.epoch != 0 {
            return Err(RpcError::mls("creation GroupInfo must be for epoch 0"));
        }
        let s = mls::check_session_extensions(&ctx.extensions).map_err(RpcError::mls)?;
        let (initiator, responder) = s.addresses().map_err(RpcError::mls)?;
        let members = mls::members_of(&g.roster().members()).map_err(RpcError::mls)?;
        let t = now();
        Ok((
            Session {
                id: session_id.to_vec(),
                initiator,
                responder,
                cipher_suite: *ctx.cipher_suite,
                snapshot: g.snapshot().to_bytes().map_err(RpcError::mls)?,
                epoch: 0,
                group_info: gi.to_vec(),
                log: vec![],
                contexts: vec![ctx.mls_encode_to_vec().map_err(RpcError::mls)?],
                members: vec![members],
                pending: None,
                peer: None,
                closed: false,
                last_activity: t,
            },
            s,
        ))
    }

    /// Check a Commit against the current state of a session (doc 3 §6.2)
    /// and compute the next epoch.
    pub async fn check_commit(&self, st: &State, s: &Session, commit: &[u8], welcome: Option<&[u8]>) -> RpcResult<Provisional> {
        if s.closed {
            return Err(RpcError::new(rpc::E_SESSION_CLOSED, "Session closed"));
        }
        let msg = mls::parse_mls_message(commit).map_err(RpcError::mls)?;
        // 1. A PublicMessage for this session and the current epoch.
        if msg.wire_format() != WireFormat::PublicMessage {
            return Err(RpcError::mls("Commits must be PublicMessages"));
        }
        if msg.group_id() != Some(&s.id[..]) {
            return Err(RpcError::new(rpc::E_UNKNOWN_SESSION, "Commit is for another session"));
        }
        if msg.epoch() != Some(s.epoch) {
            return Err(stale(s.epoch));
        }
        // 2, 3, 5, 6: mls-rs checks the sender, signature, proposals,
        // new LeafNodes (through the SCC identity provider) and parent
        // hashes, and computes the next GroupContext.
        let obs = mls::observer_client(self.ip.clone());
        let snap = ExternalSnapshot::from_bytes(&s.snapshot).map_err(RpcError::internal)?;
        let mut g = obs.load_group(snap).map_err(RpcError::internal)?;
        let r = g.process_incoming_message(msg).map_err(|e| RpcError::mls(format!("Commit rejected: {e:?}")))?;
        let desc = match r {
            ExternalReceivedMessage::Commit(d) => d,
            _ => return Err(RpcError::mls("not a Commit")),
        };
        let session = mls::check_session_extensions(&g.group_context().extensions).map_err(RpcError::mls)?;
        let proposals: Vec<ProposalInfo<mls_rs::group::proposal::Proposal>> = match &desc.effect {
            CommitEffect::NewEpoch(e) => e.applied_proposals().to_vec(),
            CommitEffect::Removed { new_epoch, .. } => new_epoch.applied_proposals().to_vec(),
            CommitEffect::ReInit(_) => return Err(RpcError::mls("ReInit is not allowed")),
        };
        let mut added = Vec::new();
        let t = now();
        for p in &proposals {
            mls::check_proposal_allowed(&p.proposal, &session).map_err(RpcError::mls)?;
            if let mls_rs::group::proposal::Proposal::Add(a) = &p.proposal {
                // 4. Valid, unused, not last-resort, eligible.
                let kp = a.key_package();
                mls::check_not_last_resort(kp).map_err(RpcError::mls)?;
                let hash = mls::mls_hash(&kp.mls_encode_to_vec().map_err(RpcError::mls)?);
                let cred = mls::parse_leaf_credential(kp.signing_identity()).map_err(RpcError::mls)?;
                let (owner, sub) = (cred.claims.iss.clone(), cred.claims.sub.clone());
                let side: Vec<&Address> = s.addresses().into_iter().filter(|a| a.owner == owner).collect();
                if side.is_empty() || !side.iter().any(|a| cred.claims.roles.contains(&a.role)) {
                    return Err(RpcError::new(rpc::E_MEMBERSHIP_MISMATCH, format!("{owner}/{sub} is not eligible for this session")));
                }
                if self.serves(&owner).await? {
                    let e = st
                        .endpoints
                        .get(&ep_key(&owner, &sub))
                        .filter(|e| e.registered)
                        .ok_or_else(|| RpcError::new(rpc::E_MEMBERSHIP_MISMATCH, format!("{sub} is not registered here")))?;
                    let k = e
                        .kps
                        .iter()
                        .find(|k| k.hash == hash)
                        .ok_or_else(|| RpcError::mls(format!("KeyPackage of {sub} was not published here")))?;
                    if k.state == KpState::Consumed || t >= k.not_after {
                        return Err(RpcError::mls(format!("KeyPackage of {sub} was already used or expired")));
                    }
                    let mut ok = false;
                    for a in &side {
                        if cred.claims.roles.contains(&a.role) && self.eligible_local(st, a, None).await.0.contains(&sub) {
                            ok = true;
                        }
                    }
                    if !ok {
                        return Err(RpcError::new(rpc::E_MEMBERSHIP_MISMATCH, format!("{sub} is not eligible")));
                    }
                }
                added.push((owner, sub, hash));
            }
        }
        // 7. No two leaves with the same identity, and every leaf belongs
        // to a side of the session.
        let members = mls::members_of(&g.roster().members()).map_err(RpcError::mls)?;
        let mut ids = HashSet::new();
        for m in &members {
            if !ids.insert((m.owner.clone(), m.subject.clone())) {
                return Err(RpcError::mls(format!("two leaves have identity {}/{}", m.owner, m.subject)));
            }
            if !s.addresses().iter().any(|a| m.holds(a)) {
                return Err(RpcError::new(rpc::E_MEMBERSHIP_MISMATCH, format!("{}/{} holds no role of the session", m.owner, m.subject)));
            }
        }
        if !added.is_empty() && welcome.is_none() {
            return Err(RpcError::mls("a Commit that adds members needs a Welcome"));
        }
        let added_members = members
            .iter()
            .filter(|m| added.iter().any(|(d, s, _)| d == &m.owner && s == &m.subject))
            .map(|m| m.index)
            .collect();
        let ctx = g.group_context();
        Ok(Provisional {
            epoch: ctx.epoch,
            snapshot: g.snapshot().to_bytes().map_err(RpcError::internal)?,
            context: ctx.mls_encode_to_vec().map_err(RpcError::internal)?,
            members,
            added,
            added_members,
            committer: desc.committer,
        })
    }

    /// Append an accepted Commit to the log (doc 3 §6.4), consume its
    /// KeyPackages, and distribute it to this RDS's members (doc 4 §8.3).
    pub fn apply_commit(&self, st: &mut State, sid: &[u8], prov: Provisional, commit: Vec<u8>, welcome: Option<Vec<u8>>) {
        let t = now();
        for (owner, sub, hash) in &prov.added {
            if let Some(e) = st.endpoints.get_mut(&ep_key(owner, sub)) {
                for k in e.kps.iter_mut().filter(|k| &k.hash == hash) {
                    k.state = KpState::Consumed;
                }
            }
        }
        let s = st.sessions.get_mut(sid).expect("session exists");
        let committer = s.members.last().and_then(|m| m.iter().find(|m| m.index == prov.committer).cloned());
        s.epoch = prov.epoch;
        s.snapshot = prov.snapshot.clone();
        s.contexts.push(prov.context.clone());
        s.members.push(prov.members.clone());
        s.log.push(LogEntry { epoch: prov.epoch, commit: commit.clone(), welcome: welcome.clone(), accepted_at: t });
        s.pending = None;
        s.last_activity = t;
        tracing::info!("session {} epoch {} accepted ({} members)", crate::util::b64u(sid), prov.epoch, prov.members.len());
        let mut targets = Vec::new();
        for m in &prov.members {
            if committer.as_ref().map(|c| c.owner == m.owner && c.subject == m.subject).unwrap_or(false) {
                continue;
            }
            let k = ep_key(&m.owner, &m.subject);
            if !st.endpoints.contains_key(&k) {
                continue;
            }
            let new = prov.added_members.contains(&m.index);
            targets.push((k, new));
        }
        for (k, new) in targets {
            let p = crate::delivery::HandshakeParams {
                seq: 0,
                session_id: sid.to_vec(),
                epoch: prov.epoch,
                commit: if new { None } else { Some(commit.clone()) },
                welcome: if new { welcome.clone() } else { None },
            };
            self.enqueue(st, &k, "scc.handshake", rpc::to_value(&p));
        }
    }

    /// `scc.commit.submit` from a member endpoint, with two-sided
    /// acceptance (doc 3 §6.3).
    pub async fn submit_commit(&self, caller: &super::EpKey, sid: &[u8], commit: Vec<u8>, welcome: Option<Vec<u8>>, reservations: Option<Vec<String>>) -> RpcResult<u64> {
        let commit_ref = mls::mls_hash(&commit);
        let peer = {
            let mut st = self.st.lock().await;
            let s = st.sessions.get(sid).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
            if !s.members.last().unwrap().iter().any(|m| m.owner == caller.0 && m.subject == caller.1) {
                return Err(RpcError::unauthorized("caller is not a member of the session"));
            }
            if let Some(e) = s.log.iter().find(|e| mls::mls_hash(&e.commit) == commit_ref) {
                return Ok(e.epoch);
            }
            if s.pending.as_ref().map(|p| !p.superseded).unwrap_or(false) {
                return Err(RpcError::new(rpc::E_COMMIT_CONFLICT, "Commit conflict: another Commit is pending"));
            }
            let prov = self.check_commit(&st, s, &commit, welcome.as_deref()).await?;
            let peer = s.peer.clone();
            let s = st.sessions.get_mut(sid).unwrap();
            match &peer {
                None => {
                    let e = prov.epoch;
                    self.apply_commit(&mut st, sid, prov, commit, welcome);
                    return Ok(e);
                }
                Some(_) => {
                    s.pending = Some(PendingCommit { commit_ref: commit_ref.clone(), prov, commit: commit.clone(), welcome: welcome.clone(), superseded: false });
                }
            }
            peer.unwrap()
        };
        let params = crate::delivery::CommitSubmitParams { session_id: sid.to_vec(), commit: commit.clone(), welcome: welcome.clone(), reservations };
        let mut attempt = 0;
        let r = loop {
            match self.call_peer(&peer, "scc.rds.commit", rpc::to_value(&params)).await {
                Err(e) if e.code == rpc::E_INTERNAL && attempt < 5 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(200 * attempt)).await;
                }
                r => break r,
            }
        };
        let mut st = self.st.lock().await;
        let s = st.sessions.get_mut(sid).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
        let pending = match s.pending.take() {
            Some(p) if p.commit_ref == commit_ref => p,
            other => {
                s.pending = other;
                return Err(RpcError::new(rpc::E_COMMIT_CONFLICT, "Commit conflict"));
            }
        };
        match r {
            Ok(v) => {
                let _: RdsCommitResult = rpc::params(v)?;
                if pending.superseded {
                    return Err(RpcError::new(rpc::E_COMMIT_CONFLICT, "Commit conflict"));
                }
                let e = pending.prov.epoch;
                self.apply_commit(&mut st, sid, pending.prov, pending.commit, pending.welcome);
                Ok(e)
            }
            Err(e) => Err(e),
        }
    }

    /// `scc.rds.commit` from the peer RDS (doc 3 §6.3, peer side).
    pub async fn peer_commit(&self, caller: &str, sid: &[u8], commit: Vec<u8>, welcome: Option<Vec<u8>>) -> RpcResult<RdsCommitResult> {
        let commit_ref = mls::mls_hash(&commit);
        let msg = mls::parse_mls_message(&commit).map_err(RpcError::mls)?;
        let n = msg.epoch().ok_or_else(|| RpcError::mls("Commit without epoch"))?;
        let mut st = self.st.lock().await;
        let s = st.sessions.get(sid).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
        if s.peer.as_deref() != Some(caller) {
            return Err(RpcError::new(rpc::E_WRONG_RDS, "caller is not the peer RDS of this session"));
        }
        // 1. Already accepted.
        if let Some(e) = s.log.iter().find(|e| e.epoch == n + 1) {
            if mls::mls_hash(&e.commit) == commit_ref {
                return Ok(RdsCommitResult { status: "accepted".into(), epoch: e.epoch });
            }
        }
        // 2. Stale epoch.
        if s.epoch != n {
            return Err(stale(s.epoch));
        }
        // 3. Concurrent Commits: the smaller commit_ref wins.
        if let Some(p) = &s.pending {
            if !p.superseded {
                if commit_ref < p.commit_ref {
                    tracing::info!("concurrent Commit from {caller} wins");
                } else {
                    return Err(RpcError::new(rpc::E_COMMIT_CONFLICT, "Commit conflict: a concurrent Commit won"));
                }
            }
        }
        // 4. Check and append.
        let prov = self.check_commit(&st, s, &commit, welcome.as_deref()).await?;
        let s = st.sessions.get_mut(sid).unwrap();
        if let Some(p) = s.pending.as_mut() {
            p.superseded = true;
        }
        let pending = s.pending.take();
        let e = prov.epoch;
        self.apply_commit(&mut st, sid, prov, commit, welcome);
        // Keep the superseded marker so the local submitter learns it lost.
        if let Some(mut p) = pending {
            p.superseded = true;
            st.sessions.get_mut(sid).unwrap().pending = Some(p);
        }
        Ok(RdsCommitResult { status: "accepted".into(), epoch: e })
    }
}
