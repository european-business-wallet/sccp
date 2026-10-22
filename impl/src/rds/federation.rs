//! The federation JSON-RPC API between RDSes (04-delivery.md §4.3, §9).

use super::Rds;
use crate::delivery::*;
use crate::evidence::{Artefact, EvidenceBody};
use crate::rpc::{self, params, to_value, RpcError, RpcResult};
use crate::util::now;
use serde_json::{json, Value};
use std::sync::Arc;

impl Rds {
    pub async fn handle_federation(self: &Arc<Self>, caller: &str, method: &str, p: Value) -> RpcResult {
        tracing::debug!("<- {caller} {method}");
        match method {
            "scc.rds.subjects" => {
                let p: SubjectsParams = params(p)?;
                if !self.serves(&p.address.owner).await? {
                    return Err(RpcError::new(rpc::E_WRONG_RDS, "address not served here"));
                }
                let st = self.st.lock().await;
                let (subjects, no_key_packages) = self.eligible_local(&st, &p.address, Some(p.cipher_suite)).await;
                let t = now();
                let r = SubjectsResult { as_of: t, expires_at: t + self.cfg.subjects_ttl, subjects, no_key_packages };
                // The answer binds this RDS at relay until it expires (§9).
                self.note_answer(&p.address, &r);
                Ok(to_value(&r))
            }
            "scc.rds.keypackage.reserve" => {
                let p: ReserveParams = params(p)?;
                if !self.serves(&p.address.owner).await? {
                    return Err(RpcError::new(rpc::E_WRONG_RDS, "address not served here"));
                }
                self.check_caller_serves(caller, &p.requester.owner).await?;
                Ok(to_value(&self.reserve(&p.address, p.cipher_suite, p.subjects, p.requester).await?))
            }
            "scc.rds.session.create" => {
                let p: RdsSessionCreateParams = params(p)?;
                let (mut s, _) = self.observe_group_info(&p.session_id, &p.group_info)?;
                self.check_caller_serves(caller, &s.initiator.owner).await?;
                if !self.serves(&s.responder.owner).await? {
                    return Err(RpcError::new(rpc::E_WRONG_RDS, "responder not served here"));
                }
                s.peer = Some(caller.to_string());
                let mut st = self.st.lock().await;
                match st.sessions.get(&p.session_id) {
                    Some(old) if old.group_info == p.group_info => {}
                    Some(_) => return Err(RpcError::params("session ID already in use")),
                    None => {
                        tracing::info!("session {} registered by {caller}", crate::util::b64u(&p.session_id));
                        st.sessions.insert(p.session_id.clone(), s);
                    }
                }
                Ok(json!({"registered": true}))
            }
            "scc.rds.commit" => {
                let p: CommitSubmitParams = params(p)?;
                Ok(to_value(&self.peer_commit(caller, &p.session_id, p.commit, p.welcome).await?))
            }
            "scc.rds.commit.report" => {
                let p: RdsCommitReportParams = params(p)?;
                let art = Artefact::parse(&p.evidence).map_err(RpcError::params)?;
                art.verify_seal(&self.trust).map_err(RpcError::params)?;
                match &art.body {
                    EvidenceBody::CommitFailure(c) if c.session_id == p.session_id && c.issuer.provider == caller => {}
                    _ => return Err(RpcError::params("not commit failure evidence from the caller")),
                }
                let mut st = self.st.lock().await;
                let s = st.sessions.get_mut(&p.session_id).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
                if s.peer.as_deref() != Some(caller) {
                    return Err(RpcError::new(rpc::E_WRONG_RDS, "not the session's peer"));
                }
                s.closed = true;
                Ok(json!({"closed": true}))
            }
            "wmp.message.deliver" => {
                let p: DeliverParams = params(p)?;
                let ev = self.relay_in(caller, p).await?;
                Ok(to_value(&EvidenceResult { evidence: ev }))
            }
            "wmp.evidence.notify" => {
                let p: EvidenceNotifyParams = params(p)?;
                let mid = p.message_id.ok_or_else(|| RpcError::params("message_id required"))?;
                {
                    let st = self.st.lock().await;
                    let m = st.messages.get(&mid).ok_or_else(|| RpcError::params("unknown message"))?;
                    let peer = st.sessions.get(&m.session_id).and_then(|s| s.peer.clone());
                    if peer.as_deref() != Some(caller) {
                        return Err(RpcError::new(rpc::E_WRONG_RDS, "not the session's peer"));
                    }
                }
                self.accept_peer_evidence(&mid, &p.evidence).await?;
                Ok(json!({"stored": true}))
            }
            _ => Err(RpcError::new(rpc::E_METHOD_NOT_FOUND, format!("unknown method {method}"))),
        }
    }
}
