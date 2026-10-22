//! The endpoint-facing JSON-RPC API (04-delivery.md §4.1, §4.2, §5, §6,
//! §7, §8).

use super::{ep_key, EndpointRec, EpKey, Kp, KpState, Rds, ReservationRec};
use crate::credential::{ConnectProofBody, Credential};
use crate::delivery::*;
use crate::evidence::{self, CommitFailureEvidence, CommitFailureReport};
use crate::mls;
use crate::rpc::{self, params, to_value, RpcError, RpcResult};
use crate::types::EndpointRef;
use crate::util::{now, random_bytes};
use mls_rs_codec::MlsEncode;
use serde_json::{json, Value};
use std::sync::Arc;

/// Per-connection state.
#[derive(Default)]
pub struct Conn {
    pub challenge: Option<(Vec<u8>, u64, String, String)>,
    pub endpoint: Option<EpKey>,
}

impl Rds {
    pub async fn handle_endpoint(self: &Arc<Self>, conn: &mut Conn, method: &str, p: Value, tx: &tokio::sync::mpsc::UnboundedSender<String>) -> RpcResult {
        match method {
            "scc.connect" => {
                let p: ConnectParams = params(p)?;
                if !p.versions.iter().any(|v| v == VERSION) {
                    return Err(RpcError::new(rpc::E_INVALID_PARAMS, "no supported version"));
                }
                let c = random_bytes(16);
                let exp = now() + 60;
                conn.challenge = Some((c.clone(), exp, p.owner, p.subject));
                return Ok(to_value(&ConnectResult { version: VERSION.into(), challenge: c, expires_at: exp }));
            }
            "scc.authenticate" => {
                let p: AuthenticateParams = params(p)?;
                let k = self.authenticate(conn, p).await?;
                self.register_conn(k.clone(), tx.clone());
                let head = self.st.lock().await.endpoints.get(&k).map(|e| e.next_seq).unwrap_or(0);
                return Ok(to_value(&AuthenticateResult { registered: true, queue_head: head }));
            }
            _ => {}
        }
        let caller = conn.endpoint.clone().ok_or_else(|| RpcError::unauthorized("not authenticated"))?;
        match method {
            "scc.deregister" => {
                let mut st = self.st.lock().await;
                if let Some(e) = st.endpoints.get_mut(&caller) {
                    e.registered = false;
                }
                Ok(json!({"deregistered": true}))
            }
            "scc.queue.ack" => {
                let p: QueueAckParams = params(p)?;
                let removed = {
                    let mut st = self.st.lock().await;
                    let e = st.endpoints.get_mut(&caller).unwrap();
                    let mut removed = Vec::new();
                    while e.queue.front().map(|i| i.0 <= p.up_to).unwrap_or(false) {
                        let (_, m, v) = e.queue.pop_front().unwrap();
                        removed.push((m, v));
                    }
                    removed
                };
                let n = removed.len();
                self.on_queue_ack(&caller, removed).await;
                Ok(json!({"removed": n}))
            }
            "wmp.message.fetch" => {
                let p: FetchParams = params(p)?;
                let st = self.st.lock().await;
                let e = st.endpoints.get(&caller).unwrap();
                let limit = p.limit.unwrap_or(100) as usize;
                let all: Vec<QueuedItem> = e
                    .queue
                    .iter()
                    .filter(|i| i.0 > p.after)
                    .map(|(_, m, v)| QueuedItem { method: m.clone(), params: v.clone() })
                    .collect();
                let more = all.len() > limit;
                Ok(to_value(&FetchResult { items: all.into_iter().take(limit).collect(), more }))
            }
            "scc.keypackage.publish" => {
                let p: PublishParams = params(p)?;
                self.publish(&caller, p).await
            }
            "scc.keypackage.get" => {
                let p: KeyPackageGetParams = params(p)?;
                let requester = EndpointRef { owner: caller.0.clone(), subject: caller.1.clone() };
                let r = match self.peer_for_owner(&p.address.owner).await? {
                    None => self.reserve(&p.address, p.cipher_suite, p.subjects, requester).await?,
                    Some(peer) => {
                        let v = self
                            .call_peer(
                                &peer.provider,
                                "scc.rds.keypackage.reserve",
                                to_value(&ReserveParams { address: p.address, cipher_suite: p.cipher_suite, subjects: p.subjects, requester }),
                            )
                            .await?;
                        params(v)?
                    }
                };
                Ok(to_value(&r))
            }
            "wmp.session.create" => {
                let p: SessionCreateParams = params(p)?;
                self.session_create(&caller, p).await
            }
            "scc.commit.submit" => {
                let p: CommitSubmitParams = params(p)?;
                let e = self.submit_commit(&caller, &p.session_id, p.commit, p.welcome, p.reservations).await?;
                Ok(to_value(&EpochResult { epoch: e }))
            }
            "scc.commit.fetch" => {
                let p: CommitFetchParams = params(p)?;
                let st = self.st.lock().await;
                let s = self.session_for(&st, &caller, &p.session_id)?;
                let commits = s.log.iter().filter(|e| e.epoch > p.after_epoch).cloned().collect();
                Ok(to_value(&CommitsResult { commits }))
            }
            "scc.session.log" => {
                let p: SessionIdParams = params(p)?;
                let st = self.st.lock().await;
                let s = self.session_for(&st, &caller, &p.session_id)?;
                Ok(to_value(&SessionLog { group_info: s.group_info.clone(), commits: s.log.clone() }))
            }
            "scc.commit.report" => {
                let p: CommitReportParams = params(p)?;
                self.commit_report(&caller, p).await
            }
            "wmp.message.deliver" => {
                let p: DeliverParams = params(p)?;
                let ev = self.submit(&caller, p).await?;
                Ok(to_value(&EvidenceResult { evidence: ev }))
            }
            "wmp.message.ack" => {
                let p: MessageAckParams = params(p)?;
                let ev = self.message_ack(&caller, p).await?;
                Ok(to_value(&MessageAckResult { recorded: true, evidence: ev }))
            }
            "scc.evidence.get" => {
                let p: MessageIdParams = params(p)?;
                let pkg = self.evidence_package(&caller, &p.message_id).await?;
                Ok(to_value(&PackageResult { package: pkg }))
            }
            _ => Err(RpcError::new(rpc::E_METHOD_NOT_FOUND, format!("unknown method {method}"))),
        }
    }

    /// `scc.authenticate` (§4.1).
    async fn authenticate(&self, conn: &mut Conn, p: AuthenticateParams) -> RpcResult<EpKey> {
        let (challenge, exp, owner, sub) = conn.challenge.take().ok_or_else(|| RpcError::unauthorized("no challenge issued"))?;
        let t = now();
        if t >= exp {
            return Err(RpcError::unauthorized("challenge expired"));
        }
        let cred = Credential::parse(&p.credential).map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        if cred.claims.iss != owner || cred.claims.sub != sub {
            return Err(RpcError::new(rpc::E_INVALID_CREDENTIAL, "credential is for another endpoint"));
        }
        self.credential_status_ok(&cred).await.map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        let proof = ConnectProofBody::parse_and_verify(&p.signature, &cred.claims.cnf).map_err(|e| RpcError::unauthorized(format!("connect proof: {e:#}")))?;
        if proof.challenge.as_slice() != challenge || proof.provider != self.cfg.provider || proof.owner != owner || proof.subject != sub {
            return Err(RpcError::unauthorized("connect proof does not match"));
        }
        if !self.serves(&owner).await? {
            return Err(RpcError::new(rpc::E_WRONG_RDS, format!("{owner} is not served by {}", self.cfg.provider)));
        }
        let k = ep_key(&owner, &sub);
        let mut st = self.st.lock().await;
        match st.endpoints.get_mut(&k) {
            Some(e) => {
                if cred.claims.iat >= e.credential.claims.iat {
                    e.credential = cred;
                }
                e.registered = true;
                e.auth_at = t;
            }
            None => {
                tracing::info!("registered endpoint {owner}/{sub}");
                st.endpoints.insert(
                    k.clone(),
                    EndpointRec { owner, subject: sub, credential: cred, registered: true, auth_at: t, kps: vec![], queue: Default::default(), next_seq: 0 },
                );
            }
        }
        drop(st);
        self.forget_subjects();
        conn.endpoint = Some(k.clone());
        Ok(k)
    }

    /// `scc.keypackage.publish` (§6.1).
    async fn publish(&self, caller: &EpKey, p: PublishParams) -> RpcResult {
        let obs = mls::observer_client(self.ip.clone());
        let mut kps = Vec::new();
        for raw in p.key_packages {
            let msg = mls::parse_mls_message(&raw).map_err(RpcError::mls)?;
            let kp = obs.validate_key_package(msg, None).map_err(|e| RpcError::mls(format!("KeyPackage: {e:?}")))?;
            mls::check_not_last_resort(&kp).map_err(RpcError::mls)?;
            let c = mls::parse_leaf_credential(kp.signing_identity()).map_err(RpcError::mls)?;
            if c.claims.iss != caller.0 || c.claims.sub != caller.1 {
                return Err(RpcError::new(rpc::E_INVALID_CREDENTIAL, "KeyPackage credential is not the caller's"));
            }
            let not_after = kp.expiration().map(|t| t.seconds_since_epoch()).unwrap_or(0).min(c.claims.exp);
            let hash = mls::mls_hash(&kp.mls_encode_to_vec().map_err(RpcError::mls)?);
            kps.push(Kp { hash, raw, cipher_suite: *kp.cipher_suite, not_after, state: KpState::Available });
        }
        let mut st = self.st.lock().await;
        let e = st.endpoints.get_mut(caller).unwrap();
        for k in kps {
            if !e.kps.iter().any(|x| x.hash == k.hash) {
                e.kps.push(k);
            }
        }
        let pool = e.pool(now());
        drop(st);
        self.forget_subjects();
        Ok(to_value(&PoolStatus { available: pool }))
    }

    /// Reserve KeyPackages of endpoints served here (§6.2, §6.3).
    pub async fn reserve(&self, addr: &crate::types::Address, cs: u16, subjects: Option<Vec<String>>, requester: EndpointRef) -> RpcResult<Reservation> {
        let mut st = self.st.lock().await;
        let (eligible, _) = self.eligible_local(&st, addr, Some(cs)).await;
        let eligible: Vec<String> = eligible.into_iter().filter(|s| !(requester.owner == addr.owner && requester.subject == *s)).collect();
        let t = now();
        let id = crate::util::b64u(&random_bytes(12));
        let until = t + self.cfg.reservation_ttl;
        let mut out = Vec::new();
        let mut missing = Vec::new();
        let mut low = Vec::new();
        for sub in &eligible {
            if let Some(f) = &subjects {
                if !f.contains(sub) {
                    continue;
                }
            }
            let e = st.endpoints.get_mut(&ep_key(&addr.owner, sub)).unwrap();
            match e.kps.iter_mut().find(|k| k.cipher_suite == cs && k.available(t)) {
                Some(k) => {
                    k.state = KpState::Reserved { id: id.clone(), until };
                    out.push((sub.clone(), k.raw.clone(), k.hash.clone()));
                    if e.pool(t).get(&cs.to_string()).copied().unwrap_or(0) < 5 {
                        low.push(ep_key(&addr.owner, sub));
                    }
                }
                None => missing.push(sub.clone()),
            }
        }
        st.reservations.insert(
            id.clone(),
            ReservationRec {
                requester,
                expires_at: until,
                kps: out.iter().map(|(s, _, h)| (ep_key(&addr.owner, s), h.clone())).collect(),
            },
        );
        for k in low {
            let pool = st.endpoints[&k].pool(t);
            self.enqueue(&mut st, &k, "scc.keypackage.status", to_value(&KeyPackageStatusParams { seq: 0, available: pool }));
        }
        drop(st);
        self.forget_subjects();
        Ok(Reservation {
            reservation: id,
            expires_at: until,
            eligible,
            key_packages: out.into_iter().map(|(s, k, _)| SubjectKeyPackage { subject: s, key_package: k }).collect(),
            missing,
        })
    }

    fn session_for<'a>(&self, st: &'a super::State, caller: &EpKey, sid: &[u8]) -> RpcResult<&'a super::Session> {
        let s = st.sessions.get(sid).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
        if !s.addresses().iter().any(|a| a.owner == caller.0) {
            return Err(RpcError::unauthorized("not a party to this session"));
        }
        Ok(s)
    }

    /// `wmp.session.create` (§8.1).
    async fn session_create(self: &Arc<Self>, caller: &EpKey, p: SessionCreateParams) -> RpcResult {
        let (mut s, _) = self.observe_group_info(&p.session_id, &p.group_info)?;
        let creator = s.members[0].first().cloned().ok_or_else(|| RpcError::mls("empty group"))?;
        if s.members[0].len() != 1 || creator.owner != caller.0 || creator.subject != caller.1 || !creator.holds(&s.initiator) {
            return Err(RpcError::unauthorized("the creator must be the caller, on the initiator side"));
        }
        let peer = match self.peer_for_owner(&s.responder.owner).await? {
            Some(p) => Some(p),
            None => self.peer_for_owner(&s.initiator.owner).await?,
        };
        {
            let st = self.st.lock().await;
            if st.sessions.contains_key(&p.session_id) {
                return Err(RpcError::params("session ID already in use"));
            }
        }
        if let Some(peer) = &peer {
            self.call_peer(&peer.provider, "scc.rds.session.create", to_value(&RdsSessionCreateParams { session_id: p.session_id.clone(), group_info: p.group_info.clone() }))
                .await?;
            s.peer = Some(peer.provider.clone());
        }
        {
            let mut st = self.st.lock().await;
            if st.sessions.contains_key(&p.session_id) {
                return Err(RpcError::params("session ID already in use"));
            }
            tracing::info!("session {} created: {} -> {}", crate::util::b64u(&p.session_id), s.initiator, s.responder);
            st.sessions.insert(p.session_id.clone(), s);
        }
        let e = self.submit_commit(caller, &p.session_id, p.commit, Some(p.welcome), p.reservations).await?;
        Ok(to_value(&EpochResult { epoch: e }))
    }

    /// `scc.commit.report` (§8.5).
    async fn commit_report(self: &Arc<Self>, caller: &EpKey, p: CommitReportParams) -> RpcResult {
        let stmt = evidence::parse_statement::<CommitFailureReport>(&p.report).map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        if stmt.body.owner != caller.0 || stmt.body.subject != caller.1 || stmt.body.session_id != p.session_id {
            return Err(RpcError::unauthorized("report is not from the caller"));
        }
        self.credential_status_ok(&stmt.credential).await.map_err(|e| RpcError::new(rpc::E_INVALID_CREDENTIAL, format!("{e:#}")))?;
        let mut st = self.st.lock().await;
        let s = st.sessions.get_mut(&p.session_id).ok_or_else(|| RpcError::new(rpc::E_UNKNOWN_SESSION, "Unknown session"))?;
        let entry = s
            .log
            .iter()
            .find(|e| mls::mls_hash(&e.commit) == stmt.body.commit_ref)
            .ok_or_else(|| RpcError::params("commit_ref names no accepted Commit"))?;
        let t = now();
        let body = CommitFailureEvidence {
            v: 1,
            evidence_id: random_bytes(16),
            event: evidence::COMMIT_FAILURE_EVENT.into(),
            issuer: self.issuer(),
            event_time: t,
            session_id: p.session_id.clone(),
            commit_ref: stmt.body.commit_ref.clone(),
            group_context: s.contexts[entry.epoch as usize].clone(),
            report: p.report.clone(),
        };
        let art = self.sealer.seal(&body, t).map_err(RpcError::from)?;
        s.closed = true;
        let peer = s.peer.clone();
        drop(st);
        tracing::info!("session {} closed after a commit failure report", crate::util::b64u(&p.session_id));
        if let Some(peer) = peer {
            let me = self.clone();
            let params = to_value(&RdsCommitReportParams { session_id: p.session_id.clone(), evidence: art.raw.clone() });
            tokio::spawn(async move {
                if let Err(e) = me.call_peer(&peer, "scc.rds.commit.report", params).await {
                    tracing::warn!("commit report to {peer}: {e}");
                }
            });
        }
        Ok(json!({"closed": true, "evidence": crate::util::b64u(&art.raw)}))
    }
}
