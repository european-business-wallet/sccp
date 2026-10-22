//! The Registered Delivery Service (04-delivery.md, 03-mls.md §5, §6,
//! 05-evidence.md §2, §3).
//!
//! State is kept in memory (impl/NOTES.md). The endpoint API is in
//! [`endpoint_api`], the federation API in [`federation`], message flow and
//! evidence in [`messages`], sessions and Commits in [`sessions`], and the
//! HTTPS/WebSocket server in [`server`].

pub mod endpoint_api;
pub mod federation;
pub mod messages;
pub mod server;
pub mod sessions;

use crate::certs::TrustStore;
use crate::credential::Credential;
use crate::delivery::{LogEntry, Meta, RdsMetadata, SubjectsResult};
use crate::evidence::{Artefact, EvidenceSealer, Handover};
use crate::mls::{MemberInfo, SccIdentityProvider};
use crate::resolve::{LocalStatusStore, Resolver};
use crate::rpc::{self, RpcError, RpcResult};
use crate::types::{Address, Consignment, EndpointRef};
use crate::util::now;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Static configuration of an RDS.
#[derive(Clone, Debug)]
pub struct RdsConfig {
    /// Provider ID (doc 4 §3).
    pub provider: String,
    /// Legal name of the provider.
    pub name: String,
    /// Base URL (`rds.url` in registry documents).
    pub base_url: String,
    pub policies: Vec<String>,
    pub identity_policy: String,
    pub max_ttl: u64,
    pub max_clock_skew: u64,
    pub session_idle_limit: u64,
    pub max_message_size: u64,
    pub consignment_modes: Vec<Consignment>,
    /// How long a KeyPackage reservation lasts (doc 4 §6.3).
    pub reservation_ttl: u64,
    /// How long a `scc.rds.subjects` answer may be cached.
    pub subjects_ttl: u64,
}

pub type EpKey = (String, String);

pub fn ep_key(owner: &str, sub: &str) -> EpKey {
    (owner.to_string(), sub.to_string())
}

#[derive(Clone, Debug, PartialEq)]
pub enum KpState {
    Available,
    Reserved { id: String, until: u64 },
    Consumed,
}

#[derive(Clone, Debug)]
pub struct Kp {
    pub hash: Vec<u8>,
    pub raw: Vec<u8>,
    pub cipher_suite: u16,
    pub not_after: u64,
    pub state: KpState,
}

impl Kp {
    pub fn available(&self, t: u64) -> bool {
        t < self.not_after
            && match &self.state {
                KpState::Available => true,
                KpState::Reserved { until, .. } => *until <= t,
                KpState::Consumed => false,
            }
    }
}

/// A registered endpoint (doc 4 §5).
pub struct EndpointRec {
    pub owner: String,
    pub subject: String,
    pub credential: Credential,
    pub registered: bool,
    pub auth_at: u64,
    pub kps: Vec<Kp>,
    pub queue: VecDeque<(u64, String, serde_json::Value)>,
    pub next_seq: u64,
}

impl EndpointRec {
    pub fn pool(&self, t: u64) -> BTreeMap<String, u64> {
        let mut m = BTreeMap::new();
        for k in self.kps.iter().filter(|k| k.available(t)) {
            *m.entry(k.cipher_suite.to_string()).or_insert(0) += 1;
        }
        m
    }
}

pub struct ReservationRec {
    pub requester: EndpointRef,
    pub expires_at: u64,
    pub kps: Vec<(EpKey, Vec<u8>)>,
}

/// A peer RDS.
#[derive(Clone, Debug)]
pub struct PeerRef {
    pub provider: String,
    pub federation: String,
    pub metadata: RdsMetadata,
}

pub struct PendingCommit {
    pub commit_ref: Vec<u8>,
    pub prov: sessions::Provisional,
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    /// Set when a concurrent Commit from the peer won (doc 3 §6.3).
    pub superseded: bool,
}

pub struct Session {
    pub id: Vec<u8>,
    pub initiator: Address,
    pub responder: Address,
    pub cipher_suite: u16,
    pub snapshot: Vec<u8>,
    pub epoch: u64,
    pub group_info: Vec<u8>,
    pub log: Vec<LogEntry>,
    /// TLS-encoded GroupContext of each epoch, by epoch.
    pub contexts: Vec<Vec<u8>>,
    /// Members of each epoch, by epoch.
    pub members: Vec<Vec<MemberInfo>>,
    pub pending: Option<PendingCommit>,
    /// The peer RDS, or None if both owners are served here.
    pub peer: Option<String>,
    pub closed: bool,
    pub last_activity: u64,
}

impl Session {
    pub fn addresses(&self) -> [&Address; 2] {
        [&self.initiator, &self.responder]
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub subject: String,
    pub raw: Vec<u8>,
    pub result: crate::evidence::ReportResult,
    /// A `match` with the sender's epoch authenticator.
    pub success: bool,
    pub status_token: Vec<u8>,
}

#[derive(Default)]
pub struct ConsentState {
    pub notified: Vec<String>,
    pub c6: bool,
    pub decisions: Vec<(String, String, Vec<u8>, bool)>, // subject, holder, raw, accept
    pub eligible_holders: HashSet<String>,
    pub statuses: Vec<Vec<u8>>,
}

/// One message, as seen by this RDS.
pub struct Msg {
    pub meta: Meta,
    pub session_id: Vec<u8>,
    pub envelope: Vec<u8>,
    pub envelope_hash: Vec<u8>,
    pub plaintext_hash: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    pub epoch: u64,
    pub send_local: bool,
    pub recv_local: bool,
    pub sender: EpKey,
    pub sender_assurance: crate::evidence::Assurance,
    /// Every artefact for the message, own and received, in arrival order.
    pub evidence: Vec<Artefact>,
    /// Seal hashes that the next event follows.
    pub last: Vec<Vec<u8>>,
    pub terminal: Option<crate::evidence::Event>,
    /// The artefact returned to the submitter or relayer (A.1/A.2, B.1/B.2).
    pub answer: Option<Vec<u8>>,
    pub recipients: Vec<String>,
    pub handovers: BTreeMap<String, Handover>,
    pub reports: Vec<Report>,
    pub consigned: bool,
    pub consent: Option<ConsentState>,
}

#[derive(Default)]
pub struct State {
    pub endpoints: HashMap<EpKey, EndpointRec>,
    pub sessions: HashMap<Vec<u8>, Session>,
    pub messages: HashMap<Vec<u8>, Msg>,
    pub reservations: HashMap<String, ReservationRec>,
}

pub struct Rds {
    pub cfg: RdsConfig,
    pub sealer: EvidenceSealer,
    pub trust: TrustStore,
    pub resolver: Arc<Resolver>,
    pub ip: SccIdentityProvider,
    pub http: reqwest::Client,
    pub status_store: LocalStatusStore,
    pub st: tokio::sync::Mutex<State>,
    conns: std::sync::Mutex<HashMap<EpKey, mpsc::UnboundedSender<String>>>,
    peers: std::sync::Mutex<HashMap<String, PeerRef>>,
    subjects_cache: std::sync::Mutex<HashMap<(Address, u16), SubjectsResult>>,
    /// DEMO ONLY: peers this RDS treats as unreachable, to simulate a
    /// network partition (see `scc-rds partition`).
    pub partitioned: std::sync::Mutex<std::collections::HashSet<String>>,
    /// `scc.rds.subjects` answers this RDS gave: (address, expires_at,
    /// subjects). Each binds it until it expires (doc 4 §7.2, §9).
    answers: std::sync::Mutex<Vec<(Address, u64, Vec<String>)>>,
}

impl Rds {
    pub fn new(cfg: RdsConfig, sealer: EvidenceSealer, trust: TrustStore, edd_url: &str) -> anyhow::Result<Arc<Self>> {
        let status_store: LocalStatusStore = Default::default();
        let edd = crate::edd::EddClient::new(edd_url, trust.clone())?;
        let resolver = Arc::new(Resolver::new(edd, Some(status_store.clone()))?);
        Ok(Arc::new(Rds {
            ip: SccIdentityProvider::with_resolver(resolver.clone()),
            cfg,
            sealer,
            trust,
            resolver,
            http: crate::net::http_client()?,
            status_store,
            st: Default::default(),
            conns: Default::default(),
            peers: Default::default(),
            subjects_cache: Default::default(),
            answers: Default::default(),
            partitioned: Default::default(),
        }))
    }

    pub fn client_url(&self) -> String {
        format!("{}/scc", self.cfg.base_url.replacen("https://", "wss://", 1))
    }

    pub fn federation_url(&self) -> String {
        format!("{}/scc/federation", self.cfg.base_url)
    }

    /// The URI at which this RDS hosts a status list for an EBW URL.
    pub fn status_uri(base_url: &str, owner: &str) -> String {
        format!("{}/status/{}", base_url.trim_end_matches('/'), owner.strip_prefix("ebw:").unwrap_or(owner))
    }

    pub fn metadata(&self) -> RdsMetadata {
        use crate::delivery::*;
        RdsMetadata {
            provider: self.cfg.provider.clone(),
            governing_body: GoverningBody {
                name: self.cfg.name.clone(),
                identifier: format!("urn:ebw:demo:{}", self.cfg.provider),
            },
            trust_domains: vec!["eu-qualified".into()],
            versions: vec![VERSION.into()],
            endpoints: RdsEndpoints { client: self.client_url(), federation: self.federation_url() },
            cipher_suites: vec![1, 2],
            consignment_modes: self.cfg.consignment_modes.clone(),
            max_message_size: self.cfg.max_message_size,
            max_ttl: self.cfg.max_ttl,
            session_idle_limit: self.cfg.session_idle_limit,
            max_clock_skew: self.cfg.max_clock_skew,
            expiry: true,
            scheduled_delivery: false,
            assurance: AssuranceLevels {
                identity: vec![crate::evidence::LOA_HIGH.into()],
                authentication: vec![crate::evidence::LOA_HIGH.into()],
            },
            evidence: EvidenceInfo {
                policies: self.cfg.policies.clone(),
                retention: "P10Y".into(),
                seal_certificates: vec![self.sealer.seal.chain.iter().map(|c| crate::util::b64std(c)).collect()],
            },
        }
    }

    pub fn issuer(&self) -> crate::evidence::Issuer {
        crate::evidence::Issuer {
            provider: self.cfg.provider.clone(),
            name: self.cfg.name.clone(),
            policies: self.cfg.policies.clone(),
        }
    }

    // ---- EBW URLs and peers ----

    /// Whether this RDS is the home RDS of `owner`.
    pub async fn serves(&self, owner: &str) -> RpcResult<bool> {
        let st = self.resolver.resolve(owner).await.map_err(|e| RpcError::new(rpc::E_UNKNOWN_ADDRESS, format!("{e:#}")))?;
        Ok(st.document.rds.provider == self.cfg.provider)
    }

    /// The home RDS of `owner`, or None if it is this RDS.
    pub async fn peer_for_owner(&self, owner: &str) -> RpcResult<Option<PeerRef>> {
        let st = self.resolver.resolve(owner).await.map_err(|e| RpcError::new(rpc::E_UNKNOWN_ADDRESS, format!("{e:#}")))?;
        if st.document.rds.provider == self.cfg.provider {
            return Ok(None);
        }
        self.peer_by_url(&st.document.rds.provider, &st.document.rds.url).await.map(Some)
    }

    async fn peer_by_url(&self, provider: &str, url: &str) -> RpcResult<PeerRef> {
        if let Some(p) = self.peers.lock().unwrap().get(provider) {
            return Ok(p.clone());
        }
        let mu = format!("{}/.well-known/scc-rds", url.trim_end_matches('/'));
        let md: RdsMetadata = async {
            let r = self.http.get(&mu).send().await?;
            anyhow::Ok(r.error_for_status()?.json().await?)
        }
        .await
        .map_err(|e| RpcError::internal(format!("RDS metadata {mu}: {e:#}")))?;
        if md.provider != provider {
            return Err(RpcError::internal(format!("RDS at {url} is {}, not {provider}", md.provider)));
        }
        let p = PeerRef { provider: provider.into(), federation: md.endpoints.federation.clone(), metadata: md };
        self.peers.lock().unwrap().insert(provider.into(), p.clone());
        Ok(p)
    }

    /// The peer with the given provider ID (known from an earlier lookup).
    pub fn peer(&self, provider: &str) -> RpcResult<PeerRef> {
        self.peers
            .lock()
            .unwrap()
            .get(provider)
            .cloned()
            .ok_or_else(|| RpcError::internal(format!("unknown peer {provider}")))
    }

    pub async fn call_peer(&self, provider: &str, method: &str, params: serde_json::Value) -> RpcResult {
        let p = self.peer(provider)?;
        if self.partitioned.lock().unwrap().contains(&p.provider) {
            return Err(RpcError::new(rpc::E_PEER_UNREACHABLE, format!("{method} to {}: unreachable (demo partition)", p.provider)));
        }
        tracing::debug!("-> {} {method}", p.provider);
        rpc::federation_call(&self.http, &p.federation, &self.cfg.provider, method, params).await
    }

    /// Check that a federation caller is the home RDS of `owner` (§4.3).
    pub async fn check_caller_serves(&self, caller: &str, owner: &str) -> RpcResult<()> {
        let st = self.resolver.resolve(owner).await.map_err(RpcError::from)?;
        if st.document.rds.provider != caller {
            return Err(RpcError::new(rpc::E_WRONG_RDS, format!("{caller} is not the home RDS of {owner}")));
        }
        // Learn its federation endpoint for later calls.
        self.peer_by_url(&st.document.rds.provider, &st.document.rds.url).await?;
        Ok(())
    }

    // ---- Eligibility (doc 3 §4.2, §5) ----

    /// Subject IDs of the endpoints registered here that are eligible for
    /// `addr` now, and which of them have no KeyPackage for `cs`.
    pub async fn eligible_local(&self, st: &State, addr: &Address, cs: Option<u16>) -> (Vec<String>, Vec<String>) {
        let t = now();
        let mut subs = Vec::new();
        let mut missing = Vec::new();
        let mut eps: Vec<&EndpointRec> = st.endpoints.values().filter(|e| e.owner == addr.owner && e.registered).collect();
        eps.sort_by(|a, b| a.subject.cmp(&b.subject));
        for e in eps {
            let c = &e.credential.claims;
            if !c.roles.iter().any(|r| r == &addr.role) || t < c.nbf || t >= c.exp {
                continue;
            }
            if self.credential_status_ok(&e.credential).await.is_err() {
                continue;
            }
            subs.push(e.subject.clone());
            if let Some(cs) = cs {
                if !e.kps.iter().any(|k| k.cipher_suite == cs && k.available(t)) {
                    missing.push(e.subject.clone());
                }
            }
        }
        (subs, missing)
    }

    /// Check a credential's signature, validity and status now.
    pub async fn credential_status_ok(&self, c: &Credential) -> anyhow::Result<Vec<u8>> {
        let t = now();
        let st = self.resolver.resolve(&c.claims.iss).await?;
        c.verify_signature_and_time(&st.document, t)?;
        let tok = self.resolver.status(&c.claims.status_uri).await?;
        c.check_status(&tok, &st.document, t)?;
        Ok(tok.raw)
    }

    /// Eligible subjects for an address, from this RDS or its home RDS.
    /// Must be called without holding the state lock.
    pub async fn subjects(&self, addr: &Address, cs: u16) -> RpcResult<SubjectsResult> {
        match self.peer_for_owner(&addr.owner).await? {
            None => {
                let st = self.st.lock().await;
                let (subjects, no_key_packages) = self.eligible_local(&st, addr, Some(cs)).await;
                let t = now();
                Ok(SubjectsResult { as_of: t, expires_at: t + self.cfg.subjects_ttl, subjects, no_key_packages })
            }
            Some(p) => {
                let key = (addr.clone(), cs);
                if let Some(r) = self.subjects_cache.lock().unwrap().get(&key) {
                    if now() < r.expires_at {
                        return Ok(r.clone());
                    }
                }
                let v = self
                    .call_peer(
                        &p.provider,
                        "scc.rds.subjects",
                        rpc::to_value(&crate::delivery::SubjectsParams { address: addr.clone(), cipher_suite: cs }),
                    )
                    .await?;
                let r: SubjectsResult = rpc::params(v)?;
                self.subjects_cache.lock().unwrap().insert(key, r.clone());
                Ok(r)
            }
        }
    }

    /// Record an answer given to another RDS.
    pub fn note_answer(&self, addr: &Address, r: &SubjectsResult) {
        let mut a = self.answers.lock().unwrap();
        let t = now();
        a.retain(|x| x.1 > t);
        a.push((addr.clone(), r.expires_at, r.subjects.clone()));
    }

    /// Subject lists of the unexpired answers given for an address.
    pub fn answers_given(&self, addr: &Address) -> Vec<Vec<String>> {
        let t = now();
        let mut v: Vec<Vec<String>> = Vec::new();
        for (a, exp, subs) in self.answers.lock().unwrap().iter() {
            if a == addr && *exp > t && !v.contains(subs) {
                v.push(subs.clone());
            }
        }
        v
    }

    pub fn forget_subjects(&self) {
        self.subjects_cache.lock().unwrap().clear();
    }

    // ---- Queues (§4.2) ----

    pub fn register_conn(&self, k: EpKey, tx: mpsc::UnboundedSender<String>) {
        self.conns.lock().unwrap().insert(k, tx);
    }

    pub fn unregister_conn(&self, k: &EpKey, tx: &mpsc::UnboundedSender<String>) {
        let mut c = self.conns.lock().unwrap();
        if c.get(k).map(|t| t.same_channel(tx)).unwrap_or(false) {
            c.remove(k);
        }
    }

    /// Queue a notification for an endpoint and push it if connected.
    pub fn enqueue(&self, st: &mut State, k: &EpKey, method: &str, mut params: serde_json::Value) {
        let Some(e) = st.endpoints.get_mut(k) else { return };
        e.next_seq += 1;
        let seq = e.next_seq;
        params["seq"] = serde_json::json!(seq);
        e.queue.push_back((seq, method.to_string(), params.clone()));
        if let Some(tx) = self.conns.lock().unwrap().get(k) {
            let _ = tx.send(rpc::Message::notification(method, params).to_text());
        }
    }
}
