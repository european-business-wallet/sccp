//! The European Digital Directory (01-discovery.md §3 to §6): server
//! logic and client.

use crate::cbor;
use crate::certs::TrustStore;
use crate::registry::{
    url_from_create, HeadStatement, HeadStatementBody, IdentifierAttestationBody, LogEntry, OpBody, RegistrationRequest,
    RegistrationResponse, ResolutionResponse, ResolvedDocument, Sealer, Submission,
};
use crate::types::{OwnerStatus, Identifier};
use crate::util::now;
use anyhow::{anyhow, Result};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::sync::Mutex;

/// An RFC 9290 problem with an SCC problem type (01-discovery.md §6.5).
#[derive(Debug, Clone)]
pub struct Problem {
    pub status: u16,
    pub ptype: &'static str,
    pub detail: String,
}

impl Problem {
    pub fn new(status: u16, ptype: &'static str, detail: impl Into<String>) -> Self {
        Problem { status, ptype, detail: detail.into() }
    }

    pub fn not_found(what: &str) -> Self {
        Problem::new(404, "not-found", format!("{what} not found"))
    }

    /// Concise Problem Details: title (-1), detail (-2), response-code
    /// (-4), and the problem type as the custom key "type" (NOTES.md).
    pub fn to_cbor(&self) -> Vec<u8> {
        cbor::encode(&cbor::Value::Map(vec![
            (cbor::int(-1), cbor::text(self.ptype)),
            (cbor::int(-2), cbor::text(&self.detail)),
            (cbor::int(-4), cbor::int(self.status as i64)),
            (cbor::text("type"), cbor::text(self.ptype)),
        ]))
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.ptype, self.detail)
    }
}

#[derive(Clone, Debug)]
pub struct EddConfig {
    /// Public base URL, e.g. https://localhost:8440
    pub base_url: String,
    pub recovery_window: u64,
    pub head_validity: u64,
    pub attestation_validity: u64,
}

#[derive(Clone, Debug)]
struct Entry {
    /// The submission, sealed by the EBW provider (§3.6); `sub.op` is the
    /// operation.
    sub: Submission,
    received_at: u64,
    overridden: bool,
    /// Index of the signing key in the update keys it was checked against.
    signer_index: usize,
}

#[derive(Clone, Debug)]
struct RegistryRecord {
    entries: Vec<Entry>,
    status: OwnerStatus,
    successor: Option<String>,
}

impl RegistryRecord {
    fn head(&self) -> &Entry {
        self.entries.iter().rev().find(|e| !e.overridden).expect("an EBW URL has a create operation")
    }

    fn seq(&self) -> u64 {
        self.entries.iter().filter(|e| !e.overridden).count() as u64
    }

    fn closed(&self) -> bool {
        matches!(self.head().sub.op.body, OpBody::Close { .. })
    }
}

#[derive(Clone, Debug)]
struct Attestation {
    owner: String,
    raw: Vec<u8>,
    expires_at: u64,
}

#[derive(Default)]
struct EddState {
    owners: HashMap<String, RegistryRecord>,
    attestations: HashMap<(String, String), Attestation>,
}

/// The EDD.
pub struct Edd {
    pub cfg: EddConfig,
    pub sealer: Sealer,
    /// Trusted EBW provider seal certificates (stand-in for the EU
    /// Trusted Lists).
    pub trust: TrustStore,
    state: Mutex<EddState>,
}

type PResult<T> = std::result::Result<T, Problem>;

impl Edd {
    pub fn new(cfg: EddConfig, sealer: Sealer, trust: TrustStore) -> Self {
        Edd { cfg, sealer, trust, state: Mutex::new(EddState::default()) }
    }

    /// Parse a submission and check its seal (§3.6, §3.3 item 1).
    fn submission(&self, raw: &[u8]) -> PResult<Submission> {
        let sub = Submission::parse(raw).map_err(|e| Problem::new(400, "malformed-operation", format!("{e:#}")))?;
        sub.verify(&self.trust, now()).map_err(|e| Problem::new(403, "invalid-seal", format!("{e:#}")))?;
        Ok(sub)
    }

    fn head_statement(&self, owner: &str, rec: &RegistryRecord) -> Vec<u8> {
        let t = now();
        let status = if rec.closed() { OwnerStatus::Closed } else { rec.status };
        HeadStatement::issue(
            &self.sealer,
            &HeadStatementBody {
                st_type: "head-statement".into(),
                owner: owner.into(),
                head: rec.head().sub.op.hash(),
                seq: rec.seq(),
                status,
                successor: if status == OwnerStatus::Merged { rec.successor.clone() } else { None },
                issued_at: t,
                expires_at: t + self.cfg.head_validity,
            },
        )
    }

    fn attest(&self, st: &mut EddState, owner: &str, id: &Identifier) -> PResult<()> {
        let key = (id.id_type.clone(), id.value.clone());
        let t = now();
        if let Some(a) = st.attestations.get(&key) {
            if a.owner != owner && a.expires_at > t {
                return Err(Problem::new(
                    422,
                    "identifier-not-attested",
                    format!("{}:{} is attested to another EBW URL", id.id_type, id.value),
                ));
            }
        }
        let body = IdentifierAttestationBody {
            st_type: "identifier-attestation".into(),
            identifier: id.clone(),
            owner: owner.into(),
            verified_at: t,
            expires_at: t + self.cfg.attestation_validity,
        };
        let raw = self.sealer.seal(&cbor::to_vec(&body).unwrap());
        st.attestations.insert(key, Attestation { owner: owner.into(), raw, expires_at: body.expires_at });
        Ok(())
    }

    fn check_identifiers(&self, st: &EddState, owner: &str, ids: &[Identifier]) -> PResult<()> {
        let t = now();
        for id in ids {
            match st.attestations.get(&(id.id_type.clone(), id.value.clone())) {
                Some(a) if a.owner == owner && a.expires_at > t => {}
                _ => {
                    return Err(Problem::new(
                        422,
                        "identifier-not-attested",
                        format!("{}:{} is not attested for {owner}", id.id_type, id.value),
                    ))
                }
            }
        }
        Ok(())
    }

    /// `POST /register` (§6.2). Identity proofing is a stub: any proof is
    /// accepted, and the identifiers in the create operation are attested.
    pub fn register(&self, body: &[u8]) -> PResult<Vec<u8>> {
        let req: RegistrationRequest =
            cbor::from_slice(body).map_err(|e| Problem::new(400, "malformed-operation", e.to_string()))?;
        let sub = self.submission(&req.submission)?;
        let op = &sub.op;
        let OpBody::Create(state) = &op.body else {
            return Err(Problem::new(400, "malformed-operation", "registration needs a create operation"));
        };
        let idx = op.verify_with(state).map_err(|e| Problem::new(403, "unauthorized-key", e.to_string()))?;
        let owner = url_from_create(&op.raw);
        let mut st = self.state.lock().unwrap();
        if st.owners.contains_key(&owner) {
            return Err(Problem::new(409, "stale-prev", format!("{owner} is already registered")));
        }
        for id in &state.identifiers {
            self.attest(&mut st, &owner, id)?;
        }
        let rec = RegistryRecord {
            entries: vec![Entry { sub: sub.clone(), received_at: now(), overridden: false, signer_index: idx }],
            status: OwnerStatus::Active,
            successor: None,
        };
        let head = self.head_statement(&owner, &rec);
        st.owners.insert(owner.clone(), rec);
        tracing::info!("registered {owner}");
        Ok(cbor::to_vec(&RegistrationResponse { owner, head: ByteBuf::from(head) }).unwrap())
    }

    /// `POST /{url}` (§6.5): an update or close operation in a
    /// submission, with the recovery rule of §3.4.
    pub fn update(&self, owner: &str, body: &[u8]) -> PResult<Vec<u8>> {
        let sub = self.submission(body)?;
        let op = &sub.op;
        let prev = match &op.body {
            OpBody::Create(_) => return Err(Problem::new(400, "malformed-operation", "create operations use /register")),
            b => b.prev().unwrap().to_vec(),
        };
        let mut st = self.state.lock().unwrap();
        let rec = st.owners.get(owner).ok_or_else(|| Problem::not_found(owner))?.clone();
        if rec.closed() {
            return Err(Problem::new(410, "closed", format!("{owner} is closed")));
        }
        let head = rec.head();
        let mut rec2 = rec.clone();
        let signer_index;
        if head.sub.op.hash() == prev {
            let pstate = head.sub.op.body.document().unwrap();
            signer_index = op.verify_with(pstate).map_err(|e| Problem::new(403, "unauthorized-key", e.to_string()))?;
        } else {
            // Recovery (§3.4).
            let pos = rec
                .entries
                .iter()
                .position(|e| !e.overridden && e.sub.op.hash() == prev)
                .ok_or_else(|| Problem::new(409, "stale-prev", "prev names no live operation"))?;
            let pstate = rec.entries[pos]
                .sub
                .op
                .body
                .document()
                .ok_or_else(|| Problem::new(409, "stale-prev", "prev is a close operation"))?;
            let i = op.verify_with(pstate).map_err(|e| Problem::new(403, "unauthorized-key", e.to_string()))?;
            let later: Vec<&Entry> = rec.entries[pos + 1..].iter().filter(|e| !e.overridden).collect();
            if later.iter().any(|e| e.signer_index <= i) {
                return Err(Problem::new(409, "stale-prev", "a later operation was signed by a key of equal or higher priority"));
            }
            let first = later.first().map(|e| e.received_at).unwrap_or(0);
            if now() >= first + self.cfg.recovery_window {
                return Err(Problem::new(409, "stale-prev", "recovery window has passed"));
            }
            for e in rec2.entries[pos + 1..].iter_mut() {
                e.overridden = true;
            }
            signer_index = i;
        }
        if let Some(s) = op.body.document() {
            self.check_identifiers(&st, owner, &s.identifiers)?;
        }
        if matches!(op.body, OpBody::Close { .. }) {
            rec2.status = OwnerStatus::Closed;
        }
        rec2.entries.push(Entry { sub: sub.clone(), received_at: now(), overridden: false, signer_index });
        let head = self.head_statement(owner, &rec2);
        st.owners.insert(owner.into(), rec2);
        Ok(head)
    }

    /// `GET /{url}` (§6.1): the head operation, which carries the registry
    /// document, and a head statement.
    pub fn resolve(&self, owner: &str) -> PResult<Vec<u8>> {
        let st = self.state.lock().unwrap();
        let rec = st.owners.get(owner).ok_or_else(|| Problem::not_found(owner))?;
        let head = self.head_statement(owner, rec);
        Ok(cbor::to_vec(&ResolutionResponse { operation: ByteBuf::from(rec.head().sub.op.raw.clone()), head: ByteBuf::from(head) }).unwrap())
    }

    /// `GET /{url}/head`.
    pub fn head(&self, owner: &str) -> PResult<Vec<u8>> {
        let st = self.state.lock().unwrap();
        let rec = st.owners.get(owner).ok_or_else(|| Problem::not_found(owner))?;
        Ok(self.head_statement(owner, rec))
    }

    /// `GET /{url}/log`.
    pub fn log(&self, owner: &str, after: Option<&str>) -> PResult<Vec<u8>> {
        let st = self.state.lock().unwrap();
        let rec = st.owners.get(owner).ok_or_else(|| Problem::not_found(owner))?;
        let mut entries: Vec<&Entry> = rec.entries.iter().collect();
        if let Some(a) = after {
            let h = hex::decode(a).map_err(|_| Problem::new(400, "bad-request", "after must be hex"))?;
            let pos = entries.iter().position(|e| e.sub.op.hash() == h).ok_or_else(|| Problem::not_found("operation"))?;
            entries = entries[pos + 1..].to_vec();
        }
        let log: Vec<LogEntry> = entries
            .iter()
            .map(|e| LogEntry { submission: ByteBuf::from(e.sub.raw.clone()), received_at: e.received_at, overridden: e.overridden })
            .collect();
        Ok(cbor::to_vec(&log).unwrap())
    }

    /// `GET /lookup/{type}/{value}`.
    pub fn lookup(&self, id_type: &str, value: &str) -> PResult<Vec<u8>> {
        let st = self.state.lock().unwrap();
        match st.attestations.get(&(id_type.to_string(), value.to_string())) {
            Some(a) if a.expires_at > now() => Ok(a.raw.clone()),
            _ => Err(Problem::not_found("identifier")),
        }
    }

    /// `GET /.well-known/edd` (§6.6).
    pub fn metadata(&self) -> serde_json::Value {
        let certs: Vec<serde_json::Value> = self
            .sealer
            .chain
            .iter()
            .take(1)
            .map(|c| {
                let (nb, na) = crate::certs::cert_validity(c).unwrap_or((0, 0));
                serde_json::json!({
                    "x5c": self.sealer.chain.iter().map(|c| crate::util::b64std(c)).collect::<Vec<_>>(),
                    "not_before": crate::util::fmt_time(nb),
                    "not_after": crate::util::fmt_time(na),
                })
            })
            .collect();
        serde_json::json!({
            "edd": self.cfg.base_url,
            "seal_certificates": certs,
            "identifier_types": crate::types::IDENTIFIER_TYPES,
            "recovery_window": self.cfg.recovery_window,
        })
    }

    /// Demo administration (not part of the specification): set an
    /// owner's lifecycle status, as the EDD would on a court order or a
    /// register update.
    pub fn set_status(&self, owner: &str, status: OwnerStatus, successor: Option<String>) -> PResult<Vec<u8>> {
        let mut st = self.state.lock().unwrap();
        let rec = st.owners.get_mut(owner).ok_or_else(|| Problem::not_found(owner))?;
        rec.status = status;
        rec.successor = successor;
        let rec = rec.clone();
        Ok(self.head_statement(owner, &rec))
    }
}

/// A client of the EDD API.
#[derive(Clone)]
pub struct EddClient {
    pub base: String,
    pub http: reqwest::Client,
    pub trust: TrustStore,
}

impl EddClient {
    pub fn new(base: &str, trust: TrustStore) -> Result<Self> {
        Ok(EddClient { base: base.trim_end_matches('/').to_string(), http: crate::net::http_client()?, trust })
    }

    /// Register a create operation, in a submission (§6.2).
    pub async fn register(&self, submission: &[u8], proof: &[u8]) -> Result<RegistrationResponse> {
        let body = cbor::to_vec(&RegistrationRequest { submission: ByteBuf::from(submission.to_vec()), proof: ByteBuf::from(proof.to_vec()) })?;
        let resp = crate::net::post_cbor(&self.http, &format!("{}/register", self.base), body).await?;
        let r: RegistrationResponse = cbor::from_slice(&resp)?;
        HeadStatement::parse(&r.head)?.verify(&self.trust, now())?;
        Ok(r)
    }

    /// Submit an update or close operation, in a submission (§6.5).
    pub async fn update(&self, owner: &str, submission: &[u8]) -> Result<HeadStatement> {
        let resp = crate::net::post_cbor(&self.http, &format!("{}/{}", self.base, owner), submission.to_vec()).await?;
        let h = HeadStatement::parse(&resp)?;
        h.verify(&self.trust, now())?;
        Ok(h)
    }

    /// Resolve and check an EBW URL's current registry document (§6.1,
    /// §5.2).
    pub async fn resolve(&self, owner: &str) -> Result<ResolvedDocument> {
        let body = crate::net::get_cbor(&self.http, &format!("{}/{}", self.base, owner))
            .await?
            .ok_or_else(|| anyhow!("{owner} not found at the EDD"))?;
        let resp: ResolutionResponse = cbor::from_slice(&body)?;
        ResolvedDocument::from_response(owner, &resp, &self.trust, now())
    }

    pub async fn head(&self, owner: &str) -> Result<HeadStatement> {
        let body = crate::net::get_cbor(&self.http, &format!("{}/{}/head", self.base, owner))
            .await?
            .ok_or_else(|| anyhow!("{owner} not found at the EDD"))?;
        let h = HeadStatement::parse(&body)?;
        h.verify(&self.trust, now())?;
        Ok(h)
    }

    pub async fn log_raw(&self, owner: &str) -> Result<Vec<u8>> {
        crate::net::get_cbor(&self.http, &format!("{}/{}/log", self.base, owner))
            .await?
            .ok_or_else(|| anyhow!("{owner} not found at the EDD"))
    }

    pub async fn lookup(&self, id: &Identifier) -> Result<Option<Vec<u8>>> {
        crate::net::get_cbor(
            &self.http,
            &format!("{}/lookup/{}/{}", self.base, id.id_type, crate::net::pct(&id.value)),
        )
        .await
    }
}
