//! Evidence artefacts, evidence bodies, endpoint statements and evidence
//! chains (05-evidence.md).

use crate::cbor::{self, Value};
use crate::certs::{TrustKind, TrustStore};
use crate::cose::{self, ExtraHeaders, PrivateKey, Sign1};
use crate::credential::Credential;
use crate::registry::Sealer;
use crate::types::{Address, Consignment, EndpointRef};
use crate::util::sha256;
use anyhow::{anyhow, bail, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{HashMap, HashSet};

pub const ETSI_EVENT_PREFIX: &str = "http://uri.etsi.org/19522/Event/";
pub const COMMIT_FAILURE_EVENT: &str = "urn:ebw:scc:event:CommitFailure";
pub const LOA_HIGH: &str = "http://eidas.europa.eu/LoA/high";
pub const SCC_AUTH_METHOD: &str = "urn:ebw:scc:auth:endpoint-credential";

/// ETSI EN 319 522 events used by SCC (§3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Event {
    A1,
    A2,
    B1,
    B2,
    B3,
    C1,
    C2,
    C3,
    C4,
    C5,
    C6,
    D1,
    D2,
    E1,
    E2,
}

pub const ALL_EVENTS: [Event; 15] = [
    Event::A1,
    Event::A2,
    Event::B1,
    Event::B2,
    Event::B3,
    Event::C1,
    Event::C2,
    Event::C3,
    Event::C4,
    Event::C5,
    Event::C6,
    Event::D1,
    Event::D2,
    Event::E1,
    Event::E2,
];

impl Event {
    pub fn code(&self) -> &'static str {
        match self {
            Event::A1 => "A.1",
            Event::A2 => "A.2",
            Event::B1 => "B.1",
            Event::B2 => "B.2",
            Event::B3 => "B.3",
            Event::C1 => "C.1",
            Event::C2 => "C.2",
            Event::C3 => "C.3",
            Event::C4 => "C.4",
            Event::C5 => "C.5",
            Event::C6 => "C.6",
            Event::D1 => "D.1",
            Event::D2 => "D.2",
            Event::E1 => "E.1",
            Event::E2 => "E.2",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Event::A1 => "SubmissionAcceptance",
            Event::A2 => "SubmissionRejection",
            Event::B1 => "RelayAcceptance",
            Event::B2 => "RelayRejection",
            Event::B3 => "RelayFailure",
            Event::C1 => "NotificationForAcceptance",
            Event::C2 => "NotificationForAcceptanceFailure",
            Event::C3 => "ConsignmentAcceptance",
            Event::C4 => "ConsignmentRejection",
            Event::C5 => "AcceptanceRejectionExpiry",
            Event::C6 => "NotificationDelivered",
            Event::D1 => "ContentConsignment",
            Event::D2 => "ContentConsignmentFailure",
            Event::E1 => "ContentHandover",
            Event::E2 => "ContentHandoverFailure",
        }
    }

    pub fn uri(&self) -> String {
        format!("{ETSI_EVENT_PREFIX}{}", self.name())
    }

    pub fn from_uri(uri: &str) -> Option<Event> {
        ALL_EVENTS.iter().copied().find(|e| e.uri() == uri)
    }

    pub fn from_code(code: &str) -> Option<Event> {
        ALL_EVENTS.iter().copied().find(|e| e.code() == code)
    }

    /// Terminal events (§3.7).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Event::A2 | Event::B2 | Event::B3 | Event::C2 | Event::C4 | Event::C5 | Event::D2 | Event::E1 | Event::E2
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub provider: String,
    pub name: String,
    pub policies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRef {
    #[serde(with = "serde_bytes")]
    pub message_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    pub from: Address,
    pub to: Address,
    pub sent_at: u64,
    pub expires_at: u64,
    pub consignment: Consignment,
    #[serde(with = "cbor::hash32")]
    pub plaintext_hash: Vec<u8>,
    #[serde(with = "cbor::hash32")]
    pub envelope_hash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRef {
    #[serde(with = "serde_bytes")]
    pub group_context: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub epoch_authenticator: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssurance {
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthAssurance {
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assurance {
    pub identity: IdentityAssurance,
    pub authentication: AuthAssurance,
}

impl Assurance {
    /// The assurance SCC gives: the owner identified by the EDD at LoA
    /// high, the endpoint authenticated with its credential at `at`.
    pub fn scc(identity_policy: &str, at: u64) -> Self {
        Assurance {
            identity: IdentityAssurance { level: LOA_HIGH.into(), policy: Some(identity_policy.into()) },
            authentication: AuthAssurance {
                level: LOA_HIGH.into(),
                method: Some(SCC_AUTH_METHOD.into()),
                at: Some(at),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handover {
    pub subject: String,
    pub transferred_at: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acknowledged_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub text: Option<String>,
}

impl Reason {
    pub fn new(code: &str, scc: Option<&str>, text: Option<String>) -> Self {
        Reason { code: code.into(), scc: scc.map(|s| s.into()), text }
    }
}

/// `message-evidence` (§3.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageEvidence {
    pub v: u64,
    #[serde(with = "serde_bytes")]
    pub evidence_id: Vec<u8>,
    pub event: String,
    pub issuer: Issuer,
    pub event_time: u64,
    pub message: MessageRef,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mls: Option<MlsRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<Reason>,
    pub heads: Vec<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statuses: Option<Vec<ByteBuf>>,
    pub sender_assurance: Assurance,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recipient_assurance: Option<Assurance>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev: Option<Vec<ByteBuf>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint: Option<EndpointRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub handovers: Option<Vec<Handover>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub decisions: Option<Vec<ByteBuf>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reports: Option<Vec<ByteBuf>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub eligible_holders: Option<u64>,
}

impl MessageEvidence {
    pub fn event(&self) -> Result<Event> {
        Event::from_uri(&self.event).ok_or_else(|| anyhow!("unknown event {}", self.event))
    }

    pub fn prev_hashes(&self) -> Vec<Vec<u8>> {
        self.prev.iter().flatten().map(|b| b.to_vec()).collect()
    }
}

/// `commit-failure-evidence` (§3.4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitFailureEvidence {
    pub v: u64,
    #[serde(with = "serde_bytes")]
    pub evidence_id: Vec<u8>,
    pub event: String,
    pub issuer: Issuer,
    pub event_time: u64,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "cbor::hash32")]
    pub commit_ref: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub group_context: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub report: Vec<u8>,
}

/// `evidence-package` (§3.6).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackage {
    pub v: u64,
    #[serde(rename = "type")]
    pub st_type: String,
    #[serde(with = "serde_bytes")]
    pub message_id: Vec<u8>,
    pub composed_at: u64,
    pub items: Vec<(ByteBuf, ByteBuf)>,
}

#[derive(Clone, Debug)]
pub enum EvidenceBody {
    Message(Box<MessageEvidence>),
    CommitFailure(CommitFailureEvidence),
    Package(EvidencePackage),
}

impl EvidenceBody {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let v = cbor::decode(payload)?;
        let m = cbor::as_map(&v)?;
        if cbor::map_text(m, "type").and_then(|t| t.as_text()) == Some("evidence-package") {
            return Ok(EvidenceBody::Package(cbor::from_value(v)?));
        }
        match cbor::map_text(m, "event").and_then(|t| t.as_text()) {
            Some(COMMIT_FAILURE_EVENT) => Ok(EvidenceBody::CommitFailure(cbor::from_value(v)?)),
            Some(e) if Event::from_uri(e).is_some() => Ok(EvidenceBody::Message(Box::new(cbor::from_value(v)?))),
            Some(e) => bail!("unknown evidence event {e}"),
            None => bail!("evidence body has no event"),
        }
    }
}

/// An RDS's evidence sealer: its seal key and certificate, and its TSA.
#[derive(Clone)]
pub struct EvidenceSealer {
    pub seal: Sealer,
    pub tsa: Sealer,
}

impl EvidenceSealer {
    /// Seal a body as an evidence artefact (§2.1).
    pub fn seal<T: Serialize>(&self, body: &T, t: u64) -> Result<Artefact> {
        let payload = cbor::to_vec(body)?;
        let seal = self.seal.seal(&payload);
        let ts = crate::tsa::timestamp(&self.tsa, &seal, t);
        let raw = cbor::encode(&Value::Array(vec![Value::Bytes(seal), Value::Bytes(ts)]));
        Artefact::parse(&raw)
    }
}

/// A parsed evidence artefact.
#[derive(Clone, Debug)]
pub struct Artefact {
    pub raw: Vec<u8>,
    pub seal: Vec<u8>,
    pub timestamp: Vec<u8>,
    pub cose: Sign1,
    pub body: EvidenceBody,
}

impl Artefact {
    /// §2.2 step 1 (decoding, deterministic encoding).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let v = cbor::decode_deterministic(raw)?;
        let (seal, timestamp) = match v {
            Value::Array(a) if a.len() == 2 => (
                cbor::as_bytes(&a[0])?.clone(),
                cbor::as_bytes(&a[1])?.clone(),
            ),
            _ => bail!("evidence artefact must be [seal, timestamp]"),
        };
        Artefact::from_parts(&seal, &timestamp)
    }

    pub fn from_parts(seal: &[u8], timestamp: &[u8]) -> Result<Self> {
        let cose = Sign1::parse(seal)?;
        let body = EvidenceBody::parse(&cose.payload)?;
        let raw = cbor::encode(&Value::Array(vec![cbor::bytes(seal), cbor::bytes(timestamp)]));
        Ok(Artefact { raw, seal: seal.to_vec(), timestamp: timestamp.to_vec(), cose, body })
    }

    /// SHA-256 of the seal: what `prev` names (§3.7).
    pub fn seal_hash(&self) -> Vec<u8> {
        sha256(&self.seal)
    }

    pub fn message(&self) -> Option<&MessageEvidence> {
        match &self.body {
            EvidenceBody::Message(m) => Some(m),
            _ => None,
        }
    }

    pub fn event_time(&self) -> u64 {
        match &self.body {
            EvidenceBody::Message(m) => m.event_time,
            EvidenceBody::CommitFailure(c) => c.event_time,
            EvidenceBody::Package(p) => p.composed_at,
        }
    }

    /// §2.2 steps 2 to 4: the seal verifies with the leaf certificate,
    /// which is trusted and valid at the timestamp's time, and the
    /// timestamp verifies over the seal. Returns the timestamp time.
    pub fn verify_seal(&self, trust: &TrustStore) -> Result<u64> {
        let ts_time = crate::tsa::verify_timestamp(&self.timestamp, &self.seal, trust)
            .map_err(|e| anyhow!("timestamp: {e}"))?;
        let key = trust.check_chain(&self.cose.x5chain(), TrustKind::Rds, ts_time)?;
        self.cose.verify(&key).map_err(|e| anyhow!("seal: {e}"))?;
        Ok(ts_time)
    }

    pub fn as_items(&self) -> (ByteBuf, ByteBuf) {
        (ByteBuf::from(self.seal.clone()), ByteBuf::from(self.timestamp.clone()))
    }
}

// ---- Endpoint statements (§4, §5, §6) ----

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreedEpoch {
    pub epoch: u64,
    #[serde(with = "serde_bytes")]
    pub epoch_authenticator: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportResult {
    Match,
    Mismatch,
    DecryptFailed,
    InvalidEpoch,
    JoinFailure,
}

impl ReportResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportResult::Match => "match",
            ReportResult::Mismatch => "mismatch",
            ReportResult::DecryptFailed => "decrypt-failed",
            ReportResult::InvalidEpoch => "invalid-epoch",
            ReportResult::JoinFailure => "join-failure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptionReport {
    #[serde(rename = "type")]
    pub st_type: String,
    #[serde(with = "serde_bytes")]
    pub message_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "cbor::hash32")]
    pub envelope_hash: Vec<u8>,
    pub result: ReportResult,
    /// For `mismatch`: SHA-256(fresh salt || application data).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub plaintext_hash: Option<ByteBuf>,
    /// For `invalid-epoch`: the endpoint's value for `epoch`, or for
    /// `held_epoch` if given.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub epoch_authenticator: Option<ByteBuf>,
    /// For `invalid-epoch`: the latest epoch the endpoint holds, if it does
    /// not hold `epoch`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub held_epoch: Option<u64>,
    pub owner: String,
    pub subject: String,
    pub reported_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitFailure {
    ConfirmationTag,
    PathSecret,
    Welcome,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitFailureReport {
    #[serde(rename = "type")]
    pub st_type: String,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "cbor::hash32")]
    pub commit_ref: Vec<u8>,
    pub epoch: u64,
    pub failure: CommitFailure,
    /// Absent if the endpoint never joined (doc 5 §5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_agreed: Option<AgreedEpoch>,
    pub owner: String,
    pub subject: String,
    pub reported_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Accept,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDecision {
    #[serde(rename = "type")]
    pub st_type: String,
    #[serde(with = "serde_bytes")]
    pub message_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "cbor::hash32")]
    pub envelope_hash: Vec<u8>,
    pub decision: Decision,
    pub owner: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub holder: Option<String>,
    pub decided_at: u64,
}

/// Common accessors of endpoint statements.
pub trait StatementBody: Serialize + DeserializeOwned {
    const TYPE: &'static str;
    fn st_type(&self) -> &str;
    fn owner(&self) -> &str;
    fn subject(&self) -> &str;
    fn time(&self) -> u64;
}

impl StatementBody for DecryptionReport {
    const TYPE: &'static str = "decryption-report";
    fn st_type(&self) -> &str {
        &self.st_type
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn subject(&self) -> &str {
        &self.subject
    }
    fn time(&self) -> u64 {
        self.reported_at
    }
}

impl StatementBody for CommitFailureReport {
    const TYPE: &'static str = "commit-failure-report";
    fn st_type(&self) -> &str {
        &self.st_type
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn subject(&self) -> &str {
        &self.subject
    }
    fn time(&self) -> u64 {
        self.reported_at
    }
}

impl StatementBody for ConsentDecision {
    const TYPE: &'static str = "consent-decision";
    fn st_type(&self) -> &str {
        &self.st_type
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn subject(&self) -> &str {
        &self.subject
    }
    fn time(&self) -> u64 {
        self.decided_at
    }
}

/// Sign an endpoint statement with the endpoint key; the protected header
/// carries the credential in `scc-cred` (§4).
pub fn sign_statement<T: Serialize>(key: &PrivateKey, credential: &[u8], body: &T) -> Result<Vec<u8>> {
    Ok(cose::sign1(key, &cbor::to_vec(body)?, &ExtraHeaders::scc_cred(credential), false))
}

/// A parsed endpoint statement whose signature verifies under the `cnf`
/// key of its embedded credential. The credential itself is not yet
/// checked against the registry document.
#[derive(Clone, Debug)]
pub struct Statement<T> {
    pub raw: Vec<u8>,
    pub body: T,
    pub credential: Credential,
}

pub fn parse_statement<T: StatementBody>(raw: &[u8]) -> Result<Statement<T>> {
    let cose = Sign1::parse(raw)?;
    let cred = cose.scc_cred().ok_or_else(|| anyhow!("statement without scc-cred"))?;
    let credential = Credential::parse(&cred)?;
    let kid = cose.kid().ok_or_else(|| anyhow!("statement without kid"))?;
    if kid != credential.claims.cnf.thumbprint() {
        bail!("statement kid is not the credential's endpoint key");
    }
    cose.verify(&credential.claims.cnf)?;
    let body: T = cbor::from_slice(&cose.payload)?;
    if body.st_type() != T::TYPE {
        bail!("expected a {}", T::TYPE);
    }
    if body.owner() != credential.claims.iss || body.subject() != credential.claims.sub {
        bail!("statement owner/subject differ from its credential");
    }
    Ok(Statement { raw: raw.to_vec(), body, credential })
}

/// The result of checking an evidence chain.
#[derive(Debug)]
pub struct ChainSummary {
    pub start: Event,
    pub terminal: Event,
    /// Events in path order (a topological order from start to end).
    pub order: Vec<Event>,
}

/// Check that a set of message evidence forms a chain (§3.7, §7.2 step 2):
/// exactly one item has no `prev` and it is A.1 (or the sole item is A.2);
/// every `prev` names an item in the set; exactly one item is terminal and
/// nothing names it; every item lies on a path from the start to the end.
pub fn check_chain(items: &[(Vec<u8>, Event, Vec<Vec<u8>>)]) -> Result<ChainSummary> {
    if items.is_empty() {
        bail!("no evidence");
    }
    let by_hash: HashMap<&[u8], usize> = items.iter().enumerate().map(|(i, (h, _, _))| (h.as_slice(), i)).collect();
    if by_hash.len() != items.len() {
        bail!("duplicate evidence items");
    }
    let roots: Vec<usize> = items.iter().enumerate().filter(|(_, (_, _, p))| p.is_empty()).map(|(i, _)| i).collect();
    if roots.len() != 1 {
        bail!("chain must have exactly one start, found {}", roots.len());
    }
    let root = roots[0];
    match items[root].1 {
        Event::A1 => {}
        Event::A2 if items.len() == 1 => {}
        e => bail!("chain starts with {} instead of A.1", e.code()),
    }
    let mut referenced = HashSet::new();
    for (h, e, prev) in items {
        for p in prev {
            if !by_hash.contains_key(p.as_slice()) {
                bail!("{} names evidence outside the set", e.code());
            }
            if p == h {
                bail!("{} names itself", e.code());
            }
            referenced.insert(p.clone());
        }
    }
    let terminals: Vec<usize> = items.iter().enumerate().filter(|(_, (_, e, _))| e.is_terminal()).map(|(i, _)| i).collect();
    if terminals.len() != 1 {
        bail!("chain must have exactly one terminal event, found {}", terminals.len());
    }
    let term = terminals[0];
    if referenced.contains(&items[term].0) {
        bail!("terminal event {} is followed by other evidence", items[term].1.code());
    }
    // Walk back from the terminal event.
    let mut on_path = HashSet::new();
    let mut stack = vec![term];
    while let Some(i) = stack.pop() {
        if on_path.insert(i) {
            for p in &items[i].2 {
                stack.push(by_hash[p.as_slice()]);
            }
        }
    }
    if on_path.len() != items.len() {
        let off: Vec<&str> = (0..items.len()).filter(|i| !on_path.contains(i)).map(|i| items[i].1.code()).collect();
        bail!("evidence off the chain: {}", off.join(", "));
    }
    if !on_path.contains(&root) {
        bail!("terminal event does not lead back to the start");
    }
    // Topological order (also detects cycles).
    let mut order = Vec::new();
    let mut done = HashSet::new();
    let mut remaining: Vec<usize> = (0..items.len()).collect();
    while !remaining.is_empty() {
        let before = remaining.len();
        remaining.retain(|&i| {
            if items[i].2.iter().all(|p| done.contains(&by_hash[p.as_slice()])) {
                order.push(items[i].1);
                done.insert(i);
                false
            } else {
                true
            }
        });
        if remaining.len() == before {
            bail!("evidence chain has a cycle");
        }
    }
    Ok(ChainSummary { start: items[root].1, terminal: items[term].1, order })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[test]
    fn chains() {
        let ok = vec![
            (h(1), Event::A1, vec![]),
            (h(2), Event::B1, vec![h(1)]),
            (h(3), Event::D1, vec![h(2)]),
            (h(4), Event::E1, vec![h(3)]),
        ];
        let s = check_chain(&ok).unwrap();
        assert_eq!(s.terminal, Event::E1);
        let mut bad = ok.clone();
        bad.push((h(5), Event::C1, vec![h(2)]));
        assert!(check_chain(&bad).is_err());
        let mut two_terms = ok.clone();
        two_terms.push((h(6), Event::E2, vec![h(3)]));
        assert!(check_chain(&two_terms).is_err());
        assert!(check_chain(&ok[..3]).is_err());
        check_chain(&[(h(9), Event::A2, vec![])]).unwrap();
    }
}
