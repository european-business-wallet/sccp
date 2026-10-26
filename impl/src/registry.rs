//! EBW URL operations, registry document, and EDD statements (01-discovery.md).

use crate::cbor;
use crate::certs::{TrustKind, TrustStore};
use crate::cose::{self, CoseKey, ExtraHeaders, PrivateKey, Sign1};
use crate::types::{check_ebw_url, AcceptancePolicy, OwnerStatus, Identifier};
use crate::util::{base32_lower, sha256};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// The registry document set by a create or update operation (§3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryDocument {
    pub update_keys: Vec<CoseKey>,
    pub credential_keys: Vec<CoseKey>,
    /// The home RDS's URL (§3.2).
    pub rds: String,
    pub identifiers: Vec<Identifier>,
    pub acceptance_policies: BTreeMap<String, AcceptancePolicy>,
    pub signed_at: u64,
}

impl RegistryDocument {
    /// The acceptance policy for a role (the `default` entry otherwise).
    pub fn policy_for(&self, role: &str) -> AcceptancePolicy {
        self.acceptance_policies
            .get(role)
            .or_else(|| self.acceptance_policies.get("default"))
            .cloned()
            .unwrap_or(AcceptancePolicy::Any)
    }

    fn check(&self) -> Result<()> {
        if !(1..=5).contains(&self.update_keys.len()) {
            bail!("update_keys must have 1 to 5 keys");
        }
        if !(1..=5).contains(&self.credential_keys.len()) {
            bail!("credential_keys must have 1 to 5 keys");
        }
        if !self.rds.starts_with("https://") || self.rds.len() <= 8 {
            bail!("rds must be an https URL");
        }
        if !self.acceptance_policies.contains_key("default") {
            bail!("acceptance_policies must have a default entry");
        }
        for id in &self.identifiers {
            if !crate::types::IDENTIFIER_TYPES.contains(&id.id_type.as_str()) {
                bail!("unknown identifier type {}", id.id_type);
            }
        }
        Ok(())
    }
}

/// The payload of an operation (`op-body`), in wire form.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpBodyWire {
    #[serde(rename = "type")]
    op_type: String,
    prev: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    update_keys: Option<Vec<CoseKey>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    credential_keys: Option<Vec<CoseKey>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    rds: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    identifiers: Option<Vec<Identifier>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    acceptance_policies: Option<BTreeMap<String, AcceptancePolicy>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    signed_at: Option<u64>,
}

/// An operation body.
#[derive(Clone, Debug, PartialEq)]
pub enum OpBody {
    Create(RegistryDocument),
    Update { prev: Vec<u8>, state: RegistryDocument },
    Close { prev: Vec<u8> },
}

impl OpBody {
    pub fn prev(&self) -> Option<&[u8]> {
        match self {
            OpBody::Create(_) => None,
            OpBody::Update { prev, .. } | OpBody::Close { prev } => Some(prev),
        }
    }

    pub fn document(&self) -> Option<&RegistryDocument> {
        match self {
            OpBody::Create(s) | OpBody::Update { state: s, .. } => Some(s),
            OpBody::Close { .. } => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            OpBody::Create(_) => "create",
            OpBody::Update { .. } => "update",
            OpBody::Close { .. } => "close",
        }
    }

    fn to_wire(&self) -> OpBodyWire {
        let mut w = OpBodyWire {
            op_type: self.type_name().into(),
            prev: self.prev().map(|p| ByteBuf::from(p.to_vec())),
            update_keys: None,
            credential_keys: None,
            rds: None,
            identifiers: None,
            acceptance_policies: None,
            signed_at: None,
        };
        if let Some(s) = self.document() {
            w.update_keys = Some(s.update_keys.clone());
            w.credential_keys = Some(s.credential_keys.clone());
            w.rds = Some(s.rds.clone());
            w.identifiers = Some(s.identifiers.clone());
            w.acceptance_policies = Some(s.acceptance_policies.clone());
            w.signed_at = Some(s.signed_at);
        }
        w
    }

    fn from_wire(w: OpBodyWire) -> Result<Self> {
        let state = || -> Result<RegistryDocument> {
            let s = RegistryDocument {
                update_keys: w.update_keys.clone().ok_or_else(|| anyhow!("missing update_keys"))?,
                credential_keys: w.credential_keys.clone().ok_or_else(|| anyhow!("missing credential_keys"))?,
                rds: w.rds.clone().ok_or_else(|| anyhow!("missing rds"))?,
                identifiers: w.identifiers.clone().ok_or_else(|| anyhow!("missing identifiers"))?,
                acceptance_policies: w
                    .acceptance_policies
                    .clone()
                    .ok_or_else(|| anyhow!("missing acceptance_policies"))?,
                signed_at: w.signed_at.ok_or_else(|| anyhow!("missing signed_at"))?,
            };
            s.check()?;
            Ok(s)
        };
        let prev32 = |p: &Option<ByteBuf>| -> Result<Vec<u8>> {
            let p = p.as_ref().ok_or_else(|| anyhow!("missing prev"))?;
            if p.len() != 32 {
                bail!("prev must be 32 bytes");
            }
            Ok(p.to_vec())
        };
        Ok(match w.op_type.as_str() {
            "create" => {
                if w.prev.is_some() {
                    bail!("create operation must have prev = null");
                }
                OpBody::Create(state()?)
            }
            "update" => OpBody::Update { prev: prev32(&w.prev)?, state: state()? },
            "close" => {
                if w.update_keys.is_some() || w.rds.is_some() || w.signed_at.is_some() {
                    bail!("close operation carries state fields");
                }
                OpBody::Close { prev: prev32(&w.prev)? }
            }
            t => bail!("unknown operation type {t}"),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::to_vec(&self.to_wire()).expect("encodable")
    }
}

/// A signed operation.
#[derive(Clone, Debug)]
pub struct Operation {
    pub raw: Vec<u8>,
    pub cose: Sign1,
    pub body: OpBody,
}

impl Operation {
    pub fn sign(body: OpBody, key: &PrivateKey) -> Operation {
        let raw = cose::sign1(key, &body.encode(), &ExtraHeaders::default(), false);
        Operation::parse(&raw).expect("own operation parses")
    }

    /// Parse and check the shape of an operation (§3.3 item 1).
    pub fn parse(raw: &[u8]) -> Result<Operation> {
        let cose = Sign1::parse(raw)?;
        let wire: OpBodyWire = cbor::from_slice(&cose.payload)?;
        let body = OpBody::from_wire(wire)?;
        Ok(Operation { raw: raw.to_vec(), cose, body })
    }

    /// `op-hash`: SHA-256 of the encoded COSE_Sign1.
    pub fn hash(&self) -> Vec<u8> {
        sha256(&self.raw)
    }

    /// Check the signature against the update keys of `signer_state`
    /// (§3.1). Returns the index of the signing key.
    pub fn verify_with(&self, signer_state: &RegistryDocument) -> Result<usize> {
        self.cose.verify_kid(&signer_state.update_keys)
    }
}

/// The payload of a submission (`submission-body`, §3.6).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionBody {
    #[serde(rename = "type")]
    pub st_type: String,
    pub operation: ByteBuf,
    pub submitted_at: u64,
}

/// An operation sealed by the owner's EBW provider for submission to the
/// EDD (§3.6).
#[derive(Clone, Debug)]
pub struct Submission {
    pub raw: Vec<u8>,
    pub cose: Sign1,
    pub body: SubmissionBody,
    pub op: Operation,
}

impl Submission {
    pub fn seal(sealer: &Sealer, op: &Operation, t: u64) -> Vec<u8> {
        sealer.seal(
            &cbor::to_vec(&SubmissionBody {
                st_type: "submission".into(),
                operation: ByteBuf::from(op.raw.clone()),
                submitted_at: t,
            })
            .unwrap(),
        )
    }

    /// Parse a submission and the operation it carries.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        let body: SubmissionBody = cbor::from_slice(&cose.payload)?;
        if body.st_type != "submission" {
            bail!("not a submission");
        }
        let op = Operation::parse(&body.operation)?;
        Ok(Submission { raw: raw.to_vec(), cose, body, op })
    }

    /// Verify the EBW provider's seal against the trusted provider
    /// certificates, as of time `t`.
    pub fn verify(&self, trust: &TrustStore, t: u64) -> Result<()> {
        let key = trust.check_chain(&self.cose.x5chain(), TrustKind::Ebw, t)?;
        self.cose.verify(&key)
    }
}

/// Derive the EBW URL from an encoded create operation (§2).
pub fn url_from_create(raw: &[u8]) -> String {
    format!("ebw:{}", &base32_lower(&sha256(raw))[..24])
}

// ---- EDD statements (§4, §5) ----

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadStatementBody {
    #[serde(rename = "type")]
    pub st_type: String,
    pub owner: String,
    #[serde(with = "cbor::hash32")]
    pub head: Vec<u8>,
    pub seq: u64,
    pub status: OwnerStatus,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub successor: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentifierAttestationBody {
    #[serde(rename = "type")]
    pub st_type: String,
    pub identifier: Identifier,
    pub owner: String,
    pub verified_at: u64,
    pub expires_at: u64,
}

/// An EDD signing key with its certificate chain.
#[derive(Clone)]
pub struct Sealer {
    pub key: PrivateKey,
    pub chain: Vec<Vec<u8>>,
}

impl Sealer {
    pub fn seal(&self, payload: &[u8]) -> Vec<u8> {
        cose::sign1(&self.key, payload, &ExtraHeaders::x5chain(self.chain.clone()), false)
    }
}

/// A parsed and (optionally) verified head statement.
#[derive(Clone, Debug)]
pub struct HeadStatement {
    pub raw: Vec<u8>,
    pub cose: Sign1,
    pub body: HeadStatementBody,
}

impl HeadStatement {
    pub fn issue(sealer: &Sealer, body: &HeadStatementBody) -> Vec<u8> {
        sealer.seal(&cbor::to_vec(body).unwrap())
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        let body: HeadStatementBody = cbor::from_slice(&cose.payload)?;
        if body.st_type != "head-statement" {
            bail!("not a head statement");
        }
        check_ebw_url(&body.owner)?;
        Ok(HeadStatement { raw: raw.to_vec(), cose, body })
    }

    /// Verify the EDD seal against the trusted EDD certificates, and that
    /// the statement is valid at `t`.
    pub fn verify(&self, trust: &TrustStore, t: u64) -> Result<()> {
        let key = trust.check_chain(&self.cose.x5chain(), TrustKind::Edd, t)?;
        self.cose.verify(&key)?;
        if t < self.body.issued_at || t >= self.body.expires_at {
            bail!(
                "head statement for {} not valid at {} (valid {}..{})",
                self.body.owner,
                crate::util::fmt_time(t),
                crate::util::fmt_time(self.body.issued_at),
                crate::util::fmt_time(self.body.expires_at)
            );
        }
        Ok(())
    }
}

/// A parsed identifier attestation.
#[derive(Clone, Debug)]
pub struct IdentifierAttestation {
    pub raw: Vec<u8>,
    pub body: IdentifierAttestationBody,
}

impl IdentifierAttestation {
    pub fn parse_and_verify(raw: &[u8], trust: &TrustStore, t: u64) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        let body: IdentifierAttestationBody = cbor::from_slice(&cose.payload)?;
        if body.st_type != "identifier-attestation" {
            bail!("not an identifier attestation");
        }
        let key = trust.check_chain(&cose.x5chain(), TrustKind::Edd, t)?;
        cose.verify(&key)?;
        if t < body.verified_at || t >= body.expires_at {
            bail!("attestation not valid now");
        }
        Ok(IdentifierAttestation { raw: raw.to_vec(), body })
    }
}

// ---- EDD API bodies (§6) ----

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub submission: ByteBuf,
    pub proof: ByteBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationResponse {
    pub owner: String,
    pub head: ByteBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionResponse {
    pub operation: ByteBuf,
    pub head: ByteBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub submission: ByteBuf,
    pub received_at: u64,
    pub overridden: bool,
}

/// A registry document resolved from the EDD and checked against a head statement.
#[derive(Clone, Debug)]
pub struct ResolvedDocument {
    pub owner: String,
    pub operation: Operation,
    pub document: RegistryDocument,
    pub head: HeadStatement,
}

impl ResolvedDocument {
    /// Check a `resolution-response`: the head statement verifies, names
    /// this EBW URL, and its `head` is the hash of the operation.
    pub fn from_response(owner: &str, resp: &ResolutionResponse, trust: &TrustStore, now: u64) -> Result<Self> {
        let head = HeadStatement::parse(&resp.head)?;
        head.verify(trust, now)?;
        if head.body.owner != owner {
            bail!("head statement names another EBW URL");
        }
        let operation = Operation::parse(&resp.operation)?;
        if operation.hash() != head.body.head {
            bail!("head statement does not name the returned operation");
        }
        let document = match &operation.body {
            OpBody::Close { .. } => bail!("EBW URL is closed"),
            b => b.document().unwrap().clone(),
        };
        Ok(ResolvedDocument { owner: owner.into(), operation, document, head })
    }
}

/// Audit an EBW URL log (§6.4): the first entry is a create operation whose
/// hash gives the EBW URL; each entry's submission seal verifies; each
/// entry is validly signed against the registry document its `prev`
/// names; the non-overridden entries form a chain. Returns, for each entry,
/// the operation and the registry document it sets (None for close).
pub fn audit_log(owner: &str, log: &[LogEntry], trust: &TrustStore) -> Result<Vec<(Operation, Option<RegistryDocument>, bool)>> {
    let mut out: Vec<(Operation, Option<RegistryDocument>, bool)> = Vec::new();
    let mut last_live: Option<Vec<u8>> = None;
    for (i, e) in log.iter().enumerate() {
        let sub = Submission::parse(&e.submission).map_err(|err| anyhow!("entry {i}: {err:#}"))?;
        sub.verify(trust, e.received_at).map_err(|err| anyhow!("entry {i}: submission seal: {err:#}"))?;
        let op = sub.op;
        match &op.body {
            OpBody::Create(s) => {
                if i != 0 {
                    bail!("create operation not first in log");
                }
                if url_from_create(&op.raw) != owner {
                    bail!("create operation does not hash to {owner}");
                }
                op.verify_with(s)?;
            }
            b => {
                let prev = b.prev().unwrap();
                let (_, pstate, _) = out
                    .iter()
                    .find(|(o, _, _)| o.hash() == prev)
                    .ok_or_else(|| anyhow!("entry {i}: prev names no earlier operation"))?;
                let pstate = pstate.as_ref().ok_or_else(|| anyhow!("entry {i} follows a close operation"))?;
                op.verify_with(pstate)?;
                if !e.overridden && last_live.as_deref() != Some(prev) {
                    // A recovery: everything after prev must be overridden.
                    let pos = out.iter().position(|(o, _, _)| o.hash() == prev).unwrap();
                    if out[pos + 1..].iter().any(|(_, _, n)| !*n) {
                        bail!("entry {i}: recovery leaves non-overridden operations");
                    }
                }
            }
        }
        if !e.overridden {
            last_live = Some(op.hash());
        }
        let st = op.body.document().cloned();
        out.push((op, st, e.overridden));
    }
    if out.is_empty() {
        bail!("empty log");
    }
    Ok(out)
}

/// Find the state set by the operation with hash `head` in an audited log.
pub fn state_at_head(audited: &[(Operation, Option<RegistryDocument>, bool)], head: &[u8]) -> Result<RegistryDocument> {
    audited
        .iter()
        .find(|(o, _, _)| o.hash() == head)
        .and_then(|(_, s, _)| s.clone())
        .ok_or_else(|| anyhow!("head {} is not a state-setting operation in the log", hex::encode(head)))
}
