//! Parameters and results of the delivery protocol (04-delivery.md,
//! schemas/delivery.openrpc.json). Binary values are base64url in JSON.

use crate::types::{Address, Consignment, EndpointRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::util::{b64, b64opt, b64vec};

pub const VERSION: &str = "scc/1";

/// Delivery metadata sent in clear beside the ciphertext (doc 3 §7.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    #[serde(with = "b64")]
    pub message_id: Vec<u8>,
    pub from: Address,
    pub to: Address,
    pub sent_at: u64,
    pub expires_at: u64,
    pub consignment: Consignment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectParams {
    pub versions: Vec<String>,
    pub owner: String,
    pub subject: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectResult {
    pub version: String,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticateParams {
    #[serde(with = "b64")]
    pub credential: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticateResult {
    pub registered: bool,
    pub queue_head: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAckParams {
    pub up_to: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchParams {
    pub after: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedItem {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchResult {
    pub items: Vec<QueuedItem>,
    pub more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishParams {
    #[serde(with = "b64vec")]
    pub key_packages: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolStatus {
    pub available: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageGetParams {
    pub address: Address,
    pub cipher_suite: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subjects: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveParams {
    pub address: Address,
    pub cipher_suite: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subjects: Option<Vec<String>>,
    pub requester: EndpointRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectKeyPackage {
    pub subject: String,
    #[serde(with = "b64")]
    pub key_package: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub reservation: String,
    pub expires_at: u64,
    pub eligible: Vec<String>,
    pub key_packages: Vec<SubjectKeyPackage>,
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    #[serde(with = "b64")]
    pub group_info: Vec<u8>,
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    #[serde(with = "b64")]
    pub welcome: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reservations: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitSubmitParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub welcome: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reservations: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochResult {
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitFetchParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub after_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionIdParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub epoch: u64,
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub welcome: Option<Vec<u8>>,
    pub accepted_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitsResult {
    pub commits: Vec<LogEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLog {
    #[serde(with = "b64")]
    pub group_info: Vec<u8>,
    pub commits: Vec<LogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitReportParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "b64")]
    pub report: Vec<u8>,
}

/// `wmp.message.deliver`: submission (§7.1), relay (§7.2) and
/// consignment notification (§7.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    #[serde(with = "b64")]
    pub message: Vec<u8>,
    pub meta: Meta,
    #[serde(with = "b64")]
    pub plaintext_hash: Vec<u8>,
    #[serde(with = "b64")]
    pub epoch_authenticator: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub submission_evidence: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relayed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceResult {
    #[serde(with = "b64")]
    pub evidence: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AckStatus {
    Processed,
    Failed,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAckParams {
    #[serde(with = "b64")]
    pub message_id: Vec<u8>,
    pub status: AckStatus,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub report: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub decision: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAckResult {
    pub recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub evidence: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageIdParams {
    #[serde(with = "b64")]
    pub message_id: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResult {
    #[serde(with = "b64")]
    pub package: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestParams {
    pub seq: u64,
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub meta: Meta,
    #[serde(with = "b64")]
    pub envelope_hash: Vec<u8>,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeParams {
    pub seq: u64,
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub commit: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub welcome: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceNotifyParams {
    pub event: String,
    #[serde(with = "b64")]
    pub evidence: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub message_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "b64opt")]
    pub session_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageStatusParams {
    pub seq: u64,
    pub available: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectsParams {
    pub address: Address,
    pub cipher_suite: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectsResult {
    pub as_of: u64,
    pub expires_at: u64,
    pub subjects: Vec<String>,
    pub no_key_packages: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdsSessionCreateParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    #[serde(with = "b64")]
    pub group_info: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdsCommitResult {
    pub status: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdsCommitReportParams {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    #[serde(with = "b64")]
    pub evidence: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipMismatch {
    pub add: Vec<EndpointRef>,
    pub remove: Vec<u32>,
}

// ---- RDS metadata (§3) ----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GoverningBody {
    pub name: String,
    pub identifier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdsEndpoints {
    pub client: String,
    pub federation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssuranceLevels {
    pub identity: Vec<String>,
    pub authentication: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceInfo {
    pub policies: Vec<String>,
    pub retention: String,
    pub seal_certificates: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdsMetadata {
    pub provider: String,
    pub governing_body: GoverningBody,
    pub trust_domains: Vec<String>,
    pub versions: Vec<String>,
    pub endpoints: RdsEndpoints,
    pub cipher_suites: Vec<u16>,
    pub consignment_modes: Vec<Consignment>,
    pub max_message_size: u64,
    pub max_ttl: u64,
    pub session_idle_limit: u64,
    pub max_clock_skew: u64,
    pub expiry: bool,
    pub scheduled_delivery: bool,
    pub assurance: AssuranceLevels,
    pub evidence: EvidenceInfo,
}
