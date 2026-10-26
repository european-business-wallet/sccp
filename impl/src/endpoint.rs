//! An SCC endpoint: registration with its home RDS, KeyPackages, sessions,
//! sending and receiving messages, decryption reports, consent decisions,
//! and the retention of evidence and private data (03-mls.md,
//! 04-delivery.md, 05-evidence.md §4, §6, §8).
//!
//! State lives in a directory:
//!
//! - `endpoint.json`: identity, keys, credential, queue position;
//! - `mls.db`: mls-rs group and KeyPackage state (SQLite);
//! - `sessions.json`: known sessions;
//! - `epochs.json`: retained MLS state, by session and epoch (doc 5 §8);
//! - `keypackages.json`: retained private keys of published KeyPackages;
//! - `messages/<id>/`: one record per message sent or received
//!   (`record.json`), its evidence (`evidence/`), and its plaintext.

use crate::cose::PrivateKey;
use crate::credential::{ConnectProofBody, Credential, CredentialRequestBody};
use crate::delivery::*;
use crate::evidence::{self, AgreedEpoch, Artefact, ConsentDecision, Decision, DecryptionReport, ReportResult};
use crate::dispute::{RetainedKeyPackage, RetainedState};
use crate::mls::{self, AppMessage, SccIdentityProvider};
use crate::resolve::Resolver;
use crate::rpc::{self, to_value, RpcError, WsClient};
use crate::types::{Address, Consignment, EndpointRef};
use crate::util::{b64, b64u, now, random_bytes, read_json, sha256, write_file, write_json};
use anyhow::{anyhow, bail, Context, Result};
use mls_rs::client_builder::MlsConfig;
use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::{Client, ExtensionList, Group};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const KEY_PACKAGE_TARGET: usize = 10;

#[derive(Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub owner: String,
    pub subject: Option<String>,
    pub requested_roles: Vec<String>,
    /// The home RDS's base URL.
    pub rds_url: String,
    pub edd_url: String,
    pub endpoint_key: PrivateKey,
    #[serde(with = "b64")]
    pub mls_secret_key: Vec<u8>,
    #[serde(with = "b64")]
    pub mls_public_key: Vec<u8>,
    #[serde(default, with = "crate::util::b64opt")]
    pub credential: Option<Vec<u8>>,
    #[serde(default)]
    pub last_seq: u64,
    /// How to answer consent requests: accept, reject or ignore.
    #[serde(default = "default_consent")]
    pub consent: String,
    /// For demonstrations only, as a dishonest recipient would: report
    /// every message that decrypts as `decrypt-failed` or `invalid-epoch`
    /// (with a made-up epoch authenticator) instead, or take messages and
    /// send no report (`silent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub false_report: Option<String>,
}

fn default_consent() -> String {
    "accept".into()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub initiator: Address,
    pub responder: Address,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Sent by this endpoint.
    Sent,
    /// Received from the other side.
    Received,
    /// Sent by another endpoint on this endpoint's side.
    Copy,
}

/// The private data an endpoint keeps for a message (05-evidence.md §8),
/// as given to a verifier.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrivateData {
    /// The application data: plaintext with salt (doc 3 §7.1).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::b64opt")]
    pub application_data: Option<Vec<u8>>,
    /// The `MLSMessage` (ciphertext).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::b64opt")]
    pub mls_message: Option<Vec<u8>>,
    /// The retained MLS state of an epoch: the message's epoch (sender, or
    /// a recipient that reports `decrypt-failed` or `mismatch`), for a
    /// message-key dispute (doc 5 §7.4), or the anchor epoch (a recipient
    /// that reports `invalid-epoch`), for a group-state dispute (§7.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<RetainedState>,
    /// Private keys of KeyPackages the recipient may have been added with,
    /// when its anchor is its join (§7.5 step 2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_packages: Vec<RetainedKeyPackage>,
    /// For a `mismatch` report: the salt of its `plaintext_hash` (§4).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::b64opt")]
    pub report_salt: Option<Vec<u8>>,
    /// The evidence package of an earlier message of the session, in the
    /// anchor epoch, that ended in E.1: it shows that epoch was agreed
    /// (§7.5 step 1). Added when a bundle is exported.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::b64opt")]
    pub agreement: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    #[serde(with = "b64")]
    pub message_id: Vec<u8>,
    #[serde(with = "b64")]
    pub session_id: Vec<u8>,
    pub direction: Direction,
    pub meta: Meta,
    pub epoch: u64,
    #[serde(with = "b64")]
    pub plaintext_hash: Vec<u8>,
    #[serde(with = "b64")]
    pub sender_epoch_authenticator: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ReportResult>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::b64opt")]
    pub report: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub private: PrivateData,
    /// Events received so far, by short code.
    #[serde(default)]
    pub events: Vec<String>,
}

/// A verification bundle: what a verifier needs for one message.
pub struct Bundle;

impl Bundle {
    pub const PACKAGE: &'static str = "evidence-package.cbor";
    pub const SESSION_LOG: &'static str = "session-log.json";
    pub const PRIVATE: &'static str = "private.json";
    pub const REGISTRY_LOGS: &'static str = "owner-logs";
}

pub struct Endpoint {
    pub dir: PathBuf,
    pub cfg: EndpointConfig,
    pub trust: crate::certs::TrustStore,
    pub resolver: Arc<Resolver>,
    pub ip: SccIdentityProvider,
}

/// An authenticated connection to the home RDS.
pub struct Conn {
    pub ws: WsClient,
    /// The RDS URL.
    pub rds: String,
}

fn rpc_err(e: RpcError) -> anyhow::Error {
    anyhow::Error::new(e)
}

impl Endpoint {
    /// Create a new endpoint: generate its keys and a credential request
    /// for its owner (02-credentials.md §5.1).
    pub fn init(dir: &Path, owner: &str, rds_url: &str, edd_url: &str, roles: Vec<String>, subject: Option<String>) -> Result<Vec<u8>> {
        if dir.join("endpoint.json").exists() {
            bail!("{} already holds an endpoint", dir.display());
        }
        crate::types::check_ebw_url(owner)?;
        let key = PrivateKey::generate_ed25519();
        let (sk, pk) = mls::generate_signature_key()?;
        let cfg = EndpointConfig {
            owner: owner.into(),
            subject: subject.clone(),
            requested_roles: roles.clone(),
            rds_url: rds_url.trim_end_matches('/').into(),
            edd_url: edd_url.trim_end_matches('/').into(),
            endpoint_key: key.clone(),
            mls_secret_key: sk.as_bytes().to_vec(),
            mls_public_key: pk.as_bytes().to_vec(),
            credential: None,
            last_seq: 0,
            consent: default_consent(),
            false_report: None,
        };
        write_json(dir.join("endpoint.json"), &cfg)?;
        let req = CredentialRequestBody {
            st_type: "credential-request".into(),
            owner: owner.into(),
            subject: Some(subject.unwrap_or_else(crate::util::random_subject)),
            roles,
            key: key.public(),
            nonce: ByteBuf::from(random_bytes(16)),
        }
        .sign(&key);
        write_file(dir.join("credential-request.cbor"), &req)?;
        Ok(req)
    }

    pub fn open(dir: &Path, trust: crate::certs::TrustStore) -> Result<Self> {
        let cfg: EndpointConfig = read_json(dir.join("endpoint.json")).context("not an endpoint directory")?;
        let edd = crate::edd::EddClient::new(&cfg.edd_url, trust.clone())?;
        let resolver = Arc::new(Resolver::new(edd, None)?);
        Ok(Endpoint { dir: dir.into(), cfg, trust, ip: SccIdentityProvider::with_resolver(resolver.clone()), resolver })
    }

    pub fn save(&self) -> Result<()> {
        write_json(self.dir.join("endpoint.json"), &self.cfg)
    }

    pub fn credential(&self) -> Result<Credential> {
        Credential::parse(self.cfg.credential.as_ref().ok_or_else(|| anyhow!("no credential installed"))?)
    }

    pub fn install_credential(&mut self, raw: &[u8]) -> Result<()> {
        let c = Credential::parse(raw)?;
        if c.claims.iss != self.cfg.owner || c.claims.cnf != self.cfg.endpoint_key.public() {
            bail!("credential is not for this endpoint");
        }
        self.cfg.subject = Some(c.claims.sub.clone());
        self.cfg.credential = Some(raw.to_vec());
        self.save()
    }

    pub fn me(&self) -> Result<EndpointRef> {
        let c = self.credential()?;
        Ok(EndpointRef { owner: c.claims.iss, subject: c.claims.sub })
    }

    fn client(&self) -> Result<Client<impl MlsConfig>> {
        let cred = self.credential()?;
        let pk = SignaturePublicKey::new(self.cfg.mls_public_key.clone());
        let sk = SignatureSecretKey::new(self.cfg.mls_secret_key.clone());
        let leaf = mls::make_leaf_credential(&self.cfg.endpoint_key, &cred.raw, &pk);
        let si = SigningIdentity::new(leaf, pk);
        // KeyPackage lifetimes end no later than the credential (doc 3 §3).
        let life = cred.claims.exp.saturating_sub(now()).clamp(60, 30 * 86400);
        mls::endpoint_client(&self.dir.join("mls.db"), self.ip.clone(), si, sk, life)
    }

    // ---- Stores ----

    pub fn sessions(&self) -> Vec<SessionInfo> {
        read_json(self.dir.join("sessions.json")).unwrap_or_default()
    }

    fn save_session(&self, s: SessionInfo) -> Result<()> {
        let mut all = self.sessions();
        all.retain(|x| x.session_id != s.session_id);
        all.push(s);
        write_json(self.dir.join("sessions.json"), &all)
    }

    fn epochs(&self) -> BTreeMap<String, RetainedState> {
        read_json(self.dir.join("epochs.json")).unwrap_or_default()
    }

    fn epoch_key(sid: &[u8], epoch: u64) -> String {
        format!("{}/{epoch}", b64u(sid))
    }

    /// Write the group to storage and retain its state for the epoch that
    /// has just begun (05-evidence.md §8), before any message of the epoch
    /// is sent or received.
    fn note_epoch<C: MlsConfig>(&self, client: &Client<C>, g: &mut Group<C>, created: bool) -> Result<RetainedState> {
        let mut e = crate::dispute::export_state(client, g)?;
        e.created = created;
        let mut all = self.epochs();
        all.insert(Self::epoch_key(g.group_id(), e.epoch), e.clone());
        write_json(self.dir.join("epochs.json"), &all)?;
        Ok(e)
    }

    pub fn retained_state(&self, sid: &[u8], epoch: u64) -> Option<RetainedState> {
        self.epochs().get(&Self::epoch_key(sid, epoch)).cloned()
    }

    /// The retained state of the latest epoch held for a session.
    fn last_retained_state(&self, sid: &[u8]) -> Option<RetainedState> {
        self.epochs().into_values().filter(|v| v.session_id == sid).max_by_key(|v| v.epoch)
    }

    /// A received message of the session in `epoch` that this endpoint
    /// reported as `match`, or a sent one that ended in E.1: either shows
    /// that the epoch was agreed (doc 5 §7.5 step 1).
    fn agreement_message(&self, sid: &[u8], epoch: u64) -> Option<Vec<u8>> {
        self.records()
            .into_iter()
            .filter(|r| r.session_id == sid && r.epoch == epoch)
            .find(|r| match r.direction {
                Direction::Received => r.result == Some(ReportResult::Match),
                _ => r.events.iter().any(|e| e == "E.1"),
            })
            .map(|r| r.message_id)
    }

    /// The anchor of a group-state dispute about a message in `epoch`
    /// (doc 5 §7.5 step 1): the retained state of the later of the last
    /// agreed epoch and the last epoch this endpoint created, before
    /// `epoch`. None if the anchor is the join.
    fn anchor_state(&self, sid: &[u8], epoch: u64) -> Option<RetainedState> {
        self.epochs()
            .into_values()
            .filter(|v| v.session_id == sid && v.epoch < epoch)
            .filter(|v| v.created || self.agreement_message(sid, v.epoch).is_some())
            .max_by_key(|v| v.epoch)
    }

    /// Retained KeyPackage private keys (05-evidence.md §8).
    pub fn retained_key_packages(&self) -> Vec<RetainedKeyPackage> {
        read_json(self.dir.join("keypackages.json")).unwrap_or_default()
    }

    fn msg_dir(&self, mid: &[u8]) -> PathBuf {
        self.dir.join("messages").join(b64u(mid))
    }

    pub fn record(&self, mid: &[u8]) -> Result<MessageRecord> {
        read_json(self.msg_dir(mid).join("record.json"))
    }

    fn save_record(&self, r: &MessageRecord) -> Result<()> {
        write_json(self.msg_dir(&r.message_id).join("record.json"), r)
    }

    pub fn records(&self) -> Vec<MessageRecord> {
        let mut v: Vec<MessageRecord> = std::fs::read_dir(self.dir.join("messages"))
            .map(|d| d.filter_map(|e| e.ok()).filter_map(|e| read_json(e.path().join("record.json")).ok()).collect())
            .unwrap_or_default();
        v.sort_by_key(|r: &MessageRecord| r.meta.sent_at);
        v
    }

    /// Store an evidence artefact received for a message.
    fn store_evidence(&self, mid: &[u8], raw: &[u8]) -> Result<String> {
        let art = Artefact::parse(raw)?;
        let code = art.message().and_then(|b| b.event().ok()).map(|e| e.code()).unwrap_or("other");
        let dir = self.msg_dir(mid).join("evidence");
        let name = format!("{}-{}.cbor", code, &hex::encode(art.seal_hash())[..12]);
        write_file(dir.join(&name), raw)?;
        if let Ok(mut r) = self.record(mid) {
            if !r.events.iter().any(|e| e == code) {
                r.events.push(code.into());
                self.save_record(&r)?;
            }
        }
        Ok(code.to_string())
    }

    // ---- Connection (§4.1) ----

    pub async fn connect(&self) -> Result<Conn> {
        let http = crate::net::http_client()?;
        let md: RdsMetadata = http
            .get(&self.cfg.rds_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("RDS metadata")?;
        let ws = WsClient::connect(&md.endpoints.client).await?;
        let me = self.me()?;
        let r: ConnectResult = rpc::params(
            ws.call("scc.connect", to_value(&ConnectParams { versions: vec![VERSION.into()], owner: me.owner.clone(), subject: me.subject.clone() }))
                .await
                .map_err(rpc_err)?,
        )
        .map_err(rpc_err)?;
        let proof = ConnectProofBody {
            st_type: "connect-proof".into(),
            challenge: ByteBuf::from(r.challenge),
            rds: self.cfg.rds_url.clone(),
            owner: me.owner,
            subject: me.subject,
            signed_at: now(),
        }
        .sign(&self.cfg.endpoint_key);
        ws.call("scc.authenticate", to_value(&AuthenticateParams { credential: self.credential()?.raw, signature: proof }))
            .await
            .map_err(rpc_err)?;
        Ok(Conn { ws, rds: self.cfg.rds_url.clone() })
    }

    /// Publish KeyPackages up to the target pool size (§6.1).
    pub async fn publish_key_packages(&self, c: &Conn, have: usize) -> Result<PoolStatus> {
        let client = self.client()?;
        let n = KEY_PACKAGE_TARGET.saturating_sub(have).max(1);
        let mut kps = Vec::new();
        let mut retained = self.retained_key_packages();
        retained.retain(|k| k.expiration > now());
        for _ in 0..n {
            let kp = client.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)?;
            // Keep the private keys: a recipient that never joins presents
            // them in a group-state dispute (doc 5 §7.5, §8).
            retained.push(crate::dispute::retain_key_package(&client, &kp)?);
            kps.push(kp.to_bytes()?);
        }
        write_json(self.dir.join("keypackages.json"), &retained)?;
        let r = c.ws.call("scc.keypackage.publish", to_value(&PublishParams { key_packages: kps })).await.map_err(rpc_err)?;
        rpc::params(r).map_err(rpc_err)
    }

    // ---- Receiving (§4.2, §7.3 to §7.5, §8.3) ----

    /// Process every queued item. Returns a log of what happened.
    pub async fn sync(&mut self, c: &mut Conn, wait: u64) -> Result<Vec<String>> {
        let mut log = Vec::new();
        let deadline = now() + wait;
        loop {
            loop {
                let r: FetchResult = rpc::params(
                    c.ws.call("wmp.message.fetch", to_value(&FetchParams { after: self.cfg.last_seq, limit: Some(50) })).await.map_err(rpc_err)?,
                )
                .map_err(rpc_err)?;
                for item in &r.items {
                    let seq = item.params.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
                    if seq <= self.cfg.last_seq {
                        continue;
                    }
                    match self.process(c, seq, &item.method, item.params.clone()).await {
                        Ok(Some(l)) => log.push(l),
                        Ok(None) => {}
                        Err(e) => log.push(format!("error processing {} #{seq}: {e:#}", item.method)),
                    }
                    self.cfg.last_seq = seq;
                    self.save()?;
                }
                if !r.more {
                    break;
                }
            }
            let left = deadline.saturating_sub(now());
            if left == 0 {
                break;
            }
            // Wait for a pushed notification, then fetch again.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(left), c.ws.notifications.recv()).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while c.ws.notifications.try_recv().is_ok() {}
        }
        Ok(log)
    }

    async fn ack(&self, c: &Conn, seq: u64) -> Result<()> {
        c.ws.call("scc.queue.ack", to_value(&QueueAckParams { up_to: seq })).await.map_err(rpc_err)?;
        Ok(())
    }

    async fn process(&mut self, c: &mut Conn, seq: u64, method: &str, p: Value) -> Result<Option<String>> {
        match method {
            "scc.handshake" => {
                let p: HandshakeParams = serde_json::from_value(p)?;
                let r = self.on_handshake(c, &p).await;
                self.ack(c, seq).await?;
                r
            }
            "wmp.message.deliver" => {
                let p: DeliverParams = serde_json::from_value(p)?;
                // Confirming the item is the transfer step of the handover.
                self.ack(c, seq).await?;
                self.on_message(c, p).await.map(Some)
            }
            "wmp.evidence.notify" => {
                let p: EvidenceNotifyParams = serde_json::from_value(p)?;
                self.ack(c, seq).await?;
                let mid = p.message_id.clone().unwrap_or_default();
                let art = Artefact::parse(&p.evidence)?;
                art.verify_seal(&self.trust).context("evidence seal")?;
                let code = self.store_evidence(&mid, &p.evidence)?;
                Ok(Some(format!("evidence {code} for message {}", b64u(&mid))))
            }
            "scc.consent.request" => {
                let p: ConsentRequestParams = serde_json::from_value(p)?;
                self.ack(c, seq).await?;
                self.on_consent_request(c, p).await.map(Some)
            }
            "scc.keypackage.status" => {
                let p: KeyPackageStatusParams = serde_json::from_value(p)?;
                self.ack(c, seq).await?;
                let have = p.available.get("1").copied().unwrap_or(0) as usize;
                let r = self.publish_key_packages(c, have).await?;
                Ok(Some(format!("replenished KeyPackages: {:?}", r.available)))
            }
            _ => {
                self.ack(c, seq).await?;
                Ok(Some(format!("ignored {method}")))
            }
        }
    }

    async fn on_handshake(&self, c: &Conn, p: &HandshakeParams) -> Result<Option<String>> {
        let client = self.client()?;
        if let Some(w) = &p.welcome {
            if client.load_group(&p.session_id).is_ok() {
                return Ok(None);
            }
            let msg = mls::parse_mls_message(w)?;
            let (mut g, _) = client.join_group(None, &msg, None).map_err(|e| anyhow!("Welcome: {e:?}"))?;
            let s = mls::check_session_extensions(&g.context().extensions)?;
            let (i, r) = s.addresses()?;
            self.note_epoch(&client, &mut g, false)?;
            self.save_session(SessionInfo { session_id: p.session_id.clone(), initiator: i.clone(), responder: r.clone(), active: true })?;
            return Ok(Some(format!("joined session {} ({i} <-> {r}) at epoch {}", b64u(&p.session_id), g.current_epoch())));
        }
        self.catch_up(c, &p.session_id, p.epoch).await
    }

    /// Process accepted Commits until the group reaches `target`.
    async fn catch_up(&self, c: &Conn, sid: &[u8], target: u64) -> Result<Option<String>> {
        let client = self.client()?;
        let Ok(mut g) = client.load_group(sid) else { return Ok(None) };
        if g.current_epoch() >= target {
            return Ok(None);
        }
        let r: CommitsResult = rpc::params(
            c.ws.call("scc.commit.fetch", to_value(&CommitFetchParams { session_id: sid.to_vec(), after_epoch: g.current_epoch() })).await.map_err(rpc_err)?,
        )
        .map_err(rpc_err)?;
        let mut removed = false;
        for e in r.commits {
            if e.epoch <= g.current_epoch() {
                continue;
            }
            let last_agreed = g.current_epoch();
            let ea = g.epoch_authenticator()?.to_vec();
            match g.process_incoming_message(mls::parse_mls_message(&e.commit)?) {
                Ok(ReceivedMessage::Commit(d)) => {
                    if matches!(d.effect, mls_rs::group::CommitEffect::Removed { .. }) {
                        removed = true;
                        break;
                    }
                    self.note_epoch(&client, &mut g, false)?;
                }
                Ok(_) => bail!("expected a Commit"),
                Err(err) => {
                    // doc 3 §6.5: report a Commit we cannot process.
                    self.report_commit_failure(c, sid, &e, last_agreed, ea, &format!("{err:?}")).await?;
                    bail!("cannot process the Commit for epoch {}: {err:?}", e.epoch);
                }
            }
        }
        g.write_to_storage()?;
        if removed {
            let mut s = self.sessions().into_iter().find(|s| s.session_id == sid).ok_or_else(|| anyhow!("unknown session"))?;
            s.active = false;
            self.save_session(s)?;
            return Ok(Some(format!("removed from session {}", b64u(sid))));
        }
        Ok(Some(format!("session {} now at epoch {}", b64u(sid), g.current_epoch())))
    }

    async fn report_commit_failure(&self, c: &Conn, sid: &[u8], e: &LogEntry, last: u64, ea: Vec<u8>, why: &str) -> Result<()> {
        let me = self.me()?;
        let failure = if why.contains("Confirmation") || why.contains("confirmation") {
            evidence::CommitFailure::ConfirmationTag
        } else {
            evidence::CommitFailure::Other
        };
        let body = evidence::CommitFailureReport {
            st_type: "commit-failure-report".into(),
            session_id: sid.to_vec(),
            commit_ref: sha256(&e.commit),
            epoch: e.epoch,
            failure,
            last_agreed: Some(AgreedEpoch { epoch: last, epoch_authenticator: ea }),
            owner: me.owner,
            subject: me.subject,
            reported_at: now(),
        };
        let raw = evidence::sign_statement(&self.cfg.endpoint_key, &self.credential()?.raw, &body)?;
        c.ws.call("scc.commit.report", to_value(&CommitReportParams { session_id: sid.to_vec(), epoch: e.epoch, report: raw })).await.map_err(rpc_err)?;
        Ok(())
    }

    async fn on_message(&self, c: &Conn, p: DeliverParams) -> Result<String> {
        let me = self.me()?;
        let cred = self.credential()?;
        let mid = p.meta.message_id.clone();
        let recipient = p.meta.to.owner == me.owner && cred.claims.roles.contains(&p.meta.to.role);
        let msg = mls::parse_mls_message(&p.message)?;
        let epoch = msg.epoch().unwrap_or(0);
        self.catch_up(c, &p.session_id, epoch).await.ok();
        let client = self.client()?;
        let mut app_data = None;
        // The endpoint first compares its epoch authenticator with the
        // sender's (doc 5 §4).
        let mine = self.retained_state(&p.session_id, epoch);
        let result = match client.load_group(&p.session_id) {
            Err(_) => ReportResult::JoinFailure,
            Ok(_) if mine.as_ref().map(|m| m.epoch_authenticator != p.epoch_authenticator).unwrap_or(true) => ReportResult::InvalidEpoch,
            Ok(mut g) => match g.process_incoming_message(msg) {
                Ok(ReceivedMessage::ApplicationMessage(d)) => {
                    g.write_to_storage()?;
                    let data = d.data().to_vec();
                    let ok = match AppMessage::decode(&data) {
                        Ok(a) => {
                            a.message_id == p.meta.message_id
                                && a.from == p.meta.from
                                && a.to == p.meta.to
                                && a.sent_at == p.meta.sent_at
                                && a.expires_at == p.meta.expires_at
                                && a.consignment == p.meta.consignment
                                && sha256(&data) == p.plaintext_hash
                        }
                        Err(_) => false,
                    };
                    app_data = Some(data);
                    if ok {
                        ReportResult::Match
                    } else {
                        ReportResult::Mismatch
                    }
                }
                Ok(_) => ReportResult::DecryptFailed,
                Err(_) => ReportResult::DecryptFailed,
            },
        };
        // Demonstration of a dishonest recipient: claim that a message that
        // decrypted did not.
        let false_report = self.cfg.false_report.as_deref().filter(|_| recipient);
        let result = match (result, false_report) {
            (ReportResult::Match | ReportResult::Mismatch, Some("decrypt-failed")) => {
                app_data = None;
                ReportResult::DecryptFailed
            }
            (ReportResult::Match | ReportResult::Mismatch, Some("invalid-epoch")) => {
                app_data = None;
                ReportResult::InvalidEpoch
            }
            (r, _) => r,
        };
        let app = app_data.as_deref().and_then(|d| AppMessage::decode(d).ok());
        if let (Some(a), Some(_)) = (&app, &app_data) {
            write_file(self.msg_dir(&mid).join("body"), &a.body)?;
        }
        let mut rec = MessageRecord {
            message_id: mid.clone(),
            session_id: p.session_id.clone(),
            direction: if recipient { Direction::Received } else { Direction::Copy },
            meta: p.meta.clone(),
            epoch,
            plaintext_hash: p.plaintext_hash.clone(),
            sender_epoch_authenticator: p.epoch_authenticator.clone(),
            result: None,
            report: None,
            content_type: app.as_ref().map(|a| a.content_type.clone()),
            subject: app.as_ref().and_then(|a| a.subject.clone()),
            private: PrivateData { application_data: app_data.clone(), mls_message: Some(p.message.clone()), ..Default::default() },
            events: vec![],
        };
        if !recipient {
            self.save_record(&rec)?;
            return Ok(format!("copy of message {} sent from this side ({})", b64u(&mid), result.as_str()));
        }
        if false_report == Some("silent") {
            self.save_record(&rec)?;
            return Ok(format!("took message {} from {} and sent no report (demo switch)", b64u(&mid), p.meta.from));
        }
        // Decryption report (doc 5 §4), sent at once (doc 4 §7.5).
        let mut body = DecryptionReport {
            st_type: "decryption-report".into(),
            message_id: mid.clone(),
            session_id: p.session_id.clone(),
            epoch,
            envelope_hash: sha256(&p.message),
            result,
            plaintext_hash: None,
            epoch_authenticator: None,
            held_epoch: None,
            owner: me.owner.clone(),
            subject: me.subject.clone(),
            reported_at: now(),
        };
        match result {
            ReportResult::Mismatch => {
                // Commits the endpoint to what it decrypted, under a fresh salt.
                let salt = random_bytes(16);
                let data = app_data.as_deref().unwrap_or_default();
                body.plaintext_hash = Some(ByteBuf::from(sha256(&[&salt[..], data].concat())));
                rec.private.report_salt = Some(salt);
            }
            ReportResult::InvalidEpoch => match &mine {
                Some(_) if false_report == Some("invalid-epoch") => body.epoch_authenticator = Some(ByteBuf::from(random_bytes(32))),
                Some(m) => body.epoch_authenticator = Some(ByteBuf::from(m.epoch_authenticator.clone())),
                None => {
                    // It does not hold the message's epoch.
                    if let Some(l) = self.last_retained_state(&p.session_id) {
                        body.held_epoch = Some(l.epoch);
                        body.epoch_authenticator = Some(ByteBuf::from(l.epoch_authenticator));
                    }
                }
            },
            _ => {}
        }
        let raw = evidence::sign_statement(&self.cfg.endpoint_key, &cred.raw, &body)?;
        // Retention (doc 5 §8): nothing for `match`; the MLS state of the
        // message's epoch for `decrypt-failed` and `mismatch`; the anchor
        // state, or the KeyPackages if the anchor is the join, for
        // `invalid-epoch` and `join-failure`.
        match result {
            ReportResult::Match => {}
            ReportResult::DecryptFailed | ReportResult::Mismatch => rec.private.state = mine.clone(),
            ReportResult::InvalidEpoch | ReportResult::JoinFailure => {
                rec.private.state = self.anchor_state(&p.session_id, epoch);
                if rec.private.state.is_none() {
                    rec.private.key_packages = self.retained_key_packages();
                }
            }
        }
        rec.result = Some(result);
        rec.report = Some(raw.clone());
        self.save_record(&rec)?;
        let status = if result == ReportResult::Match { AckStatus::Processed } else { AckStatus::Failed };
        let r: MessageAckResult = rpc::params(
            c.ws.call("wmp.message.ack", to_value(&MessageAckParams { message_id: mid.clone(), status, report: Some(raw), decision: None })).await.map_err(rpc_err)?,
        )
        .map_err(rpc_err)?;
        let mut line = format!(
            "received message {} from {}: {} ({})",
            b64u(&mid),
            p.meta.from,
            app.as_ref().map(|a| String::from_utf8_lossy(&a.body).chars().take(60).collect::<String>()).unwrap_or_default(),
            result.as_str()
        );
        if let Some(ev) = r.evidence {
            let code = self.store_evidence(&mid, &ev)?;
            line.push_str(&format!("; evidence {code}"));
        }
        Ok(line)
    }

    async fn on_consent_request(&self, c: &Conn, p: ConsentRequestParams) -> Result<String> {
        let mid = p.meta.message_id.clone();
        let decision = match self.cfg.consent.as_str() {
            "accept" => Decision::Accept,
            "reject" => Decision::Reject,
            _ => return Ok(format!("consent request for {} left unanswered", b64u(&mid))),
        };
        let me = self.me()?;
        let cred = self.credential()?;
        let body = ConsentDecision {
            st_type: "consent-decision".into(),
            message_id: mid.clone(),
            session_id: p.session_id.clone(),
            envelope_hash: p.envelope_hash.clone(),
            decision,
            owner: me.owner,
            subject: me.subject,
            holder: cred.claims.holder.clone(),
            decided_at: now(),
        };
        let raw = evidence::sign_statement(&self.cfg.endpoint_key, &cred.raw, &body)?;
        let status = if decision == Decision::Accept { AckStatus::Accepted } else { AckStatus::Rejected };
        let r: MessageAckResult = rpc::params(
            c.ws.call("wmp.message.ack", to_value(&MessageAckParams { message_id: mid.clone(), status, report: None, decision: Some(raw) })).await.map_err(rpc_err)?,
        )
        .map_err(rpc_err)?;
        let mut line = format!("consent request for {} from {}: {:?}", b64u(&mid), p.meta.from, decision);
        if let Some(ev) = r.evidence {
            let art = Artefact::parse(&ev)?;
            let code = art.message().and_then(|b| b.event().ok()).map(|e| e.code()).unwrap_or("?");
            line.push_str(&format!("; evidence {code}"));
        }
        Ok(line)
    }

    // ---- Sending (§7.1; doc 3 §4.3, §5) ----

    fn find_session(&self, from: &Address, to: &Address) -> Option<SessionInfo> {
        let client = self.client().ok()?;
        self.sessions().into_iter().rev().find(|s| {
            s.active
                && ((&s.initiator == from && &s.responder == to) || (&s.initiator == to && &s.responder == from))
                && client.load_group(&s.session_id).is_ok()
        })
    }

    async fn get_key_packages(&self, c: &Conn, addr: &Address, subjects: Option<Vec<String>>) -> Result<Reservation> {
        let r = c
            .ws
            .call("scc.keypackage.get", to_value(&KeyPackageGetParams { address: addr.clone(), cipher_suite: *mls::CIPHER_SUITE, subjects }))
            .await
            .map_err(rpc_err)?;
        rpc::params(r).map_err(rpc_err)
    }

    /// Create a session (doc 3 §4.3).
    pub async fn create_session(&self, c: &Conn, from: &Address, to: &Address) -> Result<SessionInfo> {
        let mine = self.get_key_packages(c, from, None).await?;
        let theirs = self.get_key_packages(c, to, None).await?;
        if !theirs.missing.is_empty() || !mine.missing.is_empty() {
            tracing::warn!("endpoints without KeyPackages: {:?}", [mine.missing.clone(), theirs.missing.clone()].concat());
        }
        if theirs.key_packages.is_empty() {
            bail!("no KeyPackage available for {to}");
        }
        let client = self.client()?;
        let sid = random_bytes(16);
        let mut g = client.create_group_with_id(sid.clone(), mls::session_extensions(from, to)?, ExtensionList::new(), None)?;
        let gi = g.group_info_message(true)?.to_bytes()?;
        let mut b = g.commit_builder();
        for kp in mine.key_packages.iter().chain(theirs.key_packages.iter()) {
            b = b.add_member(mls::parse_mls_message(&kp.key_package)?).map_err(|e| anyhow!("KeyPackage of {}: {e:?}", kp.subject))?;
        }
        let out = b.build()?;
        let welcome = out.welcome_messages.first().ok_or_else(|| anyhow!("no Welcome"))?.to_bytes()?;
        let params = SessionCreateParams {
            session_id: sid.clone(),
            group_info: gi,
            commit: out.commit_message.to_bytes()?,
            welcome,
            reservations: Some(vec![mine.reservation, theirs.reservation]),
        };
        match c.ws.call("wmp.session.create", to_value(&params)).await {
            Ok(_) => {
                g.apply_pending_commit()?;
                self.note_epoch(&client, &mut g, true)?;
                let s = SessionInfo { session_id: sid, initiator: from.clone(), responder: to.clone(), active: true };
                self.save_session(s.clone())?;
                Ok(s)
            }
            Err(e) => {
                g.clear_pending_commit();
                Err(rpc_err(e))
            }
        }
    }

    /// Fix a session after a membership mismatch (doc 3 §5).
    async fn fix_membership(&self, c: &Conn, s: &SessionInfo, mm: MembershipMismatch) -> Result<()> {
        let client = self.client()?;
        let mut g = client.load_group(&s.session_id)?;
        let own = g.current_member_index();
        let mut b = g.commit_builder();
        for idx in mm.remove.iter().filter(|i| **i != own) {
            b = b.remove_member(*idx)?;
        }
        let mut reservations = Vec::new();
        let mut by_owner: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for e in &mm.add {
            by_owner.entry(e.owner.clone()).or_default().push(e.subject.clone());
        }
        for (owner, subs) in by_owner {
            let addr = if s.initiator.owner == owner { &s.initiator } else { &s.responder };
            let r = self.get_key_packages(c, addr, Some(subs)).await?;
            for kp in &r.key_packages {
                b = b.add_member(mls::parse_mls_message(&kp.key_package)?).map_err(|e| anyhow!("KeyPackage of {}: {e:?}", kp.subject))?;
            }
            reservations.push(r.reservation);
        }
        let out = b.build()?;
        let params = CommitSubmitParams {
            session_id: s.session_id.clone(),
            commit: out.commit_message.to_bytes()?,
            welcome: out.welcome_messages.first().map(|w| w.to_bytes()).transpose()?,
            reservations: Some(reservations),
        };
        match c.ws.call("scc.commit.submit", to_value(&params)).await {
            Ok(_) => {
                g.apply_pending_commit()?;
                self.note_epoch(&client, &mut g, true)?;
                Ok(())
            }
            Err(e) => {
                g.clear_pending_commit();
                g.write_to_storage()?;
                Err(rpc_err(e))
            }
        }
    }

    /// Send a message. Returns the message ID and the submission evidence
    /// (A.1, or A.2 if rejected with evidence).
    #[allow(clippy::too_many_arguments)]
    pub async fn send(&mut self, c: &mut Conn, from_role: &str, to: &Address, body: Vec<u8>, content_type: &str, subject: Option<String>, consignment: Consignment, ttl: u64) -> Result<(Vec<u8>, String)> {
        self.sync(c, 0).await?;
        let me = self.me()?;
        let from = Address::new(&me.owner, from_role);
        if !self.credential()?.claims.roles.iter().any(|r| r == from_role) {
            bail!("this endpoint does not hold the role {from_role}");
        }
        let s = match self.find_session(&from, to) {
            Some(s) => s,
            None => {
                let s = self.create_session(c, &from, to).await?;
                tracing::info!("created session {}", b64u(&s.session_id));
                s
            }
        };
        let t = now();
        let app = AppMessage {
            message_id: random_bytes(16),
            from: from.clone(),
            to: to.clone(),
            sent_at: t,
            expires_at: t + ttl,
            consignment,
            content_type: content_type.into(),
            subject,
            in_reply_to: None,
            salt: random_bytes(16),
            body: body.clone(),
        };
        let data = app.encode();
        let meta = Meta {
            message_id: app.message_id.clone(),
            from: from.clone(),
            to: to.clone(),
            sent_at: app.sent_at,
            expires_at: app.expires_at,
            consignment,
        };
        for attempt in 0..5 {
            let client = self.client()?;
            let mut g = client.load_group(&s.session_id)?;
            // The state retained when the epoch began (doc 5 §8).
            let es = match self.retained_state(&s.session_id, g.current_epoch()) {
                Some(r) => r,
                None => self.note_epoch(&client, &mut g, false)?,
            };
            let ct = g.encrypt_application_message(&data, vec![])?.to_bytes()?;
            g.write_to_storage()?;
            let params = DeliverParams {
                session_id: s.session_id.clone(),
                message: ct.clone(),
                meta: meta.clone(),
                plaintext_hash: sha256(&data),
                epoch_authenticator: es.epoch_authenticator.clone(),
                submission_evidence: None,
                relayed_at: None,
                seq: None,
            };
            let rec = MessageRecord {
                message_id: meta.message_id.clone(),
                session_id: s.session_id.clone(),
                direction: Direction::Sent,
                meta: meta.clone(),
                epoch: es.epoch,
                plaintext_hash: sha256(&data),
                sender_epoch_authenticator: es.epoch_authenticator.clone(),
                result: None,
                report: None,
                content_type: Some(content_type.into()),
                subject: app.subject.clone(),
                // Retention (doc 5 §8): plaintext with salt, and the MLS
                // state of the epoch the message was sent in.
                private: PrivateData {
                    application_data: Some(data.clone()),
                    mls_message: Some(ct.clone()),
                    state: Some(es.clone()),
                    ..Default::default()
                },
                events: vec![],
            };
            match c.ws.call("wmp.message.deliver", to_value(&params)).await {
                Ok(v) => {
                    let r: EvidenceResult = rpc::params(v).map_err(rpc_err)?;
                    self.save_record(&rec)?;
                    write_file(self.msg_dir(&meta.message_id).join("body"), &body)?;
                    let code = self.store_evidence(&meta.message_id, &r.evidence)?;
                    return Ok((meta.message_id.clone(), code));
                }
                Err(e) if e.code == rpc::E_STALE_EPOCH => {
                    tracing::info!("stale epoch, catching up (attempt {attempt})");
                    self.sync(c, 0).await?;
                    let target = e.data.as_ref().and_then(|d| d.get("epoch")).and_then(|v| v.as_u64()).unwrap_or(0);
                    self.catch_up(c, &s.session_id, target).await?;
                }
                Err(e) if e.code == rpc::E_MEMBERSHIP_MISMATCH => {
                    let mm: MembershipMismatch = serde_json::from_value(e.data.clone().unwrap_or_default())?;
                    tracing::info!("membership mismatch: add {:?}, remove {:?}", mm.add, mm.remove);
                    if let Err(err) = self.fix_membership(c, &s, mm).await {
                        tracing::warn!("fixing the session failed: {err:#}");
                        self.sync(c, 0).await?;
                    }
                }
                Err(e) => {
                    if let Some(ev) = e.evidence() {
                        self.save_record(&rec)?;
                        let code = self.store_evidence(&meta.message_id, &ev)?;
                        return Ok((meta.message_id.clone(), format!("{code} ({}: {})", e.code, e.message)));
                    }
                    return Err(rpc_err(e));
                }
            }
        }
        bail!("could not send the message after several attempts")
    }

    // ---- Evidence and verification bundles ----

    pub async fn evidence_package(&self, c: &Conn, mid: &[u8]) -> Result<Vec<u8>> {
        let mut attempt = 0;
        loop {
            match c.ws.call("scc.evidence.get", to_value(&MessageIdParams { message_id: mid.to_vec() })).await {
                Ok(v) => {
                    let r: PackageResult = rpc::params(v).map_err(rpc_err)?;
                    return Ok(r.package);
                }
                // The RDS does not yet hold the whole chain (doc 4 §7.7).
                Err(e) if e.code == rpc::E_EVIDENCE_INCOMPLETE && attempt < 10 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(rpc_err(e)),
            }
        }
    }

    /// Write a verification bundle for a message: the evidence package,
    /// the session log, this endpoint's private data, and the EBW URL logs.
    pub async fn export(&self, c: &Conn, mid: &[u8], out: &Path) -> Result<()> {
        let rec = self.record(mid)?;
        let pkg = self.evidence_package(c, mid).await?;
        write_file(out.join(Bundle::PACKAGE), &pkg)?;
        let log: SessionLog = rpc::params(c.ws.call("scc.session.log", to_value(&SessionIdParams { session_id: rec.session_id.clone() })).await.map_err(rpc_err)?).map_err(rpc_err)?;
        write_json(out.join(Bundle::SESSION_LOG), &log)?;
        let mut private = rec.private.clone();
        if let Some(st) = &private.state {
            if st.epoch < rec.epoch {
                if let Some(m) = self.agreement_message(&rec.session_id, st.epoch) {
                    private.agreement = Some(self.evidence_package(c, &m).await?);
                }
            }
        }
        write_json(out.join(Bundle::PRIVATE), &private)?;
        for owner in [&rec.meta.from.owner, &rec.meta.to.owner] {
            let raw = self.resolver.edd.log_raw(owner).await?;
            write_file(out.join(Bundle::REGISTRY_LOGS).join(format!("{owner}.cbor")), raw)?;
        }
        Ok(())
    }
}
