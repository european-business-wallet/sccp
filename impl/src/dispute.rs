//! Retained MLS state (05-evidence.md §8) and its use in disputes
//! (§7.4 message-key dispute, §7.5 group-state dispute).
//!
//! Everything here uses the public API of unmodified mls-rs:
//!
//! - An endpoint exports the state of an epoch by writing its group to
//!   storage (`Group::write_to_storage`) and reading the bytes back from the
//!   client's `GroupStateStorage` (`Client::group_state_storage().state()`).
//!   It does so when the epoch begins, before any message of the epoch is
//!   sent or received, so the state can still derive every message key of
//!   the epoch.
//! - It keeps the private keys of the KeyPackages it publishes by reading
//!   them from the client's `KeyPackageStorage` after generating them.
//! - A verifier loads a presented state by writing it into an in-memory
//!   `GroupStateStorage` and calling `Client::load_group`, and a presented
//!   KeyPackage by inserting it into an in-memory `KeyPackageStorage` and
//!   calling `Client::join_group` with the Welcome from the session log.
//!   It then processes the message or Commits with
//!   `Group::process_incoming_message`, as a member would.

use crate::delivery::SessionLog;
use crate::mls::{self, SccIdentityProvider};
use anyhow::{anyhow, bail, Result};
use mls_rs::client_builder::{ClientBuilder, MlsConfig};
use mls_rs::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs::error::MlsError;
use mls_rs::group::ReceivedMessage;
use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs::storage_provider::KeyPackageData;
use mls_rs_core::group::GroupState;
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuiteProvider, Client, Group, GroupStateStorage, KeyPackageStorage, MlsMessage};
use mls_rs_codec::{MlsDecode, MlsEncode};
use serde::{Deserialize, Serialize};

/// An endpoint's MLS state for one epoch, as mls-rs stores it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetainedState {
    #[serde(with = "crate::util::b64")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "crate::util::b64")]
    pub epoch_authenticator: Vec<u8>,
    /// The bytes mls-rs wrote to its `GroupStateStorage` for the group.
    #[serde(with = "crate::util::b64")]
    pub state: Vec<u8>,
    /// The endpoint created the epoch with its own Commit (doc 5 §7.5).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created: bool,
}

/// The private keys of a KeyPackage, as mls-rs stores them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetainedKeyPackage {
    /// The KeyPackageRef (RFC 9420 §5.2).
    #[serde(with = "crate::util::b64")]
    pub reference: Vec<u8>,
    /// The encoded KeyPackage.
    #[serde(with = "crate::util::b64")]
    pub key_package: Vec<u8>,
    #[serde(with = "crate::util::b64")]
    pub init_key: Vec<u8>,
    #[serde(with = "crate::util::b64")]
    pub leaf_node_key: Vec<u8>,
    pub expiration: u64,
}

impl RetainedKeyPackage {
    fn data(&self) -> KeyPackageData {
        KeyPackageData::new(
            self.key_package.clone(),
            HpkeSecretKey::from(self.init_key.clone()),
            HpkeSecretKey::from(self.leaf_node_key.clone()),
            self.expiration,
        )
    }
}

// ---- Endpoint side ----

/// Write the group to storage and export its state for the current epoch.
pub fn export_state<C: MlsConfig>(client: &Client<C>, g: &mut Group<C>) -> Result<RetainedState> {
    g.write_to_storage().map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    let data = client
        .group_state_storage()
        .state(g.group_id())
        .map_err(|e| anyhow!("group state storage: {e:?}"))?
        .ok_or_else(|| anyhow!("group state not in storage"))?;
    Ok(RetainedState {
        session_id: g.group_id().to_vec(),
        epoch: g.current_epoch(),
        epoch_authenticator: g.epoch_authenticator().map_err(|e| anyhow!("{e:?}"))?.to_vec(),
        state: data.to_vec(),
        created: false,
    })
}

/// Read the private keys of a KeyPackage the client just generated.
pub fn retain_key_package<C: MlsConfig>(client: &Client<C>, msg: &MlsMessage) -> Result<RetainedKeyPackage> {
    let kp = msg.as_key_package().ok_or_else(|| anyhow!("not a KeyPackage"))?;
    let cs = mls::cs_provider(kp.cipher_suite())?;
    let r = kp.to_reference(&cs).map_err(|e| anyhow!("{e:?}"))?;
    let d = client
        .key_package_store()
        .get(&r)
        .map_err(|e| anyhow!("KeyPackage storage: {e:?}"))?
        .ok_or_else(|| anyhow!("KeyPackage not in storage"))?;
    Ok(RetainedKeyPackage {
        reference: r.to_vec(),
        key_package: d.key_package_bytes.clone(),
        init_key: d.init_key.to_vec(),
        leaf_node_key: d.leaf_node_key.to_vec(),
        expiration: d.expiration,
    })
}

// ---- Verifier side ----

/// A client that holds only what a party presented.
fn verifier_client(
    ip: SccIdentityProvider,
    groups: InMemoryGroupStateStorage,
    kps: InMemoryKeyPackageStorage,
) -> Result<Client<impl MlsConfig>> {
    // mls-rs needs a signer to join a group; the verifier never signs.
    let (signer, _) = mls::generate_signature_key()?;
    Ok(ClientBuilder::new()
        .crypto_provider(mls::crypto_provider())
        .identity_provider(ip)
        .extension_type(mls_rs_core::extension::ExtensionType::new(mls::EXT_SCC_SESSION))
        .mls_rules(mls::mls_rules())
        .group_state_storage(groups)
        .key_package_repo(kps)
        .signer(signer)
        .build())
}

/// Load a presented state into mls-rs.
pub fn load_state(ip: &SccIdentityProvider, st: &RetainedState) -> Result<Group<impl MlsConfig>> {
    let mut groups = InMemoryGroupStateStorage::new();
    groups
        .write(GroupState { id: st.session_id.clone(), data: st.state.clone().into() }, vec![], vec![])
        .map_err(|e| anyhow!("{e:?}"))?;
    let client = verifier_client(ip.clone(), groups, InMemoryKeyPackageStorage::new())?;
    let g = client.load_group(&st.session_id).map_err(|e| anyhow!("mls-rs does not load the state: {e:?}"))?;
    if g.current_epoch() != st.epoch {
        bail!("the state is for epoch {}, not {}", g.current_epoch(), st.epoch);
    }
    Ok(g)
}

/// The GroupContext and epoch authenticator of a loaded group.
pub fn group_values<C: MlsConfig>(g: &Group<C>) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((g.context().mls_encode_to_vec()?, g.epoch_authenticator().map_err(|e| anyhow!("{e:?}"))?.to_vec()))
}

/// What processing a PrivateMessage under a state gave.
pub enum Processed {
    /// Decrypted, and the sender's signature verified.
    Application { sender_index: u32, data: Vec<u8> },
    /// The state is the sender's own: mls-rs does not process a member's
    /// own messages.
    FromSelf,
    /// mls-rs rejected the message.
    Rejected(String),
}

/// Process a PrivateMessage under a loaded state, as a member would.
pub fn process_message<C: MlsConfig>(g: &mut Group<C>, message: &[u8]) -> Result<Processed> {
    let msg = mls::parse_mls_message(message)?;
    if msg.wire_format() != mls_rs::WireFormat::PrivateMessage {
        return Ok(Processed::Rejected("not a PrivateMessage".into()));
    }
    Ok(match g.process_incoming_message(msg) {
        Ok(ReceivedMessage::ApplicationMessage(d)) => Processed::Application { sender_index: d.sender_index, data: d.data().to_vec() },
        Ok(_) => Processed::Rejected("not an application message".into()),
        Err(MlsError::CantProcessMessageFromSelf) => Processed::FromSelf,
        Err(e) => Processed::Rejected(format!("{e:?}")),
    })
}

/// The SCC endpoint credential of a member of a loaded group.
pub fn member_credential<C: MlsConfig>(g: &Group<C>, index: u32) -> Result<crate::credential::Credential> {
    let m = g.member_at_index(index).ok_or_else(|| anyhow!("no member at leaf {index}"))?;
    mls::parse_leaf_credential(&m.signing_identity)
}

/// What replaying Commits under a state gave (§7.5 step 3).
pub enum Replay {
    /// Every Commit was processed.
    Done,
    /// mls-rs rejected the Commit that creates `epoch`: its committer is at fault.
    Rejected { epoch: u64, error: String },
    /// The Commit that creates `epoch` was sent by the state's own member,
    /// which mls-rs does not process from a stored state.
    FromSelf { epoch: u64 },
}

/// Process the logged Commits after the group's epoch, up to `target`.
pub fn replay_commits<C: MlsConfig>(ip: &SccIdentityProvider, g: &mut Group<C>, log: &SessionLog, target: u64) -> Result<Replay> {
    let start = g.current_epoch();
    for e in log.commits.iter().filter(|e| e.epoch > start && e.epoch <= target) {
        if e.epoch != g.current_epoch() + 1 {
            bail!("the session log has no Commit for epoch {}", g.current_epoch() + 1);
        }
        ip.ctx.write().unwrap().at = Some(e.accepted_at);
        let msg = mls::parse_mls_message(&e.commit)?;
        match g.process_incoming_message_with_time(msg, MlsTime::from(e.accepted_at)) {
            Ok(ReceivedMessage::Commit(_)) => {}
            Ok(_) => return Ok(Replay::Rejected { epoch: e.epoch, error: "not a Commit".into() }),
            Err(MlsError::CantProcessMessageFromSelf) => return Ok(Replay::FromSelf { epoch: e.epoch }),
            Err(err) => return Ok(Replay::Rejected { epoch: e.epoch, error: format!("{err:?}") }),
        }
    }
    if g.current_epoch() != target {
        bail!("the session log ends at epoch {}, before epoch {target}", g.current_epoch());
    }
    Ok(Replay::Done)
}

/// Check that a presented KeyPackage's private keys match its public keys:
/// the init key and the LeafNode's encryption key (an HPKE round trip for
/// each, with the cipher suite's public operations).
pub fn check_key_package(kp: &RetainedKeyPackage) -> Result<()> {
    // mls-rs stores the encoded KeyPackage.
    let k = mls_rs::KeyPackage::mls_decode(&mut &kp.key_package[..]).map_err(|e| anyhow!("bad KeyPackage: {e:?}"))?;
    let cs = mls::cs_provider(k.cipher_suite())?;
    if k.to_reference(&cs).map_err(|e| anyhow!("{e:?}"))?.to_vec() != kp.reference {
        bail!("KeyPackageRef does not match the KeyPackage");
    }
    let leaf_pk = leaf_encryption_key(&kp.key_package)?;
    for (name, pk, sk) in [("init", &k.hpke_init_key, &kp.init_key), ("leaf", &leaf_pk, &kp.leaf_node_key)] {
        let sk = HpkeSecretKey::from(sk.clone());
        let probe = b"SCC verifier key check";
        let ct = cs.hpke_seal(pk, b"scc", None, probe).map_err(|e| anyhow!("{e:?}"))?;
        match cs.hpke_open(&ct, &sk, pk, b"scc", None) {
            Ok(pt) if pt.as_slice() == probe => {}
            _ => bail!("the {name} private key does not match the KeyPackage"),
        }
    }
    Ok(())
}

/// The LeafNode's encryption key from an encoded KeyPackage. mls-rs does
/// not expose the LeafNode, so read it from the encoding (RFC 9420 §10:
/// version, cipher_suite, init_key, then the LeafNode, which starts with
/// encryption_key).
fn leaf_encryption_key(kp: &[u8]) -> Result<HpkePublicKey> {
    let mut r = kp.get(4..).ok_or_else(|| anyhow!("bad KeyPackage"))?;
    let _init = Vec::<u8>::mls_decode(&mut r).map_err(|e| anyhow!("bad KeyPackage: {e:?}"))?;
    let enc = Vec::<u8>::mls_decode(&mut r).map_err(|e| anyhow!("bad KeyPackage: {e:?}"))?;
    Ok(HpkePublicKey::from(enc))
}

/// What joining with a presented KeyPackage gave (§7.5 step 2, join).
pub enum Join<G> {
    Joined(G),
    /// No Welcome in the log is for any presented KeyPackage.
    NoWelcome,
    /// mls-rs rejected the Welcome of the Commit that creates `epoch`.
    Rejected { epoch: u64, error: String },
}

/// Join with the Welcome of the session log that names one of the
/// presented KeyPackages.
pub fn join_with_key_packages(ip: &SccIdentityProvider, kps: &[RetainedKeyPackage], log: &SessionLog) -> Result<Join<Group<impl MlsConfig>>> {
    let store = InMemoryKeyPackageStorage::new();
    for kp in kps {
        check_key_package(kp)?;
        store.insert(kp.reference.clone(), kp.data());
    }
    let client = verifier_client(ip.clone(), InMemoryGroupStateStorage::new(), store)?;
    for e in &log.commits {
        let Some(w) = &e.welcome else { continue };
        let welcome = mls::parse_mls_message(w)?;
        let named = welcome.welcome_key_package_references().iter().any(|r| kps.iter().any(|k| k.reference == r.to_vec()));
        if !named {
            continue;
        }
        ip.ctx.write().unwrap().at = Some(e.accepted_at);
        return Ok(match client.join_group(None, &welcome, Some(MlsTime::from(e.accepted_at))) {
            Ok((g, _)) => Join::Joined(g),
            Err(err) => Join::Rejected { epoch: e.epoch, error: format!("{err:?}") },
        });
    }
    Ok(Join::NoWelcome)
}
