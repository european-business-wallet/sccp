//! The SCC MLS profile (03-mls.md) and MLS binding of endpoint credentials
//! (02-credentials.md §4), on top of mls-rs.
//!
//! - [`SccSession`]: the `scc_session` GroupContext extension (0xF0EC).
//! - [`CredentialBinding`]: the MultiCredential binding of
//!   draft-ietf-mls-extensions §6.5, carrying an `ebw_endpoint` credential
//!   (0xF0EB). mls-rs carries both as custom credentials.
//! - [`SccIdentityProvider`]: validates leaf credentials (§4.3).
//! - Retained state and disputes are in [`crate::dispute`].

use crate::cose::{CoseKey, PrivateKey};
use crate::credential::{Credential as EndpointCredential, StatusListToken};
use crate::registry::RegistryDocument;
use crate::types::{Address, Consignment};
use crate::util::sha256;
use anyhow::{anyhow, bail, Result};
use mls_rs::client_builder::MlsConfig;
use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs::error::IntoAnyError;
use mls_rs::extension::built_in::RequiredCapabilitiesExt;
use mls_rs::group::proposal::Proposal;
use mls_rs::identity::{Credential, CredentialType, CustomCredential, SigningIdentity};
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, MlsMessage};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionType, MlsCodecExtension};
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};
use mls_rs_core::time::MlsTime;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const CRED_MULTI: u16 = 0x0003;
pub const CRED_EBW_ENDPOINT: u16 = 0xF0EB;
pub const EXT_SCC_SESSION: u16 = 0xF0EC;
/// mls-rs's `last_resort` KeyPackage extension type.
pub const EXT_LAST_RESORT: u16 = 0x000A;

/// The REQUIRED cipher suite (§2).
pub const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

pub fn crypto_provider() -> mls_rs_crypto_rustcrypto::RustCryptoProvider {
    mls_rs_crypto_rustcrypto::RustCryptoProvider::default()
}

pub fn cs_provider(cs: CipherSuite) -> Result<impl CipherSuiteProvider> {
    crypto_provider().cipher_suite_provider(cs).ok_or_else(|| anyhow!("unsupported cipher suite {cs:?}"))
}

// ---- scc_session (§4.1) ----

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct SccAddress {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub owner: Vec<u8>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub role: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct SccSession {
    pub initiator: SccAddress,
    pub responder: SccAddress,
}

impl MlsCodecExtension for SccSession {
    fn extension_type() -> ExtensionType {
        ExtensionType::new(EXT_SCC_SESSION)
    }
}

impl SccAddress {
    pub fn from_address(a: &Address) -> Self {
        SccAddress { owner: a.owner.as_bytes().to_vec(), role: a.role.as_bytes().to_vec() }
    }
    pub fn to_address(&self) -> Result<Address> {
        Ok(Address { owner: String::from_utf8(self.owner.clone())?, role: String::from_utf8(self.role.clone())? })
    }
}

impl SccSession {
    pub fn new(initiator: &Address, responder: &Address) -> Result<Self> {
        if initiator == responder {
            bail!("the two addresses of a session must differ");
        }
        Ok(SccSession { initiator: SccAddress::from_address(initiator), responder: SccAddress::from_address(responder) })
    }

    pub fn addresses(&self) -> Result<(Address, Address)> {
        Ok((self.initiator.to_address()?, self.responder.to_address()?))
    }

    pub fn from_extensions(ext: &ExtensionList) -> Result<Self> {
        ext.get_as::<SccSession>()
            .map_err(|e| anyhow!("bad scc_session extension: {e:?}"))?
            .ok_or_else(|| anyhow!("GroupContext has no scc_session extension"))
    }
}

/// The GroupContext extensions of a new session (§4.1).
pub fn session_extensions(initiator: &Address, responder: &Address) -> Result<ExtensionList> {
    let mut ext = ExtensionList::new();
    ext.set_from(SccSession::new(initiator, responder)?).map_err(|e| anyhow!("{e:?}"))?;
    ext.set_from(RequiredCapabilitiesExt {
        extensions: vec![ExtensionType::new(EXT_SCC_SESSION)],
        proposals: vec![],
        credentials: vec![CredentialType::new(CRED_MULTI), CredentialType::new(CRED_EBW_ENDPOINT)],
    })
    .map_err(|e| anyhow!("{e:?}"))?;
    Ok(ext)
}

/// Check that a GroupContext's extensions follow §4.1 (scc_session with
/// two different addresses, and the required capabilities).
pub fn check_session_extensions(ext: &ExtensionList) -> Result<SccSession> {
    let s = SccSession::from_extensions(ext)?;
    let (i, r) = s.addresses()?;
    crate::types::check_ebw_url(&i.owner)?;
    crate::types::check_ebw_url(&r.owner)?;
    crate::types::check_role(&i.role)?;
    crate::types::check_role(&r.role)?;
    if i == r {
        bail!("scc_session addresses are equal");
    }
    let rc = ext
        .get_as::<RequiredCapabilitiesExt>()
        .map_err(|e| anyhow!("{e:?}"))?
        .ok_or_else(|| anyhow!("no required_capabilities extension"))?;
    if !rc.extensions.contains(&ExtensionType::new(EXT_SCC_SESSION))
        || !rc.credentials.contains(&CredentialType::new(CRED_MULTI))
        || !rc.credentials.contains(&CredentialType::new(CRED_EBW_ENDPOINT))
    {
        bail!("required_capabilities does not list the SCC types");
    }
    Ok(s)
}

// ---- Credential binding (02-credentials.md §4) ----

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct CredentialBinding {
    pub cipher_suite: CipherSuite,
    pub credential: Credential,
    pub credential_key: SignaturePublicKey,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
struct CredentialBindingTbs {
    cipher_suite: CipherSuite,
    credential: Credential,
    credential_key: SignaturePublicKey,
    signature_key: SignaturePublicKey,
}

/// Append `data` as a TLS variable-length vector (RFC 9420 §2.1.2).
pub fn tls_vec(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
    out.extend_from_slice(data);
}

/// The signed content of SignWithLabel (RFC 9420 §5.1.2).
fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    tls_vec(&mut out, format!("MLS 1.0 {label}").as_bytes());
    tls_vec(&mut out, content);
    out
}

/// SignWithLabel with an SCC key (Ed25519, or ECDSA P-256 with a DER
/// signature as MLS uses it).
pub fn sign_with_label(key: &PrivateKey, label: &str, content: &[u8]) -> Vec<u8> {
    let msg = sign_content(label, content);
    match key {
        PrivateKey::Ed25519(_) => key.sign(&msg),
        PrivateKey::P256(k) => {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = k.sign(&msg);
            sig.to_der().as_bytes().to_vec()
        }
    }
}

pub fn verify_with_label(key: &CoseKey, label: &str, content: &[u8], sig: &[u8]) -> Result<()> {
    let msg = sign_content(label, content);
    match key {
        CoseKey::Ed25519 { .. } => key.verify(&msg, sig),
        CoseKey::P256 { .. } => {
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|e| anyhow!("bad DER signature: {e}"))?;
            key.verify(&msg, &s.to_bytes())
        }
    }
}

fn binding_suite(key: &CoseKey) -> CipherSuite {
    match key {
        CoseKey::Ed25519 { .. } => CipherSuite::CURVE25519_AES128,
        CoseKey::P256 { .. } => CipherSuite::P256_AES128,
    }
}

/// Build the leaf credential: a `multi` credential with one binding of the
/// `ebw_endpoint` credential, signed by the endpoint key over the MLS
/// signature key (§4.2).
pub fn make_leaf_credential(endpoint_key: &PrivateKey, cwt: &[u8], mls_signature_key: &SignaturePublicKey) -> Credential {
    let ebw = Credential::Custom(CustomCredential::new(CredentialType::new(CRED_EBW_ENDPOINT), cwt.to_vec()));
    let ck = endpoint_key.public();
    let credential_key = SignaturePublicKey::new(ck.mls_bytes());
    let cipher_suite = binding_suite(&ck);
    let tbs = CredentialBindingTbs {
        cipher_suite,
        credential: ebw.clone(),
        credential_key: credential_key.clone(),
        signature_key: mls_signature_key.clone(),
    };
    let signature = sign_with_label(endpoint_key, "CredentialBindingTBS", &tbs.mls_encode_to_vec().unwrap());
    let binding = CredentialBinding { cipher_suite, credential: ebw, credential_key, signature };
    // MultiCredential = bindings<V>. mls-rs encodes a custom credential as
    // type || data<V>, so `data` is the concatenated bindings.
    Credential::Custom(CustomCredential::new(CredentialType::new(CRED_MULTI), binding.mls_encode_to_vec().unwrap()))
}

/// Check steps 1, 2, 4 and 5 of §4.3 and return the endpoint credential.
/// Step 3 (credential validity) needs the registry document; see
/// [`SccIdentityProvider`].
pub fn parse_leaf_credential(si: &SigningIdentity) -> Result<EndpointCredential> {
    let multi = match &si.credential {
        Credential::Custom(c) if c.credential_type == CredentialType::new(CRED_MULTI) => c,
        _ => bail!("leaf credential is not of type multi"),
    };
    let mut wrapped = Vec::new();
    tls_vec(&mut wrapped, &multi.data);
    let bindings = Vec::<CredentialBinding>::mls_decode(&mut &wrapped[..])?;
    if bindings.len() != 1 {
        bail!("multi credential must have exactly one binding");
    }
    let b = &bindings[0];
    let cwt = match &b.credential {
        Credential::Custom(c) if c.credential_type == CredentialType::new(CRED_EBW_ENDPOINT) => &c.data,
        _ => bail!("binding credential is not of type ebw_endpoint"),
    };
    let cred = EndpointCredential::parse(cwt)?;
    if b.credential_key.as_bytes() != cred.claims.cnf.mls_bytes().as_slice() {
        bail!("binding credential_key is not the credential's cnf key");
    }
    if b.cipher_suite != binding_suite(&cred.claims.cnf) {
        bail!("binding cipher suite does not match the endpoint key");
    }
    let tbs = CredentialBindingTbs {
        cipher_suite: b.cipher_suite,
        credential: b.credential.clone(),
        credential_key: b.credential_key.clone(),
        signature_key: si.signature_key.clone(),
    };
    verify_with_label(&cred.claims.cnf, "CredentialBindingTBS", &tbs.mls_encode_to_vec()?, &b.signature)
        .map_err(|e| anyhow!("credential binding signature: {e}"))?;
    Ok(cred)
}

/// The identity of a leaf: (iss, sub) (§4.3).
pub fn identity_bytes(iss: &str, sub: &str) -> Vec<u8> {
    format!("{iss}/{sub}").into_bytes()
}

// ---- Identity provider ----

/// What a party knows about registry documents and status lists.
#[derive(Clone, Debug, Default)]
pub struct TrustContext {
    pub states: HashMap<String, RegistryDocument>,
    pub statuses: HashMap<String, StatusListToken>,
    /// Require a status list token for every credential.
    pub require_status: bool,
    /// Check credentials at this time instead of now (verifiers).
    pub at: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SccIdentityError(pub String);

impl IntoAnyError for SccIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Validates SCC leaf credentials against known registry documents and status
/// lists (02-credentials.md §3, §4.3).
#[derive(Clone, Default)]
pub struct SccIdentityProvider {
    pub ctx: Arc<RwLock<TrustContext>>,
    /// If set, registry documents and status lists are resolved over the network
    /// and credentials are checked now (RDSes, endpoints).
    pub resolver: Option<Arc<crate::resolve::Resolver>>,
}

impl std::fmt::Debug for SccIdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SccIdentityProvider").finish()
    }
}

impl SccIdentityProvider {
    pub fn new(ctx: TrustContext) -> Self {
        SccIdentityProvider { ctx: Arc::new(RwLock::new(ctx)), resolver: None }
    }

    pub fn with_resolver(r: Arc<crate::resolve::Resolver>) -> Self {
        SccIdentityProvider { ctx: Arc::new(RwLock::new(TrustContext::default())), resolver: Some(r) }
    }

    pub fn check(&self, si: &SigningIdentity, timestamp: Option<MlsTime>) -> Result<EndpointCredential> {
        let cred = parse_leaf_credential(si)?;
        if let Some(r) = &self.resolver {
            let t = crate::util::now();
            let st = r.resolve_blocking(&cred.claims.iss)?;
            cred.verify_signature_and_time(&st.document, t)?;
            let tok = r.status_blocking(&cred.claims.status_uri)?;
            cred.check_status(&tok, &st.document, t)?;
            return Ok(cred);
        }
        let ctx = self.ctx.read().unwrap();
        let t = ctx
            .at
            .or_else(|| timestamp.map(|t| t.seconds_since_epoch()))
            .unwrap_or_else(crate::util::now);
        let state = ctx
            .states
            .get(&cred.claims.iss)
            .ok_or_else(|| anyhow!("no registry document known for {}", cred.claims.iss))?;
        cred.verify_signature_and_time(state, t)?;
        match ctx.statuses.get(&cred.claims.status_uri) {
            Some(tok) => cred.check_status(tok, state, t)?,
            None if ctx.require_status => bail!("no status list for {}", cred.claims.status_uri),
            None => {}
        }
        Ok(cred)
    }
}

impl IdentityProvider for SccIdentityProvider {
    type Error = SccIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.check(signing_identity, timestamp).map(|_| ()).map_err(|e| SccIdentityError(e.to_string()))
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Err(SccIdentityError("external senders are not used in SCC".into()))
    }

    fn identity(&self, signing_identity: &SigningIdentity, _extensions: &ExtensionList) -> Result<Vec<u8>, Self::Error> {
        let c = parse_leaf_credential(signing_identity).map_err(|e| SccIdentityError(e.to_string()))?;
        Ok(identity_bytes(&c.claims.iss, &c.claims.sub))
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(self.identity(predecessor, extensions)? == self.identity(successor, extensions)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::new(CRED_MULTI), CredentialType::new(CRED_EBW_ENDPOINT)]
    }
}

// ---- Clients ----

pub fn mls_rules() -> DefaultMlsRules {
    DefaultMlsRules::new()
        .with_commit_options(
            CommitOptions::new()
                .with_ratchet_tree_extension(true)
                .with_single_welcome_message(true)
                .with_path_required(true),
        )
        // Commits as PublicMessage; pad PrivateMessages (03-mls.md §6.1, §7.1).
        .with_encryption_options(EncryptionOptions::new(false, mls_rs::client_builder::PaddingMode::StepFunction))
}

/// Generate an MLS signature key pair.
pub fn generate_signature_key() -> Result<(SignatureSecretKey, SignaturePublicKey)> {
    cs_provider(CIPHER_SUITE)?
        .signature_key_generate()
        .map_err(|e| anyhow!("signature key generation: {e:?}"))
}

/// An endpoint's MLS client, with SQLite state storage.
pub fn endpoint_client(
    db: &std::path::Path,
    ip: SccIdentityProvider,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    key_package_lifetime: u64,
) -> Result<Client<impl MlsConfig>> {
    use mls_rs::storage_provider::sqlite::{connection_strategy::FileConnectionStrategy, SqLiteDataStorageEngine};
    let engine = SqLiteDataStorageEngine::new(FileConnectionStrategy::new(db))
        .map_err(|e| anyhow!("sqlite: {e:?}"))?;
    Ok(mls_rs::client_builder::ClientBuilder::new_sqlite(engine)
        .map_err(|e| anyhow!("sqlite: {e:?}"))?
        .crypto_provider(crypto_provider())
        .identity_provider(ip)
        .extension_type(ExtensionType::new(EXT_SCC_SESSION))
        .mls_rules(mls_rules())
        .key_package_lifetime(std::time::Duration::from_secs(key_package_lifetime))
        .signing_identity(signing_identity, signer, CIPHER_SUITE)
        .build())
}

/// A non-member observer (RDS, verifier) that follows the ratchet tree.
pub fn observer_client(ip: SccIdentityProvider) -> mls_rs::external_client::ExternalClient<impl mls_rs::external_client::builder::MlsConfig> {
    mls_rs::external_client::ExternalClient::builder()
        .crypto_provider(crypto_provider())
        .identity_provider(ip)
        .extension_type(ExtensionType::new(EXT_SCC_SESSION))
        .build()
}

// ---- Application message (§7.1) ----

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppMessage {
    #[serde(with = "serde_bytes")]
    pub message_id: Vec<u8>,
    pub from: Address,
    pub to: Address,
    pub sent_at: u64,
    pub expires_at: u64,
    pub consignment: Consignment,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub in_reply_to: Option<ByteBuf>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

impl AppMessage {
    pub fn encode(&self) -> Vec<u8> {
        crate::cbor::to_vec(self).unwrap()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if !crate::cbor::is_deterministic(data) {
            bail!("application data is not deterministically encoded");
        }
        let m: AppMessage = crate::cbor::from_slice(data)?;
        if m.message_id.len() != 16 || !(16..=32).contains(&m.salt.len()) {
            bail!("bad message_id or salt length");
        }
        Ok(m)
    }
}

// ---- Helpers ----

pub fn parse_mls_message(data: &[u8]) -> Result<MlsMessage> {
    MlsMessage::from_bytes(data).map_err(|e| anyhow!("bad MLSMessage: {e:?}"))
}

/// The proposals of a Commit that SCC forbids (§6.1).
pub fn check_proposal_allowed(p: &Proposal, session: &SccSession) -> Result<()> {
    match p {
        Proposal::Add(_) | Proposal::Remove(_) | Proposal::Update(_) => Ok(()),
        Proposal::GroupContextExtensions(ext) => {
            let s = check_session_extensions(ext)?;
            if &s != session {
                bail!("GroupContextExtensions changes scc_session");
            }
            Ok(())
        }
        Proposal::Psk(_) => bail!("PreSharedKey proposals are not allowed"),
        Proposal::ReInit(_) => bail!("ReInit proposals are not allowed"),
        Proposal::ExternalInit(_) => bail!("ExternalInit proposals are not allowed"),
        _ => bail!("proposal type not allowed in SCC"),
    }
}

/// Reject last-resort KeyPackages (§3).
pub fn check_not_last_resort(kp: &mls_rs::KeyPackage) -> Result<()> {
    if kp.extensions.get(ExtensionType::new(EXT_LAST_RESORT)).is_some() {
        bail!("last-resort KeyPackages are forbidden");
    }
    Ok(())
}

// ---- Members ----

/// What an observer knows about one leaf.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub index: u32,
    pub owner: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub holder: String,
    pub exp: u64,
    pub status_uri: String,
    #[serde(with = "crate::util::b64")]
    pub credential: Vec<u8>,
    #[serde(with = "crate::util::b64")]
    pub signature_key: Vec<u8>,
}

impl MemberInfo {
    pub fn from_member(m: &mls_rs::group::Member) -> Result<Self> {
        let c = parse_leaf_credential(&m.signing_identity)?;
        Ok(MemberInfo {
            index: m.index,
            owner: c.claims.iss.clone(),
            subject: c.claims.sub.clone(),
            roles: c.claims.roles.clone(),
            holder: c.claims.holder_id(),
            exp: c.claims.exp,
            status_uri: c.claims.status_uri.clone(),
            credential: c.raw.clone(),
            signature_key: m.signing_identity.signature_key.as_bytes().to_vec(),
        })
    }

    pub fn holds(&self, a: &Address) -> bool {
        self.owner == a.owner && self.roles.iter().any(|r| r == &a.role)
    }
}

pub fn members_of(roster: &[mls_rs::group::Member]) -> Result<Vec<MemberInfo>> {
    roster.iter().map(MemberInfo::from_member).collect()
}

/// SHA-256 of an encoded MLS object (commit_ref, envelope_hash, KeyPackage
/// identifiers).
pub fn mls_hash(data: &[u8]) -> Vec<u8> {
    sha256(data)
}
