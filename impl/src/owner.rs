//! An EBW owner's administration: EBW URL registration through its EBW
//! provider, endpoint credential issuance and status lists
//! (01-discovery.md §3, §6.2; 02-credentials.md §2, §5).

use crate::cose::PrivateKey;
use crate::credential::{Credential, CredentialRequestBody, EndpointClaims, StatusListToken, STATUS_INVALID, STATUS_VALID};
use crate::registry::{OpBody, Operation, RegistryDocument, Sealer, Submission};
use crate::edd::EddClient;
use crate::types::{AcceptancePolicy, Identifier};
use crate::util::{now, read_json, write_json};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub subject: String,
    pub idx: u64,
    pub status: u8,
    pub roles: Vec<String>,
    pub holder: Option<String>,
}

/// An EBW provider, which submits its owners' operations to the EDD and
/// seals each submission (01-discovery.md §3.6).
pub struct EbwProvider {
    pub provider: String,
    pub sealer: Sealer,
}

impl EbwProvider {
    /// Create a seal key and a self-signed demo certificate in `dir`.
    pub fn init(dir: &Path, provider: &str) -> Result<Self> {
        let sealer = crate::certs::init_sealer(dir, "seal", &format!("{provider} (DEMO ONLY)"), "EBW provider (demo)")?;
        crate::util::write_file(dir.join("provider.txt"), provider)?;
        Ok(EbwProvider { provider: provider.into(), sealer })
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let provider = std::fs::read_to_string(dir.join("provider.txt")).context("not an EBW provider directory")?;
        Ok(EbwProvider { provider: provider.trim().into(), sealer: crate::certs::load_sealer(dir, "seal")? })
    }

    /// Seal an operation for submission.
    pub fn submit(&self, op: &Operation) -> Vec<u8> {
        Submission::seal(&self.sealer, op, now())
    }

    /// Suspend, reinstate or retire an owner with a status operation
    /// (01-discovery.md §3.1, §5.1), and submit it.
    pub async fn set_status(&self, edd: &EddClient, owner: &str, status: crate::types::OwnerStatus) -> Result<()> {
        let cur = edd.resolve(owner).await?;
        let doc = RegistryDocument { status, signed_at: now(), ..cur.document.clone() };
        let op = Operation::seal(OpBody::Status { prev: cur.operation.hash(), state: doc }, &self.sealer);
        edd.update(owner, &self.submit(&op)).await?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OwnerConfig {
    pub owner: String,
    pub edd: String,
    /// Directory of the EBW provider that submits this owner's operations.
    pub provider: PathBuf,
    pub update_keys: Vec<PrivateKey>,
    pub credential_key: PrivateKey,
    pub rds: String,
    pub status_uri: String,
    pub issued: Vec<IssuedCredential>,
}

pub struct Owner {
    pub dir: PathBuf,
    pub cfg: OwnerConfig,
}

impl Owner {
    pub fn load(dir: &Path) -> Result<Self> {
        Ok(Owner { dir: dir.into(), cfg: read_json(dir.join("owner.json")).context("not an owner directory")? })
    }

    pub fn save(&self) -> Result<()> {
        write_json(self.dir.join("owner.json"), &self.cfg)
    }

    /// Generate keys, sign a create operation and register it with the
    /// EDD through the EBW provider in `provider` (identity proofing is
    /// stubbed).
    pub async fn init(
        dir: &Path,
        edd: &EddClient,
        provider: &Path,
        rds: String,
        identifiers: Vec<Identifier>,
        policies: BTreeMap<String, AcceptancePolicy>,
    ) -> Result<Self> {
        if dir.join("owner.json").exists() {
            bail!("{} already holds an owner", dir.display());
        }
        let update_keys = vec![PrivateKey::generate_ed25519(), PrivateKey::generate_ed25519()];
        let credential_key = PrivateKey::generate_ed25519();
        let mut acceptance_policies = policies;
        acceptance_policies.entry("default".into()).or_insert(AcceptancePolicy::Any);
        let state = RegistryDocument {
            status: crate::types::OwnerStatus::Active,
            successor: None,
            update_keys: update_keys.iter().map(|k| k.public()).collect(),
            credential_keys: vec![credential_key.public()],
            rds: rds.clone(),
            identifiers,
            acceptance_policies,
            signed_at: now(),
        };
        let op = Operation::sign(OpBody::Create(state), &update_keys[0]);
        let sub = EbwProvider::load(provider)?.submit(&op);
        let r = edd.register(&sub, b"demo identity proof").await?;
        let status_uri = crate::rds::Rds::status_uri(&rds, &r.owner);
        let o = Owner {
            dir: dir.into(),
            cfg: OwnerConfig { owner: r.owner, edd: edd.base.clone(), provider: provider.into(), update_keys, credential_key, rds, status_uri, issued: vec![] },
        };
        o.save()?;
        Ok(o)
    }

    /// Issue an endpoint credential for a credential request (§5.1).
    pub fn issue(&mut self, request: &[u8], roles: Option<Vec<String>>, holder: Option<String>, validity: u64) -> Result<Credential> {
        let req = CredentialRequestBody::parse_and_verify(request)?;
        if req.owner != self.cfg.owner {
            bail!("request is for {}, not {}", req.owner, self.cfg.owner);
        }
        let roles = roles.unwrap_or(req.roles.clone());
        if roles.is_empty() {
            bail!("an endpoint needs at least one role");
        }
        // The requested subject ID is kept, so an endpoint keeps its
        // subject ID across renewals (§2).
        let subject = req.subject.clone().unwrap_or_else(crate::util::random_subject);
        let idx = self.cfg.issued.len() as u64;
        let t = now();
        let cred = Credential::issue(
            &self.cfg.credential_key,
            &EndpointClaims {
                iss: self.cfg.owner.clone(),
                sub: subject.clone(),
                exp: t + validity,
                nbf: t - 60,
                iat: t,
                cnf: req.key.clone(),
                status_idx: idx,
                status_uri: self.cfg.status_uri.clone(),
                roles: roles.clone(),
                holder: holder.clone(),
            },
        );
        self.cfg.issued.push(IssuedCredential { subject, idx, status: STATUS_VALID, roles, holder });
        self.save()?;
        Ok(cred)
    }

    pub fn revoke(&mut self, subject: &str) -> Result<()> {
        let mut found = false;
        for i in self.cfg.issued.iter_mut().filter(|i| i.subject == subject) {
            i.status = STATUS_INVALID;
            found = true;
        }
        if !found {
            bail!("no credential issued to {subject}");
        }
        self.save()
    }

    /// Build and sign a status list token (§5.3).
    pub fn status_token(&self, validity: u64, ttl: Option<u64>) -> StatusListToken {
        let mut statuses: Vec<u8> = self.cfg.issued.iter().map(|i| i.status).collect();
        if statuses.is_empty() {
            statuses.push(STATUS_VALID);
        }
        let t = now();
        StatusListToken::build(&self.cfg.credential_key, &self.cfg.owner, &self.cfg.status_uri, &statuses, t - 5, t + validity, ttl)
    }

    /// Publish the status list token at its URI (hosted by the home RDS).
    pub async fn publish_status(&self, validity: u64, ttl: Option<u64>) -> Result<StatusListToken> {
        let tok = self.status_token(validity, ttl);
        let http = crate::net::http_client()?;
        crate::net::post_bytes(&http, &self.cfg.status_uri, crate::credential::STATUSLIST_TYP, tok.raw.clone()).await?;
        Ok(tok)
    }
}
