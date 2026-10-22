//! Demo certificates and trust anchors.
//!
//! Stubs (impl/NOTES.md): EDD and RDS seal certificates, and the TSA
//! certificate, are self-signed demo certificates made with `rcgen`. The
//! EU Trusted Lists are replaced by a configured set of trusted
//! certificates ([`TrustStore`]). TLS uses a demo CA.

use crate::cose::{CoseKey, PrivateKey};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// Adapter so that `rcgen` can sign with our Ed25519 key.
struct RcgenKey<'a>(&'a PrivateKey, Vec<u8>);

impl rcgen::PublicKeyData for RcgenKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.1
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for RcgenKey<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.sign(msg))
    }
}

/// A self-signed certificate for an Ed25519 seal key.
pub fn self_signed_seal_cert(key: &PrivateKey, common_name: &str, org: &str, days: u64) -> Result<Vec<u8>> {
    let raw = match key.public() {
        CoseKey::Ed25519 { x } => x,
        _ => bail!("seal keys are Ed25519 in this implementation"),
    };
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    dn.push(rcgen::DnType::OrganizationName, org);
    params.distinguished_name = dn;
    let now = crate::util::now();
    params.not_before = time_from_unix(now - 86400);
    params.not_after = time_from_unix(now + days * 86400);
    let cert = params.self_signed(&RcgenKey(key, raw))?;
    Ok(cert.der().to_vec())
}

fn time_from_unix(t: u64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(t as i64).unwrap()
}

/// The public key of a certificate (Ed25519 or P-256).
pub fn cert_public_key(der: &[u8]) -> Result<CoseKey> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("bad certificate: {e}"))?;
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();
    let data = spki.subject_public_key.data.to_vec();
    match oid.as_str() {
        "1.3.101.112" => CoseKey::from_ed25519_raw(&data),
        "1.2.840.10045.2.1" if data.len() == 65 && data[0] == 4 => Ok(CoseKey::P256 {
            x: data[1..33].to_vec(),
            y: data[33..65].to_vec(),
        }),
        _ => bail!("unsupported certificate key algorithm {oid}"),
    }
}

/// Validity period of a certificate (not_before, not_after), in seconds.
pub fn cert_validity(der: &[u8]) -> Result<(u64, u64)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("bad certificate: {e}"))?;
    let v = cert.validity();
    Ok((v.not_before.timestamp().max(0) as u64, v.not_after.timestamp().max(0) as u64))
}

pub fn cert_subject(der: &[u8]) -> String {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, c)| c.subject().to_string())
        .unwrap_or_else(|_| "?".into())
}

/// The trusted certificates: a stand-in for the EU Trusted Lists.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    /// EDD seal certificates (DER, base64url).
    #[serde(with = "crate::util::b64vec", default)]
    pub edd: Vec<Vec<u8>>,
    /// Qualified RDS seal certificates.
    #[serde(with = "crate::util::b64vec", default)]
    pub rds: Vec<Vec<u8>>,
    /// Timestamping authority certificates.
    #[serde(with = "crate::util::b64vec", default)]
    pub tsa: Vec<Vec<u8>>,
    /// Qualified EBW provider seal certificates (01-discovery.md §3.6).
    #[serde(with = "crate::util::b64vec", default)]
    pub ebw: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub enum TrustKind {
    Edd,
    Rds,
    Tsa,
    Ebw,
}

impl TrustStore {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        crate::util::read_json(path)
    }

    /// Check that `chain` leads to a trusted certificate of the given kind
    /// that was valid at time `t`, and return the leaf's public key.
    pub fn check_chain(&self, chain: &[Vec<u8>], kind: TrustKind, t: u64) -> Result<CoseKey> {
        let leaf = chain.first().ok_or_else(|| anyhow!("empty x5chain"))?;
        let anchors = match kind {
            TrustKind::Edd => &self.edd,
            TrustKind::Rds => &self.rds,
            TrustKind::Tsa => &self.tsa,
            TrustKind::Ebw => &self.ebw,
        };
        // Demo certificates are self-signed, so the chain is one
        // certificate that must itself be a trust anchor.
        if !anchors.iter().any(|a| a == leaf) {
            bail!("certificate {} is not on the trusted list ({kind:?})", cert_subject(leaf));
        }
        let (nb, na) = cert_validity(leaf)?;
        if t < nb || t >= na {
            bail!("certificate {} not valid at {}", cert_subject(leaf), crate::util::fmt_time(t));
        }
        cert_public_key(leaf)
    }
}

/// Demo TLS PKI: a CA and one server certificate for `localhost`.
pub struct DemoTls {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn demo_tls() -> Result<DemoTls> {
    let ca_key = rcgen::KeyPair::generate()?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "SCC demo TLS CA");
    ca_params.distinguished_name = dn;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    let cert = params.signed_by(&key, &issuer)?;
    Ok(DemoTls { ca_pem: ca_cert.pem(), cert_pem: cert.pem(), key_pem: key.serialize_pem() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_cert_roundtrip() {
        let k = PrivateKey::generate_ed25519();
        let der = self_signed_seal_cert(&k, "test", "DEMO ONLY", 10).unwrap();
        assert_eq!(cert_public_key(&der).unwrap(), k.public());
        let ts = TrustStore { rds: vec![der.clone()], ..Default::default() };
        ts.check_chain(&[der.clone()], TrustKind::Rds, crate::util::now()).unwrap();
        assert!(ts.check_chain(&[der], TrustKind::Edd, crate::util::now()).is_err());
        demo_tls().unwrap();
    }
}

/// Create a seal key and a self-signed certificate in `dir` as
/// `<name>-key.json` and `<name>-cert.der`.
pub fn init_sealer(dir: &std::path::Path, name: &str, common_name: &str, org: &str) -> Result<crate::registry::Sealer> {
    let key = PrivateKey::generate_ed25519();
    let cert = self_signed_seal_cert(&key, common_name, org, 3650)?;
    crate::util::write_json(dir.join(format!("{name}-key.json")), &key)?;
    crate::util::write_file(dir.join(format!("{name}-cert.der")), &cert)?;
    Ok(crate::registry::Sealer { key, chain: vec![cert] })
}

/// Load a seal key and certificate created by [`init_sealer`].
pub fn load_sealer(dir: &std::path::Path, name: &str) -> Result<crate::registry::Sealer> {
    let key: PrivateKey = crate::util::read_json(dir.join(format!("{name}-key.json")))?;
    let cert = crate::util::read_file(dir.join(format!("{name}-cert.der")))?;
    if cert_public_key(&cert)? != key.public() {
        bail!("{name}: certificate does not match key");
    }
    Ok(crate::registry::Sealer { key, chain: vec![cert] })
}
