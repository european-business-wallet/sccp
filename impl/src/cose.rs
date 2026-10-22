//! COSE keys and COSE_Sign1 (RFC 9052), COSE Key Thumbprints (RFC 9679).
//!
//! `coset` parses COSE_Sign1 structures and builds the `Sig_structure`.
//! Protected headers are encoded deterministically here and handed to
//! `coset` as `original_data`, so that the bytes signed are exactly the
//! deterministic encoding the specification requires.

use crate::cbor::{self, Value};
use anyhow::{anyhow, bail, Result};
use coset::{AsCborValue, CborSerializable, CoseSign1, ProtectedHeader, TaggedCborSerializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const ALG_EDDSA: i64 = -8;
pub const ALG_ES256: i64 = -7;

pub const HDR_ALG: i64 = 1;
pub const HDR_KID: i64 = 4;
pub const HDR_TYP: i64 = 16;
pub const HDR_X5CHAIN: i64 = 33;
pub const HDR_SCC_CRED: &str = "scc-cred";

/// A public key, as a COSE_Key (OKP Ed25519 or EC2 P-256).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseKey {
    Ed25519 { x: Vec<u8> },
    P256 { x: Vec<u8>, y: Vec<u8> },
}

impl CoseKey {
    pub fn to_value(&self) -> Value {
        match self {
            CoseKey::Ed25519 { x } => Value::Map(vec![
                (cbor::int(1), cbor::int(1)),
                (cbor::int(-1), cbor::int(6)),
                (cbor::int(-2), cbor::bytes(x)),
            ]),
            CoseKey::P256 { x, y } => Value::Map(vec![
                (cbor::int(1), cbor::int(2)),
                (cbor::int(-1), cbor::int(1)),
                (cbor::int(-2), cbor::bytes(x)),
                (cbor::int(-3), cbor::bytes(y)),
            ]),
        }
    }

    pub fn from_value(v: &Value) -> Result<Self> {
        let m = cbor::as_map(v)?;
        let kty = cbor::as_i64(cbor::map_int(m, 1).ok_or_else(|| anyhow!("COSE_Key without kty"))?)?;
        let crv = cbor::as_i64(cbor::map_int(m, -1).ok_or_else(|| anyhow!("COSE_Key without crv"))?)?;
        let x = cbor::as_bytes(cbor::map_int(m, -2).ok_or_else(|| anyhow!("COSE_Key without x"))?)?;
        if x.len() != 32 {
            bail!("COSE_Key x must be 32 bytes");
        }
        match (kty, crv) {
            (1, 6) => {
                if m.len() != 3 {
                    bail!("unexpected parameters in OKP key");
                }
                Ok(CoseKey::Ed25519 { x: x.clone() })
            }
            (2, 1) => {
                let y = cbor::as_bytes(cbor::map_int(m, -3).ok_or_else(|| anyhow!("EC2 key without y"))?)?;
                if y.len() != 32 || m.len() != 4 {
                    bail!("bad EC2 key");
                }
                Ok(CoseKey::P256 { x: x.clone(), y: y.clone() })
            }
            _ => bail!("unsupported COSE_Key kty {kty} crv {crv}"),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// COSE Key Thumbprint (RFC 9679) with SHA-256. All parameters we
    /// encode are the required ones.
    pub fn thumbprint(&self) -> Vec<u8> {
        crate::util::sha256(&self.encode())
    }

    pub fn alg(&self) -> i64 {
        match self {
            CoseKey::Ed25519 { .. } => ALG_EDDSA,
            CoseKey::P256 { .. } => ALG_ES256,
        }
    }

    /// Verify a raw signature (Ed25519, or ES256 as r||s).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        match self {
            CoseKey::Ed25519 { x } => {
                let pk = ed25519_dalek::VerifyingKey::from_bytes(
                    x.as_slice().try_into().map_err(|_| anyhow!("bad key"))?,
                )
                .map_err(|e| anyhow!("bad Ed25519 key: {e}"))?;
                let sig = ed25519_dalek::Signature::from_slice(sig)
                    .map_err(|e| anyhow!("bad Ed25519 signature: {e}"))?;
                pk.verify_strict(msg, &sig)
                    .map_err(|_| anyhow!("Ed25519 signature does not verify"))
            }
            CoseKey::P256 { x, y } => {
                use p256::ecdsa::signature::Verifier;
                let mut sec1 = vec![4u8];
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|e| anyhow!("bad P-256 key: {e}"))?;
                let sig = p256::ecdsa::Signature::from_slice(sig)
                    .map_err(|e| anyhow!("bad ES256 signature: {e}"))?;
                vk.verify(msg, &sig)
                    .map_err(|_| anyhow!("ES256 signature does not verify"))
            }
        }
    }

    /// The raw public key bytes as MLS uses them for Ed25519
    /// (RFC 9420 SignaturePublicKey).
    pub fn mls_bytes(&self) -> Vec<u8> {
        match self {
            CoseKey::Ed25519 { x } => x.clone(),
            CoseKey::P256 { x, y } => {
                let mut v = vec![4u8];
                v.extend_from_slice(x);
                v.extend_from_slice(y);
                v
            }
        }
    }

    pub fn from_ed25519_raw(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            bail!("Ed25519 key must be 32 bytes");
        }
        Ok(CoseKey::Ed25519 { x: raw.to_vec() })
    }
}

impl Serialize for CoseKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for CoseKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        CoseKey::from_value(&v).map_err(serde::de::Error::custom)
    }
}

/// A private signing key.
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

#[derive(Serialize, Deserialize)]
struct PrivateKeyFile {
    alg: String,
    #[serde(with = "crate::util::b64")]
    d: Vec<u8>,
}

impl PrivateKey {
    pub fn generate_ed25519() -> Self {
        let seed: [u8; 32] = crate::util::random_bytes(32).try_into().unwrap();
        PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn generate_p256() -> Self {
        loop {
            let d = crate::util::random_bytes(32);
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&d) {
                return PrivateKey::P256(k);
            }
        }
    }

    /// A key derived from a label, as `tools/scc_cbor.py` does for the
    /// spec examples (seed = SHA-256(label)).
    pub fn ed25519_from_label(label: &str) -> Self {
        let seed: [u8; 32] = crate::util::sha256(label.as_bytes()).try_into().unwrap();
        PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn ed25519_from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| anyhow!("seed must be 32 bytes"))?;
        Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub fn public(&self) -> CoseKey {
        match self {
            PrivateKey::Ed25519(k) => CoseKey::Ed25519 {
                x: k.verifying_key().to_bytes().to_vec(),
            },
            PrivateKey::P256(k) => {
                let point = k.verifying_key().to_sec1_bytes();
                // uncompressed point: 0x04 || x || y
                let (x, y) = if point.len() == 65 {
                    (point[1..33].to_vec(), point[33..65].to_vec())
                } else {
                    panic!("unexpected P-256 point encoding")
                };
                CoseKey::P256 { x, y }
            }
        }
    }

    pub fn alg(&self) -> i64 {
        match self {
            PrivateKey::Ed25519(_) => ALG_EDDSA,
            PrivateKey::P256(_) => ALG_ES256,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(msg).to_bytes().to_vec()
            }
            PrivateKey::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(msg);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// The raw private key bytes (Ed25519 seed or P-256 scalar).
    pub fn secret_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => k.to_bytes().to_vec(),
            PrivateKey::P256(k) => k.to_bytes().to_vec(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(PrivateKeyFile {
            alg: match self {
                PrivateKey::Ed25519(_) => "EdDSA".into(),
                PrivateKey::P256(_) => "ES256".into(),
            },
            d: self.secret_bytes(),
        })
        .unwrap()
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let f: PrivateKeyFile = serde_json::from_value(v.clone())?;
        match f.alg.as_str() {
            "EdDSA" => Self::ed25519_from_seed(&f.d),
            "ES256" => Ok(PrivateKey::P256(
                p256::ecdsa::SigningKey::from_slice(&f.d).map_err(|e| anyhow!("{e}"))?,
            )),
            a => bail!("unknown key algorithm {a}"),
        }
    }
}

impl Serialize for PrivateKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        PrivateKey::from_json(&v).map_err(serde::de::Error::custom)
    }
}

/// Extra protected header parameters beyond `alg` and `kid`.
#[derive(Default, Clone)]
pub struct ExtraHeaders {
    pub typ: Option<String>,
    pub x5chain: Option<Vec<Vec<u8>>>,
    pub scc_cred: Option<Vec<u8>>,
    /// Leave out `kid` (seals identified by x5chain may omit it).
    pub no_kid: bool,
}

impl ExtraHeaders {
    pub fn x5chain(chain: Vec<Vec<u8>>) -> Self {
        ExtraHeaders { x5chain: Some(chain), ..Default::default() }
    }
    pub fn scc_cred(cred: &[u8]) -> Self {
        ExtraHeaders { scc_cred: Some(cred.to_vec()), ..Default::default() }
    }
}

/// Sign `payload` (already deterministically encoded) as a COSE_Sign1 with
/// an embedded payload. If `tagged`, the result carries CBOR tag 18.
pub fn sign1(key: &PrivateKey, payload: &[u8], extra: &ExtraHeaders, tagged: bool) -> Vec<u8> {
    let mut prot = vec![(cbor::int(HDR_ALG), cbor::int(key.alg()))];
    if !extra.no_kid {
        prot.push((cbor::int(HDR_KID), cbor::bytes(&key.public().thumbprint())));
    }
    if let Some(t) = &extra.typ {
        prot.push((cbor::int(HDR_TYP), cbor::text(t)));
    }
    if let Some(chain) = &extra.x5chain {
        let v = if chain.len() == 1 {
            cbor::bytes(&chain[0])
        } else {
            Value::Array(chain.iter().map(|c| cbor::bytes(c)).collect())
        };
        prot.push((cbor::int(HDR_X5CHAIN), v));
    }
    if let Some(c) = &extra.scc_cred {
        prot.push((cbor::text(HDR_SCC_CRED), cbor::bytes(c)));
    }
    let prot_bytes = cbor::encode(&Value::Map(prot));
    let header = coset::Header::from_cbor_value(cbor::decode(&prot_bytes).unwrap())
        .expect("valid header");
    let protected = ProtectedHeader { original_data: Some(prot_bytes.clone()), header };
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        protected.clone(),
        None,
        b"",
        payload,
    );
    let signature = key.sign(&tbs);
    // Encode the outer array ourselves: [protected, {}, payload, signature].
    let arr = Value::Array(vec![
        Value::Bytes(prot_bytes),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature),
    ]);
    let v = if tagged { Value::Tag(18, Box::new(arr)) } else { arr };
    cbor::encode(&v)
}

/// A parsed COSE_Sign1.
#[derive(Clone, Debug)]
pub struct Sign1 {
    pub raw: Vec<u8>,
    pub tagged: bool,
    pub protected_bytes: Vec<u8>,
    pub protected: Vec<(Value, Value)>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    inner: CoseSign1,
}

impl Sign1 {
    /// Parse a COSE_Sign1 (tagged or untagged). Requires the whole object,
    /// its protected header and its payload to be deterministically
    /// encoded, and the unprotected header to be empty.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if !cbor::is_deterministic(raw) {
            bail!("COSE_Sign1 is not deterministically encoded");
        }
        let tagged = matches!(cbor::decode(raw)?, Value::Tag(18, _));
        let inner = if tagged {
            CoseSign1::from_tagged_slice(raw)
        } else {
            CoseSign1::from_slice(raw)
        }
        .map_err(|e| anyhow!("bad COSE_Sign1: {e:?}"))?;
        let protected_bytes = inner
            .protected
            .original_data
            .clone()
            .ok_or_else(|| anyhow!("missing protected header bytes"))?;
        let protected = match cbor::decode_deterministic(&protected_bytes)? {
            Value::Map(m) => m,
            _ => bail!("protected header is not a map"),
        };
        if !inner.unprotected.is_empty() {
            bail!("unprotected header must be empty");
        }
        let payload = inner.payload.clone().ok_or_else(|| anyhow!("detached payload"))?;
        if !cbor::is_deterministic(&payload) {
            bail!("payload is not deterministically encoded");
        }
        Ok(Sign1 {
            raw: raw.to_vec(),
            tagged,
            protected_bytes,
            protected,
            signature: inner.signature.clone(),
            payload,
            inner,
        })
    }

    pub fn alg(&self) -> Option<i64> {
        cbor::map_int(&self.protected, HDR_ALG).and_then(|v| cbor::as_i64(v).ok())
    }

    pub fn kid(&self) -> Option<Vec<u8>> {
        cbor::map_int(&self.protected, HDR_KID).and_then(|v| v.as_bytes().cloned())
    }

    pub fn typ(&self) -> Option<String> {
        cbor::map_int(&self.protected, HDR_TYP).and_then(|v| v.as_text().map(|s| s.to_string()))
    }

    pub fn x5chain(&self) -> Vec<Vec<u8>> {
        match cbor::map_int(&self.protected, HDR_X5CHAIN) {
            Some(Value::Bytes(b)) => vec![b.clone()],
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_bytes().cloned()).collect(),
            _ => vec![],
        }
    }

    pub fn scc_cred(&self) -> Option<Vec<u8>> {
        cbor::map_text(&self.protected, HDR_SCC_CRED).and_then(|v| v.as_bytes().cloned())
    }

    pub fn payload_value(&self) -> Result<Value> {
        cbor::decode(&self.payload)
    }

    /// Verify the signature with `key`. Checks that `alg` matches the key.
    pub fn verify(&self, key: &CoseKey) -> Result<()> {
        let alg = self.alg().ok_or_else(|| anyhow!("no alg in protected header"))?;
        if alg != key.alg() {
            bail!("alg {alg} does not match the key");
        }
        let tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            self.inner.protected.clone(),
            None,
            b"",
            &self.payload,
        );
        key.verify(&tbs, &self.signature)
    }

    /// Verify with the key among `keys` whose thumbprint equals `kid`.
    /// Returns the index of that key.
    pub fn verify_kid(&self, keys: &[CoseKey]) -> Result<usize> {
        let kid = self.kid().ok_or_else(|| anyhow!("no kid in protected header"))?;
        let idx = keys
            .iter()
            .position(|k| k.thumbprint() == kid)
            .ok_or_else(|| anyhow!("kid names no allowed key"))?;
        self.verify(&keys[idx])?;
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_both_algs() {
        for key in [PrivateKey::generate_ed25519(), PrivateKey::generate_p256()] {
            let payload = cbor::encode(&Value::Map(vec![(cbor::text("a"), cbor::int(1))]));
            let s = sign1(&key, &payload, &ExtraHeaders::scc_cred(b"cred"), false);
            let p = Sign1::parse(&s).unwrap();
            assert_eq!(p.payload, payload);
            assert_eq!(p.scc_cred().unwrap(), b"cred");
            assert_eq!(p.verify_kid(&[key.public()]).unwrap(), 0);
            let k2 = PrivateKey::generate_ed25519();
            assert!(p.verify(&k2.public()).is_err());
            let back = PrivateKey::from_json(&key.to_json()).unwrap();
            assert_eq!(back.public(), key.public());
        }
    }

    #[test]
    fn tagged() {
        let key = PrivateKey::generate_ed25519();
        let s = sign1(&key, &cbor::encode(&cbor::int(5)), &ExtraHeaders::default(), true);
        let p = Sign1::parse(&s).unwrap();
        assert!(p.tagged);
        p.verify(&key.public()).unwrap();
    }
}
