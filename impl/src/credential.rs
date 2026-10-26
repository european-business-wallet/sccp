//! Endpoint credentials, credential requests, connection proofs and status
//! list tokens (02-credentials.md, 04-delivery.md §4.1).

use crate::cbor::{self, Value};
use crate::cose::{self, CoseKey, ExtraHeaders, PrivateKey, Sign1};
use crate::registry::RegistryDocument;
use crate::types::{check_ebw_url, check_role, check_subject, EndpointRef};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::io::{Read, Write};

pub const CLAIM_ISS: i64 = 1;
pub const CLAIM_SUB: i64 = 2;
pub const CLAIM_EXP: i64 = 4;
pub const CLAIM_NBF: i64 = 5;
pub const CLAIM_IAT: i64 = 6;
pub const CLAIM_CNF: i64 = 8;
pub const CLAIM_TTL: i64 = 65534;
pub const CLAIM_STATUS_LIST: i64 = 65533;
pub const CLAIM_STATUS: i64 = 65535;

pub const STATUS_VALID: u8 = 0;
pub const STATUS_INVALID: u8 = 1;
pub const STATUS_SUSPENDED: u8 = 2;

/// The claims of an endpoint credential (§2).
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointClaims {
    pub iss: String,
    pub sub: String,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub cnf: CoseKey,
    pub status_idx: u64,
    pub status_uri: String,
    pub roles: Vec<String>,
    pub holder: Option<String>,
}

impl EndpointClaims {
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (cbor::int(CLAIM_ISS), cbor::text(&self.iss)),
            (cbor::int(CLAIM_SUB), cbor::text(&self.sub)),
            (cbor::int(CLAIM_EXP), cbor::int(self.exp as i64)),
            (cbor::int(CLAIM_NBF), cbor::int(self.nbf as i64)),
            (cbor::int(CLAIM_IAT), cbor::int(self.iat as i64)),
            (cbor::int(CLAIM_CNF), Value::Map(vec![(cbor::int(1), self.cnf.to_value())])),
            (
                cbor::int(CLAIM_STATUS),
                Value::Map(vec![(
                    cbor::text("status_list"),
                    Value::Map(vec![
                        (cbor::text("idx"), cbor::int(self.status_idx as i64)),
                        (cbor::text("uri"), cbor::text(&self.status_uri)),
                    ]),
                )]),
            ),
            (cbor::text("roles"), Value::Array(self.roles.iter().map(|r| cbor::text(r)).collect())),
        ];
        if let Some(h) = &self.holder {
            m.push((cbor::text("holder"), cbor::text(h)));
        }
        Value::Map(m)
    }

    pub fn from_value(v: &Value) -> Result<Self> {
        let m = cbor::as_map(v)?;
        let get = |k: i64| cbor::map_int(m, k).ok_or_else(|| anyhow!("credential lacks claim {k}"));
        let cnf = cbor::as_map(get(CLAIM_CNF)?)?;
        let cnf = CoseKey::from_value(cbor::map_int(cnf, 1).ok_or_else(|| anyhow!("cnf without COSE_Key"))?)?;
        let status = cbor::as_map(get(CLAIM_STATUS)?)?;
        let sl = cbor::as_map(cbor::map_text(status, "status_list").ok_or_else(|| anyhow!("status without status_list"))?)?;
        let idx = cbor::as_u64(cbor::map_text(sl, "idx").ok_or_else(|| anyhow!("status_list without idx"))?)?;
        let uri = cbor::as_text(cbor::map_text(sl, "uri").ok_or_else(|| anyhow!("status_list without uri"))?)?;
        if !uri.starts_with("https://") {
            bail!("status list uri must be https");
        }
        let roles: Vec<String> = match cbor::map_text(m, "roles") {
            Some(Value::Array(a)) => a.iter().map(|r| cbor::as_text(r).map(|s| s.to_string())).collect::<Result<_>>()?,
            _ => bail!("credential lacks roles"),
        };
        if roles.is_empty() {
            bail!("credential has no roles");
        }
        for r in &roles {
            check_role(r)?;
        }
        let mut uniq = roles.clone();
        uniq.sort();
        uniq.dedup();
        if uniq.len() != roles.len() {
            bail!("duplicate roles");
        }
        let holder = match cbor::map_text(m, "holder") {
            Some(h) => Some(cbor::as_text(h)?.to_string()),
            None => None,
        };
        if let Some(h) = &holder {
            if h.is_empty() || h.len() > 64 {
                bail!("bad holder");
            }
        }
        let expected = 8 + holder.is_some() as usize;
        if m.len() != expected {
            bail!("unexpected claims in credential");
        }
        let c = EndpointClaims {
            iss: cbor::as_text(get(CLAIM_ISS)?)?.into(),
            sub: cbor::as_text(get(CLAIM_SUB)?)?.into(),
            exp: cbor::as_u64(get(CLAIM_EXP)?)?,
            nbf: cbor::as_u64(get(CLAIM_NBF)?)?,
            iat: cbor::as_u64(get(CLAIM_IAT)?)?,
            cnf,
            status_idx: idx,
            status_uri: uri.into(),
            roles,
            holder,
        };
        check_ebw_url(&c.iss)?;
        check_subject(&c.sub)?;
        Ok(c)
    }

    /// The holder, or the endpoint itself if no holder is given (§2).
    pub fn holder_id(&self) -> String {
        self.holder.clone().unwrap_or_else(|| format!("endpoint:{}", self.sub))
    }

    pub fn endpoint_ref(&self) -> EndpointRef {
        EndpointRef { owner: self.iss.clone(), subject: self.sub.clone() }
    }
}

/// A parsed endpoint credential.
#[derive(Clone, Debug)]
pub struct Credential {
    pub raw: Vec<u8>,
    pub cose: Sign1,
    pub claims: EndpointClaims,
}

impl Credential {
    pub fn issue(credential_key: &PrivateKey, claims: &EndpointClaims) -> Credential {
        let raw = cose::sign1(credential_key, &cbor::encode(&claims.to_value()), &ExtraHeaders::default(), false);
        Credential::parse(&raw).expect("own credential parses")
    }

    /// §3 step 1.
    pub fn parse(raw: &[u8]) -> Result<Credential> {
        let cose = Sign1::parse(raw)?;
        if cose.tagged {
            bail!("credential must not be tagged");
        }
        let claims = EndpointClaims::from_value(&cose.payload_value()?)?;
        Ok(Credential { raw: raw.to_vec(), cose, claims })
    }

    /// §3 steps 3 to 5, against the registry document in force at `t`.
    pub fn verify_signature_and_time(&self, state: &RegistryDocument, t: u64) -> Result<()> {
        self.cose.verify_kid(&state.credential_keys).map_err(|e| anyhow!("credential signature: {e}"))?;
        if t < self.claims.nbf || t >= self.claims.exp {
            bail!("credential of {} not valid at {}", self.claims.sub, crate::util::fmt_time(t));
        }
        Ok(())
    }

    /// §3 step 6: check the status in a status list token.
    pub fn check_status(&self, token: &StatusListToken, state: &RegistryDocument, t: u64) -> Result<()> {
        token.verify(state, t)?;
        if token.claims.iss != self.claims.iss || token.claims.sub != self.claims.status_uri {
            bail!("status list token is not the one named by the credential");
        }
        match token.status(self.claims.status_idx)? {
            STATUS_VALID => Ok(()),
            STATUS_INVALID => bail!("credential of {} is revoked", self.claims.sub),
            STATUS_SUSPENDED => bail!("credential of {} is suspended", self.claims.sub),
            s => bail!("credential of {} has status {s}", self.claims.sub),
        }
    }

    /// The full check of §3.
    pub fn verify(&self, state: &RegistryDocument, t: u64, token: &StatusListToken) -> Result<()> {
        self.verify_signature_and_time(state, t)?;
        self.check_status(token, state, t)
    }
}

// ---- Status list tokens (§5.3) ----

#[derive(Clone, Debug, PartialEq)]
pub struct StatusListClaims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub nbf: Option<u64>,
    pub ttl: Option<u64>,
    pub bits: u8,
    pub lst: Vec<u8>,
}

impl StatusListClaims {
    fn to_value(&self) -> Value {
        let mut m = vec![
            (cbor::int(CLAIM_ISS), cbor::text(&self.iss)),
            (cbor::int(CLAIM_SUB), cbor::text(&self.sub)),
            (cbor::int(CLAIM_IAT), cbor::int(self.iat as i64)),
            (cbor::int(CLAIM_EXP), cbor::int(self.exp as i64)),
            (
                cbor::int(CLAIM_STATUS_LIST),
                Value::Map(vec![
                    (cbor::text("bits"), cbor::int(self.bits as i64)),
                    (cbor::text("lst"), cbor::bytes(&self.lst)),
                ]),
            ),
        ];
        if let Some(n) = self.nbf {
            m.push((cbor::int(CLAIM_NBF), cbor::int(n as i64)));
        }
        if let Some(t) = self.ttl {
            m.push((cbor::int(CLAIM_TTL), cbor::int(t as i64)));
        }
        Value::Map(m)
    }

    fn from_value(v: &Value) -> Result<Self> {
        let m = cbor::as_map(v)?;
        let get = |k: i64| cbor::map_int(m, k).ok_or_else(|| anyhow!("status list token lacks claim {k}"));
        let sl = cbor::as_map(get(CLAIM_STATUS_LIST)?)?;
        let bits = cbor::as_u64(cbor::map_text(sl, "bits").ok_or_else(|| anyhow!("no bits"))?)?;
        if bits != 1 && bits != 2 {
            bail!("bits must be 1 or 2");
        }
        Ok(StatusListClaims {
            iss: cbor::as_text(get(CLAIM_ISS)?)?.into(),
            sub: cbor::as_text(get(CLAIM_SUB)?)?.into(),
            iat: cbor::as_u64(get(CLAIM_IAT)?)?,
            exp: cbor::as_u64(get(CLAIM_EXP)?)?,
            nbf: cbor::map_int(m, CLAIM_NBF).map(cbor::as_u64).transpose()?,
            ttl: cbor::map_int(m, CLAIM_TTL).map(cbor::as_u64).transpose()?,
            bits: bits as u8,
            lst: cbor::as_bytes(cbor::map_text(sl, "lst").ok_or_else(|| anyhow!("no lst"))?)?.clone(),
        })
    }
}

/// A status list token: a tagged CWT signed by a credential key.
#[derive(Clone, Debug)]
pub struct StatusListToken {
    pub raw: Vec<u8>,
    pub cose: Sign1,
    pub claims: StatusListClaims,
    statuses: Vec<u8>,
}

pub const STATUSLIST_TYP: &str = "application/statuslist+cwt";

/// Pack statuses, `bits` per entry, least significant bits first, and
/// compress with ZLIB (draft-ietf-oauth-status-list §4).
pub fn pack_statuses(statuses: &[u8], bits: u8) -> Vec<u8> {
    let per = 8 / bits as usize;
    let mut raw = vec![0u8; statuses.len().div_ceil(per).max(1)];
    for (i, s) in statuses.iter().enumerate() {
        raw[i / per] |= (s & ((1 << bits) - 1)) << ((i % per) * bits as usize);
    }
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap()
}

impl StatusListToken {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        credential_key: &PrivateKey,
        owner: &str,
        uri: &str,
        statuses: &[u8],
        iat: u64,
        exp: u64,
        ttl: Option<u64>,
    ) -> StatusListToken {
        let bits = if statuses.iter().any(|s| *s > 1) { 2 } else { 1 };
        let claims = StatusListClaims {
            iss: owner.into(),
            sub: uri.into(),
            iat,
            exp,
            nbf: Some(iat),
            ttl,
            bits,
            lst: pack_statuses(statuses, bits),
        };
        let raw = cose::sign1(
            credential_key,
            &cbor::encode(&claims.to_value()),
            &ExtraHeaders { typ: Some(STATUSLIST_TYP.into()), ..Default::default() },
            true,
        );
        StatusListToken::parse(&raw).expect("own token parses")
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        if !cose.tagged {
            bail!("status list token must be tagged (tag 18)");
        }
        if cose.typ().as_deref() != Some(STATUSLIST_TYP) {
            bail!("status list token has wrong typ");
        }
        let claims = StatusListClaims::from_value(&cose.payload_value()?)?;
        let mut statuses = Vec::new();
        flate2::read::ZlibDecoder::new(&claims.lst[..])
            .read_to_end(&mut statuses)
            .map_err(|e| anyhow!("bad status list compression: {e}"))?;
        Ok(StatusListToken { raw: raw.to_vec(), cose, claims, statuses })
    }

    /// Check the signature against the registry document's credential keys and that
    /// the token is valid at `t`.
    pub fn verify(&self, state: &RegistryDocument, t: u64) -> Result<()> {
        self.cose
            .verify_kid(&state.credential_keys)
            .map_err(|e| anyhow!("status list token signature: {e}"))?;
        let nbf = self.claims.nbf.unwrap_or(self.claims.iat);
        if t < nbf || t >= self.claims.exp || t < self.claims.iat {
            bail!("status list token {} not valid at {}", self.claims.sub, crate::util::fmt_time(t));
        }
        Ok(())
    }

    /// The status at `idx`.
    pub fn status(&self, idx: u64) -> Result<u8> {
        let bits = self.claims.bits as usize;
        let per = 8 / bits;
        let byte = self
            .statuses
            .get(idx as usize / per)
            .ok_or_else(|| anyhow!("index {idx} beyond the status list"))?;
        Ok((byte >> ((idx as usize % per) * bits)) & ((1 << bits) - 1) as u8)
    }
}

// ---- Credential request (§5.1) and connection proof (doc 4 §4.1) ----

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequestBody {
    #[serde(rename = "type")]
    pub st_type: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<String>,
    pub roles: Vec<String>,
    pub key: CoseKey,
    pub nonce: ByteBuf,
}

impl CredentialRequestBody {
    pub fn sign(&self, key: &PrivateKey) -> Vec<u8> {
        cose::sign1(key, &cbor::to_vec(self).unwrap(), &ExtraHeaders::default(), false)
    }

    /// Parse a request and check that it is signed by the key it carries.
    pub fn parse_and_verify(raw: &[u8]) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        let body: CredentialRequestBody = cbor::from_slice(&cose.payload)?;
        if body.st_type != "credential-request" {
            bail!("not a credential request");
        }
        if !(16..=32).contains(&body.nonce.len()) {
            bail!("nonce must be 16 to 32 bytes");
        }
        cose.verify(&body.key)?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectProofBody {
    #[serde(rename = "type")]
    pub st_type: String,
    pub challenge: ByteBuf,
    pub rds: String,
    pub owner: String,
    pub subject: String,
    pub signed_at: u64,
}

impl ConnectProofBody {
    pub fn sign(&self, key: &PrivateKey) -> Vec<u8> {
        cose::sign1(key, &cbor::to_vec(self).unwrap(), &ExtraHeaders::default(), false)
    }

    pub fn parse_and_verify(raw: &[u8], key: &CoseKey) -> Result<Self> {
        let cose = Sign1::parse(raw)?;
        cose.verify(key)?;
        let body: ConnectProofBody = cbor::from_slice(&cose.payload)?;
        if body.st_type != "connect-proof" {
            bail!("not a connect proof");
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_list_roundtrip() {
        let k = PrivateKey::generate_ed25519();
        let owner = "ebw:bo6frcnfdr54irr3eybahmh6";
        let t = StatusListToken::build(&k, owner, "https://x/1", &[0, 0, 0, 1, 0, 2, 0, 0], 100, 200, Some(10));
        assert_eq!(t.claims.bits, 2);
        assert_eq!(t.status(3).unwrap(), 1);
        assert_eq!(t.status(5).unwrap(), 2);
        assert_eq!(t.status(4).unwrap(), 0);
        let t1 = StatusListToken::build(&k, owner, "https://x/1", &[0, 1, 0, 0, 0, 0, 0, 0, 1], 100, 200, None);
        assert_eq!(t1.claims.bits, 1);
        assert_eq!(t1.status(8).unwrap(), 1);
        assert_eq!(t1.status(1).unwrap(), 1);
        assert_eq!(t1.status(2).unwrap(), 0);
    }
}
