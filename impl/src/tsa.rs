//! A stand-in timestamping authority.
//!
//! Stub (impl/NOTES.md): the specification requires a qualified RFC 3161
//! TimeStampToken over the seal. This implementation uses a local TSA key
//! with a self-signed certificate, and its token is a COSE_Sign1 over a
//! small CBOR structure with the message imprint and the time. A verifier
//! checks the signature against a trusted TSA certificate and the imprint
//! against SHA-256 of the seal, which are the checks of 05-evidence.md
//! §2.2 step 4.

use crate::cbor;
use crate::certs::{TrustKind, TrustStore};
use crate::cose::Sign1;
use crate::registry::Sealer;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoTstInfo {
    #[serde(rename = "type")]
    pub st_type: String,
    pub hash_alg: String,
    pub imprint: ByteBuf,
    pub gen_time: u64,
    pub serial: ByteBuf,
}

pub const DEMO_TST_TYPE: &str = "scc-demo-timestamp-token";

/// Issue a demo timestamp token over `data` (the encoded seal).
pub fn timestamp(tsa: &Sealer, data: &[u8], t: u64) -> Vec<u8> {
    let info = DemoTstInfo {
        st_type: DEMO_TST_TYPE.into(),
        hash_alg: "sha-256".into(),
        imprint: ByteBuf::from(crate::util::sha256(data)),
        gen_time: t,
        serial: ByteBuf::from(crate::util::random_bytes(16)),
    };
    tsa.seal(&cbor::to_vec(&info).unwrap())
}

/// Verify a demo timestamp token over `data`. Returns its time.
pub fn verify_timestamp(token: &[u8], data: &[u8], trust: &TrustStore) -> Result<u64> {
    let cose = Sign1::parse(token)?;
    let info: DemoTstInfo = cbor::from_slice(&cose.payload)?;
    if info.st_type != DEMO_TST_TYPE || info.hash_alg != "sha-256" {
        bail!("unknown timestamp token format");
    }
    let key = trust.check_chain(&cose.x5chain(), TrustKind::Tsa, info.gen_time)?;
    cose.verify(&key)?;
    if info.imprint.as_slice() != crate::util::sha256(data).as_slice() {
        bail!("timestamp imprint does not match the seal");
    }
    Ok(info.gen_time)
}
