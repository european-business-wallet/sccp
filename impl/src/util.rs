//! Small helpers: hashing, base64url, time, randomness, file I/O.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;

/// SHA-256.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// base64url without padding (RFC 4648 §5), as used in JSON.
pub fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64u_dec(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| anyhow!("bad base64url: {e}"))
}

/// Standard base64 (for x5c in JSON documents).
pub fn b64std(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64std_dec(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("bad base64: {e}"))
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

/// A fresh opaque subject ID: 16 random bytes, base64url (02-credentials.md §2).
pub fn random_subject() -> String {
    b64u(&random_bytes(16))
}

/// Serde helper: `Vec<u8>` as base64url string in JSON.
pub mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::b64u(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::b64u_dec(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper: `Option<Vec<u8>>` as base64url string in JSON.
pub mod b64opt {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&super::b64u(v)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| super::b64u_dec(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Serde helper: `Vec<Vec<u8>>` as an array of base64url strings.
pub mod b64vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(|x| super::b64u(x)).collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter()
            .map(|s| super::b64u_dec(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

pub fn write_file(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

pub fn write_json<T: serde::Serialize>(path: impl AsRef<Path>, v: &T) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(v)?;
    data.push(b'\n');
    write_file(path, data)
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let data = read_file(path.as_ref())?;
    serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.as_ref().display()))
}

/// Lowercase base32 without padding (RFC 4648), used for EBW URLs.
pub fn base32_lower(data: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(data).to_lowercase()
}

/// Format a time as RFC 3339 (for human-readable output).
pub fn fmt_time(t: u64) -> String {
    let secs = t as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Set up logging to stderr (RUST_LOG overrides the default `info`).
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
