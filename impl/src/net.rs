//! Networking helpers: TLS configuration, HTTP clients, CBOR over HTTP.
//!
//! All components use TLS. The demo uses one demo CA whose certificate is
//! given to clients with the `SCC_TLS_CA` environment variable (a PEM
//! file). Mutual TLS between RDSes is not implemented (impl/NOTES.md).

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;

/// Install the rustls crypto provider (once).
pub fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn ca_pem() -> Result<Option<Vec<u8>>> {
    match std::env::var("SCC_TLS_CA") {
        Ok(p) if !p.is_empty() => Ok(Some(std::fs::read(&p).with_context(|| format!("reading {p}"))?)),
        _ => Ok(None),
    }
}

/// An HTTP client that trusts the demo CA (if configured).
pub fn http_client() -> Result<reqwest::Client> {
    init_crypto();
    let mut b = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    if let Some(pem) = ca_pem()? {
        let cert = reqwest::Certificate::from_pem(&pem)?;
        b = b.tls_certs_only([cert]);
    }
    Ok(b.build()?)
}

/// A rustls client configuration that trusts the demo CA (if configured)
/// or the WebPKI roots.
pub fn tls_client_config() -> Result<Arc<rustls::ClientConfig>> {
    init_crypto();
    let mut roots = rustls::RootCertStore::empty();
    match ca_pem()? {
        Some(pem) => {
            for c in rustls_pemfile_certs(&pem)? {
                roots.add(c)?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()))
}

fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("bad PEM: {e:?}"))
}

/// Server TLS configuration from PEM files.
pub async fn server_tls(cert_pem: &str, key_pem: &str) -> Result<axum_server::tls_rustls::RustlsConfig> {
    init_crypto();
    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_pem, key_pem)
        .await
        .map_err(|e| anyhow!("TLS configuration: {e}"))
}

pub const CBOR: &str = "application/cbor";
pub const PROBLEM: &str = "application/concise-problem-details+cbor";

/// Decode an RFC 9290 problem body into a message.
fn problem_text(body: &[u8]) -> String {
    match crate::cbor::decode(body) {
        Ok(v) => {
            let m = v.as_map().cloned().unwrap_or_default();
            let title = crate::cbor::map_int(&m, -1).and_then(|v| v.as_text().map(String::from)).unwrap_or_default();
            let detail = crate::cbor::map_int(&m, -2).and_then(|v| v.as_text().map(String::from)).unwrap_or_default();
            format!("{title}: {detail}")
        }
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

/// GET a resource's bytes.
pub async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let r = client.get(url).send().await.map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    if !r.status().is_success() {
        anyhow::bail!("GET {url}: {}", r.status());
    }
    Ok(r.bytes().await?.to_vec())
}

pub async fn get_cbor(client: &reqwest::Client, url: &str) -> Result<Option<Vec<u8>>> {
    let r = client.get(url).send().await.with_context(|| format!("GET {url}"))?;
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = r.status();
    let body = r.bytes().await?.to_vec();
    if !status.is_success() {
        bail!("GET {url}: {status}: {}", problem_text(&body));
    }
    Ok(Some(body))
}

pub async fn post_cbor(client: &reqwest::Client, url: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    post_bytes(client, url, CBOR, body).await
}

pub async fn post_bytes(client: &reqwest::Client, url: &str, ctype: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    let r = client
        .post(url)
        .header("content-type", ctype)
        .body(body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = r.status();
    let body = r.bytes().await?.to_vec();
    if !status.is_success() {
        bail!("POST {url}: {status}: {}", problem_text(&body));
    }
    Ok(body)
}

/// Percent-encode a path segment.
pub fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
