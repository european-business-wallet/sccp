//! Resolution of registry documents (from the EDD) and status list tokens (over
//! HTTPS), with caching that follows each object's own validity
//! (01-discovery.md §7, 02-credentials.md §5.3).

use crate::credential::StatusListToken;
use crate::registry::ResolvedDocument;
use crate::edd::EddClient;
use crate::util::now;
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Status list tokens hosted locally (by an RDS), by URI.
pub type LocalStatusStore = Arc<RwLock<HashMap<String, Vec<u8>>>>;

pub struct Resolver {
    pub edd: EddClient,
    http: reqwest::Client,
    states: Mutex<HashMap<String, ResolvedDocument>>,
    statuses: Mutex<HashMap<String, (StatusListToken, u64)>>,
    pub local_status: Option<LocalStatusStore>,
    handle: Option<tokio::runtime::Handle>,
}

impl Resolver {
    pub fn new(edd: EddClient, local_status: Option<LocalStatusStore>) -> Result<Self> {
        Ok(Resolver {
            edd,
            http: crate::net::http_client()?,
            states: Mutex::new(HashMap::new()),
            statuses: Mutex::new(HashMap::new()),
            local_status,
            handle: tokio::runtime::Handle::try_current().ok(),
        })
    }

    /// The current registry document and head statement. Cached for as long
    /// as the EDD status list shows the head statement current
    /// (01-discovery.md §5.3).
    pub async fn resolve(&self, owner: &str) -> Result<ResolvedDocument> {
        let cached = self.states.lock().unwrap().get(owner).cloned();
        if let Some(s) = cached {
            if self.check_current(&s).await.is_ok() {
                return Ok(s);
            }
        }
        let s = self.edd.resolve(owner).await?;
        if self.check_current(&s).await.is_err() {
            // The cached status list may predate this head statement.
            self.forget_status(&s.head.body.status_list.uri);
            self.check_current(&s).await?;
        }
        self.states.lock().unwrap().insert(owner.into(), s.clone());
        Ok(s)
    }

    /// Check that the EDD status list shows `s`'s head statement current.
    async fn check_current(&self, s: &ResolvedDocument) -> Result<()> {
        let tok = self.status(&s.head.body.status_list.uri).await?;
        s.head.check_current(&tok, &self.edd.trust, now())
    }

    /// A status list token that is valid now, fetched within its `ttl`.
    pub async fn status(&self, uri: &str) -> Result<StatusListToken> {
        let t = now();
        if let Some((tok, fetched)) = self.statuses.lock().unwrap().get(uri) {
            let fresh = tok.claims.ttl.map(|ttl| t < fetched + ttl).unwrap_or(true);
            if fresh && t + 5 < tok.claims.exp {
                return Ok(tok.clone());
            }
        }
        let raw = match self.local_status.as_ref().and_then(|l| l.read().unwrap().get(uri).cloned()) {
            Some(r) => r,
            None => {
                let r = self.http.get(uri).send().await.map_err(|e| anyhow!("fetching {uri}: {e}"))?;
                if !r.status().is_success() {
                    bail!("fetching status list {uri}: {}", r.status());
                }
                r.bytes().await?.to_vec()
            }
        };
        let tok = StatusListToken::parse(&raw)?;
        if tok.claims.sub != uri {
            bail!("status list token at {uri} names {}", tok.claims.sub);
        }
        if tok.claims.iss.starts_with("ebw:") {
            let st = Box::pin(self.resolve(&tok.claims.iss)).await?;
            tok.verify(&st.document, t)?;
        } else {
            tok.verify_edd(&self.edd.trust, t)?;
        }
        self.statuses.lock().unwrap().insert(uri.into(), (tok.clone(), t));
        Ok(tok)
    }

    pub fn resolve_blocking(&self, owner: &str) -> Result<ResolvedDocument> {
        block(self.handle.as_ref(), self.resolve(owner))
    }

    pub fn status_blocking(&self, uri: &str) -> Result<StatusListToken> {
        block(self.handle.as_ref(), self.status(uri))
    }

    /// Forget a cached status list (after the owner publishes a new one).
    pub fn forget_status(&self, uri: &str) {
        self.statuses.lock().unwrap().remove(uri);
    }
}

/// Run a future to completion from synchronous code inside a
/// multi-threaded tokio runtime (used by the MLS identity provider).
fn block<F: std::future::Future<Output = Result<T>>, T>(fallback: Option<&tokio::runtime::Handle>, f: F) -> Result<T> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) => tokio::task::block_in_place(|| h.block_on(f)),
        // A thread outside the runtime (for example a worker of mls-rs).
        Err(_) => fallback.ok_or_else(|| anyhow!("no async runtime for resolution"))?.block_on(f),
    }
}
