//! JSON-RPC 2.0 (04-delivery.md §2): message types, error codes, the
//! WebSocket client used by endpoints, and the HTTPS client used between
//! RDSes.

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

// ---- Error codes (§2.1) ----

pub const E_INVALID_REQUEST: i64 = -32600;
pub const E_METHOD_NOT_FOUND: i64 = -32601;
pub const E_INVALID_PARAMS: i64 = -32602;
pub const E_INTERNAL: i64 = -32603;
/// A federation peer could not be reached (implementation-defined).
pub const E_PEER_UNREACHABLE: i64 = -32000;
pub const E_NOT_AUTHORIZED: i64 = -31002;
pub const E_MLS: i64 = -31004;
pub const E_RATE_LIMITED: i64 = -31007;
pub const E_QUEUE_FULL: i64 = -31014;
pub const E_CONSIGNMENT_UNSUPPORTED: i64 = -31016;
pub const E_MEMBERSHIP_MISMATCH: i64 = -31100;
pub const E_STALE_EPOCH: i64 = -31101;
pub const E_COMMIT_CONFLICT: i64 = -31102;
pub const E_UNKNOWN_SESSION: i64 = -31103;
pub const E_SESSION_CLOSED: i64 = -31104;
pub const E_NO_KEYPACKAGE: i64 = -31105;
pub const E_INVALID_CREDENTIAL: i64 = -31106;
pub const E_DUPLICATE_MESSAGE_ID: i64 = -31107;
pub const E_BAD_TIME: i64 = -31108;
pub const E_OWNER_NOT_ACTIVE: i64 = -31109;
pub const E_UNKNOWN_ADDRESS: i64 = -31110;
pub const E_WRONG_RDS: i64 = -31111;
pub const E_EVIDENCE_INCOMPLETE: i64 = -31112;

/// A JSON-RPC error object.
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
#[error("JSON-RPC error {code}: {message}")]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into(), data: None }
    }
    pub fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        RpcError { code, message: message.into(), data: Some(data) }
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        RpcError::new(E_INTERNAL, e.to_string())
    }
    pub fn params(e: impl std::fmt::Display) -> Self {
        RpcError::new(E_INVALID_PARAMS, e.to_string())
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        RpcError::new(E_NOT_AUTHORIZED, m)
    }
    pub fn mls(e: impl std::fmt::Display) -> Self {
        RpcError::new(E_MLS, e.to_string())
    }
    /// The evidence carried in `data.evidence`, if any.
    pub fn evidence(&self) -> Option<Vec<u8>> {
        self.data
            .as_ref()
            .and_then(|d| d.get("evidence"))
            .and_then(|e| e.as_str())
            .and_then(|s| crate::util::b64u_dec(s).ok())
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<RpcError>() {
            Ok(r) => r,
            Err(e) => RpcError::internal(format!("{e:#}")),
        }
    }
}

pub type RpcResult<T = Value> = std::result::Result<T, RpcError>;

/// Parse JSON-RPC params into a type.
pub fn params<T: serde::de::DeserializeOwned>(v: Value) -> RpcResult<T> {
    serde_json::from_value(v).map_err(RpcError::params)
}

pub fn to_value<T: Serialize>(t: &T) -> Value {
    serde_json::to_value(t).expect("serializable")
}

/// A JSON-RPC message of any kind.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Message {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<RpcError>,
}

impl Message {
    pub fn request(id: &str, method: &str, params: Value) -> Self {
        Message { jsonrpc: "2.0".into(), id: Some(json!(id)), method: Some(method.into()), params: Some(params), ..Default::default() }
    }
    pub fn notification(method: &str, params: Value) -> Self {
        Message { jsonrpc: "2.0".into(), method: Some(method.into()), params: Some(params), ..Default::default() }
    }
    pub fn response(id: Option<Value>, r: RpcResult) -> Self {
        let mut m = Message { jsonrpc: "2.0".into(), id: Some(id.unwrap_or(Value::Null)), ..Default::default() };
        match r {
            Ok(v) => m.result = Some(v),
            Err(e) => m.error = Some(e),
        }
        m
    }
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).expect("serializable")
    }
}

// ---- WebSocket client (endpoint side, §4.1) ----

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<RpcResult>>>>;

/// A JSON-RPC client over WebSocket. Responses are matched to requests by
/// id; notifications from the RDS arrive on `notifications`.
pub struct WsClient {
    out: mpsc::UnboundedSender<String>,
    pending: Pending,
    next: AtomicU64,
    pub notifications: mpsc::UnboundedReceiver<(String, Value)>,
}

impl WsClient {
    pub async fn connect(url: &str) -> Result<Self> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url.into_client_request()?;
        req.headers_mut().insert("Sec-WebSocket-Protocol", "scc.v1".parse()?);
        let connector = tokio_tungstenite::Connector::Rustls(crate::net::tls_client_config()?);
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow!("connecting to {url}: {e}"))?;
        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let (ntx, nrx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(async move {
            while let Some(t) = out_rx.recv().await {
                if sink.send(tokio_tungstenite::tungstenite::Message::text(t)).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });
        let p2 = pending.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let text = match msg {
                    tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
                    tokio_tungstenite::tungstenite::Message::Close(_) => break,
                    _ => continue,
                };
                let Ok(m) = serde_json::from_str::<Message>(&text) else { continue };
                if let Some(method) = m.method {
                    let _ = ntx.send((method, m.params.unwrap_or(Value::Null)));
                } else if let Some(id) = m.id.as_ref().and_then(|i| i.as_str()) {
                    if let Some(tx) = p2.lock().unwrap().remove(id) {
                        let r = match m.error {
                            Some(e) => Err(e),
                            None => Ok(m.result.unwrap_or(Value::Null)),
                        };
                        let _ = tx.send(r);
                    }
                }
            }
            // Fail every waiting request.
            for (_, tx) in p2.lock().unwrap().drain() {
                let _ = tx.send(Err(RpcError::internal("connection closed")));
            }
        });
        Ok(WsClient { out: out_tx, pending, next: AtomicU64::new(1), notifications: nrx })
    }

    pub async fn call(&self, method: &str, params: Value) -> RpcResult {
        let id = format!("r{}", self.next.fetch_add(1, Ordering::SeqCst));
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        self.out
            .send(Message::request(&id, method, params).to_text())
            .map_err(|_| RpcError::internal("connection closed"))?;
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(RpcError::internal("connection closed")),
            Err(_) => Err(RpcError::internal(format!("{method}: timed out"))),
        }
    }
}

// ---- HTTPS client (RDS to RDS, §4.3) ----

/// Header naming the calling RDS. Stub for mutual TLS (impl/NOTES.md).
pub const PROVIDER_HEADER: &str = "x-scc-provider";

/// Send one JSON-RPC request to a peer RDS.
pub async fn federation_call(http: &reqwest::Client, url: &str, me: &str, method: &str, params: Value) -> RpcResult {
    let id = format!("f-{}", crate::util::b64u(&crate::util::random_bytes(8)));
    let r = http
        .post(url)
        .header(PROVIDER_HEADER, me)
        .json(&Message::request(&id, method, params))
        .send()
        .await
        .map_err(|e| RpcError::new(E_PEER_UNREACHABLE, format!("{method} to {url}: {e}")))?;
    let m: Message = r.json().await.map_err(|e| RpcError::new(E_PEER_UNREACHABLE, format!("{method} to {url}: bad response: {e}")))?;
    match m.error {
        Some(e) => Err(e),
        None => Ok(m.result.unwrap_or(Value::Null)),
    }
}
