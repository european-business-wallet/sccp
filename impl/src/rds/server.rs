//! HTTPS and WebSocket server of an RDS: RDS metadata (§3), the endpoint
//! WebSocket (§4.1), the federation endpoint (§4.3), and status list
//! hosting (02-credentials.md §5.3).

use super::endpoint_api::Conn;
use super::Rds;
use crate::credential::{StatusListToken, STATUSLIST_TYP};
use crate::rpc::{self, Message, RpcError};
use axum::body::Bytes;
use axum::extract::ws::{self, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;

type St = Arc<Rds>;

pub fn router(rds: Arc<Rds>) -> Router {
    Router::new()
        .route(rds.metadata_path(), get(metadata))
        .route("/scc", get(ws_upgrade))
        .route("/scc/federation", post(federation))
        .route("/status/{id}", get(status_get).post(status_put))
        .route("/admin/partition", post(admin_partition))
        .with_state(rds)
}

/// Run the expiry timer (§7.3, §7.4).
pub fn spawn_timers(rds: Arc<Rds>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            rds.expire().await;
        }
    });
}

async fn metadata(State(rds): State<St>) -> Response {
    ([(header::CACHE_CONTROL, "max-age=86400")], axum::Json(rds.metadata())).into_response()
}

async fn federation(State(rds): State<St>, headers: HeaderMap, axum::Json(m): axum::Json<Message>) -> Response {
    let caller = headers.get(rpc::RDS_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let r = match (&m.method, caller.is_empty()) {
        (_, true) => Err(RpcError::unauthorized("unidentified peer")),
        (Some(method), false) => rds.handle_federation(&caller, method, m.params.clone().unwrap_or_default()).await,
        (None, false) => Err(RpcError::new(rpc::E_INVALID_REQUEST, "not a request")),
    };
    if let Err(e) = &r {
        tracing::info!("federation {} from {caller}: error {} {}", m.method.as_deref().unwrap_or("?"), e.code, e.message);
    }
    axum::Json(Message::response(m.id, r)).into_response()
}

#[derive(serde::Deserialize)]
struct PartitionReq {
    peer: String,
    unreachable: bool,
}

/// DEMO ONLY: treat a peer as unreachable, or reachable again, to simulate
/// a network partition.
async fn admin_partition(State(rds): State<St>, axum::Json(r): axum::Json<PartitionReq>) -> Response {
    let mut p = rds.partitioned.lock().unwrap();
    if r.unreachable {
        p.insert(r.peer.clone());
    } else {
        p.remove(&r.peer);
    }
    tracing::info!("demo partition: {} {}", r.peer, if r.unreachable { "unreachable" } else { "reachable" });
    StatusCode::NO_CONTENT.into_response()
}

async fn ws_upgrade(State(rds): State<St>, ws: WebSocketUpgrade) -> Response {
    ws.protocols(["scc.v1"]).on_upgrade(move |socket| serve_ws(rds, socket))
}

async fn serve_ws(rds: St, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(t) = rx.recv().await {
            if sink.send(ws::Message::Text(t.into())).await.is_err() {
                break;
            }
        }
    });
    let mut conn = Conn::default();
    while let Some(Ok(msg)) = stream.next().await {
        let text = match msg {
            ws::Message::Text(t) => t.to_string(),
            ws::Message::Close(_) => break,
            _ => continue,
        };
        let m: Message = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let _ = tx.send(Message::response(None, Err(RpcError::new(rpc::E_INVALID_REQUEST, e.to_string()))).to_text());
                continue;
            }
        };
        let Some(method) = m.method.clone() else { continue };
        // Requests on one connection are handled in order.
        let r = rds.handle_endpoint(&mut conn, &method, m.params.unwrap_or_default(), &tx).await;
        if let Err(e) = &r {
            tracing::info!("{method}: error {} {}", e.code, e.message);
        }
        if m.id.is_some() {
            let _ = tx.send(Message::response(m.id, r).to_text());
        }
    }
    if let Some(k) = &conn.endpoint {
        rds.unregister_conn(k, &tx);
    }
}

async fn status_get(State(rds): State<St>, Path(id): Path<String>) -> Response {
    let uri = format!("{}/status/{id}", rds.origin());
    match rds.status_store.read().unwrap().get(&uri) {
        Some(t) => ([(header::CONTENT_TYPE, STATUSLIST_TYP)], t.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Accept a new status list token for an owner served here. The token is
/// signed by the owner's credential key, so no other authentication is
/// needed.
async fn status_put(State(rds): State<St>, Path(id): Path<String>, body: Bytes) -> Response {
    let uri = format!("{}/status/{id}", rds.origin());
    let r: anyhow::Result<()> = async {
        let tok = StatusListToken::parse(&body)?;
        if tok.claims.sub != uri {
            anyhow::bail!("token names {}, not {uri}", tok.claims.sub);
        }
        let st = rds.resolver.resolve(&tok.claims.iss).await?;
        if st.document.rds != rds.cfg.url {
            anyhow::bail!("{} is not served here", tok.claims.iss);
        }
        tok.verify(&st.document, crate::util::now())?;
        let mut store = rds.status_store.write().unwrap();
        if let Some(old) = store.get(&uri) {
            if StatusListToken::parse(old)?.claims.iat > tok.claims.iat {
                anyhow::bail!("an newer token is already published");
            }
        }
        store.insert(uri.clone(), body.to_vec());
        Ok(())
    }
    .await;
    match r {
        Ok(()) => {
            rds.resolver.forget_status(&uri);
            rds.forget_subjects();
            tracing::info!("status list {uri} updated");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:#}")).into_response(),
    }
}
