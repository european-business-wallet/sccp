//! scc-edd: the European Digital Directory (spec/01-discovery.md §6).

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use scc::edd::{Edd, EddConfig, Problem};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "SCC European Digital Directory")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the EDD's seal key and (self-signed demo) certificate.
    Init {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Run the EDD HTTPS API.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8440")]
        listen: String,
        /// Public base URL of the EDD.
        #[arg(long, default_value = "https://localhost:8440")]
        base_url: String,
        #[arg(long)]
        tls_cert: String,
        #[arg(long)]
        tls_key: String,
        /// Validity of status list tokens for head statements (§5.3), in
        /// seconds.
        #[arg(long, default_value_t = 86400)]
        status_list_validity: u64,
        /// `ttl` of those tokens: how long a client may use one before
        /// fetching it again, in seconds.
        #[arg(long, default_value_t = 5)]
        status_list_ttl: u64,
        /// Recovery window (§3.4), in seconds.
        #[arg(long, default_value_t = 604800)]
        recovery_window: u64,
        /// Trust store with the EBW provider seal certificates (§3.6).
        #[arg(long, env = "SCC_TRUST")]
        trust: PathBuf,
    },
    /// Demo PKI: create a TLS CA and a server certificate for localhost.
    PkiTls {
        #[arg(long)]
        out: PathBuf,
    },
    /// Demo PKI: write a trust store (stand-in for the EU Trusted Lists).
    PkiTrust {
        #[arg(long)]
        edd: Vec<PathBuf>,
        #[arg(long)]
        rds: Vec<PathBuf>,
        #[arg(long)]
        tsa: Vec<PathBuf>,
        /// EBW provider seal certificates.
        #[arg(long)]
        ebw: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

struct ProblemResponse(Problem);

impl IntoResponse for ProblemResponse {
    fn into_response(self) -> Response {
        let code = StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::BAD_REQUEST);
        (code, [(header::CONTENT_TYPE, scc::net::PROBLEM)], self.0.to_cbor()).into_response()
    }
}

fn cbor(r: Result<Vec<u8>, Problem>, ok: StatusCode) -> Response {
    match r {
        Ok(b) => (ok, [(header::CONTENT_TYPE, scc::net::CBOR), (header::CACHE_CONTROL, "max-age=60")], b).into_response(),
        Err(p) => ProblemResponse(p).into_response(),
    }
}

type St = Arc<Edd>;

async fn register(State(edd): State<St>, body: Bytes) -> Response {
    cbor(edd.register(&body), StatusCode::CREATED)
}

async fn registry_get(State(edd): State<St>, Path(owner): Path<String>) -> Response {
    cbor(edd.resolve(&owner), StatusCode::OK)
}

async fn registry_post(State(edd): State<St>, Path(owner): Path<String>, body: Bytes) -> Response {
    cbor(edd.update(&owner, &body), StatusCode::OK)
}

async fn head(State(edd): State<St>, Path(owner): Path<String>) -> Response {
    cbor(edd.head(&owner), StatusCode::OK)
}

async fn log(State(edd): State<St>, Path(owner): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    cbor(edd.log(&owner, q.get("after").map(|s| s.as_str())), StatusCode::OK)
}

async fn lookup(State(edd): State<St>, Path((t, v)): Path<(String, String)>) -> Response {
    cbor(edd.lookup(&t, &v), StatusCode::OK)
}

async fn metadata(State(edd): State<St>) -> Response {
    axum::Json(edd.metadata()).into_response()
}

async fn status_list(State(edd): State<St>) -> Response {
    ([(header::CONTENT_TYPE, scc::credential::STATUSLIST_TYP)], edd.status_list()).into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    scc::util::init_logging();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { dir } => {
            scc::certs::init_sealer(&dir, "seal", "edd.demo (DEMO ONLY)", "European Digital Directory (demo)")?;
            println!("EDD seal key and certificate written to {}", dir.display());
        }
        Cmd::PkiTls { out } => {
            let t = scc::certs::demo_tls()?;
            scc::util::write_file(out.join("ca.pem"), t.ca_pem)?;
            scc::util::write_file(out.join("server.pem"), t.cert_pem)?;
            scc::util::write_file(out.join("server-key.pem"), t.key_pem)?;
            println!("demo TLS CA and localhost certificate written to {}", out.display());
        }
        Cmd::PkiTrust { edd, rds, tsa, ebw, out } => {
            let rd = |v: Vec<PathBuf>| v.iter().map(scc::util::read_file).collect::<Result<Vec<_>>>();
            let ts = scc::certs::TrustStore { edd: rd(edd)?, rds: rd(rds)?, tsa: rd(tsa)?, ebw: rd(ebw)? };
            scc::util::write_json(&out, &ts)?;
            println!("trust store written to {}", out.display());
        }
        Cmd::Serve { dir, listen, base_url, tls_cert, tls_key, status_list_validity, status_list_ttl, recovery_window, trust } => {
            let sealer = scc::certs::load_sealer(&dir, "seal")?;
            let edd = Arc::new(Edd::new(
                EddConfig { base_url, recovery_window, status_list_validity, status_list_ttl },
                sealer,
                scc::certs::TrustStore::load(&trust)?,
            ));
            let app = Router::new()
                .route("/.well-known/edd", get(metadata))
                .route("/register", post(register))
                .route("/lookup/{t}/{v}", get(lookup))
                .route("/status-list", get(status_list))
                .route("/{url}", get(registry_get).post(registry_post))
                .route("/{url}/head", get(head))
                .route("/{url}/log", get(log))
                .with_state(edd);
            let tls = scc::net::server_tls(&tls_cert, &tls_key).await?;
            tracing::info!("EDD listening on {listen}");
            axum_server::bind_rustls(listen.parse::<std::net::SocketAddr>()?, tls).serve(app.into_make_service()).await?;
        }
    }
    Ok(())
}
