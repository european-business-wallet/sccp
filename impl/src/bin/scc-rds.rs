//! scc-rds: a Registered Delivery Service (spec/04-delivery.md).

use anyhow::Result;
use clap::{Parser, Subcommand};
use scc::evidence::EvidenceSealer;
use scc::rds::{server, Rds, RdsConfig};
use scc::types::Consignment;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "SCC Registered Delivery Service")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the RDS's evidence seal key and TSA key, with self-signed
    /// demo certificates.
    Init {
        #[arg(long)]
        dir: PathBuf,
        /// Provider ID (used in the certificate subjects).
        #[arg(long)]
        provider: String,
    },
    /// Run the RDS.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        /// Provider ID (doc 4 §3).
        #[arg(long)]
        provider: String,
        /// Legal name of the provider.
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "127.0.0.1:8441")]
        listen: String,
        /// Public base URL (the `rds.url` in owners' registry documents).
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        edd: String,
        /// Trusted certificates (stand-in for the EU Trusted Lists).
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        tls_cert: String,
        #[arg(long)]
        tls_key: String,
        #[arg(long, default_value_t = 30 * 86400)]
        max_ttl: u64,
        #[arg(long, default_value_t = 300)]
        max_clock_skew: u64,
        #[arg(long, default_value_t = 120)]
        reservation_ttl: u64,
        #[arg(long, default_value_t = 30)]
        subjects_ttl: u64,
        /// Accept only basic consignment.
        #[arg(long)]
        basic_only: bool,
    },
    /// DEMO ONLY: make a running RDS treat a peer as unreachable (or, with
    /// --heal, reachable again), to simulate a network partition.
    Partition {
        /// Base URL of the RDS.
        #[arg(long)]
        rds: String,
        /// Provider ID of the peer.
        #[arg(long)]
        peer: String,
        #[arg(long)]
        heal: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    scc::util::init_logging();
    scc::net::init_crypto();
    match Cli::parse().cmd {
        Cmd::Init { dir, provider } => {
            let org = format!("{provider} (DEMO ONLY)");
            scc::certs::init_sealer(&dir, "seal", &format!("{provider} evidence seal"), &org)?;
            scc::certs::init_sealer(&dir, "tsa", &format!("{provider} timestamping"), &org)?;
            println!("RDS seal and TSA keys written to {}", dir.display());
        }
        Cmd::Serve { dir, provider, name, listen, base_url, edd, trust, tls_cert, tls_key, max_ttl, max_clock_skew, reservation_ttl, subjects_ttl, basic_only } => {
            let sealer = EvidenceSealer { seal: scc::certs::load_sealer(&dir, "seal")?, tsa: scc::certs::load_sealer(&dir, "tsa")? };
            let trust = scc::certs::TrustStore::load(&trust)?;
            let cfg = RdsConfig {
                policies: vec![format!("{}/policy/erds-demo", base_url.trim_end_matches('/'))],
                identity_policy: "urn:ebw:edd:identification".into(),
                provider,
                name,
                base_url: base_url.trim_end_matches('/').to_string(),
                max_ttl,
                max_clock_skew,
                session_idle_limit: 365 * 86400,
                max_message_size: 25 * 1024 * 1024,
                consignment_modes: if basic_only { vec![Consignment::Basic] } else { vec![Consignment::Basic, Consignment::Consented] },
                reservation_ttl,
                subjects_ttl,
            };
            let rds = Rds::new(cfg, sealer, trust, &edd)?;
            server::spawn_timers(rds.clone());
            let app = server::router(rds.clone());
            let tls = scc::net::server_tls(&tls_cert, &tls_key).await?;
            tracing::info!("RDS {} listening on {listen}", rds.cfg.provider);
            axum_server::bind_rustls(listen.parse::<std::net::SocketAddr>()?, tls).serve(app.into_make_service()).await?;
        }
        Cmd::Partition { rds, peer, heal } => {
            let http = scc::net::http_client()?;
            let body = serde_json::to_vec(&serde_json::json!({"peer": peer, "unreachable": !heal}))?;
            scc::net::post_bytes(&http, &format!("{}/admin/partition", rds.trim_end_matches('/')), "application/json", body).await?;
            println!("{}: {peer} is {}", rds, if heal { "reachable" } else { "unreachable" });
        }
    }
    Ok(())
}
