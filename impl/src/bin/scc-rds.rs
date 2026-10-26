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
        /// Name used in the certificate subjects.
        #[arg(long)]
        name: String,
    },
    /// Run the RDS.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        /// Legal name of the provider.
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "127.0.0.1:8441")]
        listen: String,
        /// The RDS URL: where the metadata is served, and the `rds` in
        /// owners' registry documents.
        #[arg(long)]
        url: String,
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
        /// URL of the RDS.
        #[arg(long)]
        rds: String,
        /// URL of the peer RDS.
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
        Cmd::Init { dir, name } => {
            let org = format!("{name} (DEMO ONLY)");
            scc::certs::init_sealer(&dir, "seal", &format!("{name} evidence seal"), &org)?;
            scc::certs::init_sealer(&dir, "tsa", &format!("{name} timestamping"), &org)?;
            println!("RDS seal and TSA keys written to {}", dir.display());
        }
        Cmd::Serve { dir, name, listen, url, edd, trust, tls_cert, tls_key, max_ttl, max_clock_skew, reservation_ttl, subjects_ttl, basic_only } => {
            let sealer = EvidenceSealer { seal: scc::certs::load_sealer(&dir, "seal")?, tsa: scc::certs::load_sealer(&dir, "tsa")? };
            let trust = scc::certs::TrustStore::load(&trust)?;
            let cfg = RdsConfig {
                policies: vec![format!("{}/policy/erds-demo", scc::rds::origin(&url))],
                identity_policy: "urn:ebw:edd:identification".into(),
                name,
                url,
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
            tracing::info!("RDS {} listening on {listen}", rds.cfg.url);
            axum_server::bind_rustls(listen.parse::<std::net::SocketAddr>()?, tls).serve(app.into_make_service()).await?;
        }
        Cmd::Partition { rds, peer, heal } => {
            let http = scc::net::http_client()?;
            let body = serde_json::to_vec(&serde_json::json!({"peer": peer, "unreachable": !heal}))?;
            scc::net::post_bytes(&http, &format!("{}/admin/partition", scc::rds::origin(&rds)), "application/json", body).await?;
            println!("{}: {peer} is {}", rds, if heal { "reachable" } else { "unreachable" });
        }
    }
    Ok(())
}
