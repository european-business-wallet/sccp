//! scc-verifier: verify a message's evidence against its plaintext
//! (spec/05-evidence.md §2.2, §3.7, §7).

use anyhow::{Context, Result};
use clap::Parser;
use scc::certs::TrustStore;
use scc::endpoint::{Bundle, PrivateData};
use scc::verifier::{self, Inputs, Status};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Verify SCC evidence against a plaintext message")]
struct Cli {
    /// A verification bundle written by `scc-endpoint export`.
    #[arg(long)]
    bundle: Option<PathBuf>,
    /// Evidence package (overrides the bundle's).
    #[arg(long)]
    evidence: Option<PathBuf>,
    /// Session log, JSON (overrides the bundle's).
    #[arg(long)]
    session_log: Option<PathBuf>,
    /// Private data from an endpoint, JSON (overrides the bundle's).
    #[arg(long)]
    private: Option<PathBuf>,
    /// The plaintext message body to verify against.
    #[arg(long)]
    plaintext: Option<PathBuf>,
    /// Trusted certificates (stand-in for the EU Trusted Lists).
    #[arg(long, env = "SCC_TRUST")]
    trust: PathBuf,
    /// Print only the verdict.
    #[arg(long, short)]
    quiet: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pick = |explicit: &Option<PathBuf>, name: &str| -> Option<PathBuf> {
        explicit.clone().or_else(|| cli.bundle.as_ref().map(|b| b.join(name)).filter(|p| p.exists()))
    };
    let package = scc::util::read_file(pick(&cli.evidence, Bundle::PACKAGE).context("an evidence package is required")?)?;
    let session_log = pick(&cli.session_log, Bundle::SESSION_LOG).map(scc::util::read_json).transpose()?;
    let private: PrivateData = pick(&cli.private, Bundle::PRIVATE).map(scc::util::read_json).transpose()?.unwrap_or_default();
    let mut registry_logs = HashMap::new();
    if let Some(dir) = cli.bundle.as_ref().map(|b| b.join(Bundle::REGISTRY_LOGS)).filter(|p| p.exists()) {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if let Some(owner) = p.file_stem().and_then(|s| s.to_str()) {
                registry_logs.insert(owner.to_string(), scc::cbor::from_slice(&scc::util::read_file(&p)?)?);
            }
        }
    }
    let inputs = Inputs {
        package,
        session_log,
        private,
        registry_logs,
        plaintext: cli.plaintext.as_ref().map(scc::util::read_file).transpose()?,
        trust: TrustStore::load(&cli.trust)?,
    };
    let report = verifier::verify(&inputs);
    let verdict = report.verdict();
    if !cli.quiet {
        for s in &report.summary {
            println!("  {s}");
        }
        for c in &report.checks {
            println!("  [{:<10}] {:<5} {}: {}", c.status.to_string(), c.section, c.name, c.detail);
        }
    }
    println!("VERDICT: {verdict}");
    std::process::exit(match verdict {
        Status::Ok => 0,
        Status::Incomplete => 2,
        Status::Fail => 1,
    });
}
