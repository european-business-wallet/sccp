//! scc-endpoint: an SCC endpoint, and the owner's administration tool.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use scc::certs::TrustStore;
use scc::endpoint::Endpoint;
use scc::owner::Owner;
use scc::types::{AcceptancePolicy, Address, Consignment, Identifier};
use scc::util::{b64u, b64u_dec};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "SCC endpoint and owner administration")]
struct Cli {
    /// Trusted certificates (stand-in for the EU Trusted Lists).
    #[arg(long, env = "SCC_TRUST", global = true)]
    trust: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Owner administration: EBW URL, credentials, status lists.
    Owner {
        #[command(subcommand)]
        cmd: OwnerCmd,
    },
    /// Create an endpoint: keys and a credential request.
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        owner: String,
        /// Base URL of the home RDS.
        #[arg(long)]
        rds: String,
        #[arg(long)]
        edd: String,
        /// Requested roles, comma-separated.
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        /// How to answer consent requests: accept, reject or ignore.
        #[arg(long, default_value = "accept")]
        consent: String,
    },
    /// Install the credential, register with the home RDS and publish
    /// KeyPackages.
    Register {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        credential: PathBuf,
    },
    /// Send a message.
    Send {
        #[arg(long)]
        dir: PathBuf,
        /// Role to send from.
        #[arg(long)]
        from_role: String,
        /// Recipient address: owner or owner#role.
        #[arg(long)]
        to: String,
        /// Message body (text).
        #[arg(long, conflicts_with = "body_file")]
        body: Option<String>,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long, default_value = "text/plain")]
        content_type: String,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value = "basic")]
        consignment: String,
        /// Seconds until expiry.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Write the message ID to this file.
        #[arg(long)]
        id_out: Option<PathBuf>,
    },
    /// Process queued handshakes, messages, consent requests and evidence.
    Sync {
        #[arg(long)]
        dir: PathBuf,
        /// Keep listening for this many seconds.
        #[arg(long, default_value_t = 0)]
        wait: u64,
    },
    /// List messages sent and received.
    List {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Change how the endpoint answers.
    Configure {
        #[arg(long)]
        dir: PathBuf,
        /// How to answer consent requests: accept, reject or ignore.
        #[arg(long)]
        consent: Option<String>,
        /// DEMO ONLY: report messages that decrypt as `decrypt-failed` or
        /// `invalid-epoch`, or send no reports (`silent`), as a dishonest
        /// recipient would (`none` to stop).
        #[arg(long)]
        false_report: Option<String>,
    },
    /// Write a verification bundle for a message.
    Export {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum OwnerCmd {
    /// Generate keys and register an EBW URL with the EDD.
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        edd: String,
        /// Directory of the EBW provider that submits the owner's
        /// operations (made with `owner provider-init`).
        #[arg(long)]
        provider: PathBuf,
        /// URL of the home RDS (its metadata).
        #[arg(long)]
        rds_url: String,
        /// Existing identifiers (type:value), e.g. vat:DE123456789.
        #[arg(long)]
        identifier: Vec<String>,
        /// Acceptance policies: role=any|all|quorum:N.
        #[arg(long)]
        policy: Vec<String>,
    },
    /// Issue an endpoint credential for a credential request.
    Issue {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Roles (default: as requested), comma-separated.
        #[arg(long, value_delimiter = ',')]
        roles: Option<Vec<String>>,
        #[arg(long)]
        holder: Option<String>,
        /// Validity in seconds.
        #[arg(long, default_value_t = 30 * 86400)]
        validity: u64,
    },
    /// Sign and publish the status list token.
    PublishStatus {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value_t = 86400)]
        validity: u64,
        #[arg(long, default_value_t = 60)]
        ttl: u64,
    },
    /// Revoke an endpoint's credential and publish the status list.
    Revoke {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        subject: String,
    },
    /// Print the owner's EBW URL.
    Url {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Create an EBW provider's seal key and (self-signed demo)
    /// certificate. The provider submits its owners' operations to the
    /// EDD (01-discovery.md §3.6).
    ProviderInit {
        #[arg(long)]
        dir: PathBuf,
        /// Name of the EBW provider (used in its certificate subject).
        #[arg(long)]
        provider: String,
    },
}

fn trust(p: &Option<PathBuf>) -> Result<TrustStore> {
    TrustStore::load(p.as_ref().context("--trust (or SCC_TRUST) is required")?)
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn");
    }
    scc::util::init_logging();
    scc::net::init_crypto();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Owner { cmd } => match cmd {
            OwnerCmd::Init { dir, edd, provider, rds_url, identifier, policy } => {
                let edd = scc::edd::EddClient::new(&edd, trust(&cli.trust)?)?;
                let ids = identifier.iter().map(|i| Identifier::parse(i)).collect::<Result<Vec<_>>>()?;
                let mut pols = BTreeMap::new();
                for p in policy {
                    let (r, v) = p.split_once('=').context("policy must be role=policy")?;
                    pols.insert(r.to_string(), AcceptancePolicy::parse(v)?);
                }
                let o = Owner::init(&dir, &edd, &provider, rds_url, ids, pols).await?;
                println!("{}", o.cfg.owner);
            }
            OwnerCmd::Issue { dir, request, out, roles, holder, validity } => {
                let mut o = Owner::load(&dir)?;
                let cred = o.issue(&scc::util::read_file(&request)?, roles, holder, validity)?;
                scc::util::write_file(&out, &cred.raw)?;
                println!("issued credential for {} (subject {}, roles {})", o.cfg.owner, cred.claims.sub, cred.claims.roles.join(","));
            }
            OwnerCmd::PublishStatus { dir, validity, ttl } => {
                let o = Owner::load(&dir)?;
                let t = o.publish_status(validity, Some(ttl)).await?;
                println!("published status list {} ({} entries)", t.claims.sub, o.cfg.issued.len());
            }
            OwnerCmd::Revoke { dir, subject } => {
                let mut o = Owner::load(&dir)?;
                o.revoke(&subject)?;
                o.publish_status(86400, Some(60)).await?;
                println!("revoked {subject}");
            }
            OwnerCmd::Url { dir } => println!("{}", Owner::load(&dir)?.cfg.owner),
            OwnerCmd::ProviderInit { dir, provider } => {
                scc::owner::EbwProvider::init(&dir, &provider)?;
                println!("EBW provider {provider}: seal key and certificate written to {}", dir.display());
            }
        },
        Cmd::Init { dir, owner, rds, edd, roles, consent } => {
            Endpoint::init(&dir, &owner, &rds, &edd, roles, None)?;
            let mut cfg: scc::endpoint::EndpointConfig = scc::util::read_json(dir.join("endpoint.json"))?;
            cfg.consent = consent;
            scc::util::write_json(dir.join("endpoint.json"), &cfg)?;
            println!("credential request written to {}", dir.join("credential-request.cbor").display());
        }
        Cmd::Register { dir, credential } => {
            let mut e = Endpoint::open(&dir, trust(&cli.trust)?)?;
            e.install_credential(&scc::util::read_file(&credential)?)?;
            let c = e.connect().await?;
            let pool = e.publish_key_packages(&c, 0).await?;
            let me = e.me()?;
            println!("registered {}/{} at {} (KeyPackages: {:?})", me.owner, me.subject, c.rds, pool.available);
        }
        Cmd::Send { dir, from_role, to, body, body_file, content_type, subject, consignment, ttl, id_out } => {
            let mut e = Endpoint::open(&dir, trust(&cli.trust)?)?;
            let to = Address::parse(&to)?;
            let body = match (body, body_file) {
                (Some(b), _) => b.into_bytes(),
                (None, Some(f)) => scc::util::read_file(&f)?,
                _ => bail!("--body or --body-file is required"),
            };
            let consignment = match consignment.as_str() {
                "basic" => Consignment::Basic,
                "consented" => Consignment::Consented,
                _ => bail!("consignment must be basic or consented"),
            };
            let mut c = e.connect().await?;
            let (mid, code) = e.send(&mut c, &from_role, &to, body, &content_type, subject, consignment, ttl).await?;
            if let Some(p) = id_out {
                scc::util::write_file(p, b64u(&mid))?;
            }
            println!("sent message {} to {to}: {code}", b64u(&mid));
        }
        Cmd::Sync { dir, wait } => {
            let mut e = Endpoint::open(&dir, trust(&cli.trust)?)?;
            let mut c = e.connect().await?;
            for l in e.sync(&mut c, wait).await? {
                println!("{l}");
            }
        }
        Cmd::List { dir } => {
            let e = Endpoint::open(&dir, trust(&cli.trust)?)?;
            for r in e.records() {
                println!(
                    "{} {:<8} {} -> {} epoch {} result {} events [{}]",
                    b64u(&r.message_id),
                    format!("{:?}", r.direction).to_lowercase(),
                    r.meta.from,
                    r.meta.to,
                    r.epoch,
                    r.result.map(|x| x.as_str()).unwrap_or("-"),
                    r.events.join(" ")
                );
            }
        }
        Cmd::Configure { dir, consent, false_report } => {
            let mut cfg: scc::endpoint::EndpointConfig = scc::util::read_json(dir.join("endpoint.json"))?;
            if let Some(c) = consent {
                cfg.consent = c;
            }
            match false_report.as_deref() {
                None => {}
                Some("none") => cfg.false_report = None,
                Some(x @ ("decrypt-failed" | "invalid-epoch" | "silent")) => cfg.false_report = Some(x.into()),
                Some(x) => bail!("--false-report must be decrypt-failed, invalid-epoch, silent or none, not {x}"),
            }
            scc::util::write_json(dir.join("endpoint.json"), &cfg)?;
        }
        Cmd::Export { dir, message, out } => {
            let e = Endpoint::open(&dir, trust(&cli.trust)?)?;
            let c = e.connect().await?;
            e.export(&c, &b64u_dec(&message)?, &out).await?;
            println!("verification bundle for {message} written to {}", out.display());
        }
    }
    Ok(())
}
