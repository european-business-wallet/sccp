//! Types shared by all documents (spec/README.md "Identifiers",
//! schemas/common.cddl).

use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// An address: an EBW URL and a role.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub owner: String,
    pub role: String,
}

impl Address {
    pub fn new(owner: &str, role: &str) -> Self {
        Address { owner: owner.into(), role: role.into() }
    }

    /// Parse `owner` or `owner#role` (the role defaults to `default`).
    pub fn parse(s: &str) -> Result<Self> {
        let (owner, role) = match s.split_once('#') {
            Some((d, r)) => (d, r),
            None => (s, "default"),
        };
        check_ebw_url(owner)?;
        check_role(role)?;
        Ok(Address::new(owner, role))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.owner, self.role)
    }
}

/// An endpoint reference: an EBW URL and a subject ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRef {
    pub owner: String,
    pub subject: String,
}

pub fn check_ebw_url(owner: &str) -> Result<()> {
    let ok = owner
        .strip_prefix("ebw:")
        .map(|p| p.len() == 24 && p.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)))
        .unwrap_or(false);
    if !ok {
        bail!("invalid EBW URL {owner:?}");
    }
    Ok(())
}

pub fn check_role(role: &str) -> Result<()> {
    let ok = (1..=32).contains(&role.len())
        && role.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!("invalid role {role:?}");
    }
    Ok(())
}

pub fn check_subject(s: &str) -> Result<()> {
    let ok = (1..=64).contains(&s.len())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        bail!("invalid subject ID {s:?}");
    }
    Ok(())
}

/// Consignment mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Consignment {
    Basic,
    Consented,
}

/// An acceptance policy (01-discovery.md §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptancePolicy {
    Any,
    All,
    Quorum(u64),
}

impl AcceptancePolicy {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "any" => AcceptancePolicy::Any,
            "all" => AcceptancePolicy::All,
            _ => match s.strip_prefix("quorum:") {
                Some(n) => {
                    let n: u64 = n.parse()?;
                    if n < 1 {
                        bail!("quorum must be at least 1");
                    }
                    AcceptancePolicy::Quorum(n)
                }
                None => bail!("unknown acceptance policy {s}"),
            },
        })
    }
}

impl Serialize for AcceptancePolicy {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            AcceptancePolicy::Any => s.serialize_str("any"),
            AcceptancePolicy::All => s.serialize_str("all"),
            AcceptancePolicy::Quorum(n) => ("quorum", *n).serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for AcceptancePolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Name(String),
            Quorum(String, u64),
        }
        match Raw::deserialize(d)? {
            Raw::Name(n) if n == "any" => Ok(AcceptancePolicy::Any),
            Raw::Name(n) if n == "all" => Ok(AcceptancePolicy::All),
            Raw::Quorum(q, n) if q == "quorum" && n >= 1 => Ok(AcceptancePolicy::Quorum(n)),
            _ => Err(serde::de::Error::custom("bad acceptance policy")),
        }
    }
}

/// An existing identifier (01-discovery.md §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

pub const IDENTIFIER_TYPES: [&str; 5] = ["euid", "lei", "vat", "eori", "iso6523"];

impl Identifier {
    /// Parse `type:value`.
    pub fn parse(s: &str) -> Result<Self> {
        let (t, v) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("expected type:value"))?;
        if !IDENTIFIER_TYPES.contains(&t) {
            bail!("unknown identifier type {t}");
        }
        Ok(Identifier { id_type: t.into(), value: v.into() })
    }
}

/// The owner's home RDS (01-discovery.md §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdsRef {
    pub provider: String,
    pub url: String,
}

/// Owner lifecycle status (01-discovery.md §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerStatus {
    Active,
    Suspended,
    Retired,
    Merged,
    Closed,
}

impl OwnerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwnerStatus::Active => "active",
            OwnerStatus::Suspended => "suspended",
            OwnerStatus::Retired => "retired",
            OwnerStatus::Merged => "merged",
            OwnerStatus::Closed => "closed",
        }
    }
}

/// Encode a 16-byte message or evidence ID for display.
pub fn id_str(id: &[u8]) -> String {
    crate::util::b64u(id)
}
