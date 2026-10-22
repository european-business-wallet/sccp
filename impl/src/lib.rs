//! Reference implementation of the EBW Secure Communication Channel (SCC).
//!
//! The library holds the code shared by the binaries:
//!
//! - [`cbor`], [`cose`]: deterministic CBOR and COSE_Sign1;
//! - [`owner`]: EBW URL operations and EDD statements (spec doc 1);
//! - [`credential`]: endpoint credentials and status lists (doc 2);
//! - [`evidence`], [`tsa`]: evidence artefacts and chains (doc 5);
//! - [`certs`]: demo certificates and trust anchors.

pub mod cbor;
pub mod certs;
pub mod cose;
pub mod credential;
pub mod delivery;
pub mod registry;
pub mod dispute;
pub mod edd;
pub mod endpoint;
pub mod net;
pub mod owner;
pub mod rds;
pub mod resolve;
pub mod rpc;
pub mod schema;
pub mod evidence;
pub mod mls;
pub mod tsa;
pub mod types;
pub mod util;
pub mod verifier;
