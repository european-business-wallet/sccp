//! Reproduce and validate the generated examples in spec/examples/.
//!
//! The examples are signed with Ed25519 keys derived from fixed labels
//! (tools/scc_cbor.py), and Ed25519 signatures are deterministic, so
//! several examples can be reproduced byte for byte.

use scc::cbor;
use scc::certs::TrustStore;
use scc::cose::{PrivateKey, Sign1};
use scc::credential::{Credential, EndpointClaims, StatusListToken};
use scc::registry::{self, RegistryDocument, HeadStatement, OpBody, Operation};
use scc::evidence::{self, Artefact, ConsentDecision, DecryptionReport, EvidenceBody};
use scc::types::{AcceptancePolicy, Identifier};
use std::collections::BTreeMap;
use std::path::PathBuf;

const T0: u64 = 1792310400;

fn ex(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec/examples").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn manifest_owner(o: &str) -> String {
    let m: serde_json::Value = serde_json::from_slice(&ex("manifest.json")).unwrap();
    m["owners"][o].as_str().unwrap().to_string()
}

fn owner_a_state() -> (RegistryDocument, Vec<PrivateKey>, PrivateKey) {
    let ukeys: Vec<PrivateKey> = (0..2).map(|i| PrivateKey::ed25519_from_label(&format!("demo/owner-a/update/{i}"))).collect();
    let cred = PrivateKey::ed25519_from_label("demo/owner-a/credential/0");
    let mut pol = BTreeMap::new();
    pol.insert("default".to_string(), AcceptancePolicy::Any);
    let st = RegistryDocument {
        update_keys: ukeys.iter().map(|k| k.public()).collect(),
        credential_keys: vec![cred.public()],
        rds: "https://rds.example-provider.eu/scc-rds".into(),
        identifiers: vec![Identifier { id_type: "vat".into(), value: "DE123456789".into() }],
        acceptance_policies: pol,
        status: scc::types::OwnerStatus::Active,
        successor: None,
        signed_at: T0 - 86400,
    };
    (st, ukeys, cred)
}

#[test]
fn create_op_reproduces() {
    let (st, ukeys, _) = owner_a_state();
    let op = Operation::sign(OpBody::Create(st), &ukeys[0]);
    assert_eq!(op.raw, ex("create-op.cbor"), "create-op.cbor differs");
    assert_eq!(registry::url_from_create(&op.raw), manifest_owner("A"));
}

#[test]
fn update_op_verifies_and_reproduces() {
    let (st, ukeys, _) = owner_a_state();
    let create = Operation::parse(&ex("create-op.cbor")).unwrap();
    let upd = Operation::parse(&ex("update-op.cbor")).unwrap();
    assert_eq!(upd.body.prev().unwrap(), create.hash().as_slice());
    assert_eq!(upd.verify_with(&st).unwrap(), 1);
    let mut st2 = upd.body.document().clone();
    st2.signed_at = T0 - 3600;
    let again = Operation::sign(OpBody::Update { prev: create.hash(), state: st2 }, &ukeys[1]);
    assert_eq!(again.raw, upd.raw);
    // The log audits.
    let log: Vec<registry::LogEntry> = cbor::from_slice(&ex("log.cbor")).unwrap();
    let audited = registry::audit_log(&manifest_owner("A"), &log, &edd_trust()).unwrap();
    assert_eq!(audited.len(), 2);
}

fn edd_trust() -> TrustStore {
    let head = Sign1::parse(&ex("head-statement.cbor")).unwrap();
    let rds_a = Artefact::parse(&ex("evidence-a1.cbor")).unwrap().cose.x5chain();
    let rds_b = Artefact::parse(&ex("evidence-b1.cbor")).unwrap().cose.x5chain();
    let sub = Sign1::parse(&ex("submission.cbor")).unwrap();
    TrustStore { edd: head.x5chain(), rds: vec![rds_a[0].clone(), rds_b[0].clone()], tsa: vec![], ebw: sub.x5chain() }
}

#[test]
fn head_statement_and_attestation_verify() {
    let trust = edd_trust();
    let h = HeadStatement::parse(&ex("head-statement.cbor")).unwrap();
    h.verify(&trust, T0 + 10).unwrap();
    // The EDD status list shows it current (01-discovery.md §5.3).
    let sl = StatusListToken::parse(&ex("edd-status-list.cbor")).unwrap();
    h.check_current(&sl, &trust, T0 + 10).unwrap();
    assert!(h.check_current(&sl, &trust, T0 + 2 * 86400).is_err(), "expired status list accepted");
    // The status operation is sealed by A's EBW provider and changes only
    // the status of the update operation's registry document.
    let st_op = Operation::parse(&ex("status-op.cbor")).unwrap();
    st_op.verify_seal(&trust, T0).unwrap();
    let upd = Operation::parse(&ex("update-op.cbor")).unwrap();
    registry::check_status_change(Some(upd.body.document()), &st_op.body).unwrap();
    registry::IdentifierAttestation::parse_and_verify(&ex("identifier-attestation.cbor"), &trust, T0).unwrap();
    let sr: registry::ResolutionResponse = cbor::from_slice(&ex("resolution-response.cbor")).unwrap();
    registry::ResolvedDocument::from_response(&manifest_owner("A"), &sr, &trust, T0 + 1).unwrap();
    let req: registry::RegistrationRequest = cbor::from_slice(&ex("registration-request.cbor")).unwrap();
    let sub = registry::Submission::parse(&req.submission).unwrap();
    sub.verify(&trust, T0).unwrap();
    assert_eq!(sub.op.raw, ex("create-op.cbor"));
    let ukeys = registry::Submission::parse(&ex("submission.cbor")).unwrap();
    ukeys.verify(&trust, T0).unwrap();
    assert_eq!(ukeys.op.raw, ex("update-op.cbor"));
}

#[test]
fn credential_reproduces_and_verifies() {
    let (st, _, cred_key) = owner_a_state();
    let c = Credential::parse(&ex("endpoint-credential.cbor")).unwrap();
    c.verify_signature_and_time(&st, T0).unwrap();
    let ep = PrivateKey::ed25519_from_label("demo/owner-a/Kq7vT2mXr9Lp");
    assert_eq!(c.claims.cnf, ep.public());
    let claims = EndpointClaims {
        iss: manifest_owner("A"),
        sub: "Kq7vT2mXr9Lp".into(),
        exp: T0 + 30 * 86400 - 86400,
        nbf: T0 - 86400,
        iat: T0 - 86400,
        cnf: ep.public(),
        status_idx: 7,
        status_uri: c.claims.status_uri.clone(),
        roles: vec!["default".into(), "purchasing".into()],
        holder: Some("h-41c9".into()),
    };
    assert_eq!(Credential::issue(&cred_key, &claims).raw, c.raw);
    scc::credential::CredentialRequestBody::parse_and_verify(&ex("credential-request.cbor")).unwrap();
    scc::credential::ConnectProofBody::parse_and_verify(&ex("connect-proof.cbor"), &ep.public()).unwrap();
}

#[test]
fn status_list_token_decodes() {
    let t = StatusListToken::parse(&ex("status-list-token.cbor")).unwrap();
    let b_cred = PrivateKey::ed25519_from_label("demo/owner-b/credential/0");
    assert_eq!(t.cose.kid().unwrap(), b_cred.public().thumbprint());
    let statuses: Vec<u8> = (0..8).map(|i| t.status(i).unwrap()).collect();
    assert_eq!(statuses, vec![0, 0, 0, 1, 0, 2, 0, 0]);
    let b_cred_ep = Credential::parse(&ex("endpoint-credential-b.cbor")).unwrap();
    assert_eq!(t.claims.sub, b_cred_ep.claims.status_uri);
}

#[test]
fn evidence_package_chain_and_statements() {
    let trust = edd_trust();
    let pkg = Artefact::parse(&ex("evidence-package.cbor")).unwrap();
    let key = trust.check_chain(&pkg.cose.x5chain(), scc::certs::TrustKind::Rds, T0 + 100).unwrap();
    pkg.cose.verify(&key).unwrap();
    let EvidenceBody::Package(p) = &pkg.body else { panic!("not a package") };
    let mut items = vec![];
    for (seal, ts) in &p.items {
        let a = Artefact::from_parts(seal, ts).unwrap();
        let k = trust.check_chain(&a.cose.x5chain(), scc::certs::TrustKind::Rds, T0 + 100).unwrap();
        a.cose.verify(&k).unwrap();
        let m = a.message().unwrap();
        for r in m.reports.iter().flatten() {
            let s = evidence::parse_statement::<DecryptionReport>(r).unwrap();
            assert_eq!(s.body.result, evidence::ReportResult::Match);
        }
        for d in m.decisions.iter().flatten() {
            evidence::parse_statement::<ConsentDecision>(d).unwrap();
        }
        items.push((a.seal_hash(), m.event().unwrap(), m.prev_hashes()));
    }
    let s = evidence::check_chain(&items).unwrap();
    assert_eq!(s.terminal, evidence::Event::E1);
    // Re-encoding a parsed body gives the same bytes.
    for name in ["evidence-a1.cbor", "evidence-e2-decryption-failed.cbor", "evidence-commit-failure.cbor", "evidence-a2.cbor"] {
        let a = Artefact::parse(&ex(name)).unwrap();
        let again = match &a.body {
            EvidenceBody::Message(m) => cbor::to_vec(m.as_ref()).unwrap(),
            EvidenceBody::CommitFailure(c) => cbor::to_vec(c).unwrap(),
            EvidenceBody::Package(p) => cbor::to_vec(p).unwrap(),
        };
        assert_eq!(again, a.cose.payload, "{name} does not round-trip");
    }
    evidence::parse_statement::<evidence::CommitFailureReport>(&ex("commit-failure-report.cbor")).unwrap();
}

#[test]
fn invalid_examples_are_rejected() {
    assert!(Operation::parse(&ex("invalid/create-op-six-update-keys.cbor")).is_err());
    assert!(Credential::parse(&ex("invalid/credential-no-roles.cbor")).is_err());
    assert!(Credential::parse(&ex("invalid/credential-no-status.cbor")).is_err());
    assert!(HeadStatement::parse(&ex("invalid/head-statement-bad-owner.cbor")).is_err());
    assert!(Artefact::parse(&ex("invalid/evidence-bad-event.cbor")).is_err());
}
