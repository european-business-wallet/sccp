//! EDD registration, update and recovery (01-discovery.md §3, §6).

use scc::cbor;
use scc::certs::{self, TrustStore};
use scc::cose::PrivateKey;
use scc::registry::{self, HeadStatement, OpBody, Operation, RegistryDocument, Sealer, Submission};
use scc::edd::{Edd, EddConfig};
use scc::credential::{StatusListToken, STATUS_INVALID, STATUS_VALID};
use scc::types::{AcceptancePolicy, Identifier, OwnerStatus};
use std::collections::BTreeMap;

/// A test EBW provider's sealer.
fn provider() -> Sealer {
    let key = PrivateKey::generate_ed25519();
    let cert = certs::self_signed_seal_cert(&key, "ebw", "test", 10).unwrap();
    Sealer { key, chain: vec![cert] }
}

/// Seal an operation for submission (01-discovery.md §3.6).
fn sub(p: &Sealer, op: &Operation) -> Vec<u8> {
    Submission::seal(p, op, scc::util::now())
}

fn edd(p: &Sealer) -> (Edd, TrustStore) {
    let key = PrivateKey::generate_ed25519();
    let cert = certs::self_signed_seal_cert(&key, "edd", "test", 10).unwrap();
    let trust = TrustStore { edd: vec![cert.clone()], ebw: p.chain.clone(), ..Default::default() };
    let cfg = EddConfig {
        base_url: "https://edd.test".into(),
        recovery_window: 3600,
        status_list_validity: 300,
        status_list_ttl: 5,
        attestation_validity: 86400,
    };
    (Edd::new(cfg, Sealer { key, chain: vec![cert] }, trust.clone()), trust)
}

fn state(ukeys: &[PrivateKey], vat: &str) -> RegistryDocument {
    let mut pol = BTreeMap::new();
    pol.insert("default".to_string(), AcceptancePolicy::Any);
    pol.insert("invoices".to_string(), AcceptancePolicy::Quorum(2));
    RegistryDocument {
        update_keys: ukeys.iter().map(|k| k.public()).collect(),
        credential_keys: vec![PrivateKey::generate_ed25519().public()],
        rds: "https://rds.test/scc-rds".into(),
        identifiers: vec![Identifier { id_type: "vat".into(), value: vat.into() }],
        acceptance_policies: pol,
        status: scc::types::OwnerStatus::Active,
        successor: None,
        signed_at: 1,
    }
}

fn register(edd: &Edd, trust: &TrustStore, p: &Sealer, ukeys: &[PrivateKey], vat: &str) -> (String, Operation) {
    let op = Operation::sign(OpBody::Create(state(ukeys, vat)), &ukeys[0]);
    let req = cbor::to_vec(&registry::RegistrationRequest {
        submission: serde_bytes::ByteBuf::from(sub(p, &op)),
        proof: serde_bytes::ByteBuf::from(b"demo".to_vec()),
    })
    .unwrap();
    let resp: registry::RegistrationResponse = cbor::from_slice(&edd.register(&req).unwrap()).unwrap();
    let h = HeadStatement::parse(&resp.head).unwrap();
    h.verify(trust, scc::util::now()).unwrap();
    assert_eq!(h.body.head, op.hash());
    (resp.owner, op)
}

#[test]
fn register_update_recover() {
    let p = provider();
    let (edd, trust) = edd(&p);
    let ukeys: Vec<PrivateKey> = (0..2).map(|_| PrivateKey::generate_ed25519()).collect();
    let (owner, create) = register(&edd, &trust, &p, &ukeys, "DE1");
    // Same identifier for another EBW URL is refused.
    let rot2: Vec<PrivateKey> = (0..1).map(|_| PrivateKey::generate_ed25519()).collect();
    let op2 = Operation::sign(OpBody::Create(state(&rot2, "DE1")), &rot2[0]);
    let req2 = cbor::to_vec(&registry::RegistrationRequest {
        submission: serde_bytes::ByteBuf::from(sub(&p, &op2)),
        proof: serde_bytes::ByteBuf::from(vec![]),
    })
    .unwrap();
    assert_eq!(edd.register(&req2).unwrap_err().status, 422);

    // Update signed by the lower-priority key.
    let u1 = Operation::sign(OpBody::Update { prev: create.hash(), state: state(&ukeys, "DE1") }, &ukeys[1]);
    let h = HeadStatement::parse(&edd.update(&owner, &sub(&p, &u1)).unwrap()).unwrap();
    assert_eq!(h.body.seq, 2);
    // Stale prev with the same key: refused.
    let u_stale = Operation::sign(OpBody::Update { prev: create.hash(), state: state(&ukeys, "DE1") }, &ukeys[1]);
    assert_eq!(edd.update(&owner, &sub(&p, &u_stale)).unwrap_err().status, 409);
    // Unknown signer.
    let other = PrivateKey::generate_ed25519();
    let u_bad = Operation::sign(OpBody::Update { prev: u1.hash(), state: state(&ukeys, "DE1") }, &other);
    assert_eq!(edd.update(&owner, &sub(&p, &u_bad)).unwrap_err().status, 403);
    // A submission sealed by an untrusted provider.
    let u_seal = Operation::sign(OpBody::Update { prev: u1.hash(), state: state(&ukeys, "DE1") }, &ukeys[1]);
    let e = edd.update(&owner, &sub(&provider(), &u_seal)).unwrap_err();
    assert_eq!((e.status, e.ptype), (403, "invalid-seal"));
    // Unattested identifier.
    let u_id = Operation::sign(OpBody::Update { prev: u1.hash(), state: state(&ukeys, "DE2") }, &ukeys[1]);
    assert_eq!(edd.update(&owner, &sub(&p, &u_id)).unwrap_err().status, 422);
    // Recovery with the higher-priority key overrides u1.
    let r = Operation::sign(OpBody::Update { prev: create.hash(), state: state(&ukeys, "DE1") }, &ukeys[0]);
    let h = HeadStatement::parse(&edd.update(&owner, &sub(&p, &r)).unwrap()).unwrap();
    assert_eq!(h.body.head, r.hash());
    assert_eq!(h.body.seq, 2);
    let log: Vec<registry::LogEntry> = cbor::from_slice(&edd.log(&owner, None).unwrap()).unwrap();
    assert_eq!(log.len(), 3);
    assert!(log[1].overridden);
    let audited = registry::audit_log(&owner, &log, &trust).unwrap();
    assert_eq!(audited.len(), 3);
    let r_doc = r.body.document().clone();
    let with_status = |s: OwnerStatus| RegistryDocument { status: s, ..r_doc.clone() };

    // The EBW provider suspends the owner with a status operation (§3.1).
    let s1 = Operation::seal(OpBody::Status { prev: r.hash(), state: with_status(OwnerStatus::Suspended) }, &p);
    let h_r = HeadStatement::parse(&edd.head(&owner).unwrap()).unwrap();
    let h_s1 = HeadStatement::parse(&edd.update(&owner, &sub(&p, &s1)).unwrap()).unwrap();
    // The status list now shows the old head statement replaced (§5.3).
    let sl = StatusListToken::parse(&edd.status_list()).unwrap();
    sl.verify_edd(&trust, scc::util::now()).unwrap();
    assert_eq!(sl.status(h_r.body.status_list.idx).unwrap(), STATUS_INVALID);
    assert_eq!(sl.status(h_s1.body.status_list.idx).unwrap(), STATUS_VALID);
    h_s1.check_current(&sl, &trust, scc::util::now()).unwrap();
    assert!(h_r.check_current(&sl, &trust, scc::util::now()).is_err());
    // A status operation may not change anything but the status...
    let mut other_doc = with_status(OwnerStatus::Active);
    other_doc.rds = "https://elsewhere.test/scc-rds".into();
    let s_bad = Operation::seal(OpBody::Status { prev: s1.hash(), state: other_doc }, &p);
    assert_eq!(edd.update(&owner, &sub(&p, &s_bad)).unwrap_err().ptype, "invalid-status-change");
    // ...nor set a status reserved to the owner.
    let s_merge = Operation::seal(
        OpBody::Status { prev: s1.hash(), state: RegistryDocument { successor: Some(owner.clone()), ..with_status(OwnerStatus::Merged) } },
        &p,
    );
    assert_eq!(edd.update(&owner, &sub(&p, &s_merge)).unwrap_err().ptype, "invalid-status-change");
    // An update operation cannot lift the suspension, nor can a status
    // operation be signed with an update key.
    let u_lift = Operation::sign(OpBody::Update { prev: s1.hash(), state: with_status(OwnerStatus::Active) }, &ukeys[0]);
    assert_eq!(edd.update(&owner, &sub(&p, &u_lift)).unwrap_err().ptype, "invalid-status-change");
    let s_key = Operation::sign(OpBody::Status { prev: s1.hash(), state: with_status(OwnerStatus::Active) }, &ukeys[0]);
    assert_eq!(edd.update(&owner, &sub(&p, &s_key)).unwrap_err().status, 403);
    // A status operation cannot be overridden by recovery.
    let u_rec = Operation::sign(OpBody::Update { prev: r.hash(), state: with_status(OwnerStatus::Active) }, &ukeys[0]);
    assert_eq!(edd.update(&owner, &sub(&p, &u_rec)).unwrap_err().status, 409);
    // The provider reinstates the owner, who then closes the EBW URL.
    let s2 = Operation::seal(OpBody::Status { prev: s1.hash(), state: with_status(OwnerStatus::Active) }, &p);
    edd.update(&owner, &sub(&p, &s2)).unwrap();
    let d = Operation::sign(OpBody::Update { prev: s2.hash(), state: with_status(OwnerStatus::Closed) }, &ukeys[0]);
    edd.update(&owner, &sub(&p, &d)).unwrap();
    let u_after = Operation::sign(OpBody::Update { prev: d.hash(), state: with_status(OwnerStatus::Closed) }, &ukeys[0]);
    assert_eq!(edd.update(&owner, &sub(&p, &u_after)).unwrap_err().status, 410);
    // The whole log audits.
    let log: Vec<registry::LogEntry> = cbor::from_slice(&edd.log(&owner, None).unwrap()).unwrap();
    assert_eq!(registry::audit_log(&owner, &log, &trust).unwrap().len(), 6);
    // Lookup and resolution.
    assert!(edd.lookup("vat", "DE1").is_ok());
    let resp: registry::ResolutionResponse = cbor::from_slice(&edd.resolve(&owner).unwrap()).unwrap();
    assert_eq!(Operation::parse(&resp.operation).unwrap().hash(), d.hash());
}
