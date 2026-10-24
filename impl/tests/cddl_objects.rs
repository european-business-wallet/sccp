//! Objects produced by this implementation match the specification's CDDL
//! (spec/schemas/*.cddl). Evidence produced by running RDSes is also
//! validated by scc-verifier (05-evidence.md §2.2 step 5), which the demo
//! runs.

use scc::cose::PrivateKey;
use scc::credential::{ConnectProofBody, Credential, CredentialRequestBody, EndpointClaims, StatusListToken};
use scc::registry::{HeadStatement, HeadStatementBody, Sealer};
use scc::evidence::*;
use scc::mls::AppMessage;
use scc::schema::validate;
use scc::types::{Address, Consignment, OwnerStatus, EndpointRef};
use scc::util::{now, random_bytes};
use serde_bytes::ByteBuf;

const A: &str = "ebw:ytf2ob7mxuljkyweuwq4jpr3";
const B: &str = "ebw:hp7dsh3axazs4spf7xytom23";

fn sealer(name: &str) -> Sealer {
    let key = PrivateKey::generate_ed25519();
    let cert = scc::certs::self_signed_seal_cert(&key, name, "test", 10).unwrap();
    Sealer { key, chain: vec![cert] }
}

#[test]
fn produced_objects_match_cddl() {
    let t = now();
    let cred_key = PrivateKey::generate_ed25519();
    let ep_key = PrivateKey::generate_p256();
    let uri = format!("https://rds.test/status/{}", &B["ebw:".len()..]);
    let cred = Credential::issue(
        &cred_key,
        &EndpointClaims {
            iss: B.into(),
            sub: "Bx4nW8sYt2Qe".into(),
            exp: t + 100,
            nbf: t - 10,
            iat: t - 10,
            cnf: ep_key.public(),
            status_idx: 3,
            status_uri: uri.clone(),
            roles: vec!["default".into(), "invoices".into()],
            holder: Some("h-1".into()),
        },
    );
    validate("endpoint-credential", &cred.raw).unwrap();
    let tok = StatusListToken::build(&cred_key, B, &uri, &[0, 0, 1, 0], t - 5, t + 100, Some(60));
    validate("status-list-token", &tok.raw).unwrap();
    let req = CredentialRequestBody {
        st_type: "credential-request".into(),
        owner: B.into(),
        subject: Some("Bx4nW8sYt2Qe".into()),
        roles: vec!["invoices".into()],
        key: ep_key.public(),
        nonce: ByteBuf::from(random_bytes(16)),
    }
    .sign(&ep_key);
    validate("credential-request", &req).unwrap();
    let proof = ConnectProofBody {
        st_type: "connect-proof".into(),
        challenge: ByteBuf::from(random_bytes(16)),
        provider: "rds.test".into(),
        owner: B.into(),
        subject: "Bx4nW8sYt2Qe".into(),
        signed_at: t,
    }
    .sign(&ep_key);
    validate("connect-proof", &proof).unwrap();

    let from = Address::new(A, "purchasing");
    let to = Address::new(B, "invoices");
    let mid = random_bytes(16);
    let sid = random_bytes(16);
    let app = AppMessage {
        message_id: mid.clone(),
        from: from.clone(),
        to: to.clone(),
        sent_at: t,
        expires_at: t + 60,
        consignment: Consignment::Consented,
        content_type: "text/plain".into(),
        subject: Some("s".into()),
        in_reply_to: Some(ByteBuf::from(random_bytes(16))),
        salt: random_bytes(16),
        body: b"hello".to_vec(),
    };
    validate("app-message", &app.encode()).unwrap();

    let report = sign_statement(
        &ep_key,
        &cred.raw,
        &DecryptionReport {
            st_type: "decryption-report".into(),
            message_id: mid.clone(),
            session_id: sid.clone(),
            epoch: 4,
            envelope_hash: vec![1; 32],
            result: ReportResult::Match,
            plaintext_hash: None,
            epoch_authenticator: None,
            held_epoch: None,
            owner: B.into(),
            subject: "Bx4nW8sYt2Qe".into(),
            reported_at: t,
        },
    )
    .unwrap();
    validate("signed-decryption-report", &report).unwrap();
    // The other results, with their fields (doc 5 §4).
    for (result, ph, ea, held) in [
        (ReportResult::Mismatch, Some(vec![4; 32]), None, None),
        (ReportResult::DecryptFailed, None, None, None),
        (ReportResult::InvalidEpoch, None, Some(vec![2; 32]), None),
        (ReportResult::InvalidEpoch, None, Some(vec![2; 32]), Some(3)),
        (ReportResult::JoinFailure, None, None, None),
    ] {
        let r = sign_statement(
            &ep_key,
            &cred.raw,
            &DecryptionReport {
                st_type: "decryption-report".into(),
                message_id: mid.clone(),
                session_id: sid.clone(),
                epoch: 4,
                envelope_hash: vec![1; 32],
                result,
                plaintext_hash: ph.map(ByteBuf::from),
                epoch_authenticator: ea.map(ByteBuf::from),
                held_epoch: held,
                owner: B.into(),
                subject: "Bx4nW8sYt2Qe".into(),
                reported_at: t,
            },
        )
        .unwrap();
        validate("signed-decryption-report", &r).unwrap();
    }
    let decision = sign_statement(
        &ep_key,
        &cred.raw,
        &ConsentDecision {
            st_type: "consent-decision".into(),
            message_id: mid.clone(),
            session_id: sid.clone(),
            envelope_hash: vec![1; 32],
            decision: Decision::Accept,
            owner: B.into(),
            subject: "Bx4nW8sYt2Qe".into(),
            holder: Some("h-1".into()),
            decided_at: t,
        },
    )
    .unwrap();
    validate("signed-consent-decision", &decision).unwrap();
    let cfr = sign_statement(
        &ep_key,
        &cred.raw,
        &CommitFailureReport {
            st_type: "commit-failure-report".into(),
            session_id: sid.clone(),
            commit_ref: vec![5; 32],
            epoch: 5,
            failure: CommitFailure::ConfirmationTag,
            last_agreed: Some(AgreedEpoch { epoch: 4, epoch_authenticator: vec![2; 32] }),
            owner: B.into(),
            subject: "Bx4nW8sYt2Qe".into(),
            reported_at: t,
        },
    )
    .unwrap();
    validate("signed-commit-failure-report", &cfr).unwrap();

    let edd = sealer("edd");
    let head = HeadStatement::issue(
        &edd,
        &HeadStatementBody {
            st_type: "head-statement".into(),
            owner: B.into(),
            head: vec![7; 32],
            seq: 1,
            status: OwnerStatus::Active,
            successor: None,
            issued_at: t,
            expires_at: t + 300,
        },
    );
    validate("head-statement", &head).unwrap();

    let es = EvidenceSealer { seal: sealer("rds"), tsa: sealer("tsa") };
    let body = MessageEvidence {
        v: 1,
        evidence_id: random_bytes(16),
        event: Event::E1.uri(),
        issuer: Issuer { provider: "rds.test".into(), name: "RDS".into(), policies: vec!["https://rds.test/policy".into()] },
        event_time: t,
        message: MessageRef {
            message_id: mid.clone(),
            session_id: sid.clone(),
            from,
            to,
            sent_at: t,
            expires_at: t + 60,
            consignment: Consignment::Consented,
            plaintext_hash: vec![4; 32],
            envelope_hash: vec![1; 32],
        },
        mls: Some(MlsRef { group_context: vec![0; 40], epoch_authenticator: vec![2; 32] }),
        reason: Some(Reason::new("RE01", None, None)),
        heads: vec![ByteBuf::from(head)],
        statuses: Some(vec![ByteBuf::from(tok.raw.clone())]),
        sender_assurance: Assurance::scc("urn:x", t),
        recipient_assurance: Some(Assurance::scc("urn:x", t)),
        peer: Some("rds-a.test".into()),
        prev: Some(vec![ByteBuf::from(vec![9; 32])]),
        endpoint: Some(EndpointRef { owner: B.into(), subject: "Bx4nW8sYt2Qe".into() }),
        handovers: Some(vec![Handover { subject: "Bx4nW8sYt2Qe".into(), transferred_at: t, acknowledged_at: Some(t), result: Some("match".into()) }]),
        decisions: Some(vec![ByteBuf::from(decision)]),
        reports: Some(vec![ByteBuf::from(report)]),
        eligible_holders: Some(2),
    };
    let art = es.seal(&body, t).unwrap();
    validate("evidence-artefact", &art.raw).unwrap();
    let cf = es
        .seal(
            &CommitFailureEvidence {
                v: 1,
                evidence_id: random_bytes(16),
                event: COMMIT_FAILURE_EVENT.into(),
                issuer: body.issuer.clone(),
                event_time: t,
                session_id: sid,
                commit_ref: vec![5; 32],
                group_context: vec![0; 40],
                report: cfr,
            },
            t,
        )
        .unwrap();
    validate("evidence-artefact", &cf.raw).unwrap();
    let pkg = es
        .seal(&EvidencePackage { v: 1, st_type: "evidence-package".into(), message_id: mid, composed_at: t, items: vec![art.as_items()] }, t)
        .unwrap();
    validate("evidence-artefact", &pkg.raw).unwrap();
    // A wrong object is rejected.
    assert!(validate("signed-decryption-report", &pkg.raw).is_err());
}
