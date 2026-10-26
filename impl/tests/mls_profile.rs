//! The SCC MLS profile with mls-rs: credentials, the scc_session
//! extension, an observer following Commits, epoch values, and disputes
//! settled with retained MLS state (05-evidence.md §7.4, §7.5, §8).

use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::ExtensionList;
use mls_rs_codec::MlsEncode;
use scc::cose::PrivateKey;
use scc::credential::{Credential, EndpointClaims, StatusListToken};
use scc::registry::{url_from_create, RegistryDocument, OpBody, Operation};
use scc::delivery::{LogEntry, SessionLog};
use scc::dispute::{self, Join, Processed, Replay};
use scc::mls::{self, SccIdentityProvider, TrustContext};
use scc::types::{AcceptancePolicy, Address};
use std::collections::BTreeMap;

struct Owner {
    owner: String,
    state: RegistryDocument,
    cred_key: PrivateKey,
}

fn owner() -> Owner {
    let ukeys = PrivateKey::generate_ed25519();
    let cred_key = PrivateKey::generate_ed25519();
    let mut pol = BTreeMap::new();
    pol.insert("default".into(), AcceptancePolicy::Any);
    let state = RegistryDocument {
        update_keys: vec![ukeys.public()],
        credential_keys: vec![cred_key.public()],
        rds: "https://rds.test/scc-rds".into(),
        identifiers: vec![],
        acceptance_policies: pol,
        status: scc::types::OwnerStatus::Active,
        successor: None,
        signed_at: 0,
    };
    let op = Operation::sign(OpBody::Create(state.clone()), &ukeys);
    Owner { owner: url_from_create(&op.raw), state, cred_key }
}

fn issue(o: &Owner, sub: &str, roles: &[&str], ep: &PrivateKey, idx: u64) -> Credential {
    let t = scc::util::now();
    Credential::issue(
        &o.cred_key,
        &EndpointClaims {
            iss: o.owner.clone(),
            sub: sub.into(),
            exp: t + 86400,
            nbf: t - 60,
            iat: t - 60,
            cnf: ep.public(),
            status_idx: idx,
            status_uri: format!("https://rds.test/status/{}", &o.owner["ebw:".len()..]),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            holder: None,
        },
    )
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", scc::util::random_subject()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn session_lifecycle() {
    let a = owner();
    let b = owner();
    let mut ctx = TrustContext::default();
    ctx.states.insert(a.owner.clone(), a.state.clone());
    ctx.states.insert(b.owner.clone(), b.state.clone());
    for o in [&a, &b] {
        let uri = format!("https://rds.test/status/{}", &o.owner["ebw:".len()..]);
        let t = scc::util::now();
        ctx.statuses.insert(uri.clone(), StatusListToken::build(&o.cred_key, &o.owner, &uri, &[0, 0, 0], t - 10, t + 3600, None));
    }
    ctx.require_status = true;
    let ip = SccIdentityProvider::new(ctx);
    let dir = tmpdir("mls");

    let mk = |o: &Owner, sub: &str, roles: &[&str], idx: u64| {
        let ep = PrivateKey::generate_ed25519();
        let cred = issue(o, sub, roles, &ep, idx);
        let (sk, pk) = mls::generate_signature_key().unwrap();
        let leaf = mls::make_leaf_credential(&ep, &cred.raw, &pk);
        let si = SigningIdentity::new(leaf, pk);
        let parsed = mls::parse_leaf_credential(&si).unwrap();
        assert_eq!(parsed.claims.sub, sub);
        mls::endpoint_client(&dir.join(format!("{sub}.db")), ip.clone(), si, sk, 3600).unwrap()
    };
    let a1 = mk(&a, "a1", &["purchasing"], 0);
    let a2 = mk(&a, "a2", &["purchasing", "default"], 1);
    let b1 = mk(&b, "b1", &["invoices"], 0);

    let kp_a2 = a2.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let kp_b1 = b1.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();

    let from = Address::new(&a.owner, "purchasing");
    let to = Address::new(&b.owner, "invoices");
    let gid = scc::util::random_bytes(16);
    let mut g = a1
        .create_group_with_id(gid.clone(), mls::session_extensions(&from, &to).unwrap(), ExtensionList::new(), None)
        .unwrap();
    let gi0 = g.group_info_message(true).unwrap();
    let out = g.commit_builder().add_member(kp_a2).unwrap().add_member(kp_b1).unwrap().build().unwrap();
    assert_eq!(out.welcome_messages.len(), 1);

    // The observer follows the commit.
    let observer = mls::observer_client(ip.clone());
    let gi0_bytes = gi0.to_bytes().unwrap();
    let mut obs = observer.observe_group(mls::parse_mls_message(&gi0_bytes).unwrap(), None, None).unwrap();
    assert_eq!(obs.group_context().epoch, 0);
    let commit_bytes = out.commit_message.to_bytes().unwrap();
    let r = obs.process_incoming_message(mls::parse_mls_message(&commit_bytes).unwrap()).unwrap();
    assert!(matches!(r, mls_rs::external_client::ExternalReceivedMessage::Commit(_)));
    g.apply_pending_commit().unwrap();
    assert_eq!(obs.group_context().mls_encode_to_vec().unwrap(), g.context().mls_encode_to_vec().unwrap());
    let s = mls::check_session_extensions(&obs.group_context().extensions).unwrap();
    assert_eq!(s.addresses().unwrap(), (from.clone(), to.clone()));
    assert_eq!(obs.roster().members().len(), 3);

    let (mut gb, _) = b1.join_group(None, &out.welcome_messages[0], None).unwrap();
    let (mut ga2, _) = a2.join_group(None, &out.welcome_messages[0], None).unwrap();
    assert_eq!(gb.epoch_authenticator().unwrap(), g.epoch_authenticator().unwrap());

    // Each endpoint retains its state when the epoch begins (doc 5 §8).
    let st_a1 = dispute::export_state(&a1, &mut g).unwrap();
    let st_b1 = dispute::export_state(&b1, &mut gb).unwrap();
    let st_a2 = dispute::export_state(&a2, &mut ga2).unwrap();
    assert_eq!(st_a1.epoch, 1);
    assert_eq!(st_a1.epoch_authenticator, st_b1.epoch_authenticator);
    let t0 = scc::util::now();
    let mut log = SessionLog {
        group_info: gi0_bytes.clone(),
        commits: vec![LogEntry { epoch: 1, commit: commit_bytes.clone(), welcome: Some(out.welcome_messages[0].to_bytes().unwrap()), accepted_at: t0 }],
    };

    // Application message.
    let app = mls::AppMessage {
        message_id: scc::util::random_bytes(16),
        from: from.clone(),
        to: to.clone(),
        sent_at: 1,
        expires_at: 2,
        consignment: scc::types::Consignment::Basic,
        content_type: "text/plain".into(),
        subject: None,
        in_reply_to: None,
        salt: scc::util::random_bytes(16),
        body: b"hello".to_vec(),
    };
    let ct = g.encrypt_application_message(&app.encode(), vec![]).unwrap();
    let ct_bytes = ct.to_bytes().unwrap();

    let gc1 = g.context().mls_encode_to_vec().unwrap();
    match gb.process_incoming_message(mls::parse_mls_message(&ct_bytes).unwrap()).unwrap() {
        ReceivedMessage::ApplicationMessage(d) => {
            assert_eq!(mls::AppMessage::decode(d.data()).unwrap(), app);
            assert_eq!(d.sender_index, 0);
        }
        _ => panic!("expected an application message"),
    }
    match ga2.process_incoming_message(mls::parse_mls_message(&ct_bytes).unwrap()).unwrap() {
        ReceivedMessage::ApplicationMessage(_) => {}
        _ => panic!("expected an application message"),
    }

    // Message-key dispute (doc 5 §7.4): the recipient's retained state,
    // loaded by a verifier with mls-rs, decrypts the message, although b1
    // has since consumed the key in its live state.
    let vip = SccIdentityProvider::new(TrustContext { states: ip.ctx.read().unwrap().states.clone(), ..Default::default() });
    let mut loaded = dispute::load_state(&vip, &st_b1).unwrap();
    let (gc, ea) = dispute::group_values(&loaded).unwrap();
    assert_eq!(gc, gc1);
    assert_eq!(ea, st_a1.epoch_authenticator);
    match dispute::process_message(&mut loaded, &ct_bytes).unwrap() {
        Processed::Application { sender_index, data } => {
            assert_eq!(sender_index, 0);
            assert_eq!(data, app.encode());
            assert_eq!(dispute::member_credential(&loaded, 0).unwrap().claims.sub, "a1");
        }
        _ => panic!("the message should decrypt under the recipient's state"),
    }
    // The sender's own state: mls-rs does not process a member's own message.
    let mut own = dispute::load_state(&vip, &st_a1).unwrap();
    assert!(matches!(dispute::process_message(&mut own, &ct_bytes).unwrap(), Processed::FromSelf));
    // A bogus ciphertext is rejected.
    let mut bogus = ct_bytes.clone();
    let n = bogus.len();
    bogus[n - 3] ^= 1;
    let mut again = dispute::load_state(&vip, &st_b1).unwrap();
    assert!(matches!(dispute::process_message(&mut again, &bogus).unwrap(), Processed::Rejected(_)));
    // A state for another epoch is refused.
    let mut wrong = st_b1.clone();
    wrong.epoch = 2;
    assert!(dispute::load_state(&vip, &wrong).is_err());

    // b1 commits an update; the observer and the others follow.
    let up = gb.commit_builder().build().unwrap();
    let up_bytes = up.commit_message.to_bytes().unwrap();
    obs.process_incoming_message(mls::parse_mls_message(&up_bytes).unwrap()).unwrap();
    gb.apply_pending_commit().unwrap();
    let st_b1_2 = dispute::export_state(&b1, &mut gb).unwrap();
    g.process_incoming_message(mls::parse_mls_message(&up_bytes).unwrap()).unwrap();
    assert_eq!(obs.group_context().mls_encode_to_vec().unwrap(), g.context().mls_encode_to_vec().unwrap());
    assert_eq!(gb.epoch_authenticator().unwrap(), g.epoch_authenticator().unwrap());
    log.commits.push(LogEntry { epoch: 2, commit: up_bytes.clone(), welcome: None, accepted_at: t0 });
    g.write_to_storage().unwrap();
    let g_again = a1.load_group(&gid).unwrap();
    assert_eq!(g_again.current_epoch(), 2);
    assert_eq!(g_again.epoch_authenticator().unwrap(), g.epoch_authenticator().unwrap());

    // a1 adds b2, whose KeyPackage private keys b2 retains.
    let b2 = mk(&b, "b2", &["invoices"], 1);
    let kp_b2 = b2.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let kept_b2 = dispute::retain_key_package(&b2, &kp_b2).unwrap();
    dispute::check_key_package(&kept_b2).unwrap();
    let mut bad_kp = kept_b2.clone();
    let other = dispute::retain_key_package(&b1, &b1.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap()).unwrap();
    bad_kp.init_key = other.init_key.clone();
    assert!(dispute::check_key_package(&bad_kp).is_err());
    let mut bad_kp = kept_b2.clone();
    bad_kp.leaf_node_key = other.leaf_node_key;
    let e = dispute::check_key_package(&bad_kp).unwrap_err().to_string();
    assert!(e.contains("leaf private key"), "{e}");
    let add = g.commit_builder().add_member(kp_b2).unwrap().build().unwrap();
    g.apply_pending_commit().unwrap();
    log.commits.push(LogEntry { epoch: 3, commit: add.commit_message.to_bytes().unwrap(), welcome: Some(add.welcome_messages[0].to_bytes().unwrap()), accepted_at: t0 });
    let ct3 = g.encrypt_application_message(&app.encode(), vec![]).unwrap().to_bytes().unwrap();
    let ea3 = g.epoch_authenticator().unwrap().to_vec();

    // The observer replay of the log gives the same GroupContexts.
    let rep = scc::verifier::replay_log(&log, ip.ctx.read().unwrap().states.clone()).unwrap();
    assert_eq!(rep.contexts.len(), 4);
    assert_eq!(rep.contexts[3], g.context().mls_encode_to_vec().unwrap());
    assert_eq!(rep.committers[2], Some(gb.current_member_index()));

    // Group-state dispute (doc 5 §7.5): a2 says it does not hold epoch 3;
    // its last agreed epoch is 1. From a2's retained state, the verifier
    // replays the Commits for epochs 2 and 3 and reaches the sender's
    // epoch authenticator; the message then decrypts.
    let mut anchor = dispute::load_state(&vip, &st_a2).unwrap();
    assert_eq!(dispute::group_values(&anchor).unwrap().0, rep.contexts[1]);
    assert!(matches!(dispute::replay_commits(&vip, &mut anchor, &log, 3).unwrap(), Replay::Done));
    assert_eq!(dispute::group_values(&anchor).unwrap().1, ea3);
    assert!(matches!(dispute::process_message(&mut anchor, &ct3).unwrap(), Processed::Application { sender_index: 0, .. }));

    // b1 cannot replay its own Commit for epoch 2 from its state of epoch
    // 1, so its anchor is epoch 2, which it created (doc 5 §7.5 step 1).
    let mut anchor = dispute::load_state(&vip, &st_b1).unwrap();
    assert!(matches!(dispute::replay_commits(&vip, &mut anchor, &log, 3).unwrap(), Replay::FromSelf { epoch: 2 }));
    let mut anchor = dispute::load_state(&vip, &st_b1_2).unwrap();
    assert_eq!(dispute::group_values(&anchor).unwrap().0, rep.contexts[2]);
    assert!(matches!(dispute::replay_commits(&vip, &mut anchor, &log, 3).unwrap(), Replay::Done));
    assert_eq!(dispute::group_values(&anchor).unwrap().1, ea3);
    assert!(matches!(dispute::process_message(&mut anchor, &ct3).unwrap(), Processed::Application { sender_index: 0, .. }));

    // A Commit that mls-rs rejects puts the committer at fault.
    let mut forged = log.clone();
    let c = &mut forged.commits[1].commit;
    let n = c.len();
    c[n - 1] ^= 1;
    let mut anchor = dispute::load_state(&vip, &st_a2).unwrap();
    assert!(matches!(dispute::replay_commits(&vip, &mut anchor, &forged, 3).unwrap(), Replay::Rejected { epoch: 2, .. }));

    // b2 never processed its Welcome: it presents its KeyPackage's private
    // keys, and the verifier joins with the logged Welcome.
    match dispute::join_with_key_packages(&vip, &[kept_b2], &log).unwrap() {
        Join::Joined(mut gj) => {
            assert_eq!(gj.current_epoch(), 3);
            assert_eq!(dispute::group_values(&gj).unwrap().1, ea3);
            assert!(matches!(dispute::process_message(&mut gj, &ct3).unwrap(), Processed::Application { .. }));
        }
        _ => panic!("the verifier should join with b2's KeyPackage"),
    }
}
