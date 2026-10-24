#!/usr/bin/env python3
"""Generate the SCC examples in spec/examples/.

Every signed example is signed with a demo key derived from a fixed label,
so the output is reproducible. Signatures, EBW URLs, thumbprints and hashes are
real. Certificates are self-signed demo certificates. Timestamp tokens are
placeholders, marked as such, since no TSA is involved.

Writes, for each example, <name>.cbor and <name>.diag, plus manifest.json
listing the CDDL rule each example must (or must not) match.
"""

import base64
import datetime
import json
import os
import sys
import zlib

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(__file__))
from scc_cbor import (  # noqa: E402
    b64u, cose_key, dcbor, diag, url_from_create, ed25519_key, raw_public, sha256, sign1,
    thumbprint, u16, u64, vec, verify1,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "spec", "examples")
T0 = 1792310400  # 2026-10-17T12:00:00Z

manifest = []


def write(name, data: bytes, rule: str, valid=True):
    sub = "" if valid else "invalid"
    d = os.path.join(OUT, sub)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name + ".cbor")
    with open(path, "wb") as f:
        f.write(data)
    with open(os.path.join(d, name + ".diag"), "w") as f:
        f.write(diag(cbor2.loads(data)) + "\n")
    manifest.append({"file": os.path.relpath(path, OUT), "rule": rule, "valid": valid})


def demo_cert(key, cn: str) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DEMO ONLY")])
    t = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(t).not_valid_after(t + datetime.timedelta(days=730))
            .sign(key, None))
    return cert.public_bytes(Encoding.DER)


def placeholder_timestamp(seal: bytes) -> bytes:
    return b"DEMO-PLACEHOLDER-RFC3161-TOKEN:" + sha256(seal)


# ---- Keys and certificates ----

edd_key = ed25519_key("demo/edd/seal")
edd_cert = demo_cert(edd_key, "edd.europa.eu (demo)")
rds_a_key = ed25519_key("demo/rds-a/seal")
rds_a_cert = demo_cert(rds_a_key, "rds.example-provider.eu (demo)")
rds_b_key = ed25519_key("demo/rds-b/seal")
rds_b_cert = demo_cert(rds_b_key, "rds.other-provider.eu (demo)")
ebw_a_key = ed25519_key("demo/ebw-a/seal")
ebw_a_cert = demo_cert(ebw_a_key, "wallet.example-provider.eu (demo)")


def owner(label, provider, url, identifiers, policies):
    ukeys = [ed25519_key(f"demo/{label}/update/{i}") for i in range(2)]
    cred = ed25519_key(f"demo/{label}/credential/0")
    body = {
        "type": "create",
        "prev": None,
        "update_keys": [cose_key(k) for k in ukeys],
        "credential_keys": [cose_key(cred)],
        "rds": {"provider": provider, "url": url},
        "identifiers": identifiers,
        "acceptance_policies": policies,
        "signed_at": T0 - 86400,
    }
    op = sign1(ukeys[0], body)
    return {"ukeys": ukeys, "cred": cred, "body": body, "create": op, "owner": url_from_create(op)}


A = owner("owner-a", "rds.example-provider.eu", "https://rds.example-provider.eu",
          [{"type": "vat", "value": "DE123456789"}],
          {"default": "any"})
B = owner("owner-b", "rds.other-provider.eu", "https://rds.other-provider.eu",
          [{"type": "euid", "value": "FRRCS.552100554"}, {"type": "lei", "value": "969500XXDEMO00000001"}],
          {"default": "any", "invoices": ["quorum", 2]})

# ---- Discovery (01-discovery.md) ----

write("create-op", A["create"], "operation")

upd_body = dict(A["body"], type="update", prev=sha256(A["create"]), signed_at=T0 - 3600,
                acceptance_policies={"default": "any", "contracts": ["quorum", 2]})
update_op = sign1(A["ukeys"][1], upd_body)
write("update-op", update_op, "operation")


def head(owner_, op, seq, status="active", t=T0):
    return sign1(edd_key, {
        "type": "head-statement", "owner": owner_["owner"], "head": sha256(op), "seq": seq,
        "status": status, "issued_at": t, "expires_at": t + 300,
    }, {33: edd_cert})


head_a = head(A, update_op, 2)
head_b = head(B, B["create"], 1)
write("head-statement", head_a, "head-statement")

attest = sign1(edd_key, {
    "type": "identifier-attestation", "identifier": {"type": "vat", "value": "DE123456789"},
    "owner": A["owner"], "verified_at": T0 - 86400, "expires_at": T0 + 30 * 86400,
}, {33: edd_cert})
write("identifier-attestation", attest, "identifier-attestation")



def submission(op, t):
    """An operation sealed by owner A's EBW provider (01 §3.6)."""
    return sign1(ebw_a_key, {
        "type": "submission", "operation": op, "provider": "wallet.example-provider.eu",
        "submitted_at": t,
    }, {33: ebw_a_cert})


sub_create = submission(A["create"], T0 - 86400)
sub_update = submission(update_op, T0 - 3600)
write("submission", sub_update, "submission")
write("registration-request", dcbor({"submission": sub_create, "proof": b"EDD-defined proof"}),
      "registration-request")
write("resolution-response", dcbor({"operation": update_op, "head": head_a}), "resolution-response")
write("log", dcbor([
    {"submission": sub_create, "received_at": T0 - 86390, "overridden": False},
    {"submission": sub_update, "received_at": T0 - 3590, "overridden": False},
]), "log")

# ---- Credentials (02-credentials.md) ----

ep_a_key = ed25519_key("demo/owner-a/Kq7vT2mXr9Lp")
ep_b_key = ed25519_key("demo/owner-b/Bx4nW8sYt2Qe")
ep_b2_key = ed25519_key("demo/owner-b/Hc3pZ6uVj5Rd")


def status_uri(owner_):
    host = "status.example-provider.eu" if owner_ is A else "status.other-provider.eu"
    return f"https://{host}/{owner_['owner'][8:16]}/1"


def status_list_token(owner_, statuses, t):
    """A Token Status List CWT (draft-ietf-oauth-status-list), 2 bits per entry."""
    raw = bytearray((len(statuses) * 2 + 7) // 8)
    for i, s in enumerate(statuses):
        raw[(i * 2) // 8] |= s << ((i * 2) % 8)
    claims = {1: owner_["owner"], 2: status_uri(owner_), 6: t, 5: t, 4: t + 86400, 65534: 3600,
              65533: {"bits": 2, "lst": zlib.compress(bytes(raw), 9)}}
    cose = cbor2.loads(sign1(owner_["cred"], claims, {16: "application/statuslist+cwt"}))
    return dcbor(cbor2.CBORTag(18, cose))


# Owner B's list: entries 0 and 1 are B's two endpoints, entry 3 is revoked
# and entry 5 suspended (other endpoints, not used in the examples).
STATUSES_B = [0, 0, 0, 1, 0, 2, 0, 0]
STATUSES_A = [0] * 7 + [0]


def credential(owner_, ep_id, ep_key, roles, holder, idx):
    claims = {1: owner_["owner"], 2: ep_id, 4: T0 + 30 * 86400 - 86400, 5: T0 - 86400,
              6: T0 - 86400, 8: {1: cose_key(ep_key)},
              65535: {"status_list": {"idx": idx, "uri": status_uri(owner_)}},
              "roles": roles}
    if holder:
        claims["holder"] = holder
    return sign1(owner_["cred"], claims)


cred_a = credential(A, "Kq7vT2mXr9Lp", ep_a_key, ["default", "purchasing"], "h-41c9", 7)
cred_b = credential(B, "Bx4nW8sYt2Qe", ep_b_key, ["default", "invoices"], "h-07aa", 0)
cred_b2 = credential(B, "Hc3pZ6uVj5Rd", ep_b2_key, ["invoices"], "h-5f31", 1)
write("endpoint-credential", cred_a, "endpoint-credential")
write("endpoint-credential-b", cred_b, "endpoint-credential")

write("credential-request", sign1(ep_a_key, {
    "type": "credential-request", "owner": A["owner"], "subject": "Kq7vT2mXr9Lp",
    "roles": ["purchasing"], "key": cose_key(ep_a_key), "nonce": sha256(b"issuer nonce")[:16],
}), "credential-request")

write("connect-proof", sign1(ep_a_key, {
    "type": "connect-proof", "challenge": sha256(b"challenge")[:16],
    "provider": "rds.example-provider.eu", "owner": A["owner"],
    "subject": "Kq7vT2mXr9Lp", "signed_at": T0 + 50,
}), "connect-proof")

# ---- MLS (03-mls.md) ----

addr_a = {"owner": A["owner"], "role": "purchasing"}
addr_b = {"owner": B["owner"], "role": "invoices"}
message_id = sha256(b"message 1")[:16]
session_id = sha256(b"session 1")[:16]
sent_at = T0 + 60
expires_at = sent_at + 14 * 86400

app_message = dcbor({
    "message_id": message_id, "from": addr_a, "to": addr_b,
    "sent_at": sent_at, "expires_at": expires_at, "consignment": "consented",
    "content_type": "application/pdf", "subject": "Invoice 2026-0815",
    "salt": sha256(b"salt 1")[:16], "body": b"%PDF-1.7 (demo body)",
})
write("app-message", app_message, "app-message")
plaintext_hash = sha256(app_message)

# A fake MLSMessage. Its bytes are not a real PrivateMessage; only its
# hash (envelope_hash) appears in evidence.
mls_message = b"\x00\x01\x00\x02" + vec(session_id) + u64(6) + b"(demo ciphertext)"
envelope_hash = sha256(mls_message)


def address_tls(a):
    return vec(a["owner"].encode()) + vec(a["role"].encode())


def group_context(epoch):
    scc_session = address_tls(addr_a) + address_tls(addr_b)
    required_caps = vec(u16(0xF0EC)) + vec(b"") + vec(u16(0x0003) + u16(0xF0EB))
    extensions = (u16(0xF0EC) + vec(scc_session)) + (u16(0x0003) + vec(required_caps))
    return (u16(1) + u16(1) + vec(session_id) + u64(epoch)
            + vec(sha256(b"tree hash %d" % epoch))
            + vec(sha256(b"confirmed transcript hash %d" % epoch))
            + vec(extensions))


gc6 = group_context(6)
epoch_auth = sha256(b"demo epoch authenticator 6")

# ---- Evidence (05-evidence.md) ----

ETSI = "http://uri.etsi.org/19522/Event/"
EVENTS = {
    "A.1": "SubmissionAcceptance", "A.2": "SubmissionRejection", "B.1": "RelayAcceptance",
    "B.2": "RelayRejection", "B.3": "RelayFailure", "C.1": "NotificationForAcceptance",
    "C.2": "NotificationForAcceptanceFailure", "C.3": "ConsignmentAcceptance",
    "C.4": "ConsignmentRejection", "C.5": "AcceptanceRejectionExpiry",
    "C.6": "NotificationDelivered", "D.1": "ContentConsignment",
    "D.2": "ContentConsignmentFailure",
    "E.1": "ContentHandover", "E.2": "ContentHandoverFailure",
}


def message_ref_for(mid, mode, ph, eh):
    return {"message_id": mid, "session_id": session_id, "from": addr_a, "to": addr_b,
            "sent_at": sent_at, "expires_at": expires_at, "consignment": mode,
            "plaintext_hash": ph, "envelope_hash": eh}


message_ref = message_ref_for(message_id, "consented", plaintext_hash, envelope_hash)
mls_ref = {"group_context": gc6, "epoch_authenticator": epoch_auth}
policy = ["https://rds.example-provider.eu/policy/erds-2026"]
issuer_a = {"provider": "rds.example-provider.eu", "name": "Example Provider SE", "policies": policy}
issuer_b = {"provider": "rds.other-provider.eu", "name": "Other Provider SAS",
            "policies": ["https://rds.other-provider.eu/policy/erds"]}
LOA_HIGH = "http://eidas.europa.eu/LoA/high"
SCC_AUTH = "urn:ebw:scc:auth:endpoint-credential"
EDD_ID_POLICY = "https://edd.europa.eu/policy/identification"
sender_assurance = {"identity": {"level": LOA_HIGH, "policy": EDD_ID_POLICY},
                    "authentication": {"level": LOA_HIGH, "method": SCC_AUTH, "at": T0 + 50}}


def recipient_assurance(t):
    return {"identity": {"level": LOA_HIGH, "policy": EDD_ID_POLICY},
            "authentication": {"level": LOA_HIGH, "method": SCC_AUTH, "at": t}}


def artefact(key, cert, body):
    seal = sign1(key, body, {33: cert})
    return dcbor([seal, placeholder_timestamp(seal)])


def seal_hash(art):
    return sha256(cbor2.loads(art)[0])


def evid(n):
    return sha256(b"evidence %d" % n)[:16]


def message_evidence(n, code, issuer, t, mref=None, **extra):
    body = {"v": 1, "evidence_id": evid(n), "event": ETSI + EVENTS[code], "issuer": issuer,
            "event_time": t, "message": mref or message_ref, "mls": mls_ref,
            # head statements fetched shortly before the event, so unexpired at it
            "heads": [head(A, update_op, 2, t=t - 30), head(B, B["create"], 1, t=t - 30)],
            "sender_assurance": sender_assurance}
    body.update(extra)
    return body


ep_ref_a = {"owner": A["owner"], "subject": "Kq7vT2mXr9Lp"}
status_a = status_list_token(A, STATUSES_A, sent_at - 600)
status_b = status_list_token(B, STATUSES_B, sent_at - 600)
write("status-list-token", status_b, "status-list-token")
a1 = artefact(rds_a_key, rds_a_cert, message_evidence(
    1, "A.1", issuer_a, sent_at + 1, endpoint=ep_ref_a, statuses=[status_a]))
b1 = artefact(rds_b_key, rds_b_cert, message_evidence(
    2, "B.1", issuer_b, sent_at + 2, prev=[seal_hash(a1)], peer="rds.example-provider.eu"))
c1 = artefact(rds_b_key, rds_b_cert, message_evidence(
    3, "C.1", issuer_b, sent_at + 3, prev=[seal_hash(b1)], eligible_holders=2))
c6 = artefact(rds_b_key, rds_b_cert, message_evidence(
    4, "C.6", issuer_b, sent_at + 120, prev=[seal_hash(c1)],
    endpoint={"owner": B["owner"], "subject": "Bx4nW8sYt2Qe"}, statuses=[status_b]))


def endpoint_statement(key, cred, body):
    return sign1(key, body, {"scc-cred": cred})


decisions = [
    endpoint_statement(k, c, {
        "type": "consent-decision", "message_id": message_id, "session_id": session_id,
        "envelope_hash": envelope_hash, "decision": "accept", "owner": B["owner"],
        "subject": ep, "holder": h, "decided_at": sent_at + dt})
    for k, c, ep, h, dt in [(ep_b_key, cred_b, "Bx4nW8sYt2Qe", "h-07aa", 600),
                            (ep_b2_key, cred_b2, "Hc3pZ6uVj5Rd", "h-5f31", 900)]
]
write("consent-decision", decisions[0], "signed-consent-decision")

c3 = artefact(rds_b_key, rds_b_cert, message_evidence(
    5, "C.3", issuer_b, sent_at + 901, prev=[seal_hash(c6)], decisions=decisions,
    statuses=[status_b],
    recipient_assurance=recipient_assurance(sent_at + 880)))
d1 = artefact(rds_b_key, rds_b_cert, message_evidence(
    6, "D.1", issuer_b, sent_at + 902, prev=[seal_hash(c3)]))

report = endpoint_statement(ep_b_key, cred_b, {
    "type": "decryption-report", "message_id": message_id, "session_id": session_id,
    "epoch": 6, "envelope_hash": envelope_hash, "result": "match",
    "owner": B["owner"], "subject": "Bx4nW8sYt2Qe",
    "reported_at": sent_at + 910,
})
write("decryption-report", report, "signed-decryption-report")
e1 = artefact(rds_b_key, rds_b_cert, message_evidence(
    7, "E.1", issuer_b, sent_at + 911, prev=[seal_hash(d1)],
    endpoint={"owner": B["owner"], "subject": "Bx4nW8sYt2Qe"},
    handovers=[{"subject": "Bx4nW8sYt2Qe", "transferred_at": sent_at + 905,
                "acknowledged_at": sent_at + 910, "result": "match"}],
    reports=[report], reason={"code": "RE01"}, statuses=[status_b],
    recipient_assurance=recipient_assurance(sent_at + 880)))

for name, art in [("evidence-a1", a1), ("evidence-b1", b1), ("evidence-c1", c1),
                  ("evidence-c6", c6), ("evidence-c3", c3), ("evidence-d1", d1),
                  ("evidence-e1", e1)]:
    write(name, art, "evidence-artefact")

package = artefact(rds_a_key, rds_a_cert, {
    "v": 1, "type": "evidence-package", "message_id": message_id,
    "composed_at": sent_at + 1000,
    "items": [cbor2.loads(x) for x in (a1, b1, c1, c6, c3, d1, e1)],
})
write("evidence-package", package, "evidence-artefact")

# A second message, in basic mode, whose handover failed: one recipient
# endpoint reported a decryption failure, and no match report arrived
# before expires_at.
message_id2 = sha256(b"message 2")[:16]
envelope_hash2 = sha256(b"demo ciphertext 2")
mref2 = message_ref_for(message_id2, "basic", sha256(b"plaintext 2"), envelope_hash2)
report2 = endpoint_statement(ep_b_key, cred_b, {
    "type": "decryption-report", "message_id": message_id2, "session_id": session_id,
    "epoch": 6, "envelope_hash": envelope_hash2, "result": "decrypt-failed",
    "owner": B["owner"], "subject": "Bx4nW8sYt2Qe", "reported_at": sent_at + 1300,
})
e2_failed = artefact(rds_b_key, rds_b_cert, message_evidence(
    8, "E.2", issuer_b, expires_at, mref=mref2,
    prev=[sha256(b"seal of message 2's D.1, not shown")],
    reason={"code": "REXX", "scc": "decryption-failed"},
    handovers=[{"subject": "Bx4nW8sYt2Qe", "transferred_at": sent_at + 1290,
                "acknowledged_at": sent_at + 1300, "result": "decrypt-failed"}],
    reports=[report2], statuses=[status_list_token(B, STATUSES_B, sent_at + 1240)]))
write("evidence-e2-decryption-failed", e2_failed, "evidence-artefact")

# A fourth message, transferred to an endpoint that never sent a
# decryption report before expires_at.
mref4 = message_ref_for(sha256(b"message 4")[:16], "basic", sha256(b"plaintext 4"),
                        sha256(b"demo ciphertext 4"))
e2_silent = artefact(rds_b_key, rds_b_cert, message_evidence(
    12, "E.2", issuer_b, expires_at, mref=mref4,
    prev=[sha256(b"seal of message 4's D.1, not shown")],
    reason={"code": "RE04", "scc": "not-acknowledged"},
    handovers=[{"subject": "Hc3pZ6uVj5Rd", "transferred_at": sent_at + 3600}]))
write("evidence-e2-not-acknowledged", e2_silent, "evidence-artefact")

# A third message, rejected at submission because an eligible endpoint of
# the recipient has no KeyPackage (03-mls.md §5.1).
mref3 = message_ref_for(sha256(b"message 3")[:16], "basic", sha256(b"plaintext 3"),
                        sha256(b"demo ciphertext 3"))
a2 = artefact(rds_a_key, rds_a_cert, message_evidence(
    9, "A.2", issuer_a, sent_at + 2, mref=mref3, endpoint=ep_ref_a, statuses=[status_a],
    reason={"code": "RA05", "scc": "no-keypackage",
            "text": "Recipient endpoint Mf8kD1yGn7Ta has no KeyPackage"}))
write("evidence-a2", a2, "evidence-artefact")

commit_ref = sha256(b"demo commit 7")
cf_report = endpoint_statement(ep_b2_key, cred_b2, {
    "type": "commit-failure-report", "session_id": session_id, "commit_ref": commit_ref,
    "epoch": 7, "failure": "confirmation-tag",
    "last_agreed": {"epoch": 6, "epoch_authenticator": epoch_auth},
    "owner": B["owner"], "subject": "Hc3pZ6uVj5Rd", "reported_at": sent_at + 2000,
})
write("commit-failure-report", cf_report, "signed-commit-failure-report")
x2 = artefact(rds_b_key, rds_b_cert, {
    "v": 1, "evidence_id": evid(10), "event": "urn:ebw:scc:event:CommitFailure",
    "issuer": issuer_b, "event_time": sent_at + 2001, "session_id": session_id,
    "commit_ref": commit_ref, "group_context": group_context(7), "report": cf_report,
})
write("evidence-commit-failure", x2, "evidence-artefact")

# ---- Invalid examples: each must fail its rule ----

too_many = dict(A["body"], update_keys=[cose_key(ed25519_key(f"x{i}")) for i in range(6)])
write("create-op-six-update-keys", sign1(A["ukeys"][0], too_many), "operation", valid=False)

bad_claims = {1: A["owner"], 2: "Zz0aaaaaaaa0", 4: T0, 5: T0, 6: T0, 8: {1: cose_key(ep_a_key)}, "roles": []}
write("credential-no-roles", sign1(A["cred"], bad_claims), "endpoint-credential", valid=False)

no_status = cbor2.loads(cbor2.loads(cred_a)[2])
del no_status[65535]
write("credential-no-status", sign1(A["cred"], no_status), "endpoint-credential", valid=False)

# D.3 ConsignmentNotification is not used by SCC (04-delivery.md §7.6)
bad_event = message_evidence(11, "D.1", issuer_b, sent_at)
bad_event["event"] = ETSI + "ConsignmentNotification"
write("evidence-bad-event", artefact(rds_b_key, rds_b_cert, bad_event), "evidence-artefact",
      valid=False)

write("app-message-short-salt", dcbor({
    "message_id": message_id, "from": addr_a, "to": addr_b, "sent_at": sent_at,
    "expires_at": expires_at, "consignment": "basic", "content_type": "text/plain",
    "salt": b"short", "body": b"hi",
}), "app-message", valid=False)

write("head-statement-bad-owner", sign1(edd_key, {
    "type": "head-statement", "owner": "ebw:TOO-SHORT", "head": sha256(b"x"), "seq": 1,
    "status": "active", "issued_at": T0, "expires_at": T0 + 300,
}, {33: edd_cert}), "head-statement", valid=False)

# ---- JSON-RPC examples (04-delivery.md) ----

rpc_manifest = []


def rpc(name, direction, *messages):
    d = os.path.join(OUT, "delivery")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name + ".json"), "w") as f:
        json.dump({"direction": direction, "messages": list(messages)}, f, indent=2)
        f.write("\n")
    rpc_manifest.append(f"delivery/{name}.json")


def req(id_, method, params):
    m = {"jsonrpc": "2.0", "method": method, "params": params}
    if id_ is not None:
        m = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}
    return m


def res(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def err(id_, code, message, data=None):
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": e}


ep_a = "Kq7vT2mXr9Lp"
challenge = sha256(b"challenge")[:16]
fake_kp = [b64u(b"\x00\x01\x00\x01(demo KeyPackage %d)" % i) for i in range(3)]
meta = {"message_id": b64u(message_id), "from": addr_a, "to": addr_b,
        "sent_at": sent_at, "expires_at": expires_at, "consignment": "consented"}
msg_fields = {"session_id": b64u(session_id), "message": b64u(mls_message), "meta": meta,
              "plaintext_hash": b64u(plaintext_hash), "epoch_authenticator": b64u(epoch_auth)}
fake_commit = b64u(b"\x00\x01\x00\x01" + vec(session_id) + u64(5) + b"(demo Commit)")
fake_welcome = b64u(b"\x00\x01\x00\x03(demo Welcome)")
fake_group_info = b64u(b"\x00\x01\x00\x04" + vec(session_id) + u64(0) + b"(demo GroupInfo)")

rpc("connect", "endpoint-to-rds",
    req("c1", "scc.connect", {"versions": ["scc/1"], "owner": A["owner"], "subject": ep_a}),
    res("c1", {"version": "scc/1", "challenge": b64u(challenge), "expires_at": T0 + 120}),
    req("c2", "scc.authenticate", {"credential": b64u(cred_a), "signature": b64u(
        sign1(ep_a_key, {"type": "connect-proof", "challenge": challenge,
                         "provider": "rds.example-provider.eu", "owner": A["owner"],
                         "subject": ep_a, "signed_at": T0 + 50}))}),
    res("c2", {"registered": True, "queue_head": 417}),
    req("c3", "wmp.message.fetch", {"after": 412}),
    res("c3", {"items": [{"method": "scc.keypackage.status",
                          "params": {"seq": 413, "available": {"1": 4}}}],
               "more": False}),
    req("c4", "scc.queue.ack", {"up_to": 413}),
    res("c4", {"removed": 1}))

rpc("keypackages", "endpoint-to-rds",
    req("k1", "scc.keypackage.publish", {"key_packages": fake_kp}),
    res("k1", {"available": {"1": 12}}),
    req("k2", "scc.keypackage.get", {"address": addr_b, "cipher_suite": 1}),
    res("k2", {"reservation": "Tz0b5sN1cWQe7uJ9", "expires_at": T0 + 360, "eligible": ["Bx4nW8sYt2Qe", "Hc3pZ6uVj5Rd"],
               "key_packages": [{"subject": "Bx4nW8sYt2Qe", "key_package": fake_kp[0]},
                                {"subject": "Hc3pZ6uVj5Rd", "key_package": fake_kp[1]}],
               "missing": []}))

rpc("session", "endpoint-to-rds",
    req("s1", "wmp.session.create", {"session_id": b64u(session_id), "group_info": fake_group_info,
                                     "commit": fake_commit, "welcome": fake_welcome,
                                     "reservations": ["Tz0b5sN1cWQe7uJ9"]}),
    res("s1", {"epoch": 1}),
    req("s2", "scc.commit.submit", {"session_id": b64u(session_id), "commit": fake_commit}),
    err("s2", -31102, "Commit conflict"),
    req("s3", "scc.commit.fetch", {"session_id": b64u(session_id), "after_epoch": 5}),
    res("s3", {"commits": [{"epoch": 6, "commit": fake_commit, "accepted_at": T0 + 30}]}))

rpc("submit", "endpoint-to-rds",
    req("m1", "wmp.message.deliver", msg_fields),
    err("m1", -31100, "Membership mismatch",
        {"add": [{"owner": B["owner"], "subject": "Mf8kD1yGn7Ta"}], "remove": []}),
    req("m2", "wmp.message.deliver", msg_fields),
    res("m2", {"evidence": b64u(a1)}),
    req("m3", "wmp.message.deliver", dict(msg_fields, meta=dict(meta, message_id=b64u(mref3["message_id"])))),
    err("m3", -31105, "No KeyPackage",
        {"subjects": [{"owner": B["owner"], "subject": "Mf8kD1yGn7Ta"}], "evidence": b64u(a2)}))

rpc("relay", "rds-to-rds",
    req("r1", "wmp.message.deliver", dict(msg_fields, submission_evidence=b64u(a1),
                                         relayed_at=sent_at + 2)),
    res("r1", {"evidence": b64u(b1)}),
    req("r2", "wmp.evidence.notify", {"event": "E.1", "message_id": b64u(message_id),
                                      "evidence": b64u(e1)}),
    res("r2", {"stored": True}))

rpc("federation", "rds-to-rds",
    req("f1", "scc.rds.subjects", {"address": addr_b, "cipher_suite": 1}),
    res("f1", {"as_of": T0 + 55, "expires_at": T0 + 115, "subjects": ["Bx4nW8sYt2Qe", "Hc3pZ6uVj5Rd", "Mf8kD1yGn7Ta"],
               "no_key_packages": ["Mf8kD1yGn7Ta"]}),
    req("f2", "scc.rds.commit", {"session_id": b64u(session_id), "commit": fake_commit}),
    res("f2", {"status": "accepted", "epoch": 6}))

rpc("consignment", "rds-to-endpoint",
    req(None, "scc.consent.request", {"seq": 501, "session_id": b64u(session_id), "meta": meta,
                                      "envelope_hash": b64u(envelope_hash), "size": len(mls_message)}),
    req(None, "wmp.message.deliver", dict(msg_fields, seq=502)),
    req(None, "scc.handshake", {"seq": 503, "session_id": b64u(session_id), "epoch": 7,
                                "commit": fake_commit}),
    req(None, "wmp.evidence.notify", {"seq": 504, "event": "C.3", "message_id": b64u(message_id),
                                      "evidence": b64u(c3)}))

rpc("acks", "endpoint-to-rds",
    req("a1", "wmp.message.ack", {"message_id": b64u(message_id), "status": "accepted",
                                  "decision": b64u(decisions[0])}),
    res("a1", {"recorded": True}),
    req("a2", "wmp.message.ack", {"message_id": b64u(message_id), "status": "processed",
                                  "report": b64u(report)}),
    res("a2", {"recorded": True, "evidence": b64u(e1)}),
    req("a3", "scc.evidence.get", {"message_id": b64u(message_id)}),
    res("a3", {"package": b64u(package)}))

rpc("commit-failure", "endpoint-to-rds",
    req("x1", "scc.commit.report", {"session_id": b64u(session_id), "epoch": 7,
                                    "report": b64u(cf_report)}),
    res("x1", {"closed": True, "evidence": b64u(x2)}),
    req("x2", "scc.session.log", {"session_id": b64u(session_id)}),
    res("x2", {"group_info": fake_group_info,
               "commits": [{"epoch": 1, "commit": fake_commit, "welcome": fake_welcome,
                            "accepted_at": T0}]}),
    req("x3", "scc.deregister", {}),
    res("x3", {"deregistered": True}))

rpc("federation-sessions", "rds-to-rds",
    req("g1", "scc.rds.keypackage.reserve", {
        "address": addr_b, "cipher_suite": 1,
        "requester": {"owner": A["owner"], "subject": ep_a}}),
    res("g1", {"reservation": "Tz0b5sN1cWQe7uJ9", "expires_at": T0 + 360, "eligible": ["Bx4nW8sYt2Qe", "Hc3pZ6uVj5Rd"],
               "key_packages": [{"subject": "Bx4nW8sYt2Qe", "key_package": fake_kp[0]}],
               "missing": ["Hc3pZ6uVj5Rd"]}),
    req("g2", "scc.rds.session.create", {"session_id": b64u(session_id),
                                         "group_info": fake_group_info}),
    res("g2", {"registered": True}),
    req("g3", "scc.rds.commit.report", {"session_id": b64u(session_id), "evidence": b64u(x2)}),
    res("g3", {"closed": True}))

rpc("keypackage-status", "rds-to-endpoint",
    req(None, "scc.keypackage.status", {"seq": 505, "available": {"1": 4, "2": 9}}))

# ---- JSON documents (01-discovery.md, 04-delivery.md) ----

def write_json(name, obj, schema):
    path = os.path.join(OUT, "json", name + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    rpc_manifest.append({"file": f"json/{name}.json", "schema": schema})


write_json("rds-metadata", {
    "provider": "rds.example-provider.eu",
    "governing_body": {"name": "Example Provider SE", "identifier": "urn:ebw:euid:DEHRB.HRB999999"},
    "trust_domains": ["eu-qualified"], "versions": ["scc/1"],
    "endpoints": {"client": "wss://rds.example-provider.eu/scc",
                  "federation": "https://rds.example-provider.eu/scc/federation"},
    "cipher_suites": [1, 2], "consignment_modes": ["basic", "consented"],
    "max_message_size": 26214400, "max_ttl": 2592000, "session_idle_limit": 31536000,
    "max_clock_skew": 300,
    "expiry": True, "scheduled_delivery": False,
    "assurance": {"identity": [LOA_HIGH], "authentication": [LOA_HIGH]},
    "evidence": {"policies": ["https://rds.example-provider.eu/policy/erds-2026"], "retention": "P10Y",
                 "seal_certificates": [[base64.b64encode(rds_a_cert).decode()]]},
}, "rds-metadata.schema.json")

write_json("edd-metadata", {
    "edd": "https://edd.europa.eu",
    "seal_certificates": [{"x5c": [base64.b64encode(edd_cert).decode()],
                           "not_before": "2026-01-01T00:00:00Z", "not_after": "2028-01-01T00:00:00Z"}],
    "identifier_types": ["euid", "lei", "vat", "eori", "iso6523"],
    "recovery_window": 604800,
}, "edd.openapi.yaml#EddMetadata")

# ---- Self-checks ----

assert verify1(raw_public(A["ukeys"][0]), A["create"])["type"] == "create"
assert verify1(raw_public(A["ukeys"][1]), update_op)["prev"] == sha256(A["create"])
claims = verify1(raw_public(A["cred"]), cred_a)
assert claims[8][1] == cose_key(ep_a_key)
assert thumbprint(cose_key(A["cred"])) == cbor2.loads(
    cbor2.loads(cred_a)[0])[4]
verify1(raw_public(ep_b_key), report)

with open(os.path.join(OUT, "manifest.json"), "w") as f:
    json.dump({"generated_by": "tools/gen_examples.py", "owners": {"A": A["owner"], "B": B["owner"]},
               "examples": manifest, "json": rpc_manifest}, f, indent=2)
    f.write("\n")

print(f"owner A: {A['owner']}\nowner B: {B['owner']}\nwrote {len(manifest)} examples to {OUT}")
