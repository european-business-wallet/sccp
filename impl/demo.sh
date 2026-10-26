#!/usr/bin/env bash
# End-to-end demo of the SCC reference implementation.
#
#   EDD + two RDSes (different providers) + two owners with two endpoints
#   each; a session; messages in both directions; evidence collection;
#   verification against the plaintext; and negative cases.
#
# Usage: ./demo.sh            (work directory: target/demo)
#        WORK=/tmp/x ./demo.sh
#        KEEP=1 ./demo.sh     (leave servers running until Enter is pressed)

set -euo pipefail
cd "$(dirname "$0")"

WORK="${WORK:-$PWD/target/demo}"
EDD_PORT="${EDD_PORT:-18440}"
RDSA_PORT="${RDSA_PORT:-18441}"
RDSB_PORT="${RDSB_PORT:-18442}"
EDD="https://localhost:$EDD_PORT"
RDSA="https://localhost:$RDSA_PORT/scc-rds"
RDSB="https://localhost:$RDSB_PORT/scc-rds"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
step() { printf '\033[36m-- %s\033[0m\n' "$*"; }

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

bold "Building"
cargo build --quiet --bins
BIN="$PWD/target/debug"
EDD_BIN="$BIN/scc-edd"; RDS_BIN="$BIN/scc-rds"; EP="$BIN/scc-endpoint"; VERIFY="$BIN/scc-verifier"

rm -rf "$WORK"; mkdir -p "$WORK"/{edd,rds-a,rds-b,ebw-a,ebw-b,pki,logs,owners,ep,bundles}

bold "PKI (demo stand-ins: self-signed seals, local TSA, configured trust anchors)"
"$EDD_BIN" pki-tls --out "$WORK/pki" >/dev/null
"$EDD_BIN" init --dir "$WORK/edd" >/dev/null
"$RDS_BIN" init --dir "$WORK/rds-a" --name "RDS A" >/dev/null
"$RDS_BIN" init --dir "$WORK/rds-b" --name "RDS B" >/dev/null
"$EP" owner provider-init --dir "$WORK/ebw-a" --provider ebw-a.demo >/dev/null
"$EP" owner provider-init --dir "$WORK/ebw-b" --provider ebw-b.demo >/dev/null
"$EDD_BIN" pki-trust --out "$WORK/pki/trust.json" \
  --edd "$WORK/edd/seal-cert.der" \
  --rds "$WORK/rds-a/seal-cert.der" --rds "$WORK/rds-b/seal-cert.der" \
  --tsa "$WORK/rds-a/tsa-cert.der" --tsa "$WORK/rds-b/tsa-cert.der" \
  --ebw "$WORK/ebw-a/seal-cert.der" --ebw "$WORK/ebw-b/seal-cert.der" >/dev/null
export SCC_TLS_CA="$WORK/pki/ca.pem"
export SCC_TRUST="$WORK/pki/trust.json"
TLS=(--tls-cert "$WORK/pki/server.pem" --tls-key "$WORK/pki/server-key.pem")
echo "trust store: $SCC_TRUST"

bold "Starting the EDD and two RDSes"
"$EDD_BIN" serve --dir "$WORK/edd" --listen "127.0.0.1:$EDD_PORT" --base-url "$EDD" "${TLS[@]}" \
  >"$WORK/logs/edd.log" 2>&1 & PIDS+=($!)
"$RDS_BIN" serve --dir "$WORK/rds-a" --name "RDS A Provider SE (demo)" \
  --listen "127.0.0.1:$RDSA_PORT" --url "$RDSA" --edd "$EDD" --trust "$SCC_TRUST" "${TLS[@]}" --subjects-ttl 2 \
  >"$WORK/logs/rds-a.log" 2>&1 & PIDS+=($!)
"$RDS_BIN" serve --dir "$WORK/rds-b" --name "RDS B Provider AB (demo)" \
  --listen "127.0.0.1:$RDSB_PORT" --url "$RDSB" --edd "$EDD" --trust "$SCC_TRUST" "${TLS[@]}" --subjects-ttl 2 \
  >"$WORK/logs/rds-b.log" 2>&1 & PIDS+=($!)
for url in "$EDD/.well-known/edd" "$RDSA" "$RDSB"; do
  for _ in $(seq 1 50); do curl -sf --cacert "$SCC_TLS_CA" "$url" >/dev/null && break; sleep 0.2; done
  curl -sf --cacert "$SCC_TLS_CA" "$url" >/dev/null || { echo "$url did not start"; exit 1; }
done
echo "EDD $EDD, RDS A $RDSA, RDS B $RDSB"
PY=python3; [ -x ../.venv/bin/python ] && PY=../.venv/bin/python
if "$PY" -c "import jsonschema" 2>/dev/null; then
  for r in "$RDSA" "$RDSB"; do
    curl -sf --cacert "$SCC_TLS_CA" "$r" >"$WORK/metadata.json"
    "$PY" -c "import json,jsonschema,sys; jsonschema.validate(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))" \
      "$WORK/metadata.json" ../spec/schemas/rds-metadata.schema.json && echo "RDS metadata at $r matches rds-metadata.schema.json"
  done
fi

bold "Registering two EBW owners with the EDD (each through its EBW provider, which seals the submission)"
A=$("$EP" owner init --dir "$WORK/owners/a" --edd "$EDD" --provider "$WORK/ebw-a" --rds-url "$RDSA" \
    --identifier vat:DE123456789 --policy invoices=any)
B=$("$EP" owner init --dir "$WORK/owners/b" --edd "$EDD" --provider "$WORK/ebw-b" --rds-url "$RDSB" \
    --identifier vat:SE556677889901 --policy invoices=quorum:2)
echo "owner A: $A  (home RDS $RDSA)"
echo "owner B: $B  (home RDS $RDSB)"

# new_endpoint OWNER NAME RDSURL ROLES HOLDER
new_endpoint() {
  local owner=$1 name=$2 rds=$3 roles=$4 holder=$5 url
  url=$("$EP" owner url --dir "$WORK/owners/$owner")
  "$EP" init --dir "$WORK/ep/$name" --owner "$url" --rds "$rds" --edd "$EDD" --roles "$roles" >/dev/null
  "$EP" owner issue --dir "$WORK/owners/$owner" --request "$WORK/ep/$name/credential-request.cbor" \
    --out "$WORK/ep/$name/credential.cbor" --holder "$holder"
}

bold "Enrolling endpoints (credentials issued by each owner)"
new_endpoint a a1 "$RDSA" default,purchasing h-a1
new_endpoint a a2 "$RDSA" default,purchasing h-a2
new_endpoint b b1 "$RDSB" default,invoices h-b1
new_endpoint b b2 "$RDSB" default,invoices h-b2
step "owners publish their status lists (hosted by their home RDS)"
"$EP" owner publish-status --dir "$WORK/owners/a"
"$EP" owner publish-status --dir "$WORK/owners/b"
step "endpoints register with their home RDS and publish KeyPackages"
for e in a1 a2 b1 b2; do "$EP" register --dir "$WORK/ep/$e" --credential "$WORK/ep/$e/credential.cbor"; done

send() { # FROM_EP ROLE TO BODY [extra args]
  local ep=$1 role=$2 to=$3 body=$4; shift 4
  "$EP" send --dir "$WORK/ep/$ep" --from-role "$role" --to "$to" --body "$body" --id-out "$WORK/last-id" "$@" >&2
  cat "$WORK/last-id"
}
sync() { for e in "$@"; do echo "[$e]"; "$EP" sync --dir "$WORK/ep/$e" | sed 's/^/  /'; done; }

bold "Message 1: A/purchasing (a1) -> B/invoices, creating a session"
M1=$(send a1 purchasing "$B#invoices" "Purchase order 4711: 100 widgets at EUR 2.50" --subject "PO 4711")
sleep 1
step "B's endpoints process their queues (Welcome, message, decryption report)"
sync b1 b2
sleep 1
step "A's endpoints process their queues (Welcome for a2, evidence for a1)"
sync a1 a2

bold "Message 2: B/invoices (b2) -> A/purchasing, in the same session"
M2=$(send b2 invoices "$A#purchasing" "Invoice 2026-0815 for PO 4711: EUR 250.00" --subject "Invoice")
sleep 1
sync a2 a1
sleep 1
sync b2 b1
step "b2 exports its verification bundle for message 2 now (it is revoked later)"
"$EP" export --dir "$WORK/ep/b2" --message="$M2" --out "$WORK/bundles/m2-sender"

bold "Message 3: A/purchasing (a2) -> B/invoices"
M3=$(send a2 purchasing "$B#invoices" "Payment of EUR 250.00 sent for invoice 2026-0815")
sleep 1
sync b1 b2
sleep 1
sync a2 a1

bold "Membership change: owner B enrols a third endpoint (b3, same holder as b1)"
new_endpoint b b3 "$RDSB" default,invoices h-b1
"$EP" owner publish-status --dir "$WORK/owners/b"
"$EP" register --dir "$WORK/ep/b3" --credential "$WORK/ep/b3/credential.cbor"
sleep 3
step "the next send gets -31100 (membership mismatch) and a1 commits an Add for b3 before resending"
M4=$(RUST_LOG=info send a1 purchasing "$B#invoices" "Delivery note for PO 4711" 2> >(grep -E "membership|created" >&2 || true))
sleep 1
sync b3 b1 b2
sleep 1
sync a1 a2

bold "Message 5: consented consignment; B's policy for invoices is quorum:2 (holders, not endpoints)"
M5=$(send a1 purchasing "$B#invoices" "Contract amendment 7: please accept" --consignment consented --subject "Amendment 7")
sleep 1
step "b1 and b3 accept (one holder, h-b1), then b2 accepts (holder h-b2): quorum met -> C.3, D.1"
sync b1 b3 b2
sleep 1
step "handover"
sync b1 b2 b3
sleep 1
sync a1 a2

bold "Message 6: short expiry, and the recipients stay offline -> E.2 (expired)"
M6=$(send a2 purchasing "$B#invoices" "This one will not be collected in time" --ttl 4)
echo "waiting for expiry..."
sleep 7
sync a2

bold "Revocation: owner B revokes b2's credential and publishes a new status list"
B2SUB=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['subject'])" "$WORK/ep/b2/endpoint.json")
"$EP" owner revoke --dir "$WORK/owners/b" --subject="$B2SUB"
sleep 3
step "the next send gets -31100 with b2's leaf in 'remove'; a1 commits a Remove and resends"
M7=$(RUST_LOG=info send a1 purchasing "$B#invoices" "Final reminder for PO 4711" 2> >(grep -E "membership" >&2 || true))
sleep 1
step "b2 can no longer authenticate to its RDS"
"$EP" sync --dir "$WORK/ep/b2" 2>&1 | sed 's/^/  [b2] /' || true
sync b1 b3
sleep 1
sync a1 a2

bold "Message 8: dishonest recipients claim they cannot decrypt (message-key dispute, doc 5 §7.4)"
step "b1 and b3 are set to report every message as decrypt-failed (a demo switch)"
"$EP" configure --dir "$WORK/ep/b1" --false-report decrypt-failed
"$EP" configure --dir "$WORK/ep/b3" --false-report decrypt-failed
M8=$(send a1 purchasing "$B#invoices" "Order confirmation 4712")
sleep 1
sync b1 b3
sleep 1
sync a1 a2
"$EP" configure --dir "$WORK/ep/b1" --false-report none
"$EP" configure --dir "$WORK/ep/b3" --false-report none

bold "Message 9: RDS B unreachable at submission (store and forward, doc 3 §5)"
step "RDS A loses contact with RDS B (a demo switch simulating a network partition)"
"$RDS_BIN" partition --rds "$RDSA" --peer "$RDSB"
sleep 3   # let RDS A's cached scc.rds.subjects answer expire
step "a1 sends: RDS A checks A's side only, issues A.1, and holds the message for relay"
M9=$(send a1 purchasing "$B#invoices" "Shipping notice for PO 4712")
"$EP" list --dir "$WORK/ep/a1" | grep -F "$M9" | sed 's/^/  /' || true
step "contact returns; RDS A relays, and RDS B checks B's side: B.1, then delivery"
"$RDS_BIN" partition --rds "$RDSA" --peer "$RDSB" --heal
sleep 6
sync b1 b3
sleep 1
sync a1 a2

bold "Message 10: B's membership changes while RDS B is unreachable"
"$RDS_BIN" partition --rds "$RDSA" --peer "$RDSB"
sleep 3
M10=$(send a1 purchasing "$B#invoices" "Shipping notice for PO 4713")
step "meanwhile owner B enrols b4; RDS A cannot see it"
new_endpoint b b4 "$RDSB" default,invoices h-b4
"$EP" owner publish-status --dir "$WORK/owners/b"
"$EP" register --dir "$WORK/ep/b4" --credential "$WORK/ep/b4/credential.cbor"
step "contact returns; RDS B finds b4 missing from the session: B.2 membership-mismatch"
"$RDS_BIN" partition --rds "$RDSA" --peer "$RDSB" --heal
sleep 6
sync a1
step "the sender sends again as a new message: -31100, a1 commits an Add for b4, and the message is delivered"
M11=$(send a1 purchasing "$B#invoices" "Shipping notice for PO 4713")
sleep 1
sync b1 b3 b4
sleep 1
sync a1 a2

bold "Message 12: dishonest recipients claim the group state is wrong (group-state dispute, doc 5 §7.5)"
step "b1, b3 and b4 are set to report every message as invalid-epoch, with a made-up epoch authenticator"
for e in b1 b3 b4; do "$EP" configure --dir "$WORK/ep/$e" --false-report invalid-epoch; done
M12=$(send a1 purchasing "$B#invoices" "Order confirmation 4714")
sleep 1
sync b1 b3 b4
sleep 1
sync a1 a2

bold "Message 13: the recipients take the message but never report (silence)"
for e in b1 b3 b4; do "$EP" configure --dir "$WORK/ep/$e" --false-report silent; done
M13=$(send a1 purchasing "$B#invoices" "Order confirmation 4715" --ttl 4)
sleep 1
sync b1 b3 b4
echo "waiting for expiry..."
sleep 7
sync a1 a2
for e in b1 b3 b4; do "$EP" configure --dir "$WORK/ep/$e" --false-report none; done

bold "Owner status: B's EBW provider suspends B with a status operation (doc 1 §3.1)"
"$EP" owner provider-status --provider "$WORK/ebw-b" --edd "$EDD" --owner "$B" --status suspended
echo "waiting for the RDSes to refetch the EDD status list (doc 1 §5.3)..."
sleep 6
"$EP" send --dir "$WORK/ep/a1" --from-role purchasing --to "$B#invoices" --body "Order while suspended" \
  --id-out "$WORK/suspended-id" 2>&1 | tee "$WORK/suspended.out"
grep -q "A.2 (-31109" "$WORK/suspended.out" || { echo "UNEXPECTED: message to a suspended owner not rejected"; exit 1; }
step "The provider reinstates B; messages flow again"
"$EP" owner provider-status --provider "$WORK/ebw-b" --edd "$EDD" --owner "$B" --status active
sleep 6
M14=$(send a1 purchasing "$B#invoices" "Order 4716, after reinstatement")
sleep 1
sync b1 b3 b4
sleep 1
sync a1

bold "Endpoint records"
for e in a1 a2 b1 b2 b3 b4; do echo "[$e]"; "$EP" list --dir "$WORK/ep/$e" | sed 's/^/  /'; done

bold "Collecting evidence and private data (verification bundles)"
"$EP" export --dir "$WORK/ep/a1" --message="$M1" --out "$WORK/bundles/m1-sender"
"$EP" export --dir "$WORK/ep/b1" --message="$M1" --out "$WORK/bundles/m1-recipient"
"$EP" export --dir "$WORK/ep/a2" --message="$M3" --out "$WORK/bundles/m3-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M4" --out "$WORK/bundles/m4-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M5" --out "$WORK/bundles/m5-sender"
"$EP" export --dir "$WORK/ep/a2" --message="$M6" --out "$WORK/bundles/m6-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M7" --out "$WORK/bundles/m7-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M8" --out "$WORK/bundles/m8-sender"
"$EP" export --dir "$WORK/ep/b1" --message="$M8" --out "$WORK/bundles/m8-recipient"
"$EP" export --dir "$WORK/ep/a1" --message="$M9" --out "$WORK/bundles/m9-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M10" --out "$WORK/bundles/m10-sender"
"$EP" export --dir "$WORK/ep/a1" --message="$M11" --out "$WORK/bundles/m11-sender"
"$EP" export --dir "$WORK/ep/b1" --message="$M12" --out "$WORK/bundles/m12-recipient"
"$EP" export --dir "$WORK/ep/a1" --message="$M13" --out "$WORK/bundles/m13-sender"

bold "Verifying evidence against the plaintext"
verify() { # NAME BUNDLE PLAINTEXT
  echo "-- $1"
  set +e; "$VERIFY" --bundle "$WORK/bundles/$2" --plaintext <(printf '%s' "$3"); local rc=$?; set -e
  return $rc
}
verify "message 1, sender's bundle (A -> B)" m1-sender "Purchase order 4711: 100 widgets at EUR 2.50"
verify "message 1, recipient's bundle" m1-recipient "Purchase order 4711: 100 widgets at EUR 2.50"
verify "message 2 (B -> A)" m2-sender "Invoice 2026-0815 for PO 4711: EUR 250.00"
verify "message 3 (A -> B)" m3-sender "Payment of EUR 250.00 sent for invoice 2026-0815"
verify "message 4 (after the membership change, epoch 2)" m4-sender "Delivery note for PO 4711"
verify "message 5 (consented, quorum 2)" m5-sender "Contract amendment 7: please accept"
verify "message 7 (after b2's revocation, epoch 3)" m7-sender "Final reminder for PO 4711"
step "message 6 expired before handover: the evidence verifies, but decryptability cannot be shown"
verify "message 6 (E.2 expired)" m6-sender "This one will not be collected in time" || echo "(exit $?: INCOMPLETE, as expected)"
step "message 8: E.2 decryption-failed; decrypt-failed reports agree with the sender's epoch authenticator (message-key dispute)"
step "with the recipient's retained MLS state, the verifier processes the message with mls-rs: the claim fails"
verify "message 8, recipient b1's bundle (its retained state)" m8-recipient "Order confirmation 4712"
step "the sender's own retained state cannot settle it: mls-rs does not process a member's own message (see NOTES.md)"
verify "message 8, sender's bundle (its own retained state)" m8-sender "Order confirmation 4712" || echo "(exit $?: INCOMPLETE, as expected)"
verify "message 9 (held while RDS B was unreachable, then relayed)" m9-sender "Shipping notice for PO 4712"
verify "message 10 (B.2 membership-mismatch at relay)" m10-sender "Shipping notice for PO 4713"
verify "message 11 (message 10 sent again, epoch 4)" m11-sender "Shipping notice for PO 4713"
step "message 12: E.2 decryption-failed with invalid-epoch reports (group-state dispute)"
step "b1 presents its state for epoch 3, agreed through message 9's E.1; the verifier replays the Commit for epoch 4: the claim fails"
verify "message 12, recipient b1's bundle (its anchor state)" m12-recipient "Order confirmation 4714"
step "message 13: E.2 not-acknowledged; with no report, decryptability cannot be shown"
verify "message 13 (E.2 not-acknowledged)" m13-sender "Order confirmation 4715" || echo "(exit $?: INCOMPLETE, as expected)"

if command -v cddl >/dev/null; then
  bold "Validating stored evidence with the cddl tool (as tools/check.py does)"
  cat <(echo "scc-root = evidence-artefact") ../spec/schemas/{common,discovery,credentials,mls,evidence}.cddl >"$WORK/scc.cddl"
  n=0
  for f in "$WORK"/ep/a1/messages/*/evidence/*.cbor; do
    cddl validate --cddl "$WORK/scc.cddl" --cbor "$f" >/dev/null 2>&1 || { echo "CDDL FAIL: $f"; exit 1; }
    n=$((n+1))
  done
  echo "$n evidence artefacts received by a1 match evidence-artefact"
fi

bold "Negative cases"
NEG_OK=1
if verify "tampered plaintext" m1-sender "Purchase order 4711: 900 widgets at EUR 2.50"; then
  echo "UNEXPECTED: tampered plaintext verified"; NEG_OK=0
else echo "(FAIL, as expected)"; fi
cp -r "$WORK/bundles/m1-sender" "$WORK/bundles/m1-tampered"
python3 - "$WORK/bundles/m1-tampered/evidence-package.cbor" <<'PY'
import sys
p = sys.argv[1]; d = bytearray(open(p, "rb").read())
d[len(d) // 2] ^= 0x01
open(p, "wb").write(bytes(d))
PY
if verify "tampered evidence package (one bit flipped)" m1-tampered "Purchase order 4711: 100 widgets at EUR 2.50" >/dev/null; then
  echo "UNEXPECTED: tampered evidence verified"; NEG_OK=0
else echo "-- tampered evidence package: FAIL, as expected"; fi
cp -r "$WORK/bundles/m2-sender" "$WORK/bundles/m2-wrong-message"
cp "$WORK/bundles/m3-sender/private.json" "$WORK/bundles/m2-wrong-message/private.json"
if verify "evidence of message 2 with the ciphertext and plaintext of message 3" m2-wrong-message "Payment of EUR 250.00 sent for invoice 2026-0815" >/dev/null; then
  echo "UNEXPECTED: substituted message verified"; NEG_OK=0
else echo "-- substituted message: FAIL, as expected"; fi
[ "$NEG_OK" = 1 ] || exit 1

if [ -n "${KEEP:-}" ]; then
  read -r -p "Servers still running; press Enter to stop. " _
fi
bold "Done. Work directory: $WORK"
