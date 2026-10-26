# SCC reference implementation

A reference implementation of the Secure Communication Channel specified in
[`../spec/`](../spec/README.md): one Rust crate (`scc`) with the common code
in a library and four binaries.

| Binary | Role |
|---|---|
| `scc-edd` | The European Digital Directory (01-discovery.md §6), plus demo PKI helpers |
| `scc-rds` | A Registered Delivery Service (04-delivery.md): endpoint WebSocket API, federation API, status list hosting, evidence |
| `scc-endpoint` | An endpoint (send, sync, export), and `owner` subcommands for the EBW owner's administration (register an EBW URL, issue credentials, publish status lists) |
| `scc-verifier` | Verifies a message's evidence against its plaintext (05-evidence.md §2.2, §3.7, §7) and prints OK / INCOMPLETE / FAIL with reasons |

MLS is [mls-rs](https://crates.io/crates/mls-rs) 0.56 from crates.io,
unmodified and used through its public API only. In a dispute, a party
presents the MLS state it retained, and the verifier loads it into mls-rs
and processes the message or Commits under it (see [NOTES.md](NOTES.md)).

## Building and testing

```sh
cargo build
cargo test
```

The tests reproduce the spec's examples, check EDD logic, run a session with
the MLS profile (credential binding, `scc_session`, an RDS-style observer,
epoch authenticators) and settle disputes with retained state (a
message-key dispute from the recipient's state; group-state disputes from
a last agreed epoch, an epoch the recipient created, and a retained
KeyPackage; a rejected Commit),
and validate objects produced by the implementation against
`spec/schemas/*.cddl`.

## Running the demo

```sh
./demo.sh
```

The script builds the binaries and, in `target/demo/`:

1. creates the demo PKI (TLS CA, EDD, RDS and EBW provider seal
   certificates, TSA certificates, trust store);
2. starts the EDD and two RDSes from different providers on localhost
   ports over TLS, and checks their metadata against
   `rds-metadata.schema.json` (if Python `jsonschema` is available);
3. registers two owners with the EDD, each through its EBW provider,
   which seals the submission (A served by RDS A, B by RDS B, with an
   acceptance policy `quorum:2` for B's `invoices` role);
4. enrols two endpoints per owner: each endpoint makes a credential
   request, the owner issues a credential and publishes its status list,
   and the endpoint registers with its home RDS and publishes KeyPackages;
5. sends messages in both directions within one session: A1 creates the
   session (KeyPackages from both RDSes, two-sided Commit acceptance,
   Welcomes), then messages flow A→B, B→A, A→B with evidence
   A.1 → B.1 → D.1 → E.1 and decryption reports;
6. enrols a third B endpoint: the next send gets `-31100` (membership
   mismatch), the sender commits an Add, and resends in the new epoch;
7. sends a message in consented mode: B's endpoints accept, two of them
   with the same holder, so the quorum of two holders is met only by the
   third (C.1, C.6, C.3, then D.1, E.1);
8. sends a message with a 4-second expiry that nobody collects (E.2
   `expired`);
9. revokes an endpoint's credential: the next send removes it;
10. sends a message that the recipients b1 and b3 falsely report as
    `decrypt-failed` (a demo switch), giving E.2 `decryption-failed`.
    That result says they agree with the sender's epoch authenticator, so
    this is a message-key dispute;
11. cuts RDS A off from RDS B (a demo switch) and sends: RDS A checks
    A's side only, issues A.1 and holds the message; once contact
    returns, it relays and the message is delivered. A second message
    sent while cut off, during which B enrols a new endpoint, ends with
    B.2 `membership-mismatch`; the sender sends it again, gets `-31100`,
    commits an Add, and the message is delivered;
12. sends a message that the recipients falsely report as `invalid-epoch`
    (a demo switch): a group-state dispute. Then sends one that they take
    but never report on, giving E.2 `not-acknowledged`;
13. exports verification bundles (evidence package, session log, the
    endpoint's private data with its retained MLS state, EBW URL logs) and
    runs `scc-verifier` against the plaintexts: every delivered message
    verifies **OK**, the expired one **INCOMPLETE**; for the disputed
    message, the recipient's bundle verifies **OK** (its retained state
    decrypts the message, so its claim fails) and the sender's own
    bundle **INCOMPLETE** (mls-rs does not process a member's own
    message); the B.2 message's evidence verifies **OK**; for the
    group-state dispute, the recipient's bundle verifies **OK** (from its
    agreed anchor, the verifier replays the next Commit and decrypts the
    message); the unreported message verifies **INCOMPLETE**;
14. validates every evidence artefact received by one endpoint with the
    `cddl` tool, if installed;
15. negative cases: a tampered plaintext, a package with one flipped bit,
    and evidence paired with another message's ciphertext all **FAIL**.

Servers are stopped when the script exits. Set `KEEP=1` to keep them
running until you press Enter, and `WORK=dir` to use another directory.
Server logs are in `target/demo/logs/`.

## Using the binaries

All commands that talk to servers need the demo CA and the trust store:

```sh
export SCC_TLS_CA=target/demo/pki/ca.pem
export SCC_TRUST=target/demo/pki/trust.json
```

Owner and endpoint lifecycle:

```sh
scc-endpoint owner provider-init --dir ebw --provider ebw-a.demo   # add its seal-cert.der to the trust store
scc-endpoint owner init --dir own --edd https://localhost:18440 --provider ebw \
    --rds-url https://localhost:18441/scc-rds --policy invoices=any
scc-endpoint init --dir ep1 --owner "$(scc-endpoint owner url --dir own)" \
    --rds https://localhost:18441/scc-rds --edd https://localhost:18440 --roles default,invoices
scc-endpoint owner issue --dir own --request ep1/credential-request.cbor --out ep1/credential.cbor --holder h1
scc-endpoint owner publish-status --dir own
scc-endpoint register --dir ep1 --credential ep1/credential.cbor
```

Messages and evidence:

```sh
scc-endpoint send --dir ep1 --from-role invoices --to 'ebw:...#purchasing' --body 'hello'
scc-endpoint sync --dir ep1 [--wait 10]
scc-endpoint list --dir ep1
scc-endpoint export --dir ep1 --message <id> --out bundle
scc-verifier --bundle bundle --plaintext body.txt
scc-endpoint configure --dir ep1 --consent reject     # or --false-report decrypt-failed|invalid-epoch|silent (demo only)
```

An endpoint directory holds `endpoint.json` (keys, credential, queue
position), `mls.db` (mls-rs state), `sessions.json`, `epochs.json` (the
MLS state retained at the start of each epoch, as mls-rs stores it),
`keypackages.json` (private keys of published KeyPackages) and
`messages/<id>/` with `record.json` (metadata, the decryption report, and
the private data needed for verification: the application data with its
salt, the `MLSMessage`, and the retained MLS state that 05-evidence.md §8
asks for), the received evidence artefacts, and the plaintext body.

## What is implemented

- **Discovery (doc 1):** EBW URLs, operations and registry documents,
  submissions sealed by the EBW provider, registration, updates with
  recovery, head statements, identifier attestations, resolution, log
  auditing (`scc-edd`, `src/registry.rs`, `src/edd.rs`, `src/owner.rs`).
- **Credentials (doc 2):** endpoint credentials (CWT), credential requests,
  status list tokens (OAuth Token Status List, CWT, ZLIB), the
  `ebw_endpoint` credential inside a MultiCredential binding signed by the
  endpoint key over the leaf signature key, and LeafNode validation in an
  mls-rs identity provider that resolves registry documents and status lists
  (`src/credential.rs`, `src/mls.rs`, `src/resolve.rs`).
- **MLS profile (doc 3):** sessions with `scc_session` and
  `required_capabilities`, Commits as PublicMessage, RDS-side observation
  of Commits with an mls-rs external client and the §6.2 checks, two-sided
  acceptance with the `commit_ref` tie-break, the Commit log, membership
  checks with `-31100` and `-31105`/A.2 `no-keypackage`, no last-resort
  KeyPackages, the application message, plaintext hash, epoch
  authenticator, retained MLS state.
- **Delivery (doc 4):** JSON-RPC over WebSocket (endpoint ↔ RDS, `scc.v1`
  subprotocol) and HTTPS (RDS ↔ RDS); connection authentication with
  connect proofs; queues with `seq`, push, fetch and ack; KeyPackage pools,
  reservations and pool notifications; session creation, Commit
  submission, fetch, session log and Commit failure reports; submission
  with checks 1 to 9, relay (earlier epochs, membership as of the
  message's epoch, binding `scc.rds.subjects` answers), basic and
  consented consignment, handover
  (transfer + acknowledgement), the E.1/E.2 outcomes, expiry, evidence
  notification, evidence packages (`-31112` until the chain is complete);
  RDS metadata.
- **Evidence (doc 5):** sealed and timestamped artefacts, all message
  events used by the flows above (A.1, A.2, B.1, B.2, B.3, C.1–C.6, D.1,
  E.1, E.2), hash chains with `prev`, embedded head statements, status
  list tokens, endpoint credentials, decryption reports and consent
  decisions, commit failure evidence, evidence packages, and the verifier,
  including the message-key (§7.4) and group-state (§7.5) disputes with
  presented MLS state.

What is stubbed or simplified, and the problems found in the
specification, are in [NOTES.md](NOTES.md).

## Source layout

| Path | Contents |
|---|---|
| `src/cbor.rs`, `src/cose.rs` | Deterministic CBOR, COSE_Sign1, COSE keys and thumbprints |
| `src/registry.rs`, `src/edd.rs` | EBW URLs and the EDD |
| `src/credential.rs`, `src/owner.rs` | Credentials, status lists, owner administration |
| `src/mls.rs` | The MLS profile on mls-rs |
| `src/dispute.rs` | Retained MLS state: export and reload with mls-rs's public API, processing for disputes |
| `src/rpc.rs`, `src/delivery.rs` | JSON-RPC and the delivery protocol's types |
| `src/rds/` | The RDS: sessions and Commits, messages and evidence, endpoint and federation APIs, server |
| `src/endpoint.rs` | The endpoint |
| `src/evidence.rs`, `src/tsa.rs`, `src/certs.rs` | Evidence artefacts and chains, demo TSA, demo PKI and trust store |
| `src/verifier.rs`, `src/schema.rs` | The verifier and CDDL validation |
| `src/bin/` | The four binaries |
