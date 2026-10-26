# Implementation notes

Notes on the reference implementation: simplifications, deviations from
the specification, and problems found in the specification.

## mls-rs and retained MLS state

mls-rs 0.56 is used unmodified from crates.io, through its public API
only. Nothing is extracted from MLS state (05-evidence.md §7.4, §8):

- **Export.** When an epoch begins (session creation, Welcome, own or
  received Commit), the endpoint writes the group to storage
  (`Group::write_to_storage`) and reads the bytes back from the client's
  `GroupStateStorage` (`Client::group_state_storage().state(group_id)`).
  It keeps them in `epochs.json`, with the epoch and its authenticator
  (`src/dispute.rs`, `export_state`). The state is taken before any
  message of the epoch is sent or received, because mls-rs deletes each
  message key once used: only the state at the start of the epoch can
  still process every message of the epoch.
- **KeyPackages.** After generating a KeyPackage, the endpoint reads its
  private keys from the client's `KeyPackageStorage`
  (`Client::key_package_store().get(ref)`) and keeps them in
  `keypackages.json`, since mls-rs deletes them on join.
- **Decryption reports (05 §4).** A recipient endpoint first compares its
  epoch authenticator with the sender's: if they differ, or it does not
  hold the epoch, it reports `invalid-epoch` (with its value, and
  `held_epoch` if needed); if it holds no group for the session,
  `join-failure`. Otherwise it decrypts and reports `match`, `mismatch`
  (with a plaintext hash under a fresh salt, which it retains) or
  `decrypt-failed`. The RDS counts a `match` from a holder of the `to`
  role as a successful handover; it no longer compares values.
- **Private data.** A message record holds the retained state of the
  message's epoch (sender; a recipient that reports `decrypt-failed` or
  `mismatch`), or of the anchor epoch (a recipient that reports
  `invalid-epoch`): the later of the last epoch in which it reported
  `match` (or sent a message that ended in E.1) and the last epoch it
  created with its own Commit. If neither exists, it holds the retained
  KeyPackages. When a bundle is exported for an agreed anchor, the
  endpoint adds the evidence package of the message that shows the
  agreement.
- **Load.** The verifier writes a presented state into an
  `InMemoryGroupStateStorage` and calls `Client::load_group`; or inserts
  presented KeyPackages into an `InMemoryKeyPackageStorage` and calls
  `Client::join_group` with the Welcome from the session log. It then uses
  `Group::context`, `Group::epoch_authenticator`,
  `Group::process_incoming_message[_with_time]` and
  `Group::member_at_index`. The verifier's client has a throwaway
  signer, which mls-rs requires for joining.

mls-rs is built without its default `rayon` feature: the SCC identity
provider resolves registry documents and status lists over the network
from inside mls-rs callbacks, which needs a thread of the async runtime.

## Stubs

These are stand-ins allowed by the brief. Each is marked in the code.

| Specified | Implemented |
|---|---|
| Qualified RFC 3161 timestamp over each seal (05 §2.1) | A local TSA per RDS. The token is a COSE_Sign1 over `{type, hash_alg, imprint, gen_time, serial}`; the verifier checks the TSA certificate, the signature and that the imprint is SHA-256 of the seal (`src/tsa.rs`). |
| QSealC for RDS, EDD and EBW provider seals (01 §3.6, §5.3, 05 §2.1) | Self-signed Ed25519 certificates made with `rcgen`, with "DEMO ONLY" in the subject. |
| EU Trusted Lists (05 §2.2 step 3, 04 §4.3) | A JSON trust store listing the trusted EDD, RDS and TSA certificates (`scc-edd pki-trust`). |
| EDD identity proofing and identifier attestation (01 §4, §6.2) | Any `proof` is accepted; the identifiers in the create operation are attested. |
| EBW provider (01 §3.6) | The owner tool holds its provider's seal key (`owner provider-init`) and seals its own submissions. The EDD accepts any provider whose certificate is in the trust store. |
| Network partitions (03 §5, 04 §7.1) | Simulated with a demo switch (`scc-rds partition`): the RDS treats a peer as unreachable for its own outgoing federation calls. A real unreachable peer (connection error or unparseable response) is handled the same way. |
| TLS 1.3 with mutual authentication between RDSes (04 §4.3) | Server-authenticated TLS with a demo CA (`SCC_TLS_CA`). The calling RDS gives its RDS URL in an `x-scc-rds` header, which is not authenticated. Each federation handler still checks that the caller is the home RDS of the EBW URL it acts for (04 §4.3 check 2), using the registry document. All servers use one `localhost` certificate, so RDSes differ only by port. |

## Simplifications

- **State.** The EDD and the RDSes keep their state in memory. Restarting a
  server loses it. Endpoints keep their state in a directory (JSON files
  and the mls-rs SQLite store).
- **Endpoints are command-line programs**, not long-running wallets. Each
  command connects, authenticates, works through the queue, and
  disconnects. `sync --wait N` keeps listening for pushed notifications.
  Registration (04 §5) therefore lasts until credential expiry or
  `scc.deregister`, as specified, not for the lifetime of a connection.
- **Cipher suites.** Endpoints publish KeyPackages and create sessions only
  for `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001). Endpoint
  keys may be Ed25519 or P-256 (P-256 is exercised for signed statements
  in the tests), but the CLI creates Ed25519 keys.
- **Status lists** are hosted by the owner's home RDS at
  `<origin of the RDS URL>/status/<EBW URL suffix>`. The owner uploads a new token with
  `POST`; the RDS accepts it because it is signed by the owner's
  credential key and is newer. Tokens carry `ttl` 60 s in the demo.
- **Eligibility of added endpoints (03 §6.2 check 4).** Each RDS checks
  the KeyPackages and eligibility of its own owners' endpoints (published
  here, unused, registered, credential valid, role held). For the other
  side's endpoints it checks the credential (via the identity provider) and
  that the leaf holds the side's role, and relies on the peer RDS, whose
  acceptance is also required, for the rest.
- **Membership check (03 §5).** As specified, with `scc.rds.subjects` for
  the other side, cached until its `expires_at`. The answering RDS records
  each answer and, at relay, accepts a session whose members match any
  unexpired answer it gave, or its current list (04 §7.2, §9). The default
  answer lifetime is 30 s; the demo uses 2 s.
- **Relay (04 §7.2).** The receiving RDS accepts a message in an earlier
  epoch if A.1's `group_context` is its own GroupContext for that epoch.
  Membership is checked as of the message's epoch. Only the `expires_at` parts of check 6 apply.
- **Evidence packages (04 §7.7).** Composed only when the RDS holds the
  whole chain from A.1 to the terminal event; until then
  `scc.evidence.get` returns `-31112`, and `scc-endpoint export` retries
  for a few seconds.
- **Status lists in evidence (05 §3.2).** A.1, A.2 and C.6 carry the
  status list token for the endpoint they name; A.2 only if the RDS could
  check it.
- **Reservations (04 §6.3).** Implemented with expiry and release, but
  without per-requester quotas, and without checking that the KeyPackage
  used in a Commit came from the caller's own reservation.
- **Handovers.** Transfer is recorded on `scc.queue.ack` of the
  `wmp.message.deliver` item, acknowledgement on `wmp.message.ack`. E.1,
  E.2 (`decryption-failed`, `not-acknowledged`, `expired`) are issued as in
  04 §7.3. Expiry is checked once a second.
- **Consented mode (04 §7.4)** is implemented: C.1 with `eligible_holders`,
  C.6 on the first confirmation of a consent request, C.3 when the policy
  (`any`, `all`, `quorum`) is met counting distinct holders, C.4 on the
  first refusal, C.2/C.5 on expiry. For `all`, the holders counted are
  those eligible when C.1 is issued (right after B.1). If a decision
  arrives before any consent request was confirmed, C.6 is issued first,
  naming the deciding endpoint.
- **Evidence notifications** go to the sender's member endpoints on the
  `from` side (all of them, not only the submitting endpoint). Recipient
  endpoints get E.1 in the `wmp.message.ack` result and can fetch packages
  with `scc.evidence.get`.
- **Positive reason codes** are set only on C.3 (RC07); others are left
  out (they are optional, 05 §3.5).
- **Message padding.** mls-rs's step-function padding is used, not padding
  to a multiple of 1024 bytes (03 §7.1, SHOULD).
- **Not implemented:** holds for suspended owners in flight (04 §7.8;
  suspension is detected at submission and relay, check 8), D.2 for
  owners retired after consignment, closing idle sessions (03 §4.4),
  credential renewal and self-updates (Update / UpdatePath-only Commits),
  retention deletion schedules (endpoints keep every retained state and
  KeyPackage), and re-timestamping.
- **Commit failures (03 §6.5)** are reported by endpoints that fail to
  process a Commit and produce commit failure evidence and session
  closure, but no demo scenario exercises them (mls-rs will not create a
  bogus Commit). `last_agreed` is always present in them, since an
  endpoint processes Commits only after joining.
- **Dishonest recipient (demo only).** `scc-endpoint configure
  --false-report` makes an endpoint report messages that decrypt as
  `decrypt-failed` (to exercise §7.4) or as `invalid-epoch` with a
  made-up epoch authenticator (§7.5), or take messages and send no
  report (`silent`, for E.2 `not-acknowledged`).
- **Verifier.**
  - §2.2 steps 1 to 7 are implemented, including CDDL validation with the
    `cddl` crate (the same validator as the `cddl` tool used by
    `tools/check.py`) against the schema files of `spec/schemas`.
  - The registry document "in force" for an endpoint statement is the
    one named by the head statement embedded in the same artefact,
    taken from the EBW URL log in the bundle (audited as in 01 §6.4).
  - §7.2 step 3 replays the session log with an mls-rs external client.
    During replay, credentials are checked against the registry
    documents named by the evidence, at each Commit's acceptance time,
    without status lists (the log does not carry them).
  - The credential of the endpoint named in `endpoint` is taken from its
    leaf in the tree at the message's epoch, and checked as an endpoint
    statement's credential is (§2.2 step 7), against the embedded status
    list token. An A.2 endpoint may be absent from the tree.
  - A presented retained state of the message's epoch is always loaded
    and checked against the evidence `group_context` and the sender's
    epoch authenticator (§8).
  - §7.4 (message-key dispute) runs when the terminal event is E.2 with
    `decrypt-failed` or `mismatch` reports, which say the recipient's
    epoch authenticator equals the sender's: mls-rs processes the
    `PrivateMessage` under it; the sender's leaf must be the endpoint
    named in A.1; SHA-256 of the application data
    must equal `plaintext_hash`. A rejection by mls-rs puts the sender at
    fault (FAIL). If the bundle has no application data, the data
    recovered here is used for the §7.2 plaintext check. For `mismatch`,
    a presented salt and application data are checked against the
    report's `plaintext_hash` and the decrypted data. If the state is
    the sender's own, mls-rs refuses to process the message
    (`CantProcessMessageFromSelf`) and the result is INCOMPLETE (spec
    issue 1).
  - §7.5 (group-state dispute) runs when the reports are `invalid-epoch`
    or `join-failure`: the recipient's state for an agreed epoch (shown
    by an E.1 with a `match` report in the bundle's agreement package),
    or for an epoch it created with its own Commit, is loaded and checked
    against the GroupContext recomputed from the log (and, for an agreed
    epoch, the E.1's epoch authenticator); or, if it never
    joined, its KeyPackages are checked (init and leaf keys by HPKE round
    trips, KeyPackageRef) and the logged Welcome is processed with them. The
    logged Commits up to the message's epoch are then processed, the
    resulting authenticator is compared with the sender's, and the
    message is processed as in §7.4. A Commit or Welcome that mls-rs
    rejects puts its committer (named from the log) at fault. The
    library test exercises the three anchors and a rejected Commit; the
    demo exercises an agreed anchor.
  - The verdict is the worst result over all checks. A message that
    ended in E.2 `expired` therefore verifies as INCOMPLETE (decryptability
    cannot be shown from recipient reports), even though all evidence is
    valid.

## Spec issues found

The issues reported earlier (relay epoch, clock skew and cached answers
at relay, `last_agreed` for an endpoint that never joined, decisions
before C.6, the sender's credential, `queue_head`, evidence ordering,
`cipher_suite` in `scc.rds.subjects`) are fixed in the spec and
implemented. These remain:

1. **The sender's own state cannot process its message** (05 §7.4,
   §8). §7.4 says "**either** party" settles the dispute by presenting its
   state, and the sender retains its state for this purpose. But an
   ordinary MLS implementation does not process a member's own
   `PrivateMessage`: mls-rs returns `CantProcessMessageFromSelf` after
   decrypting the sender data, and RFC 9420 does not describe processing
   one's own message. So, with only normal operations, a verifier can
   settle §7.4 only with the state of another member: the recipient
   (which must then retain it), or another endpoint of either side. The
   spec should say so, and require the recipient (or every member) to
   retain the state of the epoch of a message it reports other than
   `match`. (The retention table's "state at its last agreed epoch" covers
   this only implicitly.) The demo shows both: the recipient's state
   settles the dispute, the sender's gives INCOMPLETE.
2. **A presented state is not self-authenticating** (05 §7.4 step 1, §7.5
   step 2). The verifier checks the state's GroupContext and epoch
   authenticator, but in mls-rs (as in most implementations) the state
   stores the authenticator, the secret tree and the sender data secret
   as separate values, and not the epoch secret they come from. A party
   can therefore edit a serialized state so that it keeps the right
   GroupContext and authenticator but yields other message keys (or
   another own leaf index). A recipient could make a good message look
   undecryptable; a sender could make a bogus message look decryptable to
   a verifier while the real recipients got other keys. Checking the
   authenticator binds the keys only if the verifier recomputes them from
   a secret bound to it, which needs the epoch secret (or the
   `init_secret` of the previous epoch and the Commit's `commit_secret`)
   and so leaves an implementation's normal API. The spec should note
   this limit, or say what a verifier may trust in a presented state.
