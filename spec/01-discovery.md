# SCC Discovery: EBW URLs and the European Digital Directory

**Element:** Discovery · **Schemas:** [`schemas/discovery.cddl`](schemas/discovery.cddl), [`schemas/edd.openapi.yaml`](schemas/edd.openapi.yaml)

## 1. Introduction

Each EBW owner has a digital address: an **EBW URL**, such as
`ebw:zloeskxezkk6rcwjazemu3kv`. The part after `ebw:` is derived from a
hash of the operation that created it. The European Digital Directory
(EDD) stores, for each EBW URL, a log of signed operations. The latest
valid operation sets the URL's **registry document**, which holds:

- the **update keys** that may sign later operations;
- the **credential keys** that may sign endpoint credentials (doc 2);
- the owner's **home RDS**;
- the owner's **existing identifiers**, such as an EUID or VAT number;
- the owner's **acceptance policies**;
- the owner's **status**: active, suspended, retired, merged or closed.

The EDD also signs:

- an **identifier attestation**, which binds an existing identifier to an
  EBW URL;
- a **head statement**, which names the current head of an EBW URL's log
  and points to a status list;
- **status lists**, which show whether each head statement is still
  current.

Operations are signed by the owner's update keys, except that the
owner's EBW provider can suspend, reinstate or retire the owner with a
**status operation**, which it seals. The
EBW provider submits every operation to the EDD on the owner's behalf,
and seals each one when it submits it (§3.6).

The scheme is based on the Public Ledger of Credentials (PLC) used by the
AT Protocol. The main differences are CBOR/COSE encoding, the EDD in
place of the PLC directory, provider seals on submissions, EDD-attested
identifiers, and EDD-managed lifecycle status.

### 1.1 Trust in the EDD

The EDD cannot forge or corrupt a registry document, because every
operation is signed by an update key or sealed by the owner's EBW
provider. Relying parties can check a
registry document without trusting the EDD. The EDD is trusted only:

1. not to refuse valid operations;
2. not to serve stale registry documents, or withhold operations when
   serving a log;
3. not to falsely attest identifier mappings;
4. to mark head statements as replaced in its status list (§5.3).

Points 1 and 2 can be checked by auditing the log (§6.4), but not
prevented. The status list limits how stale a registry document can be
(§5.3). Points 3 and 4 rest on the EDD's role under Article 10 of the
draft EBW Regulation.

## 2. EBW URLs

An EBW URL uses the `ebw` scheme. Its path is 24 lowercase base32
characters:

```
ebw-url = "ebw:" 24( %x61-7A / %x32-37 )   ; lowercase base32
```

The path is derived from the signed create operation (§3):

```
url = "ebw:" || base32lower(SHA-256(create_operation))[0..24]
```

where `create_operation` is the encoded COSE_Sign1 of the create
operation, and `base32lower` is RFC 4648 base32 with lowercase letters and
no padding. The 24 characters carry 120 bits. The EDD MUST reject a create
operation whose EBW URL is already registered.

## 3. Operations

An operation is a COSE_Sign1. Its payload is an `op-body`:

```cddl
op-body = create-op / update-op / status-op

create-op = {
  "type": "create",
  "prev": null,
  registry-document,
}

update-op = {
  "type": "update",
  "prev": op-hash,
  registry-document,
}

status-op = {
  "type": "status",
  "prev": op-hash,
  registry-document,
}

registry-document = (
  "update_keys": [1*5 COSE_Key],
  "credential_keys": [1*5 COSE_Key],
  "rds": rds-url,
  "identifiers": [* identifier],
  "acceptance_policies": acceptance-policies,
  "status": owner-status,
  ? "successor": ebw-url,     ; present if status is "merged"
  "signed_at": time,
)
```

Every operation carries the **complete** registry document, not a
change. This keeps each registry document readable
without replaying the log.

`op-hash` is SHA-256 over the encoded COSE_Sign1 of an operation. It is the
operation's identifier.

### 3.1 Signing

The protected header of the COSE_Sign1 MUST contain:

| Label | Value |
|---|---|
| `alg` (1) | `-8` (EdDSA) or `-7` (ES256) |
| `kid` (4) | COSE Key Thumbprint of the signing key |

The signing key MUST be one of:

- for a create operation: the operation's own `update_keys`;
- for an update operation: the `update_keys` of the registry document
  set by the operation named in `prev`.

A status operation is instead sealed by the owner's current EBW
provider: the provider that sealed the submission (§3.6) of the latest
create or update operation. The signing key is the provider's seal key,
and the protected header also carries `x5chain` (label 33) with its
qualified certificate for electronic seals. The certificate MUST
identify the same legal person as the one on that submission.

### 3.2 Fields

**`update_keys`** — keys that may sign operations, in order of priority.
Index 0 has the highest priority. Priority matters only for recovery
(§3.4).

**`credential_keys`** — keys that may sign endpoint credentials. They
SHOULD NOT also be update keys.

**`rds`** — the owner's home RDS, identified by the URL of its metadata
(doc 4 §3):

```cddl
rds-url = tstr .regexp "https://.+"
```

**`identifiers`** — existing identifiers the owner claims. The EDD MUST
NOT accept an operation that adds an identifier until it has attested that
identifier for this EBW URL (§4).

```cddl
identifier = {
  "type": identifier-type,
  "value": tstr,
}
identifier-type = "euid" / "lei" / "vat" / "eori" / "iso6523"
```

| Type | Value | Example |
|---|---|---|
| `euid` | European Unique Identifier (BRIS) | `DEHRB.HRB123456` |
| `lei` | Legal Entity Identifier (ISO 17442) | `5299000J2N45DDNE4Y28` |
| `vat` | EU VAT number with country prefix | `DE123456789` |
| `eori` | EORI number | `DE1234567890123` |
| `iso6523` | ISO 6523 ICD and identifier, separated by `:` | `0007:5567164818` |

**`acceptance_policies`** — how many holders of a role must accept a
message sent in `consented` mode (doc 4 §7.4):

```cddl
acceptance-policies = {
  "default": acceptance-policy,
  * tstr => acceptance-policy,   ; key: a role
}
acceptance-policy = "any" / "all" / quorum
quorum = [ "quorum", uint .ge 1 ]
```

| Policy | Meaning |
|---|---|
| `"any"` | One holder of the role accepts. |
| `"all"` | Every holder of the role, as of relay acceptance, accepts. |
| `["quorum", n]` | `n` distinct holders of the role accept. |

The `default` entry applies to any role without its own entry. Holders
are counted, not endpoints (doc 2 §2).

**`status`** — the owner's lifecycle status (§5.1). A create operation
sets `active`. After that, the status changes only as follows:

| Change | Made by |
|---|---|
| `active` to `suspended`, and `suspended` to `active` | Status operation (EBW provider) |
| `active` or `suspended` to `retired` | Status operation (EBW provider) |
| `active` to `merged`, with `successor` | Update operation (owner) |
| `active` to `closed` | Update operation (owner) |

Any other update operation keeps the status of the registry document
before it. A status operation changes only `status` and `signed_at`.
`retired`, `merged` and `closed` are final: the EDD MUST NOT accept later
operations.

**`successor`** — for `merged`, the EBW URL of the entity the owner
merged into.

**`signed_at`** — the time the operation was signed. It is
informational. The EDD records its own receipt time (§6.4).

### 3.3 Validity

The EDD MUST accept an operation only if all of these hold:

1. It is a valid COSE_Sign1, with a deterministically encoded payload
   matching `op-body`, in a valid submission (§3.6).
2. The signature verifies with a key allowed by §3.1. For a status
   operation, the certificate is valid and qualified, using the EU
   Trusted Lists.
3. The registry document follows the rules for `status` in §3.2.
4. `prev` names the current head, or the recovery rule (§3.4) applies.
5. The current status is not `retired`, `merged` or `closed`.
6. Every identifier in the new registry document is attested for this
   EBW URL (§4).
7. `rds` is an `https` URL.

A create operation is accepted only through registration (§6.2).

### 3.4 Recovery

An update key can override recent operations signed by lower-priority
keys. This lets an owner undo changes made by a compromised or misbehaving
key, such as one held by its RDS.

An update operation MAY name in `prev` an operation `P` that is not the
current head, if:

1. it is signed by the update key at index `i` in the registry
   document set by `P`;
2. every operation after `P` was signed by an update key with an index
   greater than `i` in the registry document that operation was checked
   against (so a status operation cannot be overridden); and
3. the EDD received the first operation after `P` less than its
   recovery window ago. The EDD publishes the window in its metadata
   (§6.6).

The operations after `P` are then **overridden**. They stay in the log,
marked as overridden, and the new operation becomes the head.

```mermaid
flowchart LR
    C[create] --> U1[update 1<br/>signed by update key 1]
    U1 --> U2[update 2<br/>signed by update key 1]
    C -. recovery .-> R[update R<br/>signed by update key 0]
    U1:::overridden
    U2:::overridden
    classDef overridden stroke-dasharray: 5 5
```

### 3.5 Closing

An owner closes its EBW URL with an update operation that sets `status`
to `closed`. The EDD MUST NOT accept later operations.

### 3.6 Submission

The owner's EBW provider submits each operation to the EDD on the owner's
behalf. It seals the operation in a **submission**, a COSE_Sign1:

```cddl
submission-body = {
  "type": "submission",
  "operation": bstr .cbor operation,
  "submitted_at": time,
}
```

The protected header carries `x5chain` (label 33) with the provider's
qualified certificate for electronic seals. The EDD MUST check that the
seal verifies, and that the certificate was valid and qualified when the
EDD received the submission, using the EU Trusted Lists.

The seal records which provider submitted the operation. It does not
authorize the operation: only the update key's signature does (§3.1).
The EDD keeps the submission in the log (§6.4), so an auditor can see
which provider submitted each operation.

## 4. Identifier attestations

The EDD verifies that the owner of an EBW URL is the entity known by an
existing identifier, using the identification process set by the EBW
Regulation. That process is out of scope here. The result is an
**identifier attestation**, a COSE_Sign1 signed by the EDD:

```cddl
identifier-attestation-body = {
  "type": "identifier-attestation",
  "identifier": identifier,
  "owner": ebw-url,
  "verified_at": time,
  "expires_at": time,
}
```

Rules:

- An identifier maps to at most one EBW URL at a time. The EDD MUST revoke
  an attestation before attesting the same identifier to another EBW URL.
- An owner MAY remove an identifier from its registry document at any
  time. The
  attestation stays valid until the EDD revokes it.
- Lookup (§6.3) returns the current attestation. A revoked attestation is
  not returned.
- An attestation is valid from `verified_at` until `expires_at`. The EDD
  issues a new one before the current one expires, for as long as the
  mapping holds.

## 5. Status and head statements

### 5.1 Status

The owner's lifecycle status is in its registry document (§3.2).

| Status | Meaning | Effect on SCC |
|---|---|---|
| `active` | Normal operation | Messages can be sent and delivered. |
| `suspended` | The owner has temporarily ceased its activity | RDSes hold in-flight messages and reject new ones. Held messages expire normally. |
| `retired` | The owner has permanently ceased its activity | Messages fail with reason `recipient-retired`. |
| `merged` | The owner merged into another entity | Messages fail with reason `recipient-merged`. The registry document names the successor EBW URL. |
| `closed` | The owner closed the EBW URL | As `retired`. |

The owner sets `merged` and `closed` itself. Suspension, reinstatement
and retirement are made by the owner's EBW provider with status
operations (§3.1, §3.2). The draft EBW Regulation makes the provider
responsible for revoking the wallet's validity when the owner
temporarily or permanently ceases its activity (Article 6(2)(f)), and
for reporting changes to the EDD (Article 10(5)). These are the cases in
which the owner cannot be relied on to sign, so the owner's update keys
are not needed for them.

### 5.2 Head statement

A head statement is a COSE_Sign1 signed by the EDD. It names the current
head of an EBW URL's log, and so its registry document:

```cddl
head-statement-body = {
  "type": "head-statement",
  "owner": ebw-url,
  "head": op-hash,
  "seq": uint,                ; number of non-overridden operations
  "status_list": {
    "uri": tstr,              ; the EDD status list (§5.3)
    "idx": uint,              ; this statement's entry in it
  },
  "issued_at": time,
}
owner-status = "active" / "suspended" / "retired" / "merged" / "closed"
```

The EDD issues one head statement for each operation that becomes the
head, and returns the same statement until a later operation replaces
it. A head statement does not expire. Whether it is still current is
shown by its entry in the status list.

### 5.3 Status list

The EDD publishes a status list in the format of doc 2 §5.3, with these
differences:

- It is signed by the EDD (§5.5), with `x5chain`. `iss` is
  the EDD's base URL.
- Each entry belongs to one head statement. VALID (0) means the statement
  names the current head. INVALID (1) means a later operation has
  replaced it.

When an operation becomes the head, the EDD sets the entry of the
previous head statement to INVALID, as well as those of any operations it
overrides (§3.4).

Each token states its own validity period, which the EDD chooses. A
longer one lets delivery continue through a longer EDD outage. A shorter
one makes changes take effect sooner. Changes reach the EDD only as fast
as EBW providers report them (one working day under Article 10(5) of the
draft EBW Regulation), so a validity much shorter than that gains little.

### 5.4 Use by RDSes

An RDS MUST hold, for both owners, a head statement whose entry is VALID
in a currently valid status list token, and whose registry document has
status `active`, before it issues evidence that a message was submitted,
relayed, accepted or handed over (doc 5). The evidence includes the head
statements and status list tokens it relied on. This lets a verifier see
which registry document was in force, and therefore which credential
keys and acceptance policy applied.

If the EDD is unreachable, an RDS MAY rely on a status list token until
it expires. After that it MUST stop issuing such evidence. In-flight
messages are held until they expire.

### 5.5 EDD keys

The EDD signs with keys certified by qualified certificates for electronic
seals (QSealC). Its current and past keys are published at
`/.well-known/edd` (§6.6). Each signature's protected header carries
`x5chain` (label 33) with the certificate chain.

## 6. EDD API

The EDD offers an HTTPS API. Request and response bodies are CBOR
(`application/cbor`), except the EDD metadata (§6.6), which is JSON.
Errors use Concise Problem Details (RFC 9290,
`application/concise-problem-details+cbor`). The full contract is in
[`schemas/edd.openapi.yaml`](schemas/edd.openapi.yaml).

| Operation | Method and path | Returns |
|---|---|---|
| Resolution | `GET /{url}` | Registry document and head statement |
| Head | `GET /{url}/head` | Head statement |
| Status list | `GET /status-list` | Status list token for head statements |
| Auditing | `GET /{url}/log` | Log entries |
| Lookup | `GET /lookup/{type}/{value}` | Identifier attestation |
| Registration | `POST /register` | EBW URL and head statement |
| Update | `POST /{url}` | Head statement |
| EDD metadata | `GET /.well-known/edd` | EDD keys and limits (JSON) |

`{url}` is the whole EBW URL, for example
`GET /ebw:zloeskxezkk6rcwjazemu3kv`. All reads are public. Signed objects
state their own validity, and MUST NOT be relied on outside it. For other
responses, clients follow the HTTP caching headers the EDD sends.

### 6.1 Resolution

`GET /{url}` returns the current registry document, in the operation
that set it, with its head statement:

```cddl
resolution-response = {
  "operation": bstr .cbor operation,  ; the head operation
  "head": bstr .cbor head-statement,
}
```

The client checks that the head statement verifies, names the URL, and
names the operation as its head, and that its entry in a currently
valid status list token (§5.3) is VALID. It then has the registry document
without trusting the EDD for its content. A client that needs to know
how the registry document came about fetches the log (§6.4).

### 6.2 Registration

`POST /register` creates an EBW URL. The body is:

```cddl
registration-request = {
  "submission": bstr .cbor submission,  ; of a create operation
  "proof": bstr,              ; evidence of identification, EDD-defined
}
```

The EDD verifies `proof` under its identification process, attests the
identifiers in the create operation, and stores the submission. The proof
is not stored in the log, which is public. The EDD returns the EBW URL
and the first head statement.

```mermaid
sequenceDiagram
    participant O as EBW owner
    participant P as EBW provider
    participant EDD
    O->>O: generate update and credential keys
    O->>O: build and sign create operation
    O->>P: create operation, identification
    P->>P: seal submission
    P->>EDD: POST /register {submission, proof}
    EDD->>EDD: verify proof and seal, attest identifiers
    EDD->>EDD: check operation (§3.3), derive EBW URL
    EDD-->>P: 201 {owner, head statement}
    P-->>O: EBW URL
```

### 6.3 Lookup

`GET /lookup/{type}/{value}` returns the identifier attestation for an
existing identifier, or 404. The `value` is percent-encoded.

### 6.4 Auditing

`GET /{url}/log` returns every operation for the EBW URL in order,
including overridden ones, in the submissions that carried them:

```cddl
log = [+ log-entry]
log-entry = {
  "submission": bstr .cbor submission,
  "received_at": time,        ; EDD receipt time
  "overridden": bool,
}
```

The optional query parameter `after` (a hex `op-hash`) returns only later
entries.

An auditor checks that:

1. the first entry is a create operation whose hash gives the EBW URL;
2. each entry is valid under §3.3 against the registry document before
   it, or is a valid recovery (§3.4), and its submission seal verifies
   (§3.6);
3. the head in a recent head statement is the last non-overridden entry.

Auditors SHOULD compare logs fetched at different times and from
different vantage points. A log that shrinks, or two logs that disagree
on an operation's successor, shows the EDD misbehaving.

### 6.5 Update

`POST /{url}` submits an update or status operation, in an encoded
submission (§3.6). The EDD checks it (§3.3) and returns the new head
statement.

| Error | Status | Problem type |
|---|---|---|
| Malformed submission or operation | 400 | `malformed-operation` |
| Seal does not verify, or certificate not qualified | 403 | `invalid-seal` |
| Bad signature or key not allowed | 403 | `unauthorized-key` |
| Status operation not sealed by the owner's current EBW provider | 403 | `unauthorized-provider` |
| Registry document breaks the rules for `status` (§3.2) | 422 | `invalid-status-change` |
| `prev` is not the head and recovery does not apply | 409 | `stale-prev` |
| Identifier not attested | 422 | `identifier-not-attested` |
| EBW URL retired, merged or closed | 410 | `ended` |

### 6.6 EDD metadata

`GET /.well-known/edd` returns JSON:

```json
{
  "edd": "https://edd.europa.eu",
  "seal_certificates": [
    {"x5c": ["MIIC...", "MIID..."], "not_before": "2026-01-01T00:00:00Z", "not_after": "2028-01-01T00:00:00Z"}
  ],
  "identifier_types": ["euid", "lei", "vat", "eori", "iso6523"],
  "recovery_window": 604800
}
```

## 7. Caching and freshness

No time is fixed by this specification. Each object says how long it
may be used:

| Item | Usable until |
|---|---|
| Status list token | Its `exp` |
| Head statement | As long as a usable status list token shows it VALID |
| Identifier attestation | Its `expires_at`, unless revoked earlier |
| Registry document | As long as its head statement is usable |
| Log | As the HTTP caching headers say |

An endpoint MAY keep using a cached registry document to build a session
while the EDD is unreachable. RDSes enforce freshness for evidence
(§5.4).

## 8. Example

A create operation, in CBOR diagnostic notation (payload shown decoded):

```
/ COSE_Sign1 / [
  / protected / << { 1: -8, 4: h'90f8...88f1' } >>,
  / unprotected / {},
  / payload / << {
    "type": "create",
    "prev": null,
    "update_keys": [
      { 1: 1, -1: 6, -2: h'b0a8...406f' },
      { 1: 1, -1: 6, -2: h'5943...581d' }
    ],
    "credential_keys": [ { 1: 1, -1: 6, -2: h'3c01...c387' } ],
    "rds": "https://rds.example-provider.eu/scc-rds",
    "identifiers": [ { "type": "vat", "value": "DE123456789" } ],
    "acceptance_policies": { "default": "any" },
    "status": "active",
    "signed_at": 1792224000
  } >>,
  / signature / h'c3e3...490b'
]
```

Complete examples are in [`examples/`](examples/): `create-op.diag`,
`update-op.diag`, `status-op.diag`, `submission.diag`,
`head-statement.diag`, `edd-status-list.diag` and
`identifier-attestation.diag`.

## 9. Security considerations

- **Update key custody.** An owner SHOULD hold its highest-priority
  update key offline. A lower-priority key MAY be held by the RDS for
  routine updates. The owner can then undo the RDS's changes within the
  recovery window.
- **Withholding.** The EDD could serve different logs to different
  parties. Head statements are signed, so two conflicting statements for
  the same `seq` are proof of misbehaviour.
- **Status timing.** A status change takes effect for RDSes when the
  last status list token showing the old head statement as VALID
  expires. The EDD controls this delay through the validity it gives its
  tokens.
- **Status operations.** The owner's EBW provider can suspend,
  reinstate or retire the owner without the owner's keys, as the draft
  EBW Regulation requires. It cannot make any other change. Its
  seal on each status operation makes it accountable for the change, and
  the operation stays in the public log.
- **Privacy.** The registry document is public. It names the RDS, the
  identifiers and role names used in policies. It does not list
  endpoints or holders. Endpoint revocation is not recorded here but in
  status lists (doc 2 §5.3).
