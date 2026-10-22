# EBW Secure Communication Channel

> **This is a work in progress.** It is not an official proposal, deliverable or
> position of the European Commission, of any Member State, or of any standards
> body, and it confers no status. Any part of it may change.

This repository holds the design of the Secure Communication Channel (SCC)
for the European Business Wallet: a specification set with
machine-checkable schemas, the tooling that checks them, and a reference
implementation in Rust.

SCC carries messages between EBW owners (legal persons) with end-to-end
encryption, and produces registered-delivery evidence in the shape of
ETSI EN 319 522, without the delivery services ever seeing plaintext. It
is built around four elements:

1. **Discovery.** Each EBW owner has an EBW URL. Its registry document
   is set by a log of signed operations in the European Digital
   Directory (EDD).
2. **End-to-end encryption.** Messages travel in MLS groups. Both
   delivery services log each group's Commits and check its membership on
   every send.
3. **Delivery.** A profile of the Wallet Messaging Protocol (WMP), in the
   four-corner model: each owner uses its own Registered Delivery Service
   (RDS).
4. **Evidence.** RDSes issue sealed, timestamped evidence bound to the
   ciphertext, a salted plaintext hash and the MLS group state.

## Layout

```
spec/
  README.md            overview, terminology, conventions
  01-discovery.md      EBW URLs and the EDD
  02-credentials.md    endpoint credentials and their MLS binding
  03-mls.md            MLS profile: sessions, Commit logs, membership checks
  04-delivery.md       delivery protocol (WMP profile)
  05-evidence.md       evidence, decryption reports, disputes
  schemas/             CDDL, OpenAPI, OpenRPC and JSON Schema
  examples/            generated examples (see its README)
tools/
  gen_examples.py      generates spec/examples/
  check.py             validates schemas and examples
impl/                  reference implementation (Rust crate; see its README)
  src/bin/             scc-edd, scc-rds, scc-endpoint, scc-verifier
  demo.sh              end-to-end demo
```

## Checking the specification

`make check` validates every schema and example, and checks that the
documents agree with the schema files. It needs:

- Python 3. `make` creates a virtual environment in `.venv` and installs
  [`requirements.txt`](requirements.txt).
- The `cddl` and `cbor-diag` tools:

  ```sh
  cargo install cddl --locked
  cargo install cbor-diag-cli --locked
  ```

`make examples` regenerates `spec/examples/`. The examples use real
signatures with demo keys; MLS messages and timestamp tokens are
placeholders (see [`spec/examples/README.md`](spec/examples/README.md)).

## Running the reference implementation

`impl/` is a single Rust crate, using `mls-rs` for MLS. It has binaries
for the EDD, the RDS, endpoints (including owner tooling), and a verifier
that checks evidence against a message's plaintext. `impl/demo.sh` builds
it and runs a complete scenario: an EDD and two RDSes, two owners with
several endpoints each, messages in both directions within a session, and
verification of the evidence. See [`impl/README.md`](impl/README.md) for
details, and [`impl/NOTES.md`](impl/NOTES.md) for what is simplified or
stubbed.

## Inputs

The design draws on:

- **SBM**, the Secure Business Messaging design study:
  <https://github.com/european-business-wallet/sbm-design-study>
- **WMP**, the Wallet Messaging Protocol:
  <https://github.com/sirosfoundation/wmp>
- **ETSI EN 319 522** parts 1 to 3 (V1.2.1), Electronic Registered
  Delivery Services
- **MLS**: RFC 9420 and draft-ietf-mls-extensions

## Status

This is a draft design. The specification set has a reference
implementation, which runs the full demo, but neither has been reviewed.
The implementation stubs the qualified parts of the system (timestamps,
seal certificates, Trusted List checks, identity proofing), as described
in [`impl/NOTES.md`](impl/NOTES.md).
