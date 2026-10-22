#!/usr/bin/env python3
"""Validate the SCC schemas and examples.

Checks:
  1. The CDDL files compile together.
  2. Every CBOR example matches (or, if marked invalid, fails) its CDDL rule.
  3. Every valid CBOR example, and every COSE protected header and payload
     inside it, uses deterministic encoding.
  4. Every .diag file converts back to its .cbor file.
  5. The CDDL shown in the documents matches the schema files.
  6. The EDD OpenAPI document is valid.
  7. The OpenRPC document is valid against the OpenRPC meta-schema.
  8. Every JSON-RPC example matches its method's parameter, result or error
     schema, and its direction tag.
  9. The method and error tables in 04-delivery.md match the OpenRPC document.
 10. JSON documents match their JSON Schemas.

Requires the `cddl` and `cbor-diag` tools (cargo install cddl cbor-diag-cli)
and the Python packages in requirements.txt.
"""

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

import cbor2
import jsonschema
import yaml
from openapi_spec_validator import validate as validate_openapi

sys.path.insert(0, os.path.dirname(__file__))
from scc_cbor import is_deterministic  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "spec")
SCHEMAS = os.path.join(SPEC, "schemas")
EXAMPLES = os.path.join(SPEC, "examples")
CDDL_FILES = ["common.cddl", "discovery.cddl", "credentials.cddl", "mls.cddl", "evidence.cddl"]

failures = []
passes = 0


def ok(msg):
    global passes
    passes += 1
    if "-v" in sys.argv:
        print("  ok   " + msg)


def fail(msg):
    failures.append(msg)
    print("  FAIL " + msg)


def section(title):
    print(title)


# ---- CDDL ----

def cddl_source():
    return "".join(open(os.path.join(SCHEMAS, f)).read() + "\n" for f in CDDL_FILES)


def cddl_validate(rule, cbor_path):
    with tempfile.NamedTemporaryFile("w", suffix=".cddl", delete=False) as t:
        t.write(f"scc-root = {rule}\n" + cddl_source())
        name = t.name
    try:
        out = subprocess.run(["cddl", "validate", "--cddl", name, "--cbor", cbor_path],
                             capture_output=True, text=True)
    finally:
        os.unlink(name)
    text = out.stdout + out.stderr
    return "is successful" in text and "[ERROR]" not in text, text


def check_cddl():
    section("1. CDDL compiles")
    with tempfile.NamedTemporaryFile("w", suffix=".cddl", delete=False) as t:
        t.write("scc-root = any\n" + cddl_source())
        name = t.name
    out = subprocess.run(["cddl", "compile-cddl", "--cddl", name], capture_output=True, text=True)
    os.unlink(name)
    if "is conformant" in out.stdout + out.stderr:
        ok("combined CDDL")
    else:
        fail("CDDL does not compile:\n" + out.stdout + out.stderr)


def cose_parts(v, found):
    """Collect protected headers and payloads of COSE_Sign1 structures."""
    if isinstance(v, list):
        if (len(v) == 4 and isinstance(v[0], bytes) and isinstance(v[1], dict)
                and isinstance(v[2], bytes) and isinstance(v[3], bytes)):
            found.extend([v[0], v[2]])
            for part in (v[0], v[2]):
                try:
                    cose_parts(cbor2.loads(part), found)
                except Exception:
                    pass
        for x in v:
            cose_parts(x, found)
    elif isinstance(v, dict):
        for x in v.values():
            cose_parts(x, found)
    elif isinstance(v, bytes) and v[:1] and v[0] >> 5 in (4, 5):
        try:
            cose_parts(cbor2.loads(v), found)
        except Exception:
            pass


def check_cbor_examples(manifest):
    section("2-4. CBOR examples")
    for ex in manifest["examples"]:
        path = os.path.join(EXAMPLES, ex["file"])
        valid, text = cddl_validate(ex["rule"], path)
        if valid == ex["valid"]:
            ok(f"{ex['file']} {'matches' if valid else 'is rejected by'} {ex['rule']}")
        else:
            expect = "match" if ex["valid"] else "be rejected by"
            fail(f"{ex['file']} should {expect} {ex['rule']}\n{text}")
        data = open(path, "rb").read()
        if ex["valid"]:
            parts = []
            cose_parts(cbor2.loads(data), parts)
            if is_deterministic(data) and all(is_deterministic(p) for p in parts):
                ok(f"{ex['file']} deterministic ({len(parts)} COSE parts)")
            else:
                fail(f"{ex['file']} is not deterministically encoded")
        diag = open(path[:-5] + ".diag", "rb").read()
        back = subprocess.run(["cbor-diag", "--from", "diag", "--to", "bytes"],
                              input=diag, capture_output=True).stdout
        if back == data:
            ok(f"{ex['file']} diag round-trips")
        else:
            fail(f"{ex['file']}: .diag does not convert back to .cbor")


def normalize_rule(text):
    text = re.sub(r";[^\n]*", "", text)
    return re.sub(r"\s+", " ", text).strip()


def cddl_rules(text):
    """Split CDDL text into {name: normalized definition}."""
    text = re.sub(r";[^\n]*", "", text)
    rules = {}
    for m in re.finditer(r"^([A-Za-z][A-Za-z0-9_-]*(?:<[^>]*>)?)\s*=(.*?)(?=^[A-Za-z][A-Za-z0-9_-]*(?:<[^>]*>)?\s*=|\Z)",
                         text, re.S | re.M):
        rules[m.group(1).split("<")[0]] = normalize_rule(m.group(2))
    return rules


def check_doc_cddl():
    section("5. CDDL in documents matches schema files")
    schema_rules = cddl_rules(cddl_source())
    for doc in sorted(os.listdir(SPEC)):
        if not doc.endswith(".md"):
            continue
        text = open(os.path.join(SPEC, doc)).read()
        for block in re.findall(r"```cddl\n(.*?)```", text, re.S):
            for name, body in cddl_rules(block).items():
                if name not in schema_rules:
                    fail(f"{doc}: rule {name} is not in the schema files")
                elif schema_rules[name] != body:
                    fail(f"{doc}: rule {name} differs from the schema files\n"
                         f"    doc:    {body}\n    schema: {schema_rules[name]}")
                else:
                    ok(f"{doc}: {name}")


# ---- OpenAPI ----

def check_openapi():
    section("6. EDD OpenAPI")
    doc = yaml.safe_load(open(os.path.join(SCHEMAS, "edd.openapi.yaml")))
    try:
        validate_openapi(doc)
        ok("edd.openapi.yaml")
    except Exception as e:  # noqa: BLE001
        fail(f"edd.openapi.yaml: {e}")
    cddl_names = set(cddl_rules(cddl_source()))
    for ref in re.findall(r"x-cddl: ([a-z-]+)", open(os.path.join(SCHEMAS, "edd.openapi.yaml")).read()):
        if ref in cddl_names:
            ok(f"x-cddl {ref} exists")
        else:
            fail(f"edd.openapi.yaml: x-cddl {ref} is not a CDDL rule")
    return doc


# ---- OpenRPC ----

def load_openrpc():
    return json.load(open(os.path.join(SCHEMAS, "delivery.openrpc.json")))


def check_openrpc(doc):
    section("7. OpenRPC document")
    meta = json.load(open(os.path.join(ROOT, "tools", "vendor", "openrpc-meta-schema-1.14.9.json")))
    meta.pop("$schema", None)
    errors = list(jsonschema.Draft7Validator(meta).iter_errors(doc))
    if errors:
        for e in errors[:5]:
            fail(f"delivery.openrpc.json: {e.message} at {list(e.path)}")
    else:
        ok("delivery.openrpc.json against the OpenRPC meta-schema")
    names = [m["name"] for m in doc["methods"]]
    if len(names) == len(set(names)):
        ok("method names unique")
    else:
        fail("duplicate method names in OpenRPC document")
    # every $ref resolves
    for ref in re.findall(r'"\$ref": "#/([^"]+)"', json.dumps(doc)):
        node = doc
        try:
            for part in ref.split("/"):
                node = node[part]
            ok(f"$ref {ref}")
        except KeyError:
            fail(f"delivery.openrpc.json: unresolved $ref #/{ref}")


def with_components(schema, doc):
    s = copy.deepcopy(schema)
    s["components"] = doc["components"]
    return s


def resolve(doc, ref):
    node = doc
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def params_schema(method, doc):
    return with_components({
        "type": "object",
        "properties": {p["name"]: p["schema"] for p in method["params"]},
        "required": [p["name"] for p in method["params"] if p.get("required")],
        "additionalProperties": False,
    }, doc)


def check_rpc_examples(doc, manifest):
    section("8. JSON-RPC examples")
    methods = {m["name"]: m for m in doc["methods"]}
    used = set()
    for rel in [x for x in manifest["json"] if isinstance(x, str)]:
        ex = json.load(open(os.path.join(EXAMPLES, rel)))
        direction = ex["direction"]
        pending = {}
        for i, msg in enumerate(ex["messages"]):
            where = f"{rel} message {i}"
            if msg.get("jsonrpc") != "2.0":
                fail(f"{where}: not JSON-RPC 2.0")
                continue
            if "method" in msg:
                m = methods.get(msg["method"])
                if not m:
                    fail(f"{where}: unknown method {msg['method']}")
                    continue
                used.add(m["name"])
                tags = [t["name"] for t in m.get("tags", [])]
                if direction not in tags:
                    fail(f"{where}: {m['name']} is not tagged {direction}")
                if "id" not in msg and "result" in m and direction != "rds-to-endpoint":
                    fail(f"{where}: {m['name']} expects a response but was sent as a notification")
                try:
                    jsonschema.validate(msg["params"], params_schema(m, doc))
                    ok(f"{where}: {m['name']} params")
                except jsonschema.ValidationError as e:
                    fail(f"{where}: {m['name']} params: {e.message}")
                if "id" in msg:
                    pending[msg["id"]] = m
            else:
                m = pending.pop(msg.get("id"), None)
                if not m:
                    fail(f"{where}: response to unknown id {msg.get('id')}")
                    continue
                if "result" in msg:
                    try:
                        jsonschema.validate(msg["result"], with_components(m["result"]["schema"], doc))
                        ok(f"{where}: {m['name']} result")
                    except jsonschema.ValidationError as e:
                        fail(f"{where}: {m['name']} result: {e.message}")
                else:
                    code = msg["error"]["code"]
                    errs = [resolve(doc, e["$ref"]) if "$ref" in e else e for e in m.get("errors", [])]
                    match = [e for e in errs if e["code"] == code]
                    if not match:
                        fail(f"{where}: error {code} is not listed for {m['name']}")
                        continue
                    if "data" in match[0]:
                        try:
                            jsonschema.validate(msg["error"].get("data"), with_components(match[0]["data"], doc))
                            ok(f"{where}: {m['name']} error {code} data")
                        except jsonschema.ValidationError as e:
                            fail(f"{where}: error data: {e.message}")
                    else:
                        ok(f"{where}: {m['name']} error {code}")
        for id_ in pending:
            fail(f"{rel}: request {id_} has no response")
    unused = sorted(set(methods) - used)
    if unused:
        print("  note methods without examples: " + ", ".join(unused))


def check_delivery_tables(doc):
    section("9. 04-delivery.md tables match the OpenRPC document")
    text = open(os.path.join(SPEC, "04-delivery.md")).read()
    in_doc = set(re.findall(r"`((?:scc|wmp)\.[a-z.]*[a-z])`", text))
    in_rpc = {m["name"] for m in doc["methods"]}
    for name in sorted(in_rpc - in_doc):
        fail(f"OpenRPC method {name} is not mentioned in 04-delivery.md")
    for name in sorted(in_doc - in_rpc):
        if name not in ("wmp.message.status",):  # mentioned as replaced
            fail(f"04-delivery.md mentions {name}, which is not in the OpenRPC document")
    codes_doc = {int(c) for c in re.findall(r"^\| (-31\d{3}) \|", text, re.M)}
    codes_rpc = {e["code"] for e in doc["components"]["errors"].values()}
    if codes_doc == codes_rpc:
        ok("error codes agree")
    else:
        fail(f"error codes differ: doc only {sorted(codes_doc - codes_rpc)}, "
             f"OpenRPC only {sorted(codes_rpc - codes_doc)}")
    if not failures:
        ok("method names agree")


TERMINAL = {"SubmissionRejection", "RelayRejection", "RelayFailure",
            "NotificationForAcceptanceFailure", "ConsignmentRejection",
            "AcceptanceRejectionExpiry", "ContentConsignmentFailure",
            "ContentHandover", "ContentHandoverFailure"}


def check_evidence_chain():
    """Check the evidence package's items form a chain (05-evidence.md §3.7)."""
    section("12. Evidence package chain")
    art = cbor2.loads(open(os.path.join(EXAMPLES, "evidence-package.cbor"), "rb").read())
    package = cbor2.loads(cbor2.loads(art[0])[2])
    items = {}
    for item in package["items"]:
        seal = item[0]
        body = cbor2.loads(cbor2.loads(seal)[2])
        items[hashlib.sha256(seal).digest()] = body
    names = {h: b["event"].rsplit("/", 1)[-1] for h, b in items.items()}
    roots = [h for h, b in items.items() if "prev" not in b]
    terminals = [h for h in items if names[h] in TERMINAL]
    referenced = {p for b in items.values() for p in b.get("prev", [])}
    problems = []
    if len(roots) != 1 or names[roots[0]] not in ("SubmissionAcceptance", "SubmissionRejection"):
        problems.append(f"roots: {[names[r] for r in roots]}")
    if len(terminals) != 1:
        problems.append(f"terminals: {[names[t] for t in terminals]}")
    if referenced - set(items):
        problems.append("a prev names evidence outside the package")
    if terminals and terminals[0] in referenced:
        problems.append("the terminal event is followed by other evidence")
    # every item must lie on a path from the root to the terminal
    if roots and terminals:
        on_path, stack = set(), [terminals[0]]
        while stack:
            h = stack.pop()
            if h not in on_path and h in items:
                on_path.add(h)
                stack.extend(items[h].get("prev", []))
        if set(items) - on_path:
            problems.append(f"off the chain: {[names[h] for h in set(items) - on_path]}")
        if roots[0] not in on_path:
            problems.append("the terminal event does not lead back to A.1")
    if problems:
        fail("evidence-package: " + "; ".join(problems))
    else:
        chain = " -> ".join(names[h] for h in items)
        ok(f"evidence-package chain: {chain}")


def check_example_urls(manifest):
    section("11. EBW URLs in the documents match the generated examples")
    owners = set(manifest["owners"].values())
    for doc in sorted(os.listdir(SPEC)) + [os.path.join("examples", "README.md")]:
        if not doc.endswith(".md"):
            continue
        for owner in set(re.findall(r"ebw:[a-z2-7]{24}", open(os.path.join(SPEC, doc)).read())):
            if owner in owners:
                ok(f"{doc}: {owner}")
            else:
                fail(f"{doc}: {owner} is not one of the example owners {sorted(owners)}")


# ---- JSON documents ----

def check_json_documents(openapi, manifest):
    section("10. JSON documents")
    for entry in [x for x in manifest["json"] if isinstance(x, dict)]:
        data = json.load(open(os.path.join(EXAMPLES, entry["file"])))
        target = entry["schema"]
        if "#" in target:
            fname, comp = target.split("#")
            schema = copy.deepcopy(openapi["components"]["schemas"][comp])
            schema["components"] = openapi["components"]
        else:
            schema = json.load(open(os.path.join(SCHEMAS, target)))
        try:
            jsonschema.validate(data, schema)
            ok(f"{entry['file']} against {target}")
        except jsonschema.ValidationError as e:
            fail(f"{entry['file']} against {target}: {e.message}")


def main():
    manifest = json.load(open(os.path.join(EXAMPLES, "manifest.json")))
    check_cddl()
    check_cbor_examples(manifest)
    check_doc_cddl()
    openapi = check_openapi()
    rpc = load_openrpc()
    check_openrpc(rpc)
    check_rpc_examples(rpc, manifest)
    check_delivery_tables(rpc)
    check_json_documents(openapi, manifest)
    check_example_urls(manifest)
    check_evidence_chain()
    print(f"\n{passes} checks passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
