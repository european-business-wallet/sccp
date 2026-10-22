"""Small helpers shared by the SCC example generator and checker.

Deterministic CBOR (RFC 8949 §4.2.1), COSE_Sign1 with Ed25519, COSE Key
thumbprints (RFC 9679), and the TLS encoding used by MLS (RFC 9420 §2.1).
"""

import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---- Deterministic CBOR ----

def _sorted(obj):
    if isinstance(obj, dict):
        items = [(cbor2.dumps(_sorted(k)), _sorted(k), _sorted(v)) for k, v in obj.items()]
        items.sort(key=lambda t: t[0])
        return {k: v for _, k, v in items}
    if isinstance(obj, (list, tuple)):
        return [_sorted(x) for x in obj]
    if isinstance(obj, cbor2.CBORTag):
        return cbor2.CBORTag(obj.tag, _sorted(obj.value))
    return obj


def dcbor(obj) -> bytes:
    """Encode with core deterministic encoding: map keys in bytewise order."""
    return cbor2.dumps(_sorted(obj))


def is_deterministic(data: bytes) -> bool:
    return dcbor(cbor2.loads(data)) == data


# ---- Keys ----

def ed25519_key(label: str) -> Ed25519PrivateKey:
    """A demo key derived from a label, so that examples are reproducible."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def raw_public(key) -> bytes:
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def cose_key(key) -> dict:
    return {1: 1, -1: 6, -2: raw_public(key)}


def thumbprint(ckey: dict) -> bytes:
    """COSE Key Thumbprint (RFC 9679) over the required parameters."""
    required = {k: ckey[k] for k in (1, -1, -2, -3) if k in ckey}
    return hashlib.sha256(dcbor(required)).digest()


# ---- COSE_Sign1 ----

def sign1(key: Ed25519PrivateKey, payload, extra_protected=None) -> bytes:
    protected = {1: -8, 4: thumbprint(cose_key(key))}
    if extra_protected:
        protected.update(extra_protected)
    protected_b = dcbor(protected)
    payload_b = dcbor(payload)
    to_sign = dcbor(["Signature1", protected_b, b"", payload_b])
    sig = key.sign(to_sign)
    return dcbor([protected_b, {}, payload_b, sig])


def verify1(public_raw: bytes, cose: bytes) -> dict:
    protected_b, _, payload_b, sig = cbor2.loads(cose)
    to_sign = dcbor(["Signature1", protected_b, b"", payload_b])
    Ed25519PublicKey.from_public_bytes(public_raw).verify(sig, to_sign)
    return cbor2.loads(payload_b)


# ---- TLS encoding (RFC 9420 §2.1) ----

def varint(n: int) -> bytes:
    if n < 1 << 6:
        return n.to_bytes(1, "big")
    if n < 1 << 14:
        return (n | 0x4000).to_bytes(2, "big")
    if n < 1 << 30:
        return (n | 0x80000000).to_bytes(4, "big")
    raise ValueError("vector too long")


def vec(data: bytes) -> bytes:
    return varint(len(data)) + data


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u64(n: int) -> bytes:
    return n.to_bytes(8, "big")


# ---- Misc ----

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def url_from_create(op: bytes) -> str:
    return "ebw:" + base64.b32encode(sha256(op)).decode().lower()[:24]


# ---- CBOR diagnostic notation (RFC 8949 §8) with embedded CBOR shown ----

def _embedded(b: bytes):
    """Return the decoded value if b is deterministic CBOR holding a map, array or tag."""
    if len(b) < 3 or b[0] >> 5 not in (4, 5, 6):
        return None
    try:
        v = cbor2.loads(b)
    except Exception:
        return None
    return v if isinstance(v, (dict, list, cbor2.CBORTag)) and dcbor(v) == b else None


def diag(v, indent=0) -> str:
    pad, inner = "  " * indent, "  " * (indent + 1)
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (bytes, bytearray)):
        e = _embedded(bytes(v))
        if e is not None:
            return "<< " + diag(e, indent) + " >>"
        return "h'" + bytes(v).hex() + "'"
    if isinstance(v, (list, tuple)):
        if not v:
            return "[]"
        return "[\n" + ",\n".join(inner + diag(x, indent + 1) for x in v) + "\n" + pad + "]"
    if isinstance(v, cbor2.CBORTag):
        return f"{v.tag}(" + diag(v.value, indent) + ")"
    if isinstance(v, (dict, cbor2.frozendict)):
        if not v:
            return "{}"
        return "{\n" + ",\n".join(inner + diag(k, indent + 1) + ": " + diag(x, indent + 1)
                                  for k, x in v.items()) + "\n" + pad + "}"
    raise TypeError(type(v))
