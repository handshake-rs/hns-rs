#!/usr/bin/env python3
"""Generate source-independent exact Handshake Resource Manifest v1 fixtures.

This generator uses only Python's standard library. It deliberately implements
deterministic CBOR, BLAKE2b-256 domain hashing, RFC6979 secp256k1 signing,
strict DER encoding, low-S normalization, and HRM commitment formatting rather
than invoking Rust code. The checked-in vectors therefore remain an independent
wire-format oracle for the hns-hrm crate.

The example resource profile is test-only. Its entries exercise HRM Core's
generic resource and delegation encoding, but do not assert operational
authority under a deployed resource profile.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from pathlib import Path
import struct
from typing import TypeAlias


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "hrm-v1"
PACKAGE_FIXTURE_DIR = ROOT / "crates" / "hns-hrm" / "fixtures" / "hrm-v1"
FIXTURE_NAME = "hns-hrm-core-v1.txt"

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

NETWORK_MAGIC = 0xAE3895CF
WRONG_NETWORK_MAGIC = NETWORK_MAGIC ^ 1
PRIVATE_KEY = bytes([1]) * 32
OTHER_PRIVATE_KEY = bytes([2]) * 32
SUBJECT = bytes([0x0F]) * 32
WRONG_SUBJECT = bytes([0x0E]) * 32
SEQUENCE = 7
ISSUED_AT = 1_700_000_000
EXPIRES_AT = 1_700_086_400
RESOURCE_EXPIRES_AT = 1_700_080_000
DELEGATION_NOT_BEFORE = 1_700_000_100
DELEGATION_EXPIRES_AT = 1_700_070_000

SIGNATURE_DOMAIN = b"HNS-HRM-v1\x00"
RESOURCE_ID_DOMAIN = b"HNS-HRM-CORE-FIXTURE-RESOURCE-ID-V1\x00"
DELEGATION_ID_DOMAIN = b"HNS-HRM-CORE-FIXTURE-DELEGATION-ID-V1\x00"

CborValue: TypeAlias = (
    int | bytes | str | bool | list["CborValue"] | dict[int, "CborValue"]
)
VectorValue: TypeAlias = bytes | str | int


def cbor_head(major: int, argument: int) -> bytes:
    if argument < 0:
        raise ValueError("CBOR argument must be non-negative")
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    if argument <= 0xFF:
        return bytes([prefix | 24, argument])
    if argument <= 0xFFFF:
        return bytes([prefix | 25]) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + argument.to_bytes(4, "big")
    if argument <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + argument.to_bytes(8, "big")
    raise ValueError("CBOR integer exceeds u64")


def cbor(value: CborValue) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return cbor_head(0, value)
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return cbor_head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return cbor_head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        entries = [(cbor(key), cbor(item)) for key, item in value.items()]
        entries.sort(key=lambda entry: (len(entry[0]), entry[0]))
        return cbor_head(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise TypeError(f"unsupported CBOR fixture value: {type(value)!r}")


def point_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_mul(
    scalar: int, point: tuple[int, int] = (GX, GY)
) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def public_key(private_key: bytes) -> bytes:
    scalar = int.from_bytes(private_key, "big")
    if not 1 <= scalar < N:
        raise ValueError("invalid secp256k1 private key")
    point = point_mul(scalar)
    assert point is not None
    x, y = point
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def deterministic_nonces(private_key: bytes, digest: bytes):
    """Yield RFC6979 HMAC-SHA256 nonces for a 256-bit prehash."""

    scalar = int.from_bytes(private_key, "big")
    reduced_digest = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    key = b"\x00" * 32
    value = b"\x01" * 32
    seed = scalar.to_bytes(32, "big") + reduced_digest
    key = hmac.new(key, value + b"\x00" + seed, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + seed, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        nonce = int.from_bytes(value, "big")
        if 1 <= nonce < N:
            yield nonce
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def der_integer(value: int) -> bytes:
    encoded = value.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + bytes([len(encoded)]) + encoded


def der_signature(r: int, s: int) -> bytes:
    encoded = der_integer(r) + der_integer(s)
    return b"\x30" + bytes([len(encoded)]) + encoded


def sign_components(private_key: bytes, digest: bytes) -> tuple[int, int]:
    scalar = int.from_bytes(private_key, "big")
    z = int.from_bytes(digest, "big")
    for nonce in deterministic_nonces(private_key, digest):
        point = point_mul(nonce)
        assert point is not None
        r = point[0] % N
        if r == 0:
            continue
        s = (pow(nonce, -1, N) * (z + r * scalar)) % N
        if s == 0:
            continue
        if s > N // 2:
            s = N - s
        return r, s
    raise AssertionError("unreachable RFC6979 nonce exhaustion")


def sign_der(private_key: bytes, digest: bytes) -> bytes:
    return der_signature(*sign_components(private_key, digest))


def signature_digest(network_magic: int, payload: bytes) -> bytes:
    return hashlib.blake2b(
        SIGNATURE_DOMAIN + struct.pack("<I", network_magic) + payload,
        digest_size=32,
    ).digest()


def signature_object(public_key_bytes: bytes, signature: bytes) -> dict[int, CborValue]:
    return {0: 1, 1: public_key_bytes, 2: signature}


def envelope(payload: bytes, public_key_bytes: bytes, signature: bytes) -> bytes:
    return cbor({0: payload, 1: [signature_object(public_key_bytes, signature)]})


def base64url_no_pad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def fixture_vectors() -> list[tuple[str, VectorValue]]:
    controller_public_key = public_key(PRIVATE_KEY)
    other_public_key = public_key(OTHER_PRIVATE_KEY)

    identifier = cbor({0: "core-fixture", 1: 1})
    resource_id = hashlib.sha256(RESOURCE_ID_DOMAIN + identifier).digest()
    child_identifier = cbor({0: "core-fixture-child", 1: 1})
    child_resource_id = hashlib.sha256(
        RESOURCE_ID_DOMAIN + child_identifier
    ).digest()
    delegation_body: dict[int, CborValue] = {
        1: resource_id,
        2: "example.hrm-core/v1",
        3: child_resource_id,
        4: child_identifier,
        5: bytes([5]) * 32,
        6: {0: 1, 1: other_public_key},
        7: ["inspect", "operate"],
        8: DELEGATION_NOT_BEFORE,
        9: DELEGATION_EXPIRES_AT,
        10: False,
        11: {0: 1, 1: 600},
    }
    delegation_id = hashlib.sha256(
        DELEGATION_ID_DOMAIN + cbor(delegation_body)
    ).digest()
    delegation = {0: delegation_id, **delegation_body}
    resource: dict[int, CborValue] = {
        0: "example.hrm-core/v1",
        1: resource_id,
        2: identifier,
        3: {0: 0},
        4: ISSUED_AT,
        5: RESOURCE_EXPIRES_AT,
        6: {0: 0, 1: bytes(32)},
    }
    payload_object: dict[int, CborValue] = {
        0: 1,
        1: SUBJECT,
        2: SEQUENCE,
        3: ISSUED_AT,
        4: EXPIRES_AT,
        5: {0: 1, 1: controller_public_key},
        6: [resource],
        7: [delegation],
        8: {0: "source-independent", 1: True},
    }
    payload = cbor(payload_object)
    digest = signature_digest(NETWORK_MAGIC, payload)
    signature = sign_der(PRIVATE_KEY, digest)
    encoded_envelope = envelope(payload, controller_public_key, signature)
    envelope_hash = hashlib.sha256(encoded_envelope).digest()

    wrong_network_digest = signature_digest(WRONG_NETWORK_MAGIC, payload)
    wrong_network_signature = sign_der(PRIVATE_KEY, wrong_network_digest)
    wrong_network_envelope = envelope(
        payload, controller_public_key, wrong_network_signature
    )

    other_signature = sign_der(OTHER_PRIVATE_KEY, digest)
    wrong_controller_envelope = envelope(payload, other_public_key, other_signature)

    tampered_payload_object = dict(payload_object)
    tampered_payload_object[2] = SEQUENCE + 1
    tampered_payload = cbor(tampered_payload_object)
    tampered_payload_envelope = envelope(
        tampered_payload, controller_public_key, signature
    )

    r, low_s = sign_components(PRIVATE_KEY, digest)
    high_s_signature = der_signature(r, N - low_s)
    high_s_envelope = envelope(payload, controller_public_key, high_s_signature)

    assert payload.startswith(b"\xa9\x00\x01")
    noncanonical_payload = payload[:2] + b"\x18\x01" + payload[3:]
    unknown_key_payload = bytes([payload[0] + 1]) + payload[1:] + b"\x09\x00"

    hash_field = f"hash=sha256:{base64url_no_pad(envelope_hash)}"
    conflicting_hash = hashlib.sha256(wrong_network_envelope).digest()
    conflict_hash_field = f"hash=sha256:{base64url_no_pad(conflicting_hash)}"
    locator = f"https://fixtures.example/hrm/{base64url_no_pad(envelope_hash)}"

    return [
        ("network_magic", NETWORK_MAGIC),
        ("network_magic_u32le", struct.pack("<I", NETWORK_MAGIC)),
        ("wrong_network_magic", WRONG_NETWORK_MAGIC),
        ("private_key", PRIVATE_KEY),
        ("other_private_key", OTHER_PRIVATE_KEY),
        ("controller_public_key", controller_public_key),
        ("other_public_key", other_public_key),
        ("subject", SUBJECT),
        ("wrong_subject", WRONG_SUBJECT),
        ("sequence", SEQUENCE),
        ("issued_at", ISSUED_AT),
        ("expires_at", EXPIRES_AT),
        ("resource_id", resource_id),
        ("child_resource_id", child_resource_id),
        ("delegation_id", delegation_id),
        ("payload_v1", payload),
        ("payload_signature_digest", digest),
        ("controller_signature_der", signature),
        ("envelope_v1", encoded_envelope),
        ("envelope_sha256", envelope_hash),
        ("wrong_network_signature_envelope", wrong_network_envelope),
        ("wrong_controller_signature_envelope", wrong_controller_envelope),
        ("tampered_payload_envelope", tampered_payload_envelope),
        ("high_s_signature_envelope", high_s_envelope),
        ("noncanonical_payload", noncanonical_payload),
        ("unknown_key_payload", unknown_key_payload),
        ("trailing_envelope", encoded_envelope + b"\x00"),
        ("commitment_marker", "hrm1"),
        ("commitment_seq", f"seq={SEQUENCE}"),
        ("commitment_hash", hash_field),
        ("commitment_uri", f"uri={locator}"),
        ("commitment_replica_uri", "uri=https://replica.example/hrm/core-v1"),
        ("lower_commitment_seq", f"seq={SEQUENCE - 1}"),
        ("conflict_commitment_hash", conflict_hash_field),
        ("mismatch_commitment_hash", f"hash=sha256:{base64url_no_pad(bytes(32))}"),
        ("invalid_commitment_seq", "seq=07"),
        ("invalid_commitment_unknown", "critical=1"),
        ("invalid_commitment_uri_unclosed_literal", "uri=https://["),
        ("invalid_commitment_uri_bracketed_reg_name", "uri=https://exa[mple"),
        ("invalid_commitment_uri_repeated_fragment", "uri=https://example/a#one#two"),
    ]


def render(vectors: list[tuple[str, VectorValue]]) -> bytes:
    lines = [
        "# Handshake Resource Manifest Core v1 exact vectors",
        "# Generated by generators/generate-hrm-v1-fixtures.py; do not edit.",
        "# example.hrm-core/v1 is test-only and grants no operational authority.",
    ]
    for name, value in vectors:
        if isinstance(value, bytes):
            rendered = value.hex()
        else:
            rendered = str(value)
        lines.append(f"{name}={rendered}")
    return ("\n".join(lines) + "\n").encode("ascii")


def write_fixture(path: Path, content: bytes) -> None:
    digest = hashlib.sha256(content).hexdigest()
    sidecar_content = f"{digest}  {path.name}\n"
    if not path.exists() or path.read_bytes() != content:
        path.write_bytes(content)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if not sidecar.exists() or sidecar.read_text(encoding="ascii") != sidecar_content:
        sidecar.write_text(sidecar_content, encoding="ascii")


def check_fixture(path: Path, content: bytes) -> None:
    digest = hashlib.sha256(content).hexdigest()
    expected_sidecar = f"{digest}  {path.name}\n"
    if not path.is_file() or path.read_bytes() != content:
        raise SystemExit(f"{path} differs from deterministic generator output")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if not sidecar.is_file() or sidecar.read_text(encoding="ascii") != expected_sidecar:
        raise SystemExit(f"{sidecar} differs from deterministic generator output")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    document = render(fixture_vectors())
    if args.write:
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        PACKAGE_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        write_fixture(FIXTURE_DIR / FIXTURE_NAME, document)
        write_fixture(PACKAGE_FIXTURE_DIR / FIXTURE_NAME, document)
    elif args.check:
        check_fixture(FIXTURE_DIR / FIXTURE_NAME, document)
        check_fixture(PACKAGE_FIXTURE_DIR / FIXTURE_NAME, document)
    else:
        print(document.decode("ascii"), end="")


if __name__ == "__main__":
    main()
