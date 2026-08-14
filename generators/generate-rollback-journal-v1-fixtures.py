#!/usr/bin/env python3
"""Generate source-independent external rollback-journal v1 vectors.

This standard-library oracle deliberately duplicates the canonical codec and
domain-separated hashes without importing or invoking the Rust implementation.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NAME = "rollback-journal-v1.txt"
FIXTURE_DIRS = [
    ROOT / "fixtures/rollback-journal-v1",
    ROOT / "crates/hns-rollback-journal/fixtures/rollback-journal-v1",
]

MAGIC = b"HNSRBJ1\x00"
FORMAT_VERSION = 1
CHECKSUM_DOMAIN = b"HNS-ROLLBACK-JOURNAL-CHECKSUM-V1\x00"
RECORD_DOMAIN = b"HNS-ROLLBACK-JOURNAL-RECORD-V1\x00"
BINDING_DOMAIN = b"HNS-ROLLBACK-JOURNAL-BINDING-V1\x00"
SNAPSHOT_BYTES_DOMAIN = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-BYTES-V1\x00"
SNAPSHOT_IMAGE_DOMAIN = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-IMAGE-V1\x00"
SNAPSHOT_AAD_DOMAIN = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-AAD-V1\x00"
TRANSITION_DOMAIN = b"HNS-ROLLBACK-JOURNAL-TRANSITION-V1\x00"
RETIREMENT_DOMAIN = b"HNS-ROLLBACK-JOURNAL-RETIREMENT-V1\x00"

NETWORK_MAGIC = 0x5B6EC86B
OLD_REVISION = 9_007_199_254_740_993
NEW_REVISION = OLD_REVISION + 2
OLD_PLAINTEXT = bytes.fromhex("000102030405")
NEW_PLAINTEXT = bytes.fromhex("fffefdfcfbfa")
OLD_CIPHERTEXT = bytes(range(0xA0, 0xA0 + len(OLD_PLAINTEXT) + 28))
NEW_CIPHERTEXT = bytes(range(0xB0, 0xB0 + len(NEW_PLAINTEXT) + 28))


def blake2b256(domain: bytes, *parts: bytes) -> bytes:
    return hashlib.blake2b(domain + b"".join(parts), digest_size=32).digest()


def compact_size(value: int) -> bytes:
    if value <= 0xFC:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def binding_bytes() -> bytes:
    return b"".join(
        [
            bytes([1]) * 32,
            struct.pack("<I", NETWORK_MAGIC),
            bytes([2]) * 32,
            bytes([3]) * 32,
            bytes([4]) * 32,
            bytes([5]) * 32,
            struct.pack("<H", 3),
            struct.pack("<H", 1),
            struct.pack("<I", 7),
            bytes([6]) * 32,
            bytes([1]),
        ]
    )


def state_identity(revision: int, protocol: bytes, plaintext: bytes) -> bytes:
    return (
        struct.pack("<Q", revision)
        + protocol
        + blake2b256(SNAPSHOT_BYTES_DOMAIN, plaintext)
    )


def snapshot_image(
    revision: int, protocol: bytes, plaintext: bytes, ciphertext: bytes
) -> tuple[bytes, bytes]:
    identity = state_identity(revision, protocol, plaintext)
    image = (
        identity
        + struct.pack("<I", len(plaintext))
        + compact_size(len(ciphertext))
        + ciphertext
    )
    return identity, image


def record(journal_revision: int, state: bytes) -> bytes:
    body = (
        MAGIC
        + struct.pack("<H", FORMAT_VERSION)
        + binding_bytes()
        + struct.pack("<Q", journal_revision)
        + state
    )
    return body + blake2b256(CHECKSUM_DOMAIN, body)


def vectors() -> list[tuple[str, bytes | int]]:
    binding = binding_bytes()
    binding_fingerprint = blake2b256(BINDING_DOMAIN, binding)
    old_identity, old_image = snapshot_image(
        OLD_REVISION, bytes([0x11]) * 32, OLD_PLAINTEXT, OLD_CIPHERTEXT
    )
    new_identity, new_image = snapshot_image(
        NEW_REVISION, bytes([0x22]) * 32, NEW_PLAINTEXT, NEW_CIPHERTEXT
    )
    old_image_fingerprint = blake2b256(SNAPSHOT_IMAGE_DOMAIN, old_image)
    new_image_fingerprint = blake2b256(SNAPSHOT_IMAGE_DOMAIN, new_image)
    transition_id = blake2b256(
        TRANSITION_DOMAIN,
        binding_fingerprint,
        old_image_fingerprint,
        new_image_fingerprint,
    )

    never = record(0, b"\x00")
    stable = record(1, b"\x01" + old_image)
    prepared = record(2, b"\x02" + transition_id + old_image + new_image)
    finalized = record(3, b"\x01" + new_image)
    finalized_fingerprint = blake2b256(RECORD_DOMAIN, finalized)
    retirement_id = blake2b256(
        RETIREMENT_DOMAIN,
        binding_fingerprint,
        new_identity,
        finalized_fingerprint,
    )
    retired = record(4, b"\x03" + new_identity + retirement_id)

    return [
        ("network_magic", NETWORK_MAGIC),
        ("old_revision", OLD_REVISION),
        ("new_revision", NEW_REVISION),
        ("old_plaintext", OLD_PLAINTEXT),
        ("new_plaintext", NEW_PLAINTEXT),
        ("old_ciphertext", OLD_CIPHERTEXT),
        ("new_ciphertext", NEW_CIPHERTEXT),
        ("binding", binding),
        ("binding_fingerprint", binding_fingerprint),
        ("old_identity", old_identity),
        ("new_identity", new_identity),
        ("old_image", old_image),
        ("new_image", new_image),
        ("old_image_fingerprint", old_image_fingerprint),
        ("new_image_fingerprint", new_image_fingerprint),
        (
            "old_snapshot_aad",
            SNAPSHOT_AAD_DOMAIN
            + binding_fingerprint
            + old_identity
            + struct.pack("<I", len(OLD_PLAINTEXT)),
        ),
        ("transition_id", transition_id),
        ("never_record", never),
        ("never_record_fingerprint", blake2b256(RECORD_DOMAIN, never)),
        ("stable_record", stable),
        ("stable_record_fingerprint", blake2b256(RECORD_DOMAIN, stable)),
        ("prepared_record", prepared),
        ("prepared_record_fingerprint", blake2b256(RECORD_DOMAIN, prepared)),
        ("finalized_record", finalized),
        ("finalized_record_fingerprint", finalized_fingerprint),
        ("retirement_id", retirement_id),
        ("retired_record", retired),
        ("retired_record_fingerprint", blake2b256(RECORD_DOMAIN, retired)),
    ]


def render() -> bytes:
    lines = [
        "# External rollback journal v1 exact vectors",
        "# Generated by generators/generate-rollback-journal-v1-fixtures.py; do not edit.",
        "# All u64 revisions must remain exact across JavaScript/mobile adapters.",
    ]
    for name, value in vectors():
        rendered = value.hex() if isinstance(value, bytes) else str(value)
        lines.append(f"{name}={rendered}")
    return ("\n".join(lines) + "\n").encode("ascii")


def sidecar(path: Path, content: bytes) -> str:
    return f"{hashlib.sha256(content).hexdigest()}  {path.name}\n"


def write_fixture(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_bytes() != content:
        path.write_bytes(content)
    checksum = sidecar(path, content)
    checksum_path = path.with_suffix(path.suffix + ".sha256")
    if not checksum_path.exists() or checksum_path.read_text("ascii") != checksum:
        checksum_path.write_text(checksum, encoding="ascii")


def check_fixture(path: Path, content: bytes) -> None:
    if not path.is_file() or path.read_bytes() != content:
        raise SystemExit(f"{path} differs from deterministic generator output")
    checksum_path = path.with_suffix(path.suffix + ".sha256")
    if not checksum_path.is_file() or checksum_path.read_text("ascii") != sidecar(path, content):
        raise SystemExit(f"{checksum_path} differs from deterministic generator output")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.write:
        for directory in FIXTURE_DIRS:
            write_fixture(directory / FIXTURE_NAME, content)
    elif args.check:
        for directory in FIXTURE_DIRS:
            check_fixture(directory / FIXTURE_NAME, content)
    else:
        print(content.decode("ascii"), end="")


if __name__ == "__main__":
    main()
