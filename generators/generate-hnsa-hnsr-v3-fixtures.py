#!/usr/bin/env python3
"""Generate source-independent HRM-backed HNSA and HNSR v3 vectors.

The generator deliberately invokes only Python standard-library code and the
independent HRM fixture oracle beside it. It does not call Rust. In addition to
the complete positive chain, it emits replacement/removal/restoration HRMs,
durable service-generation observations, exact authority/requester/storage
snapshot and CAS lineages, product-lattice intermediate states, and negative
endpoint/route bytes for fail-closed conformance tests.

The application profile value is private and test-only. The vectors establish
generic authority and transport encoding, not pool-statistics semantics.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path
import runpy
import struct
from typing import TypeAlias


ROOT = Path(__file__).resolve().parents[1]
HRM_ORACLE = runpy.run_path(str(ROOT / "generators/generate-hrm-v1-fixtures.py"))

cbor = HRM_ORACLE["cbor"]
public_key = HRM_ORACLE["public_key"]
sign_components = HRM_ORACLE["sign_components"]
sign_der = HRM_ORACLE["sign_der"]
der_signature = HRM_ORACLE["der_signature"]
SECP256K1_ORDER = HRM_ORACLE["N"]

FIXTURE_NAME = "hnsa-hnsr-v3.txt"
FIXTURE_DIRS = [
    ROOT / "fixtures/hnsa-hnsr-v3",
    ROOT / "crates/hns-service-authority/fixtures/hnsa-hnsr-v3",
    ROOT / "crates/hns-hnsr-protocol/fixtures/hnsa-hnsr-v3",
]

NETWORK_MAGIC = 0xAE3895CF
WRONG_NETWORK_MAGIC = NETWORK_MAGIC ^ 1
NAME_HASH = bytes([0x0F]) * 32
WRONG_NAME_HASH = bytes([0x0E]) * 32
SERVICE_NAME = "pool-stats"
WRONG_SERVICE_NAME = "other-service"
PROFILE_ID = 0xFF00
WRONG_PROFILE_ID = 0xFF01
HRM_SEQUENCE = 9
HRM_ISSUED_AT = 1_700_000_000
HRM_EXPIRES_AT = 1_700_086_400
RESOURCE_NOT_BEFORE = HRM_ISSUED_AT
RESOURCE_EXPIRES_AT = 1_700_080_000
SERVICE_NOT_BEFORE = HRM_ISSUED_AT + 100
SERVICE_EXPIRES_AT = 1_700_070_000
# Every u64 counter in the transport chain deliberately exceeds JavaScript's
# exact Number range. Independent browser implementations must use BigInt.
HIGH_U64 = 9_007_199_254_740_993
SERVICE_GENERATION = HIGH_U64
MAX_ENDPOINT_LIFETIME = 3_600
ALLOWED_ENDPOINT_CAPABILITIES = 1
ENDPOINT_ISSUED_AT = HRM_ISSUED_AT + 200
ENDPOINT_EXPIRES_AT = ENDPOINT_ISSUED_AT + 1_800
ENDPOINT_SEQUENCE = HIGH_U64 + 10
ROUTE_ISSUED_AT = ENDPOINT_ISSUED_AT
ROUTE_EXPIRES_AT = ROUTE_ISSUED_AT + 900
ROUTE_SEQUENCE = HIGH_U64 + 20
VALIDATION_NOW = HRM_ISSUED_AT + 300

HRM_PRIVATE_KEY = bytes([1]) * 32
SERVICE_PRIVATE_KEY = bytes([3]) * 32
ENDPOINT_PRIVATE_KEY = bytes([4]) * 32
RELAY_PRIVATE_KEY = bytes([5]) * 32
REPLACEMENT_SERVICE_PRIVATE_KEY = bytes([6]) * 32
ALTERNATE_ENDPOINT_PRIVATE_KEY = bytes([7]) * 32

LEGACY_ROOT_PRIVATE_KEY = bytes([11]) * 32
LEGACY_SERVICE_PRIVATE_KEY = bytes([12]) * 32
LEGACY_ENDPOINT_PRIVATE_KEY = bytes([13]) * 32
LEGACY_RELAY_PRIVATE_KEY = bytes([14]) * 32

PROFILE = "hns.named-service/v1"
RESOURCE_ID_DOMAIN = b"HNS-HRM-NAMED-SERVICE-ID-V1\x00"
SERVICE_DELEGATION_ID_DOMAIN = b"HNS-HRM-NAMED-SERVICE-DELEGATION-ID-V1\x00"
ENDPOINT_SIGNATURE_DOMAIN = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\x00"
ENDPOINT_ID_DOMAIN = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-ID-V1\x00"
ROUTE_KEY_DOMAIN = b"HNSR-NAMED-ROUTE-V1\x00"
ROUTE_SIGNATURE_DOMAIN = b"HNSR-HRM-HNSA-ROUTE-RECORD-V3\x00"
TICKET_RELAY_DOMAIN = b"HNSR-RELAY-TICKET-V1\x00"
TICKET_ENDPOINT_DOMAIN = b"HNSR-RELAY-CONFIRM-V1\x00"
HRM_SIGNATURE_DOMAIN = b"HNS-HRM-v1\x00"
LEGACY_SERVICE_AUTH_DOMAIN = b"HNS-SERVICE-AUTH-V1\x00"
LEGACY_SERVICE_AUTH_ID_DOMAIN = b"HNS-SERVICE-AUTH-ID-V1\x00"
LEGACY_ENDPOINT_DOMAIN = b"HNS-ENDPOINT-DELEGATION-V1\x00"
LEGACY_ENDPOINT_ID_DOMAIN = b"HNS-ENDPOINT-DELEGATION-ID-V1\x00"
LEGACY_ROUTE_SIGNATURE_DOMAIN = b"HNSR-HNSA-ROUTE-RECORD-V2\x00"
SERVICE_GENERATION_OBSERVATION_MAGIC = b"HNSASGO\x00"
SERVICE_GENERATION_OBSERVATION_VERSION = 1
SERVICE_GENERATION_OBSERVATION_CHECKSUM_DOMAIN = (
    b"HNS-HRM-HNSA-SERVICE-GENERATION-OBSERVATION-V1\x00"
)
SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE = 226
SERVICE_GENERATION_OBSERVATION_SIZE = 258

# Canonical durable-state formats. These values intentionally duplicate the
# published wire contracts instead of importing or invoking their Rust
# implementations. That keeps the persistence vectors source-independent.
AUTHORITY_SNAPSHOT_MAGIC = b"HNSAAST\x00"
AUTHORITY_SNAPSHOT_VERSION = 1
AUTHORITY_SNAPSHOT_CHECKSUM_DOMAIN = (
    b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-CHECKSUM-V1\x00"
)
AUTHORITY_SNAPSHOT_FINGERPRINT_DOMAIN = (
    b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-FINGERPRINT-V1\x00"
)
AUTHORITY_SNAPSHOT_HEADER_SIZE = 178
AUTHORITY_SNAPSHOT_CAPACITY = 8

REQUESTER_SNAPSHOT_MAGIC = b"HNSRV3Q\x00"
REQUESTER_SNAPSHOT_VERSION = 1
REQUESTER_SNAPSHOT_CHECKSUM_DOMAIN = b"HNSR-NAMED-V3-REQUESTER-SNAPSHOT-V1\x00"
REQUESTER_SNAPSHOT_FINGERPRINT_DOMAIN = b"HNSR-NAMED-V3-REQUESTER-CAS-V1\x00"
CANONICAL_RECORD_HASH_DOMAIN = b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\x00"
REQUESTER_SNAPSHOT_HEADER_SIZE = 40
REQUESTER_SNAPSHOT_ENTRY_SIZE = 277
REQUESTER_SNAPSHOT_CAPACITY = 32
MAX_SERVICE_NAME_SIZE = 63

STORAGE_LEDGER_MAGIC = b"HNSRV3L\x00"
STORAGE_LEDGER_VERSION = 1
STORAGE_LEDGER_CHECKSUM_DOMAIN = b"HNSR-NAMED-V3-LEDGER-SNAPSHOT-V1\x00"
STORAGE_LEDGER_FINGERPRINT_DOMAIN = b"HNSR-NAMED-V3-LEDGER-CAS-V1\x00"
STORAGE_LEDGER_HEADER_SIZE = 44
STORAGE_LEDGER_ENTRY_SIZE = 155
STORAGE_LEDGER_CAPACITY = 32
STORAGE_LEDGER_RECORDS_PER_KEY = 16

# Trusted-time persistence must round-trip exactly in JavaScript/mobile
# implementations, so at least one time/floor vector is beyond Number's exact
# integer range as well as all route and generation counters.
PERSISTENCE_HIGH_TIME = HIGH_U64 + 1_000

CborValue: TypeAlias = int | bytes | str | bool | list["CborValue"] | dict[int, "CborValue"]
VectorValue: TypeAlias = bytes | str | int


def blake2b256(*parts: bytes) -> bytes:
    return hashlib.blake2b(b"".join(parts), digest_size=32).digest()


def deterministic_signature(domain: bytes, *parts: bytes, key: bytes) -> bytes:
    return sign_der(key, blake2b256(domain, *parts))


def encoded_signature(signature: bytes) -> bytes:
    if not 1 <= len(signature) <= 80:
        raise ValueError("signature is outside the protocol bound")
    return bytes([len(signature)]) + signature


def high_s_signature(domain: bytes, *parts: bytes, key: bytes) -> bytes:
    digest = blake2b256(domain, *parts)
    r, low_s = sign_components(key, digest)
    return der_signature(r, SECP256K1_ORDER - low_s)


def nonminimal_der_signature(signature: bytes) -> bytes:
    """Add a redundant INTEGER sign octet while preserving r and s values."""

    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2:
        raise ValueError("fixture signature is not short-form DER")
    if signature[2] != 0x02:
        raise ValueError("fixture signature has no r INTEGER")
    r_length = signature[3]
    r_end = 4 + r_length
    if r_end + 2 > len(signature) or signature[r_end] != 0x02:
        raise ValueError("fixture signature has no s INTEGER")
    malformed = bytearray(signature)
    malformed[1] += 1
    malformed[3] += 1
    malformed.insert(4, 0)
    if len(malformed) > 80:
        raise ValueError("malformed signature exceeds the protocol bound")
    return bytes(malformed)


def service_identifier(
    *,
    network_magic: int = NETWORK_MAGIC,
    name_hash: bytes = NAME_HASH,
    service_name: str = SERVICE_NAME,
    profile_id: int = PROFILE_ID,
) -> bytes:
    return cbor(
        {
            0: network_magic,
            1: name_hash,
            2: service_name,
            3: profile_id,
        }
    )


def service_resource(
    identifier: bytes,
    resource_id: bytes,
    *,
    authority: dict[int, CborValue] | None = None,
    profile_flags: int = 0,
    profile_constraints_hash: bytes = bytes(32),
) -> dict[int, CborValue]:
    if authority is None:
        authority = {0: 0}
    return {
        0: PROFILE,
        1: resource_id,
        2: identifier,
        3: authority,
        4: RESOURCE_NOT_BEFORE,
        5: RESOURCE_EXPIRES_AT,
        6: {0: profile_flags, 1: profile_constraints_hash},
    }


def service_delegation(
    identifier: bytes,
    resource_id: bytes,
    generation: int,
    service_public_key: bytes,
    *,
    child_subject: bytes = NAME_HASH,
    endpoint_constraints_hash: bytes = bytes(32),
) -> tuple[dict[int, CborValue], bytes, bytes]:
    body: dict[int, CborValue] = {
        1: resource_id,
        2: PROFILE,
        3: resource_id,
        4: identifier,
        5: child_subject,
        6: {0: 1, 1: service_public_key},
        7: ["delegate-endpoint", "operate"],
        8: SERVICE_NOT_BEFORE,
        9: SERVICE_EXPIRES_AT,
        10: False,
        11: {
            0: generation,
            1: MAX_ENDPOINT_LIFETIME,
            2: ALLOWED_ENDPOINT_CAPABILITIES,
            3: endpoint_constraints_hash,
        },
    }
    encoded_body = cbor(body)
    delegation_id = hashlib.sha256(
        SERVICE_DELEGATION_ID_DOMAIN + encoded_body
    ).digest()
    return {0: delegation_id, **body}, encoded_body, delegation_id


def hrm_envelope(
    sequence: int,
    resources: list[dict[int, CborValue]],
    delegations: list[dict[int, CborValue]],
    *,
    subject: bytes = NAME_HASH,
) -> tuple[bytes, bytes]:
    controller_public_key = public_key(HRM_PRIVATE_KEY)
    payload = cbor(
        {
            0: 1,
            1: subject,
            2: sequence,
            3: HRM_ISSUED_AT,
            4: HRM_EXPIRES_AT,
            5: {0: 1, 1: controller_public_key},
            6: resources,
            7: delegations,
        }
    )
    digest = blake2b256(
        HRM_SIGNATURE_DOMAIN, struct.pack("<I", NETWORK_MAGIC), payload
    )
    signature = sign_der(HRM_PRIVATE_KEY, digest)
    envelope = cbor(
        {
            0: payload,
            1: [{0: 1, 1: controller_public_key, 2: signature}],
        }
    )
    return payload, envelope


def endpoint_body(
    resource_id: bytes,
    delegation_id: bytes,
    generation: int = SERVICE_GENERATION,
    network_magic: int = NETWORK_MAGIC,
    capabilities: int = ALLOWED_ENDPOINT_CAPABILITIES,
    endpoint_sequence: int = ENDPOINT_SEQUENCE,
    endpoint_public_key: bytes | None = None,
    issued_at: int = ENDPOINT_ISSUED_AT,
    expires_at: int = ENDPOINT_EXPIRES_AT,
    constraints_hash: bytes = bytes(32),
) -> bytes:
    if endpoint_public_key is None:
        endpoint_public_key = public_key(ENDPOINT_PRIVATE_KEY)
    return b"".join(
        [
            b"\x01",
            struct.pack("<I", network_magic),
            resource_id,
            delegation_id,
            struct.pack("<Q", generation),
            endpoint_public_key,
            struct.pack("<Q", endpoint_sequence),
            struct.pack("<Q", issued_at),
            struct.pack("<Q", expires_at),
            struct.pack("<I", capabilities),
            constraints_hash,
        ]
    )


def signed_endpoint(
    body: bytes,
    *,
    high_s: bool = False,
    signing_key: bytes = SERVICE_PRIVATE_KEY,
    signature: bytes | None = None,
) -> bytes:
    if signature is not None:
        return body + encoded_signature(signature)
    signature = (
        high_s_signature(ENDPOINT_SIGNATURE_DOMAIN, body, key=signing_key)
        if high_s
        else deterministic_signature(ENDPOINT_SIGNATURE_DOMAIN, body, key=signing_key)
    )
    return body + encoded_signature(signature)


def ticket_unsigned(
    endpoint_public_key: bytes,
    *,
    network_magic: int = NETWORK_MAGIC,
    reservation_byte: int = 0x10,
    profile_id: int = PROFILE_ID,
    issued_at: int = ENDPOINT_ISSUED_AT,
    expires_at: int = ENDPOINT_EXPIRES_AT,
    relay_public_key: bytes | None = None,
    host: bytes | None = None,
) -> bytes:
    if relay_public_key is None:
        relay_public_key = public_key(RELAY_PRIVATE_KEY)
    if host is None:
        host = bytes(10) + bytes([0xFF, 0xFF, 127, 0, 0, 1])
    return b"".join(
        [
            b"\x01",
            struct.pack("<I", network_magic),
            struct.pack("<H", profile_id),
            b"\x00",
            b"\x01",
            host,
            struct.pack("<H", 14_039),
            relay_public_key,
            endpoint_public_key,
            bytes([reservation_byte]) * 16,
            struct.pack("<Q", issued_at),
            struct.pack("<Q", expires_at),
            struct.pack("<H", 8),
            struct.pack("<Q", 1_048_576),
            struct.pack("<Q", 8_388_608),
            struct.pack("<H", 0),
        ]
    )


def ticket_signatures(
    unsigned: bytes,
    *,
    relay_private_key: bytes = RELAY_PRIVATE_KEY,
    endpoint_private_key: bytes = ENDPOINT_PRIVATE_KEY,
) -> tuple[bytes, bytes, bytes, bytes]:
    relay_digest = blake2b256(TICKET_RELAY_DOMAIN, unsigned)
    relay_signature = deterministic_signature(
        TICKET_RELAY_DOMAIN, unsigned, key=relay_private_key
    )
    endpoint_digest = blake2b256(TICKET_ENDPOINT_DOMAIN, unsigned, relay_signature)
    endpoint_signature = deterministic_signature(
        TICKET_ENDPOINT_DOMAIN,
        unsigned,
        relay_signature,
        key=endpoint_private_key,
    )
    return relay_digest, relay_signature, endpoint_digest, endpoint_signature


def signed_ticket(
    unsigned: bytes,
    *,
    relay_private_key: bytes = RELAY_PRIVATE_KEY,
    endpoint_private_key: bytes = ENDPOINT_PRIVATE_KEY,
    relay_signature: bytes | None = None,
    endpoint_signature: bytes | None = None,
) -> bytes:
    if relay_signature is None:
        relay_signature = deterministic_signature(
            TICKET_RELAY_DOMAIN, unsigned, key=relay_private_key
        )
    if endpoint_signature is None:
        endpoint_signature = deterministic_signature(
            TICKET_ENDPOINT_DOMAIN,
            unsigned,
            relay_signature,
            key=endpoint_private_key,
        )
    return (
        unsigned
        + encoded_signature(relay_signature)
        + encoded_signature(endpoint_signature)
    )


def route_key(
    *,
    network_magic: int = NETWORK_MAGIC,
    name_hash: bytes = NAME_HASH,
    service_name: str = SERVICE_NAME,
    profile_id: int = PROFILE_ID,
) -> bytes:
    service_name_bytes = service_name.encode("ascii")
    return blake2b256(
        ROUTE_KEY_DOMAIN,
        struct.pack("<I", network_magic),
        name_hash,
        bytes([len(service_name_bytes)]),
        service_name_bytes,
        struct.pack("<H", profile_id),
    )


def route_body(
    resource_id: bytes,
    delegation_id: bytes,
    endpoint: bytes,
    tickets: list[bytes],
    *,
    record_sequence: int = ROUTE_SEQUENCE,
    route_resource_id: bytes | None = None,
    route_delegation_id: bytes | None = None,
    route_key_bytes: bytes | None = None,
    profile_id: int = PROFILE_ID,
    service_generation: int = SERVICE_GENERATION,
    service_controller_key: bytes | None = None,
    issued_at: int = ROUTE_ISSUED_AT,
    expires_at: int = ROUTE_EXPIRES_AT,
) -> bytes:
    if route_resource_id is None:
        route_resource_id = resource_id
    if route_delegation_id is None:
        route_delegation_id = delegation_id
    if route_key_bytes is None:
        route_key_bytes = route_key()
    if service_controller_key is None:
        service_controller_key = public_key(SERVICE_PRIVATE_KEY)
    return b"".join(
        [
            b"\x03",
            b"\x02",
            route_key_bytes,
            struct.pack("<H", profile_id),
            struct.pack("<Q", record_sequence),
            struct.pack("<Q", issued_at),
            struct.pack("<Q", expires_at),
            route_resource_id,
            route_delegation_id,
            struct.pack("<Q", service_generation),
            service_controller_key,
            struct.pack("<H", len(endpoint)),
            endpoint,
            bytes([len(tickets)]),
            b"".join(tickets),
        ]
    )


def signed_route(
    body: bytes,
    *,
    high_s: bool = False,
    signing_key: bytes = ENDPOINT_PRIVATE_KEY,
    signature: bytes | None = None,
) -> bytes:
    if signature is not None:
        return body + encoded_signature(signature)
    signature = (
        high_s_signature(ROUTE_SIGNATURE_DOMAIN, body, key=signing_key)
        if high_s
        else deterministic_signature(ROUTE_SIGNATURE_DOMAIN, body, key=signing_key)
    )
    return body + encoded_signature(signature)


def signed_hrm_snapshot(
    sequence: int,
    resources: list[dict[int, CborValue]],
    delegations: list[dict[int, CborValue]],
    *,
    subject: bytes = NAME_HASH,
) -> tuple[bytes, bytes]:
    return hrm_envelope(sequence, resources, delegations, subject=subject)


def named_identity_snapshot(
    *,
    network_magic: int = NETWORK_MAGIC,
    name_hash: bytes = NAME_HASH,
    service_name: str = SERVICE_NAME,
    profile_id: int = PROFILE_ID,
) -> tuple[bytes, bytes, dict[int, CborValue], dict[int, CborValue], bytes, bytes]:
    identifier = service_identifier(
        network_magic=network_magic,
        name_hash=name_hash,
        service_name=service_name,
        profile_id=profile_id,
    )
    resource_id = hashlib.sha256(RESOURCE_ID_DOMAIN + identifier).digest()
    resource = service_resource(identifier, resource_id)
    delegation, _, delegation_id = service_delegation(
        identifier,
        resource_id,
        SERVICE_GENERATION,
        public_key(SERVICE_PRIVATE_KEY),
    )
    payload, envelope = signed_hrm_snapshot(HRM_SEQUENCE + 1, [resource], [delegation])
    return identifier, resource_id, resource, delegation, payload, envelope


def chain_state(sequence: int) -> tuple[int, bytes, bytes]:
    chain_work = bytes(24) + sequence.to_bytes(8, "big")
    chain_anchor = hashlib.sha256(
        b"test-chain-anchor" + sequence.to_bytes(8, "little")
    ).digest()
    return sequence + 100, chain_work, chain_anchor


def service_generation_observation(
    *,
    network_magic: int,
    subject: bytes,
    resource_id: bytes,
    highest_generation: int,
    high_water_delegation_id: bytes,
    active: bool,
    hrm_sequence: int,
    hrm_envelope_hash: bytes,
    chain_height: int,
    chain_work: bytes,
    chain_anchor: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Independently encode one exact durable HNSA observation."""

    if len(subject) != 32:
        raise ValueError("observation subject must be 32 bytes")
    if len(resource_id) != 32:
        raise ValueError("observation resource ID must be 32 bytes")
    if len(high_water_delegation_id) != 32:
        raise ValueError("observation high-water delegation ID must be 32 bytes")
    if len(hrm_envelope_hash) != 32:
        raise ValueError("observation HRM envelope hash must be 32 bytes")
    if len(chain_work) != 32:
        raise ValueError("observation chain work must be 32 bytes")
    if len(chain_anchor) != 32:
        raise ValueError("observation chain anchor must be 32 bytes")
    if highest_generation == 0 and (active or high_water_delegation_id != bytes(32)):
        raise ValueError("zero-generation observation must be an empty tombstone")

    payload = b"".join(
        [
            SERVICE_GENERATION_OBSERVATION_MAGIC,
            bytes([SERVICE_GENERATION_OBSERVATION_VERSION]),
            struct.pack("<I", network_magic),
            subject,
            resource_id,
            struct.pack("<Q", highest_generation),
            high_water_delegation_id,
            bytes([int(active)]),
            struct.pack("<Q", hrm_sequence),
            hrm_envelope_hash,
            struct.pack("<I", chain_height),
            chain_work,
            chain_anchor,
        ]
    )
    if len(payload) != SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE:
        raise ValueError("observation payload has the wrong exact size")
    checksum = blake2b256(SERVICE_GENERATION_OBSERVATION_CHECKSUM_DOMAIN, payload)
    encoded = payload + checksum
    if len(encoded) != SERVICE_GENERATION_OBSERVATION_SIZE:
        raise ValueError("observation has the wrong exact size")
    return payload, checksum, encoded


def checksummed_snapshot(
    payload: bytes,
    checksum_domain: bytes,
    fingerprint_domain: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Return exact payload, corruption checksum, image, and CAS fingerprint."""

    checksum = blake2b256(checksum_domain, payload)
    encoded = payload + checksum
    fingerprint = blake2b256(fingerprint_domain, encoded)
    return payload, checksum, encoded, fingerprint


def authority_rollback_body(
    sequence: int,
    envelope: bytes,
    chain_height: int,
    chain_work: bytes,
    chain_anchor: bytes,
) -> bytes:
    if len(chain_work) != 32 or len(chain_anchor) != 32:
        raise ValueError("authority rollback chain fields must be 32 bytes")
    return b"".join(
        [
            struct.pack("<Q", sequence),
            hashlib.sha256(envelope).digest(),
            struct.pack("<I", chain_height),
            chain_work,
            chain_anchor,
        ]
    )


def authority_snapshot(
    *,
    revision: int,
    trusted_time: int,
    rollback_body: bytes | None,
    observations: list[bytes],
) -> tuple[bytes, bytes, bytes, bytes]:
    if observations != sorted(observations, key=lambda item: item[45:77]):
        raise ValueError("authority observations must be sorted by resource ID")
    if any(len(item) != SERVICE_GENERATION_OBSERVATION_SIZE for item in observations):
        raise ValueError("authority observation has the wrong exact size")
    rollback = bytes(108) if rollback_body is None else rollback_body
    if len(rollback) != 108:
        raise ValueError("authority rollback body has the wrong exact size")
    payload = b"".join(
        [
            AUTHORITY_SNAPSHOT_MAGIC,
            bytes([AUTHORITY_SNAPSHOT_VERSION]),
            struct.pack("<I", NETWORK_MAGIC),
            NAME_HASH,
            struct.pack("<I", AUTHORITY_SNAPSHOT_CAPACITY),
            struct.pack("<Q", revision),
            struct.pack("<Q", trusted_time),
            bytes([int(rollback_body is not None)]),
            rollback,
            struct.pack("<I", len(observations)),
            *observations,
        ]
    )
    expected_size = AUTHORITY_SNAPSHOT_HEADER_SIZE + len(observations) * SERVICE_GENERATION_OBSERVATION_SIZE
    if len(payload) != expected_size:
        raise ValueError("authority snapshot payload has the wrong exact size")
    return checksummed_snapshot(
        payload,
        AUTHORITY_SNAPSHOT_CHECKSUM_DOMAIN,
        AUTHORITY_SNAPSHOT_FINGERPRINT_DOMAIN,
    )


def requester_snapshot_entry(
    *,
    resource_id: bytes,
    route_key_bytes: bytes,
    endpoint_key: bytes,
    endpoint_high_water: int,
    endpoint_conflicted: bool,
    endpoint_canonical_id: bytes,
    route_high_water: int,
    route_conflicted: bool,
    route_canonical_hash: bytes,
) -> bytes:
    service_name = SERVICE_NAME.encode("ascii")
    if not 1 <= len(service_name) <= MAX_SERVICE_NAME_SIZE:
        raise ValueError("requester service name is outside its exact bound")
    fields = [resource_id, route_key_bytes, endpoint_key, endpoint_canonical_id, route_canonical_hash]
    if [len(item) for item in fields] != [32, 32, 33, 32, 32]:
        raise ValueError("requester scope or observation has the wrong size")
    encoded = b"".join(
        [
            NAME_HASH,
            bytes([len(service_name)]),
            service_name,
            bytes(MAX_SERVICE_NAME_SIZE - len(service_name)),
            struct.pack("<H", PROFILE_ID),
            resource_id,
            route_key_bytes,
            endpoint_key,
            struct.pack("<Q", endpoint_high_water),
            bytes([int(endpoint_conflicted)]),
            endpoint_canonical_id,
            struct.pack("<Q", route_high_water),
            bytes([int(route_conflicted)]),
            route_canonical_hash,
        ]
    )
    if len(encoded) != REQUESTER_SNAPSHOT_ENTRY_SIZE:
        raise ValueError("requester snapshot entry has the wrong exact size")
    return encoded


def requester_snapshot(
    *,
    revision: int,
    trusted_time: int,
    entries: list[bytes],
) -> tuple[bytes, bytes, bytes, bytes]:
    if any(len(item) != REQUESTER_SNAPSHOT_ENTRY_SIZE for item in entries):
        raise ValueError("requester snapshot entry has the wrong exact size")
    if entries != sorted(entries):
        raise ValueError("requester snapshot entries must be sorted canonically")
    payload = b"".join(
        [
            REQUESTER_SNAPSHOT_MAGIC,
            bytes([REQUESTER_SNAPSHOT_VERSION]),
            bytes(3),
            struct.pack("<I", NETWORK_MAGIC),
            struct.pack("<I", REQUESTER_SNAPSHOT_CAPACITY),
            struct.pack("<Q", revision),
            struct.pack("<Q", trusted_time),
            struct.pack("<I", len(entries)),
            *entries,
        ]
    )
    expected_size = REQUESTER_SNAPSHOT_HEADER_SIZE + len(entries) * REQUESTER_SNAPSHOT_ENTRY_SIZE
    if len(payload) != expected_size:
        raise ValueError("requester snapshot payload has the wrong exact size")
    return checksummed_snapshot(
        payload,
        REQUESTER_SNAPSHOT_CHECKSUM_DOMAIN,
        REQUESTER_SNAPSHOT_FINGERPRINT_DOMAIN,
    )


def storage_ledger_entry(
    *,
    route_key_bytes: bytes,
    endpoint_key: bytes,
    endpoint_high_water: int,
    endpoint_delegation_id: bytes,
    endpoint_conflicted: bool,
    route_high_water: int,
    retain_until: int,
    route_conflicted: bool,
    route_canonical_hash: bytes,
) -> bytes:
    fields = [route_key_bytes, endpoint_key, endpoint_delegation_id, route_canonical_hash]
    if [len(item) for item in fields] != [32, 33, 32, 32]:
        raise ValueError("storage ledger key or observation has the wrong size")
    encoded = b"".join(
        [
            route_key_bytes,
            endpoint_key,
            struct.pack("<Q", endpoint_high_water),
            endpoint_delegation_id,
            bytes([int(endpoint_conflicted)]),
            struct.pack("<Q", route_high_water),
            struct.pack("<Q", retain_until),
            bytes([int(route_conflicted)]),
            route_canonical_hash,
        ]
    )
    if len(encoded) != STORAGE_LEDGER_ENTRY_SIZE:
        raise ValueError("storage ledger entry has the wrong exact size")
    return encoded


def storage_ledger_snapshot(
    *,
    revision: int,
    pruned_through: int,
    entries: list[bytes],
) -> tuple[bytes, bytes, bytes, bytes]:
    if any(len(item) != STORAGE_LEDGER_ENTRY_SIZE for item in entries):
        raise ValueError("storage ledger entry has the wrong exact size")
    if entries != sorted(entries):
        raise ValueError("storage ledger entries must be sorted canonically")
    payload = b"".join(
        [
            STORAGE_LEDGER_MAGIC,
            bytes([STORAGE_LEDGER_VERSION]),
            bytes(3),
            struct.pack("<I", NETWORK_MAGIC),
            struct.pack("<I", STORAGE_LEDGER_CAPACITY),
            struct.pack("<I", STORAGE_LEDGER_RECORDS_PER_KEY),
            struct.pack("<Q", revision),
            struct.pack("<Q", pruned_through),
            struct.pack("<I", len(entries)),
            *entries,
        ]
    )
    expected_size = STORAGE_LEDGER_HEADER_SIZE + len(entries) * STORAGE_LEDGER_ENTRY_SIZE
    if len(payload) != expected_size:
        raise ValueError("storage ledger payload has the wrong exact size")
    return checksummed_snapshot(
        payload,
        STORAGE_LEDGER_CHECKSUM_DOMAIN,
        STORAGE_LEDGER_FINGERPRINT_DOMAIN,
    )


def legacy_service_authorization() -> tuple[bytes, bytes, bytes, bytes]:
    service_name = SERVICE_NAME.encode("ascii")
    unsigned = b"".join(
        [
            b"\x01",
            struct.pack("<I", NETWORK_MAGIC),
            NAME_HASH,
            struct.pack("<I", 3),
            bytes([len(service_name)]),
            service_name,
            struct.pack("<H", PROFILE_ID),
            public_key(LEGACY_SERVICE_PRIVATE_KEY),
            struct.pack("<H", 0),
            struct.pack("<Q", 1),
            struct.pack("<I", 100),
            struct.pack("<I", 200),
            struct.pack("<I", MAX_ENDPOINT_LIFETIME),
        ]
    )
    digest = blake2b256(LEGACY_SERVICE_AUTH_DOMAIN, unsigned[1:])
    signature = sign_der(LEGACY_ROOT_PRIVATE_KEY, digest)
    complete = unsigned + encoded_signature(signature)
    authorization_id = blake2b256(LEGACY_SERVICE_AUTH_ID_DOMAIN, complete)
    return unsigned, digest, signature, complete + authorization_id


def legacy_endpoint_delegation(
    authorization_id: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    issued_at = HRM_ISSUED_AT
    unsigned = b"".join(
        [
            b"\x01",
            struct.pack("<I", NETWORK_MAGIC),
            authorization_id,
            public_key(LEGACY_ENDPOINT_PRIVATE_KEY),
            struct.pack("<Q", 1),
            struct.pack("<Q", issued_at),
            struct.pack("<Q", issued_at + 1_800),
            struct.pack("<I", 1),
            bytes(32),
        ]
    )
    digest = blake2b256(LEGACY_ENDPOINT_DOMAIN, unsigned[1:])
    signature = sign_der(LEGACY_SERVICE_PRIVATE_KEY, digest)
    complete = unsigned + encoded_signature(signature)
    delegation_id = blake2b256(LEGACY_ENDPOINT_ID_DOMAIN, complete)
    return unsigned, digest, signature, complete + delegation_id


def legacy_named_route_v2() -> dict[str, bytes | str]:
    authorization_unsigned, authorization_digest, authorization_signature, packed = (
        legacy_service_authorization()
    )
    authorization = packed[:-32]
    authorization_id = packed[-32:]
    endpoint_unsigned, endpoint_digest, endpoint_signature, packed = (
        legacy_endpoint_delegation(authorization_id)
    )
    endpoint = packed[:-32]
    endpoint_id = packed[-32:]
    endpoint_key = public_key(LEGACY_ENDPOINT_PRIVATE_KEY)
    ticket_unsigned_bytes = ticket_unsigned(
        endpoint_key,
        relay_public_key=public_key(LEGACY_RELAY_PRIVATE_KEY),
        host=bytes(16),
        issued_at=HRM_ISSUED_AT,
        expires_at=HRM_ISSUED_AT + 1_800,
    )
    ticket = signed_ticket(
        ticket_unsigned_bytes,
        relay_private_key=LEGACY_RELAY_PRIVATE_KEY,
        endpoint_private_key=LEGACY_ENDPOINT_PRIVATE_KEY,
    )
    route_unsigned = b"".join(
        [
            b"\x02\x01",
            route_key(),
            struct.pack("<H", PROFILE_ID),
            struct.pack("<Q", 1),
            struct.pack("<Q", HRM_ISSUED_AT),
            struct.pack("<Q", HRM_ISSUED_AT + 900),
            struct.pack("<H", len(authorization)),
            authorization,
            struct.pack("<H", len(endpoint)),
            endpoint,
            b"\x01",
            ticket,
        ]
    )
    route_digest = blake2b256(LEGACY_ROUTE_SIGNATURE_DOMAIN, route_unsigned)
    route_signature = sign_der(LEGACY_ENDPOINT_PRIVATE_KEY, route_digest)
    route = route_unsigned + encoded_signature(route_signature)
    authority_key = public_key(LEGACY_ROOT_PRIVATE_KEY)
    authority_base32 = base64.b32encode(authority_key).decode("ascii").lower().rstrip("=")
    return {
        "authority_record": f"hsa1 k={authority_base32} e=3",
        "authorization_unsigned": authorization_unsigned,
        "authorization_signature_digest": authorization_digest,
        "authorization_signature": authorization_signature,
        "authorization": authorization,
        "authorization_id": authorization_id,
        "endpoint_unsigned": endpoint_unsigned,
        "endpoint_signature_digest": endpoint_digest,
        "endpoint_signature": endpoint_signature,
        "endpoint": endpoint,
        "endpoint_id": endpoint_id,
        "ticket": ticket,
        "route_unsigned": route_unsigned,
        "route_signature_digest": route_digest,
        "route_signature": route_signature,
        "route": route,
    }


def fixture_vectors() -> list[tuple[str, VectorValue]]:
    identifier = service_identifier()
    resource_id = hashlib.sha256(RESOURCE_ID_DOMAIN + identifier).digest()
    resource = service_resource(identifier, resource_id)
    service_public_key = public_key(SERVICE_PRIVATE_KEY)
    delegation, delegation_body, delegation_id = service_delegation(
        identifier, resource_id, SERVICE_GENERATION, service_public_key
    )
    payload, envelope = hrm_envelope(HRM_SEQUENCE, [resource], [delegation])

    equal_generation_conflict, equal_generation_conflict_body, equal_generation_conflict_id = (
        service_delegation(
            identifier,
            resource_id,
            SERVICE_GENERATION,
            public_key(REPLACEMENT_SERVICE_PRIVATE_KEY),
        )
    )
    equal_generation_conflict_payload, equal_generation_conflict_envelope = hrm_envelope(
        HRM_SEQUENCE + 1, [resource], [equal_generation_conflict]
    )
    rollback, rollback_body, rollback_id = service_delegation(
        identifier,
        resource_id,
        SERVICE_GENERATION - 1,
        public_key(REPLACEMENT_SERVICE_PRIVATE_KEY),
    )
    rollback_payload, rollback_envelope = hrm_envelope(
        HRM_SEQUENCE + 1, [resource], [rollback]
    )

    replacement_public_key = public_key(REPLACEMENT_SERVICE_PRIVATE_KEY)
    replacement, replacement_body, replacement_id = service_delegation(
        identifier, resource_id, SERVICE_GENERATION + 1, replacement_public_key
    )
    replacement_payload, replacement_envelope = hrm_envelope(
        HRM_SEQUENCE + 1, [resource], [replacement]
    )
    removal_payload, removal_envelope = hrm_envelope(HRM_SEQUENCE + 2, [resource], [])
    reorg_withdrawal_payload, reorg_withdrawal_envelope = hrm_envelope(
        HRM_SEQUENCE, [resource], []
    )
    restoration, restoration_body, restoration_id = service_delegation(
        identifier, resource_id, SERVICE_GENERATION + 2, replacement_public_key
    )
    restoration_payload, restoration_envelope = hrm_envelope(
        HRM_SEQUENCE + 3, [resource], [restoration]
    )

    wrong_identity_network = named_identity_snapshot(network_magic=WRONG_NETWORK_MAGIC)
    wrong_identity_name_hash = named_identity_snapshot(name_hash=WRONG_NAME_HASH)
    wrong_identity_service_name = named_identity_snapshot(service_name=WRONG_SERVICE_NAME)
    wrong_identity_application_profile = named_identity_snapshot(profile_id=WRONG_PROFILE_ID)

    wrong_origin_resource = service_resource(
        identifier,
        resource_id,
        authority={
            0: 1,
            1: "test.external-origin/v1",
            2: bytes([0xA1]) * 32,
            3: [],
        },
    )
    wrong_origin_payload, wrong_origin_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1, [wrong_origin_resource], [delegation]
    )
    wrong_flags_resource = service_resource(identifier, resource_id, profile_flags=1)
    wrong_flags_payload, wrong_flags_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1, [wrong_flags_resource], [delegation]
    )
    wrong_profile_constraints_resource = service_resource(
        identifier,
        resource_id,
        profile_constraints_hash=bytes([0xA2]) * 32,
    )
    wrong_profile_constraints_payload, wrong_profile_constraints_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1, [wrong_profile_constraints_resource], [delegation]
    )
    missing_operate_payload, missing_operate_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1, [resource], []
    )
    duplicate_operate_payload, duplicate_operate_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1,
        [resource],
        [delegation, equal_generation_conflict],
    )
    resource_removal_payload, resource_removal_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 2, [], []
    )
    mismatched_subject_payload, mismatched_subject_envelope = signed_hrm_snapshot(
        HRM_SEQUENCE + 1,
        [resource],
        [delegation],
        subject=WRONG_NAME_HASH,
    )
    reorg_previous_height, reorg_previous_work, reorg_previous_anchor = chain_state(
        HRM_SEQUENCE + 1
    )
    reorg_current_height, reorg_current_work, reorg_current_anchor = chain_state(HRM_SEQUENCE)
    withdrawal_height, withdrawal_work, withdrawal_anchor = chain_state(HRM_SEQUENCE + 2)

    active_observation_payload, active_observation_checksum, active_observation = (
        service_generation_observation(
            network_magic=NETWORK_MAGIC,
            subject=NAME_HASH,
            resource_id=resource_id,
            highest_generation=SERVICE_GENERATION,
            high_water_delegation_id=delegation_id,
            active=True,
            hrm_sequence=HRM_SEQUENCE,
            hrm_envelope_hash=hashlib.sha256(envelope).digest(),
            chain_height=reorg_current_height,
            chain_work=reorg_current_work,
            chain_anchor=reorg_current_anchor,
        )
    )
    withdrawn_observation_payload, withdrawn_observation_checksum, withdrawn_observation = (
        service_generation_observation(
            network_magic=NETWORK_MAGIC,
            subject=NAME_HASH,
            resource_id=resource_id,
            highest_generation=SERVICE_GENERATION + 1,
            high_water_delegation_id=replacement_id,
            active=False,
            hrm_sequence=HRM_SEQUENCE + 2,
            hrm_envelope_hash=hashlib.sha256(removal_envelope).digest(),
            chain_height=withdrawal_height,
            chain_work=withdrawal_work,
            chain_anchor=withdrawal_anchor,
        )
    )
    reorg_reset_observation_payload, reorg_reset_observation_checksum, reorg_reset_observation = (
        service_generation_observation(
            network_magic=NETWORK_MAGIC,
            subject=NAME_HASH,
            resource_id=resource_id,
            highest_generation=0,
            high_water_delegation_id=bytes(32),
            active=False,
            hrm_sequence=HRM_SEQUENCE,
            hrm_envelope_hash=hashlib.sha256(reorg_withdrawal_envelope).digest(),
            chain_height=reorg_current_height,
            chain_work=reorg_current_work,
            chain_anchor=reorg_current_anchor,
        )
    )

    body = endpoint_body(resource_id, delegation_id)
    endpoint = signed_endpoint(body)
    endpoint_signature = endpoint[len(body) + 1 :]
    endpoint_digest = blake2b256(ENDPOINT_SIGNATURE_DOMAIN, body)
    endpoint_id = hashlib.sha256(ENDPOINT_ID_DOMAIN + endpoint).digest()
    endpoint_public_key = public_key(ENDPOINT_PRIVATE_KEY)
    ticket_body = ticket_unsigned(endpoint_public_key)
    (
        ticket_relay_digest,
        ticket_relay_signature,
        ticket_endpoint_digest,
        ticket_endpoint_signature,
    ) = ticket_signatures(ticket_body)
    ticket = signed_ticket(
        ticket_body,
        relay_signature=ticket_relay_signature,
        endpoint_signature=ticket_endpoint_signature,
    )
    ticket_id = blake2b256(ticket)
    route = route_body(resource_id, delegation_id, endpoint, [ticket])
    route_record = signed_route(route)
    route_signature = route_record[len(route) + 1 :]
    route_digest = blake2b256(ROUTE_SIGNATURE_DOMAIN, route)

    assert route_key().hex() == (
        "7e1a513c71518f69164fdcc754202a769"
        "e8cbd2dd980da3fd231b9b0de90e60b"
    )
    assert len(endpoint) <= 320
    assert len(route_record) <= 8_192

    wrong_network_endpoint_body = endpoint_body(
        resource_id, delegation_id, network_magic=WRONG_NETWORK_MAGIC
    )
    wrong_resource_endpoint_body = endpoint_body(bytes([0xAA]) * 32, delegation_id)
    wrong_delegation_endpoint_body = endpoint_body(resource_id, bytes([0xAB]) * 32)
    wrong_generation_endpoint_body = endpoint_body(
        resource_id, delegation_id, generation=SERVICE_GENERATION + 1
    )
    alternate_endpoint_key_body = endpoint_body(
        resource_id,
        delegation_id,
        endpoint_public_key=public_key(ALTERNATE_ENDPOINT_PRIVATE_KEY),
    )
    wrong_capabilities_endpoint_body = endpoint_body(
        resource_id, delegation_id, capabilities=2
    )
    wrong_constraints_endpoint_body = endpoint_body(
        resource_id,
        delegation_id,
        constraints_hash=bytes([0xAC]) * 32,
    )
    not_current_endpoint_body = endpoint_body(
        resource_id,
        delegation_id,
        issued_at=VALIDATION_NOW + 1,
        expires_at=VALIDATION_NOW + 61,
    )
    expired_endpoint_body = endpoint_body(
        resource_id,
        delegation_id,
        expires_at=VALIDATION_NOW,
    )
    over_lifetime_endpoint_body = endpoint_body(
        resource_id,
        delegation_id,
        expires_at=ENDPOINT_ISSUED_AT + MAX_ENDPOINT_LIFETIME + 1,
    )
    zero_sequence_endpoint_body = endpoint_body(
        resource_id,
        delegation_id,
        endpoint_sequence=0,
    )
    wrong_network_endpoint = signed_endpoint(wrong_network_endpoint_body)
    wrong_resource_endpoint = signed_endpoint(wrong_resource_endpoint_body)
    wrong_delegation_endpoint = signed_endpoint(wrong_delegation_endpoint_body)
    wrong_generation_endpoint = signed_endpoint(wrong_generation_endpoint_body)
    alternate_endpoint_key = signed_endpoint(alternate_endpoint_key_body)
    wrong_service_key_endpoint = signed_endpoint(
        body, signing_key=REPLACEMENT_SERVICE_PRIVATE_KEY
    )
    wrong_capabilities_endpoint = signed_endpoint(wrong_capabilities_endpoint_body)
    wrong_constraints_endpoint = signed_endpoint(wrong_constraints_endpoint_body)
    not_current_endpoint = signed_endpoint(not_current_endpoint_body)
    expired_endpoint = signed_endpoint(expired_endpoint_body)
    over_lifetime_endpoint = signed_endpoint(over_lifetime_endpoint_body)
    zero_sequence_endpoint = signed_endpoint(zero_sequence_endpoint_body)
    nonminimal_der_endpoint_signature = nonminimal_der_signature(endpoint_signature)
    nonminimal_der_endpoint = signed_endpoint(
        body, signature=nonminimal_der_endpoint_signature
    )

    second_ticket = signed_ticket(ticket_unsigned(endpoint_public_key, reservation_byte=0x11))
    late_ticket_body = ticket_unsigned(
        endpoint_public_key,
        reservation_byte=0x12,
        issued_at=ROUTE_ISSUED_AT + 1,
    )
    late_ticket = signed_ticket(late_ticket_body)
    early_expiry_ticket_body = ticket_unsigned(
        endpoint_public_key,
        reservation_byte=0x13,
        expires_at=ROUTE_EXPIRES_AT - 1,
    )
    early_expiry_ticket = signed_ticket(early_expiry_ticket_body)
    wrong_profile_ticket = signed_ticket(
        ticket_unsigned(
            endpoint_public_key,
            reservation_byte=0x15,
            profile_id=WRONG_PROFILE_ID,
        )
    )
    before_endpoint_ticket = signed_ticket(
        ticket_unsigned(
            endpoint_public_key,
            reservation_byte=0x16,
            issued_at=ENDPOINT_ISSUED_AT - 1,
        )
    )
    after_endpoint_ticket = signed_ticket(
        ticket_unsigned(
            endpoint_public_key,
            reservation_byte=0x17,
            expires_at=ENDPOINT_EXPIRES_AT + 1,
        )
    )
    wrong_ticket_network = signed_ticket(
        ticket_unsigned(
            endpoint_public_key,
            network_magic=WRONG_NETWORK_MAGIC,
        )
    )
    nonminimal_relay_signature = nonminimal_der_signature(ticket_relay_signature)
    nonminimal_relay_confirmation = deterministic_signature(
        TICKET_ENDPOINT_DOMAIN,
        ticket_body,
        nonminimal_relay_signature,
        key=ENDPOINT_PRIVATE_KEY,
    )
    nonminimal_der_relay_ticket = signed_ticket(
        ticket_body,
        relay_signature=nonminimal_relay_signature,
        endpoint_signature=nonminimal_relay_confirmation,
    )
    nonminimal_endpoint_confirmation = nonminimal_der_signature(ticket_endpoint_signature)
    nonminimal_der_ticket_confirmation = signed_ticket(
        ticket_body,
        relay_signature=ticket_relay_signature,
        endpoint_signature=nonminimal_endpoint_confirmation,
    )

    conflicting_body = route_body(resource_id, delegation_id, endpoint, [second_ticket])
    product_endpoint_greater = signed_endpoint(
        endpoint_body(
            resource_id,
            delegation_id,
            endpoint_sequence=ENDPOINT_SEQUENCE + 1,
        )
    )
    product_endpoint_greater_id = hashlib.sha256(
        ENDPOINT_ID_DOMAIN + product_endpoint_greater
    ).digest()
    product_endpoint_greater_route_stale_body = route_body(
        resource_id,
        delegation_id,
        product_endpoint_greater,
        [ticket],
        record_sequence=ROUTE_SEQUENCE - 1,
    )
    product_endpoint_stale_route_greater_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        record_sequence=ROUTE_SEQUENCE + 1,
    )
    product_endpoint_stale_route_conflict_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [second_ticket],
        record_sequence=ROUTE_SEQUENCE + 1,
    )
    zero_sequence_body = route_body(
        resource_id, delegation_id, endpoint, [ticket], record_sequence=0
    )
    mismatched_resource_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        route_resource_id=bytes([0xBB]) * 32,
    )
    wrong_route_key_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        route_key_bytes=bytes([0xB1]) * 32,
    )
    wrong_route_profile_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [wrong_profile_ticket],
        profile_id=WRONG_PROFILE_ID,
    )
    wrong_route_delegation_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        route_delegation_id=bytes([0xB2]) * 32,
    )
    wrong_route_generation_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        service_generation=SERVICE_GENERATION + 1,
    )
    wrong_route_controller_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        service_controller_key=public_key(REPLACEMENT_SERVICE_PRIVATE_KEY),
    )
    alternate_endpoint_key = signed_endpoint(alternate_endpoint_key_body)
    wrong_embedded_endpoint = signed_endpoint(
        endpoint_body(
            resource_id,
            replacement_id,
            generation=SERVICE_GENERATION + 1,
            endpoint_public_key=public_key(ALTERNATE_ENDPOINT_PRIVATE_KEY),
        ),
        signing_key=REPLACEMENT_SERVICE_PRIVATE_KEY,
    )
    alternate_endpoint_ticket_body = ticket_unsigned(
        public_key(ALTERNATE_ENDPOINT_PRIVATE_KEY), reservation_byte=0x14
    )
    alternate_endpoint_ticket = signed_ticket(
        alternate_endpoint_ticket_body,
        endpoint_private_key=ALTERNATE_ENDPOINT_PRIVATE_KEY,
    )
    wrong_embedded_endpoint_body = route_body(
        resource_id,
        replacement_id,
        wrong_embedded_endpoint,
        [alternate_endpoint_ticket],
        route_delegation_id=replacement_id,
        service_generation=SERVICE_GENERATION + 1,
        service_controller_key=replacement_public_key,
    )
    not_current_route_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        issued_at=VALIDATION_NOW + 1,
        expires_at=VALIDATION_NOW + 61,
    )
    expired_route_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        expires_at=VALIDATION_NOW,
    )
    over_lifetime_route_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [ticket],
        expires_at=ROUTE_ISSUED_AT + 7_201,
    )
    route_before_endpoint_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [before_endpoint_ticket],
        issued_at=ENDPOINT_ISSUED_AT - 1,
    )
    route_after_endpoint_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [after_endpoint_ticket],
        expires_at=ENDPOINT_EXPIRES_AT + 1,
    )
    wrong_ticket_network_body = route_body(
        resource_id, delegation_id, endpoint, [wrong_ticket_network]
    )
    route_before_ticket_body = route_body(
        resource_id, delegation_id, endpoint, [late_ticket]
    )
    route_after_ticket_body = route_body(
        resource_id, delegation_id, endpoint, [early_expiry_ticket]
    )
    nonminimal_der_relay_ticket_body = route_body(
        resource_id, delegation_id, endpoint, [nonminimal_der_relay_ticket]
    )
    nonminimal_der_ticket_confirmation_body = route_body(
        resource_id,
        delegation_id,
        endpoint,
        [nonminimal_der_ticket_confirmation],
    )
    zero_ticket_body = route_body(resource_id, delegation_id, endpoint, [])
    duplicate_ticket_body = route_body(
        resource_id, delegation_id, endpoint, [ticket, ticket]
    )
    nine_ticket_body = route_body(
        resource_id, delegation_id, endpoint, [ticket] * 9
    )
    invalid_endpoint_length = bytearray(route_record)
    endpoint_length_offset = 2 + 32 + 2 + 8 + 8 + 8 + 32 + 32 + 8 + 33
    invalid_endpoint_length[endpoint_length_offset : endpoint_length_offset + 2] = struct.pack(
        "<H", len(endpoint) + 1
    )
    nonminimal_der_route_signature = nonminimal_der_signature(route_signature)
    nonminimal_der_route = signed_route(
        route, signature=nonminimal_der_route_signature
    )
    conflicting_route = signed_route(conflicting_body)
    product_endpoint_greater_route_stale = signed_route(
        product_endpoint_greater_route_stale_body
    )
    product_endpoint_stale_route_greater = signed_route(
        product_endpoint_stale_route_greater_body
    )
    product_endpoint_stale_route_conflict = signed_route(
        product_endpoint_stale_route_conflict_body
    )
    legacy = legacy_named_route_v2()

    replacement_observation_payload, replacement_observation_checksum, replacement_observation = (
        service_generation_observation(
            network_magic=NETWORK_MAGIC,
            subject=NAME_HASH,
            resource_id=resource_id,
            highest_generation=SERVICE_GENERATION + 1,
            high_water_delegation_id=replacement_id,
            active=True,
            hrm_sequence=HRM_SEQUENCE + 1,
            hrm_envelope_hash=hashlib.sha256(replacement_envelope).digest(),
            chain_height=reorg_previous_height,
            chain_work=reorg_previous_work,
            chain_anchor=reorg_previous_anchor,
        )
    )
    active_rollback = authority_rollback_body(
        HRM_SEQUENCE,
        envelope,
        reorg_current_height,
        reorg_current_work,
        reorg_current_anchor,
    )
    replacement_rollback = authority_rollback_body(
        HRM_SEQUENCE + 1,
        replacement_envelope,
        reorg_previous_height,
        reorg_previous_work,
        reorg_previous_anchor,
    )
    withdrawal_rollback = authority_rollback_body(
        HRM_SEQUENCE + 2,
        removal_envelope,
        withdrawal_height,
        withdrawal_work,
        withdrawal_anchor,
    )
    accepted_reorg_rollback = authority_rollback_body(
        HRM_SEQUENCE,
        reorg_withdrawal_envelope,
        reorg_current_height,
        reorg_current_work,
        reorg_current_anchor,
    )
    authority_fresh = authority_snapshot(
        revision=0,
        trusted_time=VALIDATION_NOW,
        rollback_body=None,
        observations=[],
    )
    authority_time_only = authority_snapshot(
        revision=1,
        trusted_time=PERSISTENCE_HIGH_TIME,
        rollback_body=None,
        observations=[],
    )
    authority_active = authority_snapshot(
        revision=1,
        trusted_time=VALIDATION_NOW,
        rollback_body=active_rollback,
        observations=[active_observation],
    )
    authority_replacement = authority_snapshot(
        revision=2,
        trusted_time=VALIDATION_NOW,
        rollback_body=replacement_rollback,
        observations=[replacement_observation],
    )
    authority_withdrawn = authority_snapshot(
        revision=3,
        trusted_time=VALIDATION_NOW,
        rollback_body=withdrawal_rollback,
        observations=[withdrawn_observation],
    )
    authority_accepted_reorg = authority_snapshot(
        revision=3,
        trusted_time=VALIDATION_NOW,
        rollback_body=accepted_reorg_rollback,
        observations=[reorg_reset_observation],
    )

    requester_active_route_hash = blake2b256(
        CANONICAL_RECORD_HASH_DOMAIN, route_record
    )
    requester_active_entry = requester_snapshot_entry(
        resource_id=resource_id,
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE,
        endpoint_conflicted=False,
        endpoint_canonical_id=endpoint_id,
        route_high_water=ROUTE_SEQUENCE,
        route_conflicted=False,
        route_canonical_hash=requester_active_route_hash,
    )
    requester_split_route_hash = blake2b256(
        CANONICAL_RECORD_HASH_DOMAIN, product_endpoint_stale_route_greater
    )
    requester_endpoint_intermediate_entry = requester_snapshot_entry(
        resource_id=resource_id,
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_conflicted=False,
        endpoint_canonical_id=product_endpoint_greater_id,
        route_high_water=ROUTE_SEQUENCE,
        route_conflicted=False,
        route_canonical_hash=requester_active_route_hash,
    )
    requester_split_entry = requester_snapshot_entry(
        resource_id=resource_id,
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_conflicted=False,
        endpoint_canonical_id=product_endpoint_greater_id,
        route_high_water=ROUTE_SEQUENCE + 1,
        route_conflicted=False,
        route_canonical_hash=requester_split_route_hash,
    )
    requester_conflict_entry = requester_snapshot_entry(
        resource_id=resource_id,
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_conflicted=False,
        endpoint_canonical_id=product_endpoint_greater_id,
        route_high_water=ROUTE_SEQUENCE + 1,
        route_conflicted=True,
        route_canonical_hash=bytes(32),
    )
    requester_fresh = requester_snapshot(
        revision=0,
        trusted_time=VALIDATION_NOW,
        entries=[],
    )
    requester_active = requester_snapshot(
        revision=1,
        trusted_time=VALIDATION_NOW,
        entries=[requester_active_entry],
    )
    requester_endpoint_intermediate = requester_snapshot(
        revision=2,
        trusted_time=VALIDATION_NOW,
        entries=[requester_endpoint_intermediate_entry],
    )
    requester_split = requester_snapshot(
        revision=3,
        trusted_time=VALIDATION_NOW,
        entries=[requester_split_entry],
    )
    requester_conflict = requester_snapshot(
        revision=4,
        trusted_time=VALIDATION_NOW,
        entries=[requester_conflict_entry],
    )
    requester_trusted_time = requester_snapshot(
        revision=5,
        trusted_time=PERSISTENCE_HIGH_TIME,
        entries=[requester_conflict_entry],
    )

    storage_retain_until = max(ROUTE_EXPIRES_AT, VALIDATION_NOW + 7_200)
    storage_active_route_hash = blake2b256(CANONICAL_RECORD_HASH_DOMAIN, route_record)
    storage_conflicting_route_hash = blake2b256(
        CANONICAL_RECORD_HASH_DOMAIN, product_endpoint_stale_route_conflict
    )
    storage_split_route_hash = blake2b256(
        CANONICAL_RECORD_HASH_DOMAIN, product_endpoint_stale_route_greater
    )
    storage_active_entry = storage_ledger_entry(
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE,
        endpoint_delegation_id=endpoint_id,
        endpoint_conflicted=False,
        route_high_water=ROUTE_SEQUENCE,
        retain_until=storage_retain_until,
        route_conflicted=False,
        route_canonical_hash=storage_active_route_hash,
    )
    storage_endpoint_intermediate_entry = storage_ledger_entry(
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_delegation_id=product_endpoint_greater_id,
        endpoint_conflicted=False,
        route_high_water=ROUTE_SEQUENCE,
        retain_until=storage_retain_until,
        route_conflicted=False,
        route_canonical_hash=storage_active_route_hash,
    )
    storage_split_entry = storage_ledger_entry(
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_delegation_id=product_endpoint_greater_id,
        endpoint_conflicted=False,
        route_high_water=ROUTE_SEQUENCE + 1,
        retain_until=storage_retain_until,
        route_conflicted=False,
        route_canonical_hash=storage_split_route_hash,
    )
    storage_conflict_entry = storage_ledger_entry(
        route_key_bytes=route_key(),
        endpoint_key=endpoint_public_key,
        endpoint_high_water=ENDPOINT_SEQUENCE + 1,
        endpoint_delegation_id=product_endpoint_greater_id,
        endpoint_conflicted=False,
        route_high_water=ROUTE_SEQUENCE + 1,
        retain_until=storage_retain_until,
        route_conflicted=True,
        route_canonical_hash=min(
            storage_split_route_hash, storage_conflicting_route_hash
        ),
    )
    storage_fresh = storage_ledger_snapshot(
        revision=0,
        pruned_through=0,
        entries=[],
    )
    storage_active = storage_ledger_snapshot(
        revision=1,
        pruned_through=0,
        entries=[storage_active_entry],
    )
    storage_endpoint_intermediate = storage_ledger_snapshot(
        revision=2,
        pruned_through=0,
        entries=[storage_endpoint_intermediate_entry],
    )
    storage_split = storage_ledger_snapshot(
        revision=3,
        pruned_through=0,
        entries=[storage_split_entry],
    )
    storage_conflict = storage_ledger_snapshot(
        revision=4,
        pruned_through=0,
        entries=[storage_conflict_entry],
    )
    storage_pruned_empty = storage_ledger_snapshot(
        revision=5,
        pruned_through=PERSISTENCE_HIGH_TIME,
        entries=[],
    )

    vectors: list[tuple[str, VectorValue]] = [
        ("network_magic", NETWORK_MAGIC),
        ("wrong_network_magic", WRONG_NETWORK_MAGIC),
        ("name_hash", NAME_HASH),
        ("wrong_name_hash", WRONG_NAME_HASH),
        ("service_name", SERVICE_NAME),
        ("wrong_service_name", WRONG_SERVICE_NAME),
        ("application_profile_id", PROFILE_ID),
        ("wrong_application_profile_id", WRONG_PROFILE_ID),
        ("hrm_sequence", HRM_SEQUENCE),
        ("hrm_issued_at", HRM_ISSUED_AT),
        ("hrm_expires_at", HRM_EXPIRES_AT),
        ("resource_not_before", RESOURCE_NOT_BEFORE),
        ("resource_expires_at", RESOURCE_EXPIRES_AT),
        ("service_not_before", SERVICE_NOT_BEFORE),
        ("service_expires_at", SERVICE_EXPIRES_AT),
        ("service_generation", SERVICE_GENERATION),
        ("max_endpoint_lifetime", MAX_ENDPOINT_LIFETIME),
        ("allowed_endpoint_capabilities", ALLOWED_ENDPOINT_CAPABILITIES),
        ("endpoint_issued_at", ENDPOINT_ISSUED_AT),
        ("endpoint_expires_at", ENDPOINT_EXPIRES_AT),
        ("endpoint_sequence", ENDPOINT_SEQUENCE),
        ("route_issued_at", ROUTE_ISSUED_AT),
        ("route_expires_at", ROUTE_EXPIRES_AT),
        ("route_record_sequence", ROUTE_SEQUENCE),
        ("validation_now", VALIDATION_NOW),
        ("hrm_private_key", HRM_PRIVATE_KEY),
        ("service_private_key", SERVICE_PRIVATE_KEY),
        ("endpoint_private_key", ENDPOINT_PRIVATE_KEY),
        ("relay_private_key", RELAY_PRIVATE_KEY),
        ("replacement_service_private_key", REPLACEMENT_SERVICE_PRIVATE_KEY),
        ("alternate_endpoint_private_key", ALTERNATE_ENDPOINT_PRIVATE_KEY),
        ("hrm_controller_public_key", public_key(HRM_PRIVATE_KEY)),
        ("service_controller_public_key", service_public_key),
        ("endpoint_public_key", endpoint_public_key),
        ("relay_public_key", public_key(RELAY_PRIVATE_KEY)),
        ("replacement_service_public_key", replacement_public_key),
        ("alternate_endpoint_public_key", public_key(ALTERNATE_ENDPOINT_PRIVATE_KEY)),
        ("named_service_identifier", identifier),
        ("service_resource_id", resource_id),
        ("service_resource", cbor(resource)),
        ("service_resource_attributes", cbor(resource[6])),
        ("service_delegation_constraints", cbor(delegation[11])),
        ("service_delegation_body", delegation_body),
        ("service_delegation_id", delegation_id),
        ("service_delegation", cbor(delegation)),
        ("hrm_payload", payload),
        ("hrm_envelope", envelope),
        ("hrm_envelope_sha256", hashlib.sha256(envelope).digest()),
        ("service_generation_observation_magic", SERVICE_GENERATION_OBSERVATION_MAGIC),
        (
            "service_generation_observation_checksum_domain",
            SERVICE_GENERATION_OBSERVATION_CHECKSUM_DOMAIN,
        ),
        ("service_generation_observation_version", SERVICE_GENERATION_OBSERVATION_VERSION),
        (
            "service_generation_observation_payload_size",
            SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE,
        ),
        ("service_generation_observation_size", SERVICE_GENERATION_OBSERVATION_SIZE),
        ("active_observation_network_magic", NETWORK_MAGIC),
        ("active_observation_subject", NAME_HASH),
        ("active_observation_resource_id", resource_id),
        ("active_observation_highest_generation", SERVICE_GENERATION),
        ("active_observation_high_water_delegation_id", delegation_id),
        ("active_observation_state", 1),
        ("active_observation_hrm_sequence", HRM_SEQUENCE),
        ("active_observation_hrm_envelope_sha256", hashlib.sha256(envelope).digest()),
        ("active_observation_chain_height", reorg_current_height),
        ("active_observation_chain_work", reorg_current_work),
        ("active_observation_chain_anchor", reorg_current_anchor),
        ("active_service_generation_observation_payload", active_observation_payload),
        (
            "active_service_generation_observation_checksum",
            active_observation_checksum,
        ),
        ("active_service_generation_observation", active_observation),
        ("wrong_identity_network_identifier", wrong_identity_network[0]),
        ("wrong_identity_network_resource_id", wrong_identity_network[1]),
        ("wrong_identity_network_hrm_payload", wrong_identity_network[4]),
        ("wrong_identity_network_hrm_envelope", wrong_identity_network[5]),
        ("wrong_identity_name_hash_identifier", wrong_identity_name_hash[0]),
        ("wrong_identity_name_hash_resource_id", wrong_identity_name_hash[1]),
        ("wrong_identity_name_hash_hrm_payload", wrong_identity_name_hash[4]),
        ("wrong_identity_name_hash_hrm_envelope", wrong_identity_name_hash[5]),
        ("wrong_identity_service_name_identifier", wrong_identity_service_name[0]),
        ("wrong_identity_service_name_resource_id", wrong_identity_service_name[1]),
        ("wrong_identity_service_name_hrm_payload", wrong_identity_service_name[4]),
        ("wrong_identity_service_name_hrm_envelope", wrong_identity_service_name[5]),
        (
            "wrong_identity_application_profile_identifier",
            wrong_identity_application_profile[0],
        ),
        (
            "wrong_identity_application_profile_resource_id",
            wrong_identity_application_profile[1],
        ),
        (
            "wrong_identity_application_profile_hrm_payload",
            wrong_identity_application_profile[4],
        ),
        (
            "wrong_identity_application_profile_hrm_envelope",
            wrong_identity_application_profile[5],
        ),
        ("wrong_resource_origin_hrm_payload", wrong_origin_payload),
        ("wrong_resource_origin_hrm_envelope", wrong_origin_envelope),
        ("wrong_resource_profile_flags_hrm_payload", wrong_flags_payload),
        ("wrong_resource_profile_flags_hrm_envelope", wrong_flags_envelope),
        (
            "wrong_resource_profile_constraints_hrm_payload",
            wrong_profile_constraints_payload,
        ),
        (
            "wrong_resource_profile_constraints_hrm_envelope",
            wrong_profile_constraints_envelope,
        ),
        ("missing_operate_delegation_hrm_payload", missing_operate_payload),
        ("missing_operate_delegation_hrm_envelope", missing_operate_envelope),
        ("duplicate_operate_delegation_hrm_payload", duplicate_operate_payload),
        ("duplicate_operate_delegation_hrm_envelope", duplicate_operate_envelope),
        ("resource_removal_hrm_payload", resource_removal_payload),
        ("resource_removal_hrm_envelope", resource_removal_envelope),
        ("ownership_transfer_subject", WRONG_NAME_HASH),
        ("ownership_transfer_hrm_payload", mismatched_subject_payload),
        ("ownership_transfer_hrm_envelope", mismatched_subject_envelope),
        ("reorg_previous_chain_height", reorg_previous_height),
        ("reorg_previous_chain_work", reorg_previous_work),
        ("reorg_previous_chain_anchor", reorg_previous_anchor),
        ("reorg_previous_hrm_sequence", HRM_SEQUENCE + 1),
        (
            "reorg_previous_hrm_envelope_sha256",
            hashlib.sha256(replacement_envelope).digest(),
        ),
        ("reorg_current_chain_height", reorg_current_height),
        ("reorg_current_chain_work", reorg_current_work),
        ("reorg_current_chain_anchor", reorg_current_anchor),
        ("reorg_current_hrm_sequence", HRM_SEQUENCE),
        ("reorg_current_hrm_envelope_sha256", hashlib.sha256(envelope).digest()),
        ("equal_generation_conflict_service_delegation_body", equal_generation_conflict_body),
        ("equal_generation_conflict_service_delegation_id", equal_generation_conflict_id),
        ("equal_generation_conflict_hrm_payload", equal_generation_conflict_payload),
        ("equal_generation_conflict_hrm_envelope", equal_generation_conflict_envelope),
        ("rollback_service_delegation_body", rollback_body),
        ("rollback_service_delegation_id", rollback_id),
        ("rollback_hrm_payload", rollback_payload),
        ("rollback_hrm_envelope", rollback_envelope),
        ("replacement_service_generation", SERVICE_GENERATION + 1),
        ("replacement_service_delegation_body", replacement_body),
        ("replacement_service_delegation_id", replacement_id),
        ("replacement_hrm_payload", replacement_payload),
        ("replacement_hrm_envelope", replacement_envelope),
        ("removal_hrm_payload", removal_payload),
        ("removal_hrm_envelope", removal_envelope),
        ("withdrawn_observation_network_magic", NETWORK_MAGIC),
        ("withdrawn_observation_subject", NAME_HASH),
        ("withdrawn_observation_resource_id", resource_id),
        ("withdrawn_observation_highest_generation", SERVICE_GENERATION + 1),
        ("withdrawn_observation_high_water_delegation_id", replacement_id),
        ("withdrawn_observation_state", 0),
        ("withdrawn_observation_hrm_sequence", HRM_SEQUENCE + 2),
        (
            "withdrawn_observation_hrm_envelope_sha256",
            hashlib.sha256(removal_envelope).digest(),
        ),
        ("withdrawn_observation_chain_height", withdrawal_height),
        ("withdrawn_observation_chain_work", withdrawal_work),
        ("withdrawn_observation_chain_anchor", withdrawal_anchor),
        (
            "withdrawn_service_generation_observation_payload",
            withdrawn_observation_payload,
        ),
        (
            "withdrawn_service_generation_observation_checksum",
            withdrawn_observation_checksum,
        ),
        ("withdrawn_service_generation_observation", withdrawn_observation),
        ("reorg_withdrawal_hrm_payload", reorg_withdrawal_payload),
        ("reorg_withdrawal_hrm_envelope", reorg_withdrawal_envelope),
        ("reorg_reset_observation_network_magic", NETWORK_MAGIC),
        ("reorg_reset_observation_subject", NAME_HASH),
        ("reorg_reset_observation_resource_id", resource_id),
        ("reorg_reset_observation_highest_generation", 0),
        ("reorg_reset_observation_high_water_delegation_id", bytes(32)),
        ("reorg_reset_observation_state", 0),
        ("reorg_reset_observation_hrm_sequence", HRM_SEQUENCE),
        (
            "reorg_reset_observation_hrm_envelope_sha256",
            hashlib.sha256(reorg_withdrawal_envelope).digest(),
        ),
        ("reorg_reset_observation_chain_height", reorg_current_height),
        ("reorg_reset_observation_chain_work", reorg_current_work),
        ("reorg_reset_observation_chain_anchor", reorg_current_anchor),
        (
            "reorg_reset_service_generation_observation_payload",
            reorg_reset_observation_payload,
        ),
        (
            "reorg_reset_service_generation_observation_checksum",
            reorg_reset_observation_checksum,
        ),
        (
            "reorg_reset_service_generation_observation",
            reorg_reset_observation,
        ),
        ("restoration_service_generation", SERVICE_GENERATION + 2),
        ("restoration_service_delegation_body", restoration_body),
        ("restoration_service_delegation_id", restoration_id),
        ("restoration_hrm_payload", restoration_payload),
        ("restoration_hrm_envelope", restoration_envelope),
        ("endpoint_delegation_body", body),
        ("endpoint_delegation_signature_digest", endpoint_digest),
        ("endpoint_delegation_signature", endpoint_signature),
        ("endpoint_delegation", endpoint),
        ("endpoint_delegation_id", endpoint_id),
        ("relay_ticket_unsigned", ticket_body),
        ("relay_ticket_relay_signature_digest", ticket_relay_digest),
        ("relay_ticket_relay_signature", ticket_relay_signature),
        ("relay_ticket_endpoint_confirmation_digest", ticket_endpoint_digest),
        ("relay_ticket_endpoint_confirmation_signature", ticket_endpoint_signature),
        ("relay_ticket", ticket),
        ("relay_ticket_id", ticket_id),
        ("named_route_key", route_key()),
        ("named_route_body_v3", route),
        ("named_route_signature_digest", route_digest),
        ("named_route_signature", route_signature),
        ("named_route_record_v3", route_record),
        ("wrong_network_endpoint", wrong_network_endpoint),
        ("wrong_resource_endpoint", wrong_resource_endpoint),
        ("wrong_delegation_id_endpoint", wrong_delegation_endpoint),
        ("wrong_generation_endpoint", wrong_generation_endpoint),
        ("alternate_endpoint_key_endpoint", alternate_endpoint_key),
        ("wrong_service_key_endpoint", wrong_service_key_endpoint),
        ("wrong_capabilities_endpoint", wrong_capabilities_endpoint),
        ("wrong_constraints_endpoint", wrong_constraints_endpoint),
        ("not_current_endpoint", not_current_endpoint),
        ("expired_endpoint", expired_endpoint),
        ("over_lifetime_endpoint", over_lifetime_endpoint),
        ("zero_sequence_endpoint", zero_sequence_endpoint),
        ("high_s_endpoint", signed_endpoint(body, high_s=True)),
        ("nonminimal_der_endpoint", nonminimal_der_endpoint),
        ("trailing_endpoint", endpoint + b"\x00"),
        ("conflicting_route_same_sequence", conflicting_route),
        ("product_endpoint_greater_delegation", product_endpoint_greater),
        ("product_endpoint_greater_delegation_id", product_endpoint_greater_id),
        (
            "product_endpoint_greater_route_stale",
            product_endpoint_greater_route_stale,
        ),
        (
            "product_endpoint_stale_route_greater",
            product_endpoint_stale_route_greater,
        ),
        (
            "product_endpoint_stale_route_conflict",
            product_endpoint_stale_route_conflict,
        ),
        ("zero_sequence_route", signed_route(zero_sequence_body)),
        ("mismatched_resource_route", signed_route(mismatched_resource_body)),
        ("wrong_route_key_route", signed_route(wrong_route_key_body)),
        ("wrong_profile_route", signed_route(wrong_route_profile_body)),
        ("wrong_delegation_id_route", signed_route(wrong_route_delegation_body)),
        ("wrong_generation_route", signed_route(wrong_route_generation_body)),
        ("wrong_controller_key_route", signed_route(wrong_route_controller_body)),
        (
            "wrong_embedded_endpoint_route",
            signed_route(
                wrong_embedded_endpoint_body,
                signing_key=ALTERNATE_ENDPOINT_PRIVATE_KEY,
            ),
        ),
        ("not_current_route", signed_route(not_current_route_body)),
        ("expired_route", signed_route(expired_route_body)),
        ("over_lifetime_route", signed_route(over_lifetime_route_body)),
        ("route_before_endpoint", signed_route(route_before_endpoint_body)),
        ("route_after_endpoint", signed_route(route_after_endpoint_body)),
        ("wrong_ticket_network_route", signed_route(wrong_ticket_network_body)),
        ("route_before_ticket", signed_route(route_before_ticket_body)),
        ("route_after_ticket", signed_route(route_after_ticket_body)),
        (
            "nonminimal_der_relay_ticket_route",
            signed_route(nonminimal_der_relay_ticket_body),
        ),
        (
            "nonminimal_der_ticket_confirmation_route",
            signed_route(nonminimal_der_ticket_confirmation_body),
        ),
        ("zero_ticket_route", signed_route(zero_ticket_body)),
        ("duplicate_ticket_route", signed_route(duplicate_ticket_body)),
        ("nine_ticket_route", signed_route(nine_ticket_body)),
        ("high_s_route", signed_route(route, high_s=True)),
        ("nonminimal_der_route", nonminimal_der_route),
        ("invalid_endpoint_length_route", bytes(invalid_endpoint_length)),
        ("legacy_hsa1_authority_record", legacy["authority_record"]),
        ("legacy_service_authorization_unsigned", legacy["authorization_unsigned"]),
        (
            "legacy_service_authorization_signature_digest",
            legacy["authorization_signature_digest"],
        ),
        ("legacy_service_authorization_signature", legacy["authorization_signature"]),
        ("legacy_service_authorization", legacy["authorization"]),
        ("legacy_service_authorization_id", legacy["authorization_id"]),
        ("legacy_endpoint_delegation_unsigned", legacy["endpoint_unsigned"]),
        (
            "legacy_endpoint_delegation_signature_digest",
            legacy["endpoint_signature_digest"],
        ),
        ("legacy_endpoint_delegation_signature", legacy["endpoint_signature"]),
        ("legacy_endpoint_delegation", legacy["endpoint"]),
        ("legacy_endpoint_delegation_id", legacy["endpoint_id"]),
        ("legacy_relay_ticket", legacy["ticket"]),
        ("legacy_named_route_body_v2", legacy["route_unsigned"]),
        ("legacy_named_route_signature_digest", legacy["route_signature_digest"]),
        ("legacy_named_route_signature", legacy["route_signature"]),
        ("legacy_named_route_record_v2", legacy["route"]),
        ("legacy_v2_authority_v1_route", legacy["route"]),
        ("wrong_v3_authority_v1_route", b"\x03\x01" + route_record[2:]),
        ("wrong_v2_authority_v2_route", b"\x02\x02" + route_record[2:]),
        ("trailing_route", route_record + b"\x00"),
    ]
    vectors.extend(
        [
            ("persistence_high_time", PERSISTENCE_HIGH_TIME),
            ("canonical_record_hash_domain", CANONICAL_RECORD_HASH_DOMAIN),
            ("authority_snapshot_magic", AUTHORITY_SNAPSHOT_MAGIC),
            ("authority_snapshot_version", AUTHORITY_SNAPSHOT_VERSION),
            (
                "authority_snapshot_checksum_domain",
                AUTHORITY_SNAPSHOT_CHECKSUM_DOMAIN,
            ),
            (
                "authority_snapshot_fingerprint_domain",
                AUTHORITY_SNAPSHOT_FINGERPRINT_DOMAIN,
            ),
            ("authority_snapshot_header_size", AUTHORITY_SNAPSHOT_HEADER_SIZE),
            ("authority_snapshot_capacity", AUTHORITY_SNAPSHOT_CAPACITY),
            ("authority_fresh_prior_expectation", "absent"),
            ("authority_fresh_revision", 0),
            ("authority_fresh_trusted_time", VALIDATION_NOW),
            ("authority_fresh_entry_count", 0),
            ("authority_fresh_snapshot_payload", authority_fresh[0]),
            ("authority_fresh_snapshot_checksum", authority_fresh[1]),
            ("authority_fresh_snapshot", authority_fresh[2]),
            ("authority_fresh_snapshot_fingerprint", authority_fresh[3]),
            ("authority_time_only_prior_revision", 0),
            ("authority_time_only_prior_fingerprint", authority_fresh[3]),
            ("authority_time_only_revision", 1),
            ("authority_time_only_trusted_time", PERSISTENCE_HIGH_TIME),
            ("authority_time_only_entry_count", 0),
            ("authority_time_only_snapshot_payload", authority_time_only[0]),
            ("authority_time_only_snapshot_checksum", authority_time_only[1]),
            ("authority_time_only_snapshot", authority_time_only[2]),
            ("authority_time_only_snapshot_fingerprint", authority_time_only[3]),
            ("authority_active_prior_revision", 0),
            ("authority_active_prior_fingerprint", authority_fresh[3]),
            ("authority_active_revision", 1),
            ("authority_active_trusted_time", VALIDATION_NOW),
            ("authority_active_entry_count", 1),
            ("authority_active_snapshot_payload", authority_active[0]),
            ("authority_active_snapshot_checksum", authority_active[1]),
            ("authority_active_snapshot", authority_active[2]),
            ("authority_active_snapshot_fingerprint", authority_active[3]),
            ("authority_replacement_prior_revision", 1),
            ("authority_replacement_prior_fingerprint", authority_active[3]),
            ("authority_replacement_revision", 2),
            ("authority_replacement_trusted_time", VALIDATION_NOW),
            ("authority_replacement_entry_count", 1),
            ("authority_replacement_snapshot_payload", authority_replacement[0]),
            ("authority_replacement_snapshot_checksum", authority_replacement[1]),
            ("authority_replacement_snapshot", authority_replacement[2]),
            (
                "authority_replacement_snapshot_fingerprint",
                authority_replacement[3],
            ),
            ("authority_withdrawn_prior_revision", 2),
            (
                "authority_withdrawn_prior_fingerprint",
                authority_replacement[3],
            ),
            ("authority_withdrawn_revision", 3),
            ("authority_withdrawn_trusted_time", VALIDATION_NOW),
            ("authority_withdrawn_entry_count", 1),
            ("authority_withdrawn_snapshot_payload", authority_withdrawn[0]),
            ("authority_withdrawn_snapshot_checksum", authority_withdrawn[1]),
            ("authority_withdrawn_snapshot", authority_withdrawn[2]),
            ("authority_withdrawn_snapshot_fingerprint", authority_withdrawn[3]),
            ("authority_accepted_reorg_prior_revision", 2),
            (
                "authority_accepted_reorg_prior_fingerprint",
                authority_replacement[3],
            ),
            ("authority_accepted_reorg_revision", 3),
            ("authority_accepted_reorg_trusted_time", VALIDATION_NOW),
            ("authority_accepted_reorg_entry_count", 1),
            (
                "authority_accepted_reorg_snapshot_payload",
                authority_accepted_reorg[0],
            ),
            (
                "authority_accepted_reorg_snapshot_checksum",
                authority_accepted_reorg[1],
            ),
            ("authority_accepted_reorg_snapshot", authority_accepted_reorg[2]),
            (
                "authority_accepted_reorg_snapshot_fingerprint",
                authority_accepted_reorg[3],
            ),
            ("requester_snapshot_magic", REQUESTER_SNAPSHOT_MAGIC),
            ("requester_snapshot_version", REQUESTER_SNAPSHOT_VERSION),
            (
                "requester_snapshot_checksum_domain",
                REQUESTER_SNAPSHOT_CHECKSUM_DOMAIN,
            ),
            (
                "requester_snapshot_fingerprint_domain",
                REQUESTER_SNAPSHOT_FINGERPRINT_DOMAIN,
            ),
            ("requester_snapshot_header_size", REQUESTER_SNAPSHOT_HEADER_SIZE),
            ("requester_snapshot_entry_size", REQUESTER_SNAPSHOT_ENTRY_SIZE),
            ("requester_snapshot_capacity", REQUESTER_SNAPSHOT_CAPACITY),
            ("requester_active_route_canonical_hash", requester_active_route_hash),
            ("requester_product_endpoint_high_water", ENDPOINT_SEQUENCE + 1),
            ("requester_product_route_high_water", ROUTE_SEQUENCE + 1),
            ("requester_product_endpoint_id", product_endpoint_greater_id),
            ("requester_split_route_canonical_hash", requester_split_route_hash),
            ("requester_fresh_prior_expectation", "absent"),
            ("requester_fresh_revision", 0),
            ("requester_fresh_trusted_time", VALIDATION_NOW),
            ("requester_fresh_entry_count", 0),
            ("requester_fresh_snapshot_payload", requester_fresh[0]),
            ("requester_fresh_snapshot_checksum", requester_fresh[1]),
            ("requester_fresh_snapshot", requester_fresh[2]),
            ("requester_fresh_snapshot_fingerprint", requester_fresh[3]),
            ("requester_active_prior_revision", 0),
            ("requester_active_prior_fingerprint", requester_fresh[3]),
            ("requester_active_revision", 1),
            ("requester_active_trusted_time", VALIDATION_NOW),
            ("requester_active_entry_count", 1),
            ("requester_active_snapshot_payload", requester_active[0]),
            ("requester_active_snapshot_checksum", requester_active[1]),
            ("requester_active_snapshot", requester_active[2]),
            ("requester_active_snapshot_fingerprint", requester_active[3]),
            ("requester_endpoint_intermediate_prior_revision", 1),
            (
                "requester_endpoint_intermediate_prior_fingerprint",
                requester_active[3],
            ),
            ("requester_endpoint_intermediate_revision", 2),
            ("requester_endpoint_intermediate_trusted_time", VALIDATION_NOW),
            ("requester_endpoint_intermediate_entry_count", 1),
            (
                "requester_endpoint_intermediate_snapshot_payload",
                requester_endpoint_intermediate[0],
            ),
            (
                "requester_endpoint_intermediate_snapshot_checksum",
                requester_endpoint_intermediate[1],
            ),
            (
                "requester_endpoint_intermediate_snapshot",
                requester_endpoint_intermediate[2],
            ),
            (
                "requester_endpoint_intermediate_snapshot_fingerprint",
                requester_endpoint_intermediate[3],
            ),
            ("requester_split_prior_revision", 2),
            (
                "requester_split_prior_fingerprint",
                requester_endpoint_intermediate[3],
            ),
            ("requester_split_revision", 3),
            ("requester_split_trusted_time", VALIDATION_NOW),
            ("requester_split_entry_count", 1),
            ("requester_split_snapshot_payload", requester_split[0]),
            ("requester_split_snapshot_checksum", requester_split[1]),
            ("requester_split_snapshot", requester_split[2]),
            ("requester_split_snapshot_fingerprint", requester_split[3]),
            ("requester_conflict_prior_revision", 3),
            ("requester_conflict_prior_fingerprint", requester_split[3]),
            ("requester_conflict_revision", 4),
            ("requester_conflict_trusted_time", VALIDATION_NOW),
            ("requester_conflict_entry_count", 1),
            ("requester_conflict_snapshot_payload", requester_conflict[0]),
            ("requester_conflict_snapshot_checksum", requester_conflict[1]),
            ("requester_conflict_snapshot", requester_conflict[2]),
            ("requester_conflict_snapshot_fingerprint", requester_conflict[3]),
            ("requester_trusted_time_prior_revision", 4),
            (
                "requester_trusted_time_prior_fingerprint",
                requester_conflict[3],
            ),
            ("requester_trusted_time_revision", 5),
            ("requester_trusted_time_high_water", PERSISTENCE_HIGH_TIME),
            ("requester_trusted_time_entry_count", 1),
            (
                "requester_trusted_time_snapshot_payload",
                requester_trusted_time[0],
            ),
            (
                "requester_trusted_time_snapshot_checksum",
                requester_trusted_time[1],
            ),
            ("requester_trusted_time_snapshot", requester_trusted_time[2]),
            (
                "requester_trusted_time_snapshot_fingerprint",
                requester_trusted_time[3],
            ),
            ("storage_ledger_magic", STORAGE_LEDGER_MAGIC),
            ("storage_ledger_version", STORAGE_LEDGER_VERSION),
            (
                "storage_ledger_checksum_domain",
                STORAGE_LEDGER_CHECKSUM_DOMAIN,
            ),
            (
                "storage_ledger_fingerprint_domain",
                STORAGE_LEDGER_FINGERPRINT_DOMAIN,
            ),
            ("storage_ledger_header_size", STORAGE_LEDGER_HEADER_SIZE),
            ("storage_ledger_entry_size", STORAGE_LEDGER_ENTRY_SIZE),
            ("storage_ledger_capacity", STORAGE_LEDGER_CAPACITY),
            (
                "storage_ledger_records_per_key",
                STORAGE_LEDGER_RECORDS_PER_KEY,
            ),
            ("storage_active_retain_until", storage_retain_until),
            ("storage_active_route_canonical_hash", storage_active_route_hash),
            ("storage_product_endpoint_high_water", ENDPOINT_SEQUENCE + 1),
            ("storage_product_route_high_water", ROUTE_SEQUENCE + 1),
            ("storage_product_endpoint_id", product_endpoint_greater_id),
            ("storage_split_route_canonical_hash", storage_split_route_hash),
            (
                "storage_conflicting_route_canonical_hash",
                storage_conflicting_route_hash,
            ),
            ("storage_fresh_prior_expectation", "absent"),
            ("storage_fresh_revision", 0),
            ("storage_fresh_pruned_through", 0),
            ("storage_fresh_entry_count", 0),
            ("storage_fresh_snapshot_payload", storage_fresh[0]),
            ("storage_fresh_snapshot_checksum", storage_fresh[1]),
            ("storage_fresh_snapshot", storage_fresh[2]),
            ("storage_fresh_snapshot_fingerprint", storage_fresh[3]),
            ("storage_active_prior_revision", 0),
            ("storage_active_prior_fingerprint", storage_fresh[3]),
            ("storage_active_revision", 1),
            ("storage_active_pruned_through", 0),
            ("storage_active_entry_count", 1),
            ("storage_active_snapshot_payload", storage_active[0]),
            ("storage_active_snapshot_checksum", storage_active[1]),
            ("storage_active_snapshot", storage_active[2]),
            ("storage_active_snapshot_fingerprint", storage_active[3]),
            ("storage_endpoint_intermediate_prior_revision", 1),
            (
                "storage_endpoint_intermediate_prior_fingerprint",
                storage_active[3],
            ),
            ("storage_endpoint_intermediate_revision", 2),
            ("storage_endpoint_intermediate_pruned_through", 0),
            ("storage_endpoint_intermediate_entry_count", 1),
            (
                "storage_endpoint_intermediate_snapshot_payload",
                storage_endpoint_intermediate[0],
            ),
            (
                "storage_endpoint_intermediate_snapshot_checksum",
                storage_endpoint_intermediate[1],
            ),
            (
                "storage_endpoint_intermediate_snapshot",
                storage_endpoint_intermediate[2],
            ),
            (
                "storage_endpoint_intermediate_snapshot_fingerprint",
                storage_endpoint_intermediate[3],
            ),
            ("storage_split_prior_revision", 2),
            (
                "storage_split_prior_fingerprint",
                storage_endpoint_intermediate[3],
            ),
            ("storage_split_revision", 3),
            ("storage_split_pruned_through", 0),
            ("storage_split_entry_count", 1),
            ("storage_split_snapshot_payload", storage_split[0]),
            ("storage_split_snapshot_checksum", storage_split[1]),
            ("storage_split_snapshot", storage_split[2]),
            ("storage_split_snapshot_fingerprint", storage_split[3]),
            ("storage_conflict_prior_revision", 3),
            ("storage_conflict_prior_fingerprint", storage_split[3]),
            ("storage_conflict_revision", 4),
            ("storage_conflict_pruned_through", 0),
            ("storage_conflict_entry_count", 1),
            ("storage_conflict_snapshot_payload", storage_conflict[0]),
            ("storage_conflict_snapshot_checksum", storage_conflict[1]),
            ("storage_conflict_snapshot", storage_conflict[2]),
            ("storage_conflict_snapshot_fingerprint", storage_conflict[3]),
            ("storage_pruned_empty_prior_revision", 4),
            (
                "storage_pruned_empty_prior_fingerprint",
                storage_conflict[3],
            ),
            ("storage_pruned_empty_revision", 5),
            ("storage_pruned_empty_pruned_through", PERSISTENCE_HIGH_TIME),
            ("storage_pruned_empty_entry_count", 0),
            (
                "storage_pruned_empty_snapshot_payload",
                storage_pruned_empty[0],
            ),
            (
                "storage_pruned_empty_snapshot_checksum",
                storage_pruned_empty[1],
            ),
            ("storage_pruned_empty_snapshot", storage_pruned_empty[2]),
            (
                "storage_pruned_empty_snapshot_fingerprint",
                storage_pruned_empty[3],
            ),
        ]
    )
    return vectors


def render(vectors: list[tuple[str, VectorValue]]) -> bytes:
    names = [name for name, _ in vectors]
    if len(names) != len(set(names)):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        raise ValueError(f"duplicate fixture field names: {', '.join(duplicates)}")
    lines = [
        "# HRM-backed HNSA and HNSR NamedRouteV3 exact vectors",
        "# Generated by generators/generate-hnsa-hnsr-v3-fixtures.py; do not edit.",
        "# profile 0xff00 and pool-stats are test-only and grant no application semantics.",
    ]
    for name, value in vectors:
        rendered = value.hex() if isinstance(value, bytes) else str(value)
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
        for directory in FIXTURE_DIRS:
            directory.mkdir(parents=True, exist_ok=True)
            write_fixture(directory / FIXTURE_NAME, document)
    elif args.check:
        for directory in FIXTURE_DIRS:
            check_fixture(directory / FIXTURE_NAME, document)
    else:
        print(document.decode("ascii"), end="")


if __name__ == "__main__":
    main()
