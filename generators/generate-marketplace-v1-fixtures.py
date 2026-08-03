#!/usr/bin/env python3
"""Generate source-independent exact hns-swap/marketplace v1 fixtures.

This generator uses only Python's standard library. It deliberately implements
the documented canonical encodings, RFC6979 secp256k1 signing, and hash domains
instead of invoking Rust code, so checked-in vectors remain an independent wire
oracle. Run from the repository root with `--write` to replace the versioned
fixture documents and their SHA-256 sidecars.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "protocol-v1"
PACKAGE_SWAP_FIXTURE_DIR = ROOT / "crates" / "hns-swap" / "fixtures" / "protocol-v1"
PACKAGE_MARKETPLACE_FIXTURE_DIR = (
    ROOT / "crates" / "hns-marketplace-protocol" / "fixtures" / "protocol-v1"
)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

LOCKTIME_FLAG = 0x80000000
HIP1_SELLER_SIGHASH = 0x84
SHAKEDEX_RECOVERY_SIGHASH = 0x83
HNS_HTLC_SIGHASH = 0x01

LISTING_SIGNATURE_DOMAIN = b"hns-rs/hns-swap/fixed-price-listing/v1/signature"
LISTING_HASH_DOMAIN = b"hns-rs/hns-swap/fixed-price-listing/v1/hash"
CANCELLATION_SIGNATURE_DOMAIN = b"hns-rs/hns-swap/listing-cancellation/v1/signature"
CANCELLATION_HASH_DOMAIN = b"hns-rs/hns-swap/listing-cancellation/v1/hash"


def le(value: int, size: int) -> bytes:
    return value.to_bytes(size, "little")


def compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + le(value, 2)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + le(value, 4)
    return b"\xff" + le(value, 8)


def varbytes(value: bytes) -> bytes:
    return compact(len(value)) + value


def b2(value: bytes) -> bytes:
    return hashlib.blake2b(value, digest_size=32).digest()


def domain_hash(domain: bytes, value: bytes) -> bytes:
    return b2(domain + value)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None):
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


def point_mul(scalar: int, point: tuple[int, int] = (GX, GY)):
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
    point = point_mul(scalar)
    assert point is not None
    x, y = point
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def deterministic_nonce(private_key: bytes, digest: bytes) -> int:
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
            return nonce
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign(private_key: bytes, digest: bytes) -> bytes:
    scalar = int.from_bytes(private_key, "big")
    nonce = deterministic_nonce(private_key, digest)
    point = point_mul(nonce)
    assert point is not None
    r = point[0] % N
    s = (pow(nonce, -1, N) * (int.from_bytes(digest, "big") + r * scalar)) % N
    if s > N // 2:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def address(version: int, program: bytes) -> bytes:
    return bytes([version, len(program)]) + program


def covenant(kind: int, items: list[bytes] | tuple[bytes, ...] = ()) -> bytes:
    return bytes([kind]) + compact(len(items)) + b"".join(varbytes(item) for item in items)


def output(value: int, address_bytes: bytes, covenant_bytes: bytes) -> bytes:
    return le(value, 8) + address_bytes + covenant_bytes


def outpoint(transaction_hash: bytes, index: int) -> bytes:
    return transaction_hash + le(index, 4)


def transaction_base(
    version: int,
    inputs: list[tuple[bytes, int]],
    outputs: list[bytes],
    locktime: int,
) -> bytes:
    return (
        le(version, 4)
        + compact(len(inputs))
        + b"".join(previous + le(sequence, 4) for previous, sequence in inputs)
        + compact(len(outputs))
        + b"".join(outputs)
        + le(locktime, 4)
    )


def transaction(
    version: int,
    inputs: list[tuple[bytes, int, list[bytes]]],
    outputs: list[bytes],
    locktime: int,
) -> tuple[bytes, bytes, bytes]:
    base = transaction_base(
        version,
        [(previous, sequence) for previous, sequence, _ in inputs],
        outputs,
        locktime,
    )
    witness = b"".join(
        compact(len(items)) + b"".join(varbytes(item) for item in items)
        for _, _, items in inputs
    )
    return base + witness, base, b2(base)


def signature_hash(
    version: int,
    inputs: list[tuple[bytes, int]],
    outputs: list[bytes],
    locktime: int,
    input_index: int,
    previous_script: bytes,
    previous_value: int,
    hash_type: int,
) -> bytes:
    base_type = hash_type & 0x1F
    anyone_can_pay = bool(hash_type & 0x80)
    no_input = bool(hash_type & 0x40)
    zero = b"\x00" * 32
    hash_prevouts = zero if anyone_can_pay else b2(b"".join(item[0] for item in inputs))
    hash_sequences = (
        zero
        if anyone_can_pay or base_type in (2, 3, 4)
        else b2(b"".join(le(item[1], 4) for item in inputs))
    )
    if base_type == 1:
        hash_outputs = b2(b"".join(outputs))
    elif base_type == 2:
        hash_outputs = zero
    elif base_type == 3:
        hash_outputs = b2(outputs[input_index]) if input_index < len(outputs) else zero
    elif base_type == 4:
        output_index = len(outputs) - 1 - input_index
        hash_outputs = b2(outputs[output_index]) if input_index < len(outputs) else zero
    else:
        raise ValueError("invalid hash type")
    current_outpoint, sequence = inputs[input_index]
    if no_input:
        current_outpoint, sequence = b"\x00" * 32 + b"\xff" * 4, 0xFFFFFFFF
    preimage = (
        le(version, 4)
        + hash_prevouts
        + hash_sequences
        + current_outpoint
        + varbytes(previous_script)
        + le(previous_value, 8)
        + le(sequence, 4)
        + hash_outputs
        + le(locktime, 4)
        + le(hash_type, 4)
    )
    return b2(preimage)


def shakedex_script(seller_public_key: bytes) -> bytes:
    return bytes.fromhex("d059876321") + seller_public_key + bytes.fromhex("ac67d05a8768")


def swap_proof_encode(proof: dict) -> bytes:
    encoded = (
        le(2, 2)
        + le(proof["magic"], 4)
        + proof["genesis"]
        + proof["locking_outpoint"]
        + varbytes(proof["name"])
        + proof["seller_public_key"]
        + proof["payment_address"]
        + le(proof["price"], 8)
        + le(proof["lock_time_seconds"], 8)
    )
    signature = proof.get("signature")
    encoded += b"\x00" if signature is None else b"\x01" + signature
    encoded += le(proof["fee"], 8)
    fee_address = proof.get("fee_address")
    encoded += b"\x00" if fee_address is None else b"\x01" + fee_address
    return encoded


def fixed_price_listing_vectors() -> dict[str, bytes]:
    """Build the complete fixed-price listing and cancellation envelopes."""
    private_key = b"\x31" * 32
    seller_public_key = public_key(private_key)
    script = shakedex_script(seller_public_key)
    name = b"market-name"
    locking_outpoint = outpoint(b"\x22" * 32, 7)
    outputs = [
        output(0, address(0, b"\x00" * 20), covenant(9)),
        output(25_000, address(0, b"\x44" * 20), covenant(0)),
        output(12_345_678, address(0, b"\x33" * 20), covenant(0)),
    ]
    locktime = LOCKTIME_FLAG | (1_800_000_000 // 512)
    digest = signature_hash(
        0,
        [(locking_outpoint, 0xFFFFFFFE)],
        outputs,
        locktime,
        0,
        script,
        900_000,
        HIP1_SELLER_SIGHASH,
    )
    proof = swap_proof_encode(
        {
            "magic": 0x5B6EC393,
            "genesis": b"\x11" * 32,
            "locking_outpoint": locking_outpoint,
            "name": name,
            "seller_public_key": seller_public_key,
            "payment_address": address(0, b"\x33" * 20),
            "price": 12_345_678,
            "lock_time_seconds": 1_800_000_000,
            "signature": sign(private_key, digest) + bytes([HIP1_SELLER_SIGHASH]),
            "fee": 25_000,
            "fee_address": address(0, b"\x44" * 20),
        }
    )
    listing_signing_bytes = (
        le(1, 2)
        + le(1_800_000_100, 8)
        + le(1_800_003_700, 8)
        + le(42, 8)
        + varbytes(proof)
    )
    listing_digest = domain_hash(LISTING_SIGNATURE_DOMAIN, listing_signing_bytes)
    listing_signature = sign(private_key, listing_digest)
    assert listing_signature.hex() == (
        "c096028fbaf60633eea9ebe29a13767111930eee36bf7fb74b21d40329730f051"
        "dd19f12ab6e30edb0ebfa6f5dcf1272d8790dfb49385bffd87513d1e9d626a0"
    )
    listing_without_hash = listing_signing_bytes + b"\x01" + listing_signature
    listing_hash = domain_hash(LISTING_HASH_DOMAIN, listing_without_hash)
    listing = listing_without_hash + listing_hash

    cancellation_signing_bytes = (
        le(1, 2)
        + le(0x5B6EC393, 4)
        + b"\x11" * 32
        + listing_hash
        + seller_public_key
        + le(1_800_000_120, 8)
        + le(1_800_003_700, 8)
        + le(43, 8)
    )
    cancellation_digest = domain_hash(
        CANCELLATION_SIGNATURE_DOMAIN,
        cancellation_signing_bytes,
    )
    cancellation_signature = sign(private_key, cancellation_digest)
    assert cancellation_signature.hex() == (
        "75ec98bd43e79f4546e802200bfbaa3da89a292e3e4f2e25a2fd696a82c03cde"
        "4c1351ab937128cd6ccddfdaa1116f384d5d89d7684cb446dcdd11d54ec5f667"
    )
    cancellation_without_hash = (
        cancellation_signing_bytes + b"\x01" + cancellation_signature
    )
    cancellation_hash = domain_hash(
        CANCELLATION_HASH_DOMAIN,
        cancellation_without_hash,
    )
    cancellation = cancellation_without_hash + cancellation_hash

    return {
        "fixed_price_listing": listing,
        "fixed_price_listing_signature_digest": listing_digest,
        "fixed_price_listing_hash": listing_hash,
        "listing_cancellation": cancellation,
        "listing_cancellation_signature_digest": cancellation_digest,
        "listing_cancellation_hash": cancellation_hash,
    }


def shakedex_vectors() -> dict[str, bytes]:
    private_key = b"\x07" * 32
    seller_public_key = public_key(private_key)
    script = shakedex_script(seller_public_key)
    name = b"handshake"
    name_hash = hashlib.sha3_256(name).digest()
    locking_outpoint = outpoint(b"\x22" * 32, 3)
    lock_address = address(0, hashlib.sha3_256(script).digest())
    locking_covenant = covenant(10, [name_hash, le(1, 4), name])
    locking_value = 42
    payment = output(1_000_000, address(0, b"\x33" * 20), covenant(0))
    placeholder_transfer = output(0, address(0, b"\x00" * 20), covenant(9))
    locktime = LOCKTIME_FLAG | 1
    presign_inputs = [(locking_outpoint, 0xFFFFFFFE)]
    presign_outputs = [placeholder_transfer, payment]
    presign_digest = signature_hash(
        0,
        presign_inputs,
        presign_outputs,
        locktime,
        0,
        script,
        locking_value,
        HIP1_SELLER_SIGHASH,
    )
    seller_signature = sign(private_key, presign_digest) + bytes([HIP1_SELLER_SIGHASH])
    proof = {
        "magic": 0x5B6EC393,
        "genesis": b"\x11" * 32,
        "locking_outpoint": locking_outpoint,
        "name": name,
        "seller_public_key": seller_public_key,
        "payment_address": address(0, b"\x33" * 20),
        "price": 1_000_000,
        "lock_time_seconds": 512,
        "signature": seller_signature,
        "fee": 0,
        "fee_address": None,
    }
    proof_bytes = swap_proof_encode(proof)
    offer_id = b2(proof_bytes + b"HIP-0001/Shakedex-v2/offer")
    presigned, _, presigned_txid = transaction(
        0,
        [(locking_outpoint, 0xFFFFFFFE, [seller_signature, script])],
        presign_outputs,
        locktime,
    )

    recipient = address(0, b"\x55" * 20)
    transfer_covenant = covenant(9, [name_hash, le(1, 4), b"\x00", b"\x55" * 20])
    transfer = output(locking_value, lock_address, transfer_covenant)
    buyer_outpoint = outpoint(b"\x66" * 32, 1)
    buyer_change = output(2_000_000, address(0, b"\x77" * 20), covenant(0))
    fulfillment_inputs = [
        (locking_outpoint, 0xFFFFFFFE, [seller_signature, script]),
        (buyer_outpoint, 0xFFFFFFFF, []),
    ]
    fulfillment_outputs = [transfer, buyer_change, payment]
    fulfillment, _, fulfillment_txid = transaction(
        0, fulfillment_inputs, fulfillment_outputs, locktime
    )

    recovery_recipient = address(0, b"\x88" * 20)
    recovery_transfer = output(
        locking_value,
        lock_address,
        covenant(9, [name_hash, le(1, 4), b"\x00", b"\x88" * 20]),
    )
    recovery_inputs_for_hash = [(locking_outpoint, 0xFFFFFFFF), (buyer_outpoint, 0xFFFFFFFF)]
    recovery_outputs = [recovery_transfer, buyer_change]
    recovery_digest = signature_hash(
        0,
        recovery_inputs_for_hash,
        recovery_outputs,
        0,
        0,
        script,
        locking_value,
        SHAKEDEX_RECOVERY_SIGHASH,
    )
    recovery_signature = sign(private_key, recovery_digest) + bytes([SHAKEDEX_RECOVERY_SIGHASH])
    recovery, _, recovery_txid = transaction(
        0,
        [
            (locking_outpoint, 0xFFFFFFFF, [recovery_signature, script]),
            (buyer_outpoint, 0xFFFFFFFF, []),
        ],
        recovery_outputs,
        0,
    )

    finalize_witness = compact(1) + varbytes(script)
    finalize_output = output(
        locking_value,
        recovery_recipient,
        covenant(
            10,
            [
                name_hash,
                le(1, 4),
                name,
                b"\x00",
                le(0, 4),
                le(0, 4),
                b"\x99" * 32,
            ],
        ),
    )
    recovery_finalize, _, recovery_finalize_txid = transaction(
        0,
        [(outpoint(recovery_txid, 0), 0xFFFFFFFF, [script])],
        [finalize_output],
        0,
    )

    return {
        "swap_proof": proof_bytes,
        "swap_proof_offer_id": offer_id,
        "swap_proof_seller_sighash": presign_digest,
        "swap_proof_presigned_transaction": presigned,
        "swap_proof_presigned_txid": presigned_txid,
        "fulfillment_transaction": fulfillment,
        "fulfillment_txid": fulfillment_txid,
        "fulfillment_recipient_address": recipient,
        "recovery_sighash": recovery_digest,
        "recovery_transaction": recovery,
        "recovery_txid": recovery_txid,
        "recovery_recipient_address": recovery_recipient,
        "recovery_finalize_witness": finalize_witness,
        "recovery_finalize_transaction": recovery_finalize,
        "recovery_finalize_txid": recovery_finalize_txid,
    }


def script_number(value: int) -> bytes:
    result = bytearray()
    while value:
        result.append(value & 0xFF)
        value >>= 8
    if result[-1] & 0x80:
        result.append(0)
    return bytes(result)


def htlc_script(hashlock: bytes, receiver: bytes, refund: bytes, locktime: int) -> bytes:
    encoded_locktime = script_number(locktime)
    return (
        bytes.fromhex("63a820")
        + hashlock
        + bytes.fromhex("8821")
        + receiver
        + b"\x67"
        + bytes([len(encoded_locktime)])
        + encoded_locktime
        + bytes.fromhex("b17521")
        + refund
        + bytes.fromhex("68ac")
    )


def htlc_vectors() -> dict[str, bytes]:
    receiver_private = b"\x41" * 32
    refund_private = b"\x42" * 32
    receiver = public_key(receiver_private)
    refund = public_key(refund_private)
    preimage = b"\x55" * 32
    hashlock = hashlib.sha256(preimage).digest()
    value = 5_000_000
    locktime = 500_000
    descriptor = (
        le(1, 2)
        + le(0x5B6EC393, 4)
        + b"\x11" * 32
        + le(value, 8)
        + hashlock
        + receiver
        + refund
        + le(locktime, 4)
    )
    script = htlc_script(hashlock, receiver, refund, locktime)
    script_hash = hashlib.sha3_256(script).digest()
    htlc_address = address(0, script_hash)
    descriptor_hash = domain_hash(b"hns-rs/hns-swap/hns-htlc/v1/descriptor", descriptor)

    source_outpoint = outpoint(b"\x22" * 32, 3)
    funding, _, funding_txid = transaction(
        1,
        [(source_outpoint, 0xFFFFFFFF, [])],
        [output(value, htlc_address, covenant(0))],
        0,
    )
    funding_outpoint = outpoint(funding_txid, 0)
    spend_output = output(value - 1_000, address(0, b"\x77" * 20), covenant(0))
    spend_inputs = [(funding_outpoint, 0xFFFFFFFE)]
    redeem_digest = signature_hash(
        1, spend_inputs, [spend_output], 0, 0, script, value, HNS_HTLC_SIGHASH
    )
    redeem_signature = sign(receiver_private, redeem_digest) + bytes([HNS_HTLC_SIGHASH])
    redeem, _, redeem_txid = transaction(
        1,
        [(funding_outpoint, 0xFFFFFFFE, [redeem_signature, preimage, b"\x01", script])],
        [spend_output],
        0,
    )
    refund_digest = signature_hash(
        1, spend_inputs, [spend_output], locktime, 0, script, value, HNS_HTLC_SIGHASH
    )
    refund_signature = sign(refund_private, refund_digest) + bytes([HNS_HTLC_SIGHASH])
    refund_tx, _, refund_txid = transaction(
        1,
        [(funding_outpoint, 0xFFFFFFFE, [refund_signature, b"", script])],
        [spend_output],
        locktime,
    )
    return {
        "htlc_descriptor": descriptor,
        "htlc_descriptor_hash": descriptor_hash,
        "htlc_script": script,
        "htlc_script_hash": script_hash,
        "htlc_address": htlc_address,
        "htlc_funding_transaction": funding,
        "htlc_funding_txid": funding_txid,
        "htlc_redeem_sighash": redeem_digest,
        "htlc_redeem_transaction": redeem,
        "htlc_redeem_txid": redeem_txid,
        "htlc_refund_sighash": refund_digest,
        "htlc_refund_transaction": refund_tx,
        "htlc_refund_txid": refund_txid,
    }


def network() -> bytes:
    return le(0x5B6EC393, 4) + b"\x01" * 32 + le(2, 2) + le(1, 8) + b"\x02" * 32


def asset(chain: int) -> bytes:
    return le(chain, 2) + b"\x00\x00"


def pair() -> bytes:
    return asset(1) + asset(2)


def header(signer: bytes, sequence: int, created: int, expires: int) -> bytes:
    return le(1, 2) + network() + pair() + signer + le(sequence, 8) + le(created, 8) + le(expires, 8)


def amount(value: int) -> bytes:
    return le(value, 16)


def rational(numerator: int, denominator: int) -> bytes:
    return le(numerator, 16) + le(denominator, 16)


def anchor(chain: int, height: int, block_hash: bytes) -> bytes:
    return le(chain, 2) + le(height, 8) + block_hash


def sign_domain(private_key: bytes, domain: bytes, value: bytes) -> bytes:
    return sign(private_key, domain_hash(domain, value))


def denuo_envelope(message_type: int, request_id: int, payload: bytes) -> bytes:
    return (
        b"DNU1"
        + le(2, 2)
        + le(2, 2)
        + le(1, 2)
        + le(message_type, 2)
        + b"\x00\x00"
        + le(request_id, 8)
        + le(len(payload), 4)
        + payload
    )


def marketplace_vectors() -> dict[str, bytes]:
    maker_identity_private = b"\x07" * 32
    maker_identity = public_key(maker_identity_private)
    maker_settlement_private = b"\x09" * 32
    maker_settlement = public_key(maker_settlement_private)
    taker_identity_private = b"\x0a" * 32
    taker_settlement_private = b"\x08" * 32
    taker_settlement = public_key(taker_settlement_private)

    intent_unsigned = header(maker_identity, 1, 100, 1_000) + asset(1) + amount(100_000_000) + amount(1_000_000) + b"\x01"
    intent_id = domain_hash(b"HNS-MARKET-INTENT-ID-V1\x00", intent_unsigned)
    intent_signature = sign_domain(
        maker_identity_private,
        b"HNS-MARKET-INTENT-SIGNATURE-V1\x00",
        intent_id + intent_unsigned,
    )
    intent = intent_unsigned + intent_id + intent_signature

    cancellation_unsigned = header(maker_identity, 2, 120, 1_000) + intent_id + le(1, 8)
    cancellation_signature = sign_domain(
        maker_identity_private,
        b"HNS-MARKET-INTENT-CANCEL-V1\x00",
        cancellation_unsigned,
    )
    cancellation = cancellation_unsigned + cancellation_signature
    cancellation_hash = domain_hash(
        b"HNS-MARKET-INTENT-CANCEL-ID-V1\x00", cancellation
    )

    hns_anchor = anchor(1, 100, b"\x03" * 32)
    btc_anchor = anchor(2, 200, b"\x04" * 32)
    observations: list[tuple[bytes, bytes, bytes, bytes]] = []
    for index in (1, 2, 3):
        private = bytes([index]) * 32
        reporter = public_key(private)
        unsigned = (
            le(1, 2)
            + network()
            + pair()
            + rational(3, 2)
            + bytes([index]) * 32
            + reporter
            + le(110, 8)
            + le(300, 8)
            + hns_anchor
            + btc_anchor
            + le(index, 8)
        )
        signature = sign_domain(
            private, b"HNS-MARKET-PRICE-OBSERVATION-V1\x00", unsigned
        )
        encoded = unsigned + signature
        observation_hash = domain_hash(
            b"HNS-MARKET-PRICE-OBSERVATION-ID-V1\x00", encoded
        )
        observations.append((observation_hash, encoded, reporter, bytes([index]) * 32))
    observations.sort(key=lambda item: item[0])
    reporters = sorted(item[2] for item in observations)
    sources = sorted(item[3] for item in observations)
    policy = le(3, 2) + le(3, 2) + le(100, 8) + le(0, 2) + le(1_000, 4)
    round_unsigned = (
        le(1, 2)
        + network()
        + pair()
        + b"\x09" * 32
        + le(100, 8)
        + le(120, 8)
        + rational(3, 2)
        + compact(len(observations))
        + b"".join(varbytes(item[1]) for item in observations)
        + compact(len(reporters))
        + b"".join(reporters)
        + compact(len(sources))
        + b"".join(sources)
        + policy
        + hns_anchor
        + btc_anchor
        + le(200, 8)
        + b"\x00" * 32
    )
    round_hash = domain_hash(b"HNS-MARKET-PRICE-ROUND-V1\x00", round_unsigned)
    price_round = round_unsigned + round_hash

    match_unsigned = (
        header(public_key(taker_identity_private), 2, 121, 190)
        + intent_id
        + le(1, 8)
        + b"\x08" * 32
        + taker_settlement
        + amount(3_000_000)
    )
    match_signature = sign_domain(
        taker_identity_private, b"HNS-MARKET-MATCH-REQUEST-V1\x00", match_unsigned
    )
    match_request = match_unsigned + match_signature

    grant_unsigned = (
        header(maker_identity, 3, 125, 180)
        + intent_id
        + le(1, 8)
        + b"\x08" * 32
        + maker_settlement
        + taker_settlement
        + amount(3_000_000)
        + amount(4_500_000)
        + round_hash
        + le(1, 8)
    )
    grant_hash = domain_hash(b"HNS-MARKET-FILL-GRANT-ID-V1\x00", grant_unsigned)
    grant_signature = sign_domain(
        maker_identity_private,
        b"HNS-MARKET-FILL-GRANT-SIGNATURE-V1\x00",
        grant_hash + grant_unsigned,
    )
    fill_grant = grant_unsigned + grant_hash + grant_signature

    reject_unsigned = (
        header(maker_identity, 3, 125, 180)
        + intent_id
        + b"\x08" * 32
        + le(4, 2)
    )
    reject_signature = sign_domain(
        maker_identity_private, b"HNS-MARKET-MATCH-REJECT-V1\x00", reject_unsigned
    )
    match_reject = reject_unsigned + reject_signature

    hashlock = hashlib.sha256(b"\x55" * 32).digest()
    hns_receiver = public_key(b"\x31" * 32)
    hns_refund = public_key(b"\x32" * 32)
    hns_descriptor = (
        le(1, 2)
        + le(0x5B6EC393, 4)
        + b"\x01" * 32
        + le(3_000_000, 8)
        + hashlock
        + hns_receiver
        + hns_refund
        + le(LOCKTIME_FLAG | 2, 4)
    )
    hns_commitment = domain_hash(
        b"hns-rs/hns-swap/hns-htlc/v1/descriptor", hns_descriptor
    )
    hello_unsigned = (
        header(maker_identity, 4, 130, 170)
        + grant_hash
        + b"\x08" * 32
        + maker_settlement
        + taker_settlement
        + asset(1)
        + amount(3_000_000)
        + asset(2)
        + amount(4_500_000)
        + round_hash
        + hashlock
        + le(1, 2)
        + hns_commitment
        + b"\x02"
        + le(900, 8)
        + le(5, 4)
        + b"\x44" * 32
        + b"\x02"
        + le(600, 8)
        + le(6, 4)
    )
    maker_hello_signature = sign_domain(
        maker_settlement_private,
        b"HNS-MARKET-SWAP-SESSION-HELLO-MAKER-V1\x00",
        hello_unsigned,
    )
    taker_hello_signature = sign_domain(
        taker_settlement_private,
        b"HNS-MARKET-SWAP-SESSION-HELLO-TAKER-V1\x00",
        hello_unsigned,
    )
    hello = hello_unsigned + maker_hello_signature + taker_hello_signature

    funding_unsigned = (
        header(maker_settlement, 5, 140, 1_000)
        + b"\x08" * 32
        + le(1, 2)
        + hns_commitment
        + b"\xaa" * 32
        + le(0, 4)
        + amount(3_000_000)
        + le(5, 4)
        + b"\x03"
    )
    funding_signature = sign_domain(
        maker_settlement_private,
        b"HNS-MARKET-SWAP-FUNDING-STATUS-V1\x00",
        funding_unsigned,
    )
    funding = funding_unsigned + funding_signature

    redeem_unsigned = (
        header(maker_settlement, 6, 150, 1_000)
        + b"\x08" * 32
        + le(2, 2)
        + b"\xbb" * 32
        + hashlock
        + le(0, 4)
        + b"\x02"
    )
    redeem_signature = sign_domain(
        maker_settlement_private,
        b"HNS-MARKET-SWAP-REDEEM-STATUS-V1\x00",
        redeem_unsigned,
    )
    redeem = redeem_unsigned + redeem_signature

    refund_unsigned = (
        header(maker_settlement, 7, 160, 1_000)
        + b"\x08" * 32
        + le(1, 2)
        + b"\xcc" * 32
        + le(0, 4)
        + b"\x01"
    )
    refund_signature = sign_domain(
        maker_settlement_private,
        b"HNS-MARKET-SWAP-REFUND-STATUS-V1\x00",
        refund_unsigned,
    )
    refund = refund_unsigned + refund_signature

    vectors = {
        "market_intent": intent,
        "market_intent_id": intent_id,
        "market_intent_cancellation": cancellation,
        "market_intent_cancellation_hash": cancellation_hash,
        "price_observation": observations[0][1],
        "price_observation_hash": observations[0][0],
        "price_round": price_round,
        "price_round_hash": round_hash,
        "match_request": match_request,
        "fill_grant": fill_grant,
        "fill_grant_hash": grant_hash,
        "match_reject": match_reject,
        "swap_session_hello": hello,
        "hns_session_descriptor": hns_descriptor,
        "hns_session_descriptor_hash": hns_commitment,
        "swap_funding_status": funding,
        "swap_redeem_status": redeem,
        "swap_refund_status": refund,
    }
    envelope_inputs = [
        ("market_intent", 3, 101),
        ("market_intent_cancellation", 4, 0),
        ("price_observation", 7, 102),
        ("price_round", 8, 0),
        ("match_request", 9, 103),
        ("fill_grant", 10, 104),
        ("match_reject", 11, 105),
        ("swap_session_hello", 12, 106),
        ("swap_funding_status", 13, 0),
        ("swap_redeem_status", 14, 0),
        ("swap_refund_status", 15, 0),
    ]
    for name, message_type, request_id in envelope_inputs:
        vectors[f"denuo_{name}_envelope"] = denuo_envelope(
            message_type, request_id, vectors[name]
        )
    return vectors


def render(title: str, vectors: dict[str, bytes]) -> bytes:
    lines = [
        f"# {title}",
        "# Generated by generators/generate-marketplace-v1-fixtures.py; do not edit.",
    ]
    lines.extend(f"{name}={value.hex()}" for name, value in vectors.items())
    return ("\n".join(lines) + "\n").encode()


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
    if path.read_bytes() != content:
        raise SystemExit(f"{path} differs from deterministic generator output")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.read_text(encoding="ascii") != expected_sidecar:
        raise SystemExit(f"{sidecar} differs from deterministic generator output")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    swap = {}
    swap.update(fixed_price_listing_vectors())
    swap.update(shakedex_vectors())
    swap.update(htlc_vectors())
    marketplace = marketplace_vectors()
    swap_document = render("hns-swap exact protocol v1 vectors", swap)
    marketplace_document = render("hns-marketplace exact protocol v1 vectors", marketplace)

    # Independent generator invariants already pinned by the Rust source.
    assert swap["htlc_script_hash"].hex() == "23c2a34d907f099fe7dec5bf92281578b519ab9a802b3b629eeb4c976d1c1a1c"
    assert swap["htlc_descriptor_hash"].hex() == "93d2e4d84d43df867c0e99e6864feac6317992a57b96e17cf851278ba869cdfc"

    if args.write:
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        write_fixture(FIXTURE_DIR / "hns-swap-v1.txt", swap_document)
        PACKAGE_SWAP_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        write_fixture(PACKAGE_SWAP_FIXTURE_DIR / "hns-swap-v1.txt", swap_document)
        write_fixture(FIXTURE_DIR / "hns-marketplace-v1.txt", marketplace_document)
        PACKAGE_MARKETPLACE_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        write_fixture(
            PACKAGE_MARKETPLACE_FIXTURE_DIR / "hns-marketplace-v1.txt",
            marketplace_document,
        )
    elif args.check:
        check_fixture(FIXTURE_DIR / "hns-swap-v1.txt", swap_document)
        check_fixture(PACKAGE_SWAP_FIXTURE_DIR / "hns-swap-v1.txt", swap_document)
        check_fixture(FIXTURE_DIR / "hns-marketplace-v1.txt", marketplace_document)
        check_fixture(
            PACKAGE_MARKETPLACE_FIXTURE_DIR / "hns-marketplace-v1.txt",
            marketplace_document,
        )
    else:
        print(swap_document.decode(), end="")
        print(marketplace_document.decode(), end="")


if __name__ == "__main__":
    main()
