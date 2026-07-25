#![doc = "Bounded cross-protocol mutation and parser conformance harnesses."]
#![forbid(unsafe_code)]

use hns_covenants::Covenant;
use hns_dns_relay_protocol::{DnsRelay, GetDnsRelay};
use hns_header_consensus::Header;
use hns_hnsr_protocol::HnsrPacket;
use hns_mining::Block;
use hns_odoh_protocol::OdnsPacket;
use hns_p2p_experimental::DenuoExtensionEnvelope;
use hns_p2p_wire::{Frame, NetworkMagic};
use hns_script::parse_script;
use hns_swap::SwapProof;
use hns_transaction::Transaction;
use hns_urkel_proof::HsdUrkelProof;
use thiserror::Error;

/// Largest byte slice admitted to the aggregate production-parser harness.
pub const MAX_CONFORMANCE_INPUT_SIZE: usize = 4_000_000;
/// Largest seed copied into the deterministic mutation corpus.
pub const MAX_MUTATION_SEED_SIZE: usize = 64 * 1024;
/// Maximum number of mutations retained from one seed.
pub const MAX_MUTATION_CASES: usize = 64;
/// Aggregate mutation bytes retained from one seed.
pub const MAX_MUTATION_CORPUS_BYTES: usize = 4 * 1024 * 1024;
const MAX_DENUO_PAYLOAD: usize = 1024 * 1024;

/// Bitset reporting which production parsers accepted an input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcceptanceMask(u16);

impl AcceptanceMask {
    pub const HEADER: u16 = 1 << 0;
    pub const BLOCK: u16 = 1 << 1;
    pub const TRANSACTION: u16 = 1 << 2;
    pub const SCRIPT: u16 = 1 << 3;
    pub const COVENANT: u16 = 1 << 4;
    pub const STANDARD_FRAME: u16 = 1 << 5;
    pub const DENUO_ENVELOPE: u16 = 1 << 6;
    pub const HIP76_REQUEST: u16 = 1 << 7;
    pub const HIP76_RESPONSE: u16 = 1 << 8;
    pub const HIP77_ENVELOPE: u16 = 1 << 9;
    pub const HIP78_ENVELOPE: u16 = 1 << 10;
    pub const URKEL_PROOF: u16 = 1 << 11;
    pub const SWAP_PROOF: u16 = 1 << 12;

    /// Whether the named parser bit accepted the input.
    pub const fn contains(self, parser: u16) -> bool {
        self.0 & parser != 0
    }

    /// Raw stable bit representation for fuzzing feedback and diagnostics.
    pub const fn bits(self) -> u16 {
        self.0
    }

    fn record(&mut self, parser: u16, accepted: bool) {
        if accepted {
            self.0 |= parser;
        }
    }
}

/// Run one bounded input through every runtime-independent production parser.
///
/// Individual parse errors are expected fuzz outcomes. Panics are deliberately
/// not caught here so deterministic tests and fuzzers report them as failures.
pub fn exercise_production_parsers(input: &[u8]) -> Result<AcceptanceMask, ConformanceError> {
    if input.len() > MAX_CONFORMANCE_INPUT_SIZE {
        return Err(ConformanceError::InputTooLarge {
            actual: input.len(),
            maximum: MAX_CONFORMANCE_INPUT_SIZE,
        });
    }

    let mut accepted = AcceptanceMask::default();
    accepted.record(AcceptanceMask::HEADER, Header::decode(input).is_ok());
    accepted.record(AcceptanceMask::BLOCK, Block::decode(input).is_ok());
    accepted.record(
        AcceptanceMask::TRANSACTION,
        Transaction::decode(input).is_ok(),
    );
    accepted.record(AcceptanceMask::SCRIPT, parse_script(input).is_ok());
    accepted.record(AcceptanceMask::COVENANT, Covenant::decode(input).is_ok());
    accepted.record(
        AcceptanceMask::STANDARD_FRAME,
        Frame::decode_exact(NetworkMagic::Regtest, input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::DENUO_ENVELOPE,
        DenuoExtensionEnvelope::decode(input, MAX_DENUO_PAYLOAD).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HIP76_REQUEST,
        GetDnsRelay::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HIP76_RESPONSE,
        DnsRelay::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HIP77_ENVELOPE,
        OdnsPacket::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HIP78_ENVELOPE,
        HnsrPacket::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::URKEL_PROOF,
        HsdUrkelProof::decode_strict(input).is_ok(),
    );
    accepted.record(AcceptanceMask::SWAP_PROOF, SwapProof::decode(input).is_ok());
    Ok(accepted)
}

/// Produce deterministic truncation, extension, bit-flip, and length-field
/// mutations without allowing corpus count or aggregate bytes to grow without
/// bound.
pub fn bounded_mutations(
    seed: &[u8],
    requested_cases: usize,
) -> Result<Vec<Vec<u8>>, ConformanceError> {
    if seed.len() > MAX_MUTATION_SEED_SIZE {
        return Err(ConformanceError::SeedTooLarge {
            actual: seed.len(),
            maximum: MAX_MUTATION_SEED_SIZE,
        });
    }
    let case_limit = requested_cases.min(MAX_MUTATION_CASES);
    if case_limit == 0 {
        return Ok(Vec::new());
    }

    let mut cases = Vec::with_capacity(case_limit);
    let mut aggregate_bytes = 0_usize;
    push_unique(&mut cases, seed.to_vec(), case_limit, &mut aggregate_bytes);

    let truncations = [
        0,
        1.min(seed.len()),
        seed.len() / 4,
        seed.len() / 2,
        seed.len().saturating_sub(1),
    ];
    for end in truncations {
        push_unique(
            &mut cases,
            seed[..end].to_vec(),
            case_limit,
            &mut aggregate_bytes,
        );
    }

    if !seed.is_empty() {
        let flips = 16.min(seed.len());
        for index in 0..flips {
            let offset = index.saturating_mul(seed.len()) / flips;
            let mut mutation = seed.to_vec();
            mutation[offset] ^= 1_u8 << (index % 8);
            push_unique(&mut cases, mutation, case_limit, &mut aggregate_bytes);
        }
    }

    for suffix in [[0_u8].as_slice(), [0xff_u8].as_slice(), &[0; 8], &[0xff; 8]] {
        let mut mutation = seed.to_vec();
        mutation.extend_from_slice(suffix);
        push_unique(&mut cases, mutation, case_limit, &mut aggregate_bytes);
    }

    for offset in 0..seed.len().min(16) {
        let mut mutation = seed.to_vec();
        mutation[offset] = if offset % 2 == 0 { 0 } else { 0xff };
        push_unique(&mut cases, mutation, case_limit, &mut aggregate_bytes);
    }
    Ok(cases)
}

fn push_unique(
    cases: &mut Vec<Vec<u8>>,
    candidate: Vec<u8>,
    case_limit: usize,
    aggregate_bytes: &mut usize,
) {
    if cases.len() >= case_limit || cases.iter().any(|existing| existing == &candidate) {
        return;
    }
    let Some(next_total) = aggregate_bytes.checked_add(candidate.len()) else {
        return;
    };
    if next_total > MAX_MUTATION_CORPUS_BYTES {
        return;
    }
    *aggregate_bytes = next_total;
    cases.push(candidate);
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConformanceError {
    #[error("conformance input length {actual} exceeds maximum {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("mutation seed length {actual} exceeds maximum {maximum}")]
    SeedTooLarge { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSACTION: &str = "0100000001080808080808080808080808080808080808080808080808080808080808080802000000feffffff012a0000000000000000140909090909090909090909090909090909090909020103616263630000000203010203020405";
    const REGTEST_PING: &str = "cf9538ae02080000004343434343434343";
    const DENUO: &str = "444e553101000100010006000102070000000000000002000000aabb";
    const HIP76: &str = "08070605040302012a00123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000";
    const HIP77: &str = "0101000008070605040302010203";
    const HIP78: &str = "011100000102030405060708deadbeef";

    #[test]
    fn exact_vectors_reach_their_production_parsers() {
        let vectors = [
            (TRANSACTION, AcceptanceMask::TRANSACTION),
            (REGTEST_PING, AcceptanceMask::STANDARD_FRAME),
            (DENUO, AcceptanceMask::DENUO_ENVELOPE),
            (HIP76, AcceptanceMask::HIP76_REQUEST),
            (HIP77, AcceptanceMask::HIP77_ENVELOPE),
            (HIP78, AcceptanceMask::HIP78_ENVELOPE),
            ("00000000", AcceptanceMask::URKEL_PROOF),
        ];
        for (encoded, parser) in vectors {
            let bytes = hex::decode(encoded).expect("static hex");
            let accepted = exercise_production_parsers(&bytes).expect("bounded");
            assert!(accepted.contains(parser), "parser bit {parser:#x}");
        }
    }

    #[test]
    fn deterministic_mutation_smoke_exercises_every_parser_without_panics() {
        let seeds = [TRANSACTION, REGTEST_PING, DENUO, HIP76, HIP77, HIP78];
        let mut mutations = 0_usize;
        for seed in seeds {
            let seed = hex::decode(seed).expect("static hex");
            for mutation in bounded_mutations(&seed, MAX_MUTATION_CASES).expect("bounded") {
                let _ = exercise_production_parsers(&mutation).expect("bounded");
                mutations += 1;
            }
        }
        assert!(mutations >= 100);
    }

    #[test]
    fn corpus_and_parser_limits_fail_closed() {
        assert!(matches!(
            bounded_mutations(&vec![0; MAX_MUTATION_SEED_SIZE + 1], 1),
            Err(ConformanceError::SeedTooLarge { .. })
        ));
        assert!(matches!(
            exercise_production_parsers(&vec![0; MAX_CONFORMANCE_INPUT_SIZE + 1]),
            Err(ConformanceError::InputTooLarge { .. })
        ));
        assert!(bounded_mutations(b"seed", 0).expect("bounded").is_empty());
        assert!(
            bounded_mutations(b"seed", usize::MAX)
                .expect("bounded")
                .len()
                <= MAX_MUTATION_CASES
        );
    }
}
