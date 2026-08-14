#![doc = "Bounded cross-protocol mutation and parser conformance harnesses."]
#![forbid(unsafe_code)]

use hns_chat_protocol::{ChatAcknowledgementV1, ChatEnvelopeV1, parse_chat_binding};
use hns_covenants::{Covenant, NameState, Resource, hash_name};
use hns_dns_relay_protocol::{DnsRelay, GetDnsRelay};
use hns_header_consensus::Header;
use hns_hnsr_protocol::{HnsrPacket, NamedRouteRecordV2, NamedRouteRecordV3};
use hns_marketplace_protocol::{CrossChainMessage, NameMarketMessage};
use hns_mining::Block;
use hns_odoh_protocol::OdnsPacket;
use hns_p2p_experimental::DenuoExtensionEnvelope;
use hns_p2p_wire::{Frame, NetworkMagic};
use hns_rollback_journal::JournalRecord;
use hns_script::parse_script;
use hns_service_authority::{
    EndpointDelegationV1 as LegacyEndpointDelegationV1, ServiceAuthorizationV1,
    hrm::EndpointDelegationV1 as HrmEndpointDelegationV1,
};
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

/// Bitset reporting which production parsers accepted an input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcceptanceMask(u32);

impl AcceptanceMask {
    pub const HEADER: u32 = 1 << 0;
    pub const BLOCK: u32 = 1 << 1;
    pub const TRANSACTION: u32 = 1 << 2;
    pub const SCRIPT: u32 = 1 << 3;
    pub const COVENANT: u32 = 1 << 4;
    pub const STANDARD_FRAME: u32 = 1 << 5;
    pub const DENUO_ENVELOPE: u32 = 1 << 6;
    pub const HIP76_REQUEST: u32 = 1 << 7;
    pub const HIP76_RESPONSE: u32 = 1 << 8;
    pub const HIP77_ENVELOPE: u32 = 1 << 9;
    pub const HIP78_ENVELOPE: u32 = 1 << 10;
    pub const URKEL_PROOF: u32 = 1 << 11;
    pub const SWAP_PROOF: u32 = 1 << 12;
    pub const DENUO_NAME_MARKET: u32 = 1 << 13;
    pub const DENUO_CROSS_CHAIN_MARKET: u32 = 1 << 14;
    pub const NAME_STATE: u32 = 1 << 15;
    pub const NAME_RESOURCE: u32 = 1 << 16;
    pub const HIP79_SERVICE_AUTHORIZATION: u32 = 1 << 17;
    /// Legacy HSA1 endpoint delegation parser.
    pub const LEGACY_HIP79_ENDPOINT_DELEGATION: u32 = 1 << 18;
    /// Backward-compatible name for [`Self::LEGACY_HIP79_ENDPOINT_DELEGATION`].
    pub const HIP79_ENDPOINT_DELEGATION: u32 = Self::LEGACY_HIP79_ENDPOINT_DELEGATION;
    /// Legacy HSA1 HNSR NamedRouteV2 parser.
    pub const LEGACY_HNSA_HNSR_NAMED_ROUTE_V2: u32 = 1 << 19;
    /// Backward-compatible name for [`Self::LEGACY_HNSA_HNSR_NAMED_ROUTE_V2`].
    pub const HNSA_HNSR_NAMED_ROUTE: u32 = Self::LEGACY_HNSA_HNSR_NAMED_ROUTE_V2;
    pub const HNS_CHAT_ENVELOPE: u32 = 1 << 20;
    pub const HNS_CHAT_ACKNOWLEDGEMENT: u32 = 1 << 21;
    pub const HNS_CHAT_BINDING: u32 = 1 << 22;
    /// HRM HNSA EndpointDelegationV1 parser.
    pub const HRM_HNSA_ENDPOINT_DELEGATION_V1: u32 = 1 << 23;
    /// HRM HNSA-HNSR NamedRouteV3 parser.
    pub const HRM_HNSA_HNSR_NAMED_ROUTE_V3: u32 = 1 << 24;
    /// External anti-rollback journal v1 parser.
    pub const ROLLBACK_JOURNAL_V1: u32 = 1 << 25;

    /// Whether the named parser bit accepted the input.
    pub const fn contains(self, parser: u32) -> bool {
        self.0 & parser != 0
    }

    /// Raw stable bit representation for fuzzing feedback and diagnostics.
    pub const fn bits(self) -> u32 {
        self.0
    }

    fn record(&mut self, parser: u32, accepted: bool) {
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
        AcceptanceMask::NAME_STATE,
        hash_name(b"alpha")
            .and_then(|name_hash| NameState::decode(name_hash, input))
            .is_ok(),
    );
    accepted.record(
        AcceptanceMask::NAME_RESOURCE,
        Resource::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::STANDARD_FRAME,
        Frame::decode_exact(NetworkMagic::Regtest, input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::DENUO_ENVELOPE,
        DenuoExtensionEnvelope::decode_canonical(input).is_ok(),
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
        AcceptanceMask::HIP79_SERVICE_AUTHORIZATION,
        ServiceAuthorizationV1::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HIP79_ENDPOINT_DELEGATION,
        LegacyEndpointDelegationV1::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HNSA_HNSR_NAMED_ROUTE,
        NamedRouteRecordV2::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HRM_HNSA_ENDPOINT_DELEGATION_V1,
        HrmEndpointDelegationV1::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HRM_HNSA_HNSR_NAMED_ROUTE_V3,
        NamedRouteRecordV3::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::ROLLBACK_JOURNAL_V1,
        JournalRecord::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HNS_CHAT_ENVELOPE,
        ChatEnvelopeV1::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HNS_CHAT_ACKNOWLEDGEMENT,
        ChatAcknowledgementV1::decode(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::HNS_CHAT_BINDING,
        std::str::from_utf8(input)
            .map(parse_chat_binding)
            .is_ok_and(|binding| binding.is_ok()),
    );
    accepted.record(
        AcceptanceMask::URKEL_PROOF,
        HsdUrkelProof::decode_strict(input).is_ok(),
    );
    accepted.record(AcceptanceMask::SWAP_PROOF, SwapProof::decode(input).is_ok());
    accepted.record(
        AcceptanceMask::DENUO_NAME_MARKET,
        NameMarketMessage::decode_envelope(input).is_ok(),
    );
    accepted.record(
        AcceptanceMask::DENUO_CROSS_CHAIN_MARKET,
        CrossChainMessage::decode_envelope(input).is_ok(),
    );
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
    use hns_chat_protocol::HNS_CHAT_PROFILE_V1;
    use hns_hnsr_protocol::{HNS_CHAT_V1, HNS_NODE_V1, HNS_WEB_V1};
    use hns_p2p_experimental::{AssignmentKind, RegistryDocument};

    use super::*;

    const SWAP_V1_FIXTURES: &str = include_str!("../../../fixtures/protocol-v1/hns-swap-v1.txt");
    const MARKETPLACE_V1_FIXTURES: &str =
        include_str!("../../../fixtures/protocol-v1/hns-marketplace-v1.txt");
    const HSD_NAME_STATE_RESOURCE_FIXTURES: &str =
        include_str!("../../../fixtures/hsd/name-state-resource-v1.txt");
    const CHAT_RESOURCE_FIXTURES: &str =
        include_str!("../../../fixtures/chat-v1/hns-chat-resource-v1.txt");
    const HNSR_PROFILE_REGISTRY: &str =
        include_str!("../../../registry/hnsr-service-profiles-v1.toml");
    const HNSA_HNSR_V3_FIXTURES: &str =
        include_str!("../../../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt");
    const ROLLBACK_JOURNAL_V1_FIXTURES: &str =
        include_str!("../../../fixtures/rollback-journal-v1/rollback-journal-v1.txt");

    fn fixture_bytes(document: &str, name: &str) -> Vec<u8> {
        let value = document
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    fn fixture_value<'a>(document: &'a str, name: &str) -> &'a str {
        document
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"))
    }

    const TRANSACTION: &str = "0100000001080808080808080808080808080808080808080808080808080808080808080802000000feffffff012a0000000000000000140909090909090909090909090909090909090909020103616263630000000203010203020405";
    const REGTEST_PING: &str = "cf9538ae02080000004343434343434343";
    const DENUO: &str = "444e553101000100010006000000070000000000000002000000aabb";
    const DENUO_NAME_MARKET: &str = "444e553101000100010002000000070000000000000000000000";
    const DENUO_CROSS_CHAIN_MARKET: &str = concat!(
        "444e55310200020001000100000007000000000000002100000001",
        "0101010101010101010101010101010101010101010101010101010101010101"
    );
    const HIP76: &str = "08070605040302012a00123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000";
    const HIP77: &str = "0101000008070605040302010203";
    const HIP78: &str = "011100000102030405060708deadbeef";

    #[test]
    fn exact_vectors_reach_their_production_parsers() {
        let vectors = [
            (TRANSACTION, AcceptanceMask::TRANSACTION),
            (REGTEST_PING, AcceptanceMask::STANDARD_FRAME),
            (DENUO, AcceptanceMask::DENUO_ENVELOPE),
            (DENUO_NAME_MARKET, AcceptanceMask::DENUO_NAME_MARKET),
            (
                DENUO_CROSS_CHAIN_MARKET,
                AcceptanceMask::DENUO_CROSS_CHAIN_MARKET,
            ),
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

        for (name, parser) in [
            ("name_state_minimal", AcceptanceMask::NAME_STATE),
            ("resource_all_records", AcceptanceMask::NAME_RESOURCE),
        ] {
            let bytes = fixture_bytes(HSD_NAME_STATE_RESOURCE_FIXTURES, name);
            let accepted = exercise_production_parsers(&bytes).expect("bounded");
            assert!(accepted.contains(parser), "parser bit {parser:#x}");
        }

        let swap_proof = fixture_bytes(SWAP_V1_FIXTURES, "swap_proof");
        assert!(
            exercise_production_parsers(&swap_proof)
                .expect("bounded")
                .contains(AcceptanceMask::SWAP_PROOF)
        );
        for name in [
            "denuo_market_intent_envelope",
            "denuo_price_round_envelope",
            "denuo_swap_session_hello_envelope",
            "denuo_swap_funding_status_envelope",
            "denuo_swap_redeem_status_envelope",
            "denuo_swap_refund_status_envelope",
        ] {
            let envelope = fixture_bytes(MARKETPLACE_V1_FIXTURES, name);
            assert!(
                exercise_production_parsers(&envelope)
                    .expect("bounded")
                    .contains(AcceptanceMask::DENUO_CROSS_CHAIN_MARKET),
                "cross-chain fixture {name}"
            );
        }

        let chat_envelope = fixture_bytes(CHAT_RESOURCE_FIXTURES, "envelope_v1");
        assert!(
            exercise_production_parsers(&chat_envelope)
                .expect("bounded")
                .contains(AcceptanceMask::HNS_CHAT_ENVELOPE)
        );
        let acknowledgement = fixture_bytes(CHAT_RESOURCE_FIXTURES, "acknowledgement_v1");
        assert!(
            exercise_production_parsers(&acknowledgement)
                .expect("bounded")
                .contains(AcceptanceMask::HNS_CHAT_ACKNOWLEDGEMENT)
        );
        let binding = fixture_value(CHAT_RESOURCE_FIXTURES, "valid_explicit").as_bytes();
        assert!(
            exercise_production_parsers(binding)
                .expect("bounded")
                .contains(AcceptanceMask::HNS_CHAT_BINDING)
        );

        let endpoint = fixture_bytes(HNSA_HNSR_V3_FIXTURES, "endpoint_delegation");
        let endpoint_mask = exercise_production_parsers(&endpoint).expect("bounded");
        assert!(endpoint_mask.contains(AcceptanceMask::HRM_HNSA_ENDPOINT_DELEGATION_V1));
        assert!(!endpoint_mask.contains(AcceptanceMask::LEGACY_HIP79_ENDPOINT_DELEGATION));

        let route = fixture_bytes(HNSA_HNSR_V3_FIXTURES, "named_route_record_v3");
        let route_mask = exercise_production_parsers(&route).expect("bounded");
        assert!(route_mask.contains(AcceptanceMask::HRM_HNSA_HNSR_NAMED_ROUTE_V3));
        assert!(!route_mask.contains(AcceptanceMask::LEGACY_HNSA_HNSR_NAMED_ROUTE_V2));

        let journal = fixture_bytes(ROLLBACK_JOURNAL_V1_FIXTURES, "prepared_record");
        let journal_mask = exercise_production_parsers(&journal).expect("bounded");
        assert!(journal_mask.contains(AcceptanceMask::ROLLBACK_JOURNAL_V1));
    }

    #[test]
    fn deterministic_mutation_smoke_exercises_every_parser_without_panics() {
        let seeds = [
            hex::decode(TRANSACTION).expect("static hex"),
            hex::decode(REGTEST_PING).expect("static hex"),
            hex::decode(DENUO).expect("static hex"),
            hex::decode(DENUO_NAME_MARKET).expect("static hex"),
            hex::decode(DENUO_CROSS_CHAIN_MARKET).expect("static hex"),
            hex::decode(HIP76).expect("static hex"),
            hex::decode(HIP77).expect("static hex"),
            hex::decode(HIP78).expect("static hex"),
            fixture_bytes(HSD_NAME_STATE_RESOURCE_FIXTURES, "name_state_minimal"),
            fixture_bytes(HSD_NAME_STATE_RESOURCE_FIXTURES, "resource_all_records"),
            fixture_bytes(CHAT_RESOURCE_FIXTURES, "envelope_v1"),
            fixture_bytes(CHAT_RESOURCE_FIXTURES, "acknowledgement_v1"),
            fixture_value(CHAT_RESOURCE_FIXTURES, "valid_explicit")
                .as_bytes()
                .to_vec(),
            fixture_bytes(HNSA_HNSR_V3_FIXTURES, "endpoint_delegation"),
            fixture_bytes(HNSA_HNSR_V3_FIXTURES, "named_route_record_v3"),
            fixture_bytes(ROLLBACK_JOURNAL_V1_FIXTURES, "prepared_record"),
        ];
        let mut mutations = 0_usize;
        for seed in seeds {
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

    #[test]
    fn exported_hnsr_profile_constants_match_the_generated_registry() {
        let registry =
            RegistryDocument::from_toml(HNSR_PROFILE_REGISTRY).expect("profile registry");
        for (semantic_name, expected) in [
            ("hnsr-profile-hns-node-v1", HNS_NODE_V1),
            ("hnsr-profile-hns-web-v1", HNS_WEB_V1),
            ("hnsr-profile-hns-chat-v1", HNS_CHAT_PROFILE_V1),
        ] {
            let assignment = registry
                .assignments
                .iter()
                .find(|assignment| assignment.semantic_name == semantic_name)
                .unwrap_or_else(|| panic!("missing profile {semantic_name}"));
            assert_eq!(assignment.kind, AssignmentKind::ServiceProfile);
            assert_eq!(assignment.value, u64::from(expected));
        }
        assert_eq!(HNS_CHAT_V1, HNS_CHAT_PROFILE_V1);
    }
}
