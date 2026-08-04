use hns_chat_protocol::{
    ChatAcknowledgementV1, ChatEnvelopeV1, ChatIdentityBindingV1, ChatKeyMode, ChatProtocolError,
    HNS_CHAT_WIRE_VERSION, MAX_CHAT_ACKNOWLEDGEMENT_SIZE, MAX_CHAT_ACKNOWLEDGEMENT_WIRE_SIZE,
    MAX_CHAT_CIPHERTEXT_SIZE, MAX_CHAT_ENVELOPE_SIZE, MAX_CHAT_EXPIRATION_WINDOW,
    encode_chat_binding, owner_authority_record, parse_chat_binding, select_chat_binding,
    select_chat_binding_from_resource, verify_current_owner_binding,
    xonly_from_compressed_public_key,
};
use hns_covenants::{Covenant, CovenantKind, Resource};
use hns_primitives::Dollarydoos;
use hns_transaction::{Address, Output};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../fixtures/chat-v1/hns-chat-resource-v1.txt");
const VECTORS_SHA256: &str = include_str!("../fixtures/chat-v1/hns-chat-resource-v1.txt.sha256");

fn vector(name: &str) -> &str {
    VECTORS
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap_or_else(|| panic!("missing release vector {name}"))
}

fn vector_bytes(name: &str) -> Vec<u8> {
    hex::decode(vector(name)).unwrap_or_else(|error| panic!("invalid hex vector {name}: {error}"))
}

fn owner_output(version: u8, program: Vec<u8>) -> Output {
    Output {
        value: Dollarydoos::new(1),
        address: Address::new(version, program).expect("valid fixture owner program"),
        covenant: Covenant {
            kind: CovenantKind::Update,
            items: Vec::new(),
        },
    }
}

#[test]
fn release_source_resource_vectors_cover_canonical_and_rejected_forms() {
    let explicit = parse_chat_binding(vector("valid_explicit")).expect("explicit binding");
    assert_eq!(explicit.generation, 7);
    assert_eq!(
        encode_chat_binding(&explicit).expect("canonical binding"),
        vector("valid_explicit")
    );
    assert_eq!(
        parse_chat_binding(vector("valid_omitted"))
            .expect("compatibility binding")
            .generation,
        1
    );
    assert_eq!(
        parse_chat_binding(vector("valid_max_generation"))
            .expect("maximum generation")
            .generation,
        u32::MAX
    );

    for name in [
        "invalid_version",
        "invalid_key_mode",
        "invalid_missing_key",
        "invalid_uppercase",
        "invalid_duplicate",
        "invalid_unknown",
        "invalid_zero_generation",
        "invalid_empty_generation",
        "invalid_leading_zero_generation",
        "invalid_overflow_generation",
        "invalid_x_coordinate",
    ] {
        assert!(
            parse_chat_binding(vector(name)).is_err(),
            "accepted invalid release vector {name}"
        );
    }
    assert!(parse_chat_binding("hnschat=v1;key=owner;pk=\u{e9}").is_err());
    assert_eq!(
        select_chat_binding(["unrelated"]),
        Err(ChatProtocolError::MissingBinding)
    );
    assert_eq!(
        select_chat_binding([vector("valid_explicit"), vector("valid_omitted")]),
        Err(ChatProtocolError::AmbiguousBinding)
    );

    let binding = vector("valid_explicit").as_bytes();
    let split = binding.len() / 2;
    let mut raw = vec![0, 6, 2, split as u8];
    raw.extend_from_slice(&binding[..split]);
    raw.push((binding.len() - split) as u8);
    raw.extend_from_slice(&binding[split..]);
    let resource = Resource::decode(&raw).expect("chunked TXT resource");
    assert_eq!(
        select_chat_binding_from_resource(&resource).expect("resource binding"),
        explicit
    );

    let mut non_ascii_record = b"hnschat=".to_vec();
    non_ascii_record.push(0xff);
    let mut non_ascii_resource = vec![0, 6, 1, non_ascii_record.len() as u8];
    non_ascii_resource.extend_from_slice(&non_ascii_record);
    let non_ascii = Resource::decode(&non_ascii_resource).expect("opaque TXT bytes");
    assert!(select_chat_binding_from_resource(&non_ascii).is_err());
}

#[test]
fn release_source_owner_vectors_preserve_parity_and_reject_false_authority() {
    let binding = parse_chat_binding(vector("valid_explicit")).expect("binding");
    for (key_name, program_name) in [
        ("owner_even_compressed", "owner_even_program"),
        ("owner_odd_compressed", "owner_odd_program"),
    ] {
        let compressed: [u8; 33] = vector_bytes(key_name)
            .try_into()
            .expect("compressed owner key");
        assert_eq!(
            xonly_from_compressed_public_key(&compressed).expect("x-only owner key"),
            binding.xonly_public_key
        );
        let derived = Address::from_compressed_public_key(&compressed).expect("owner address");
        assert_eq!(hex::encode(&derived.hash), vector(program_name));

        let verified =
            verify_current_owner_binding(&binding, &owner_output(0, vector_bytes(program_name)))
                .expect("current owner binding");
        assert_eq!(verified.original_compressed_public_key(), compressed);
        let authority = owner_authority_record(&verified).expect("owner authority");
        assert_eq!(authority.root_key, compressed);
        assert_eq!(authority.epoch, binding.generation);
    }

    assert_eq!(
        verify_current_owner_binding(
            &binding,
            &owner_output(0, vector_bytes("owner_stale_program")),
        ),
        Err(ChatProtocolError::StaleOwner)
    );
    let stale_key: [u8; 33] = vector_bytes("owner_stale_compressed")
        .try_into()
        .expect("stale compressed owner key");
    let stale_address =
        Address::from_compressed_public_key(&stale_key).expect("stale owner address");
    assert_eq!(
        hex::encode(stale_address.hash),
        vector("owner_stale_program")
    );
    assert_eq!(
        verify_current_owner_binding(&binding, &owner_output(0, vec![0x55; 32])),
        Err(ChatProtocolError::UnsupportedOwnerScript)
    );
    assert_eq!(
        verify_current_owner_binding(&binding, &owner_output(1, vec![0x55; 20])),
        Err(ChatProtocolError::UnsupportedOwnerScript)
    );

    let invalid_generation = ChatIdentityBindingV1 {
        key_mode: ChatKeyMode::Owner,
        generation: 0,
        ..binding
    };
    assert!(invalid_generation.validate().is_err());
    assert!(
        verify_current_owner_binding(
            &invalid_generation,
            &owner_output(0, vector_bytes("owner_even_program")),
        )
        .is_err()
    );
    assert!(xonly_from_compressed_public_key(&[0; 33]).is_err());
}

#[test]
fn release_source_wire_vectors_are_exact_bounded_and_fail_closed() {
    assert_eq!(HNS_CHAT_WIRE_VERSION, 1);
    assert_eq!(MAX_CHAT_ENVELOPE_SIZE, 8_276);
    assert_eq!(MAX_CHAT_ACKNOWLEDGEMENT_WIRE_SIZE, 2_092);

    let envelope_bytes = vector_bytes("envelope_v1");
    let envelope = ChatEnvelopeV1::decode(&envelope_bytes).expect("canonical envelope");
    assert_eq!(envelope.message_id, [1; 32]);
    assert_eq!(envelope.created_at, 1_700_000_000);
    assert_eq!(envelope.expires_at, 1_700_000_600);
    assert_eq!(envelope.gift_wrap.as_slice(), b"opaque gift wrap");
    assert_eq!(envelope.encode().expect("encode envelope"), envelope_bytes);

    for name in [
        "invalid_envelope_version",
        "invalid_envelope_noncanonical_length",
        "invalid_envelope_trailing",
        "invalid_envelope_zero_message",
        "invalid_envelope_zero_recipient",
        "invalid_envelope_empty_gift_wrap",
        "invalid_envelope_oversize_declared",
    ] {
        assert!(
            ChatEnvelopeV1::decode(&vector_bytes(name)).is_err(),
            "accepted invalid release vector {name}"
        );
    }

    let acknowledgement_bytes = vector_bytes("acknowledgement_v1");
    let acknowledgement =
        ChatAcknowledgementV1::decode(&acknowledgement_bytes).expect("canonical acknowledgement");
    assert_eq!(acknowledgement.message_id, envelope.message_id);
    assert_eq!(acknowledgement.received_at, 1_700_000_100);
    assert_eq!(
        acknowledgement.encrypted_receipt.as_slice(),
        b"opaque receipt"
    );
    assert_eq!(
        acknowledgement.encode().expect("encode acknowledgement"),
        acknowledgement_bytes
    );

    for name in [
        "invalid_acknowledgement_version",
        "invalid_acknowledgement_noncanonical_length",
        "invalid_acknowledgement_trailing",
        "invalid_acknowledgement_zero_message",
        "invalid_acknowledgement_zero_time",
        "invalid_acknowledgement_empty_receipt",
        "invalid_acknowledgement_oversize_declared",
    ] {
        assert!(
            ChatAcknowledgementV1::decode(&vector_bytes(name)).is_err(),
            "accepted invalid release vector {name}"
        );
    }

    let mut invalid_time = envelope.clone();
    invalid_time.expires_at = invalid_time.created_at;
    assert!(invalid_time.validate().is_err());
    invalid_time.expires_at = invalid_time.created_at + MAX_CHAT_EXPIRATION_WINDOW + 1;
    assert!(invalid_time.validate().is_err());

    let maximum_envelope = ChatEnvelopeV1 {
        gift_wrap: vec![1; MAX_CHAT_CIPHERTEXT_SIZE],
        ..envelope
    };
    assert_eq!(
        maximum_envelope.encode().expect("maximum envelope").len(),
        MAX_CHAT_ENVELOPE_SIZE
    );
    let maximum_acknowledgement = ChatAcknowledgementV1 {
        encrypted_receipt: vec![1; MAX_CHAT_ACKNOWLEDGEMENT_SIZE],
        ..acknowledgement
    };
    assert_eq!(
        maximum_acknowledgement
            .encode()
            .expect("maximum acknowledgement")
            .len(),
        MAX_CHAT_ACKNOWLEDGEMENT_WIRE_SIZE
    );
}

#[test]
fn release_source_vector_sidecar_authenticates_packaged_bytes() {
    let expected = VECTORS_SHA256
        .split_whitespace()
        .next()
        .expect("fixture digest");
    assert_eq!(hex::encode(Sha256::digest(VECTORS.as_bytes())), expected);
}
