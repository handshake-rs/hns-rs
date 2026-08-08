use std::collections::HashSet;

use hns_chat_protocol::{
    ChatIdentityBindingV1, HNS_CHAT_PROFILE_V1, HNS_CHAT_SERVICE_NAME, owner_authority_record,
    verify_current_owner_binding,
};
use hns_encoding::{Decoder, Encoder};
use hns_service_authority::{
    AuthorityRecord, EndpointDelegationV1, MAX_ENDPOINT_LIFETIME, MIN_ENDPOINT_LIFETIME,
    ServiceAuthorizationV1, ServiceIdentity,
};
use hns_transaction::Output;
use k256::ecdsa::Signature;

use crate::record::{RelayTicket, blake2b_256, decode_signature, encode_signature, sign, verify};
use crate::{
    HNS_NODE_V1, HnsrProtocolError, MAX_RECORD_SIZE, MAX_ROUTE_LIFETIME, MAX_SIGNATURE_SIZE,
};

const NAMED_ROUTE_KEY_DOMAIN: &[u8] = b"HNSR-NAMED-ROUTE-V1\0";
const NAMED_ROUTE_RECORD_DOMAIN: &[u8] = b"HNSR-HNSA-ROUTE-RECORD-V2\0";
const NAMED_ROUTE_VERSION: u8 = 2;
const HNSA_AUTHORITY_TYPE: u8 = 1;
const MAX_TICKETS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedRoutePolicy {
    pub maximum_route_lifetime: u64,
    pub allowed_authorization_flags: u16,
    pub allowed_endpoint_capabilities: u32,
    pub required_endpoint_capabilities: u32,
    pub expected_constraints_hash: [u8; 32],
    pub allow_private_relays: bool,
}

impl NamedRoutePolicy {
    fn validate(self) -> Result<(), HnsrProtocolError> {
        if self.maximum_route_lifetime == 0
            || self.maximum_route_lifetime > MAX_ROUTE_LIFETIME
            || self.required_endpoint_capabilities & !self.allowed_endpoint_capabilities != 0
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSA HNSR profile policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NamedRouteTrust<'a> {
    pub authority: &'a AuthorityRecord,
    pub identity: &'a ServiceIdentity,
    pub current_height: u32,
    pub policy: NamedRoutePolicy,
}

#[derive(Clone, Copy, Debug)]
pub struct OwnerBoundChatRouteTrust<'a> {
    pub binding: &'a ChatIdentityBindingV1,
    pub owner_output: &'a Output,
    pub identity: &'a ServiceIdentity,
    pub current_height: u32,
    pub policy: NamedRoutePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedRouteRecordV2 {
    pub route_key: [u8; 32],
    pub profile: u16,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub authorization: ServiceAuthorizationV1,
    pub delegation: EndpointDelegationV1,
    pub tickets: Vec<RelayTicket>,
    pub endpoint_signature: Vec<u8>,
}

pub fn named_route_key(identity: &ServiceIdentity) -> Result<[u8; 32], HnsrProtocolError> {
    identity
        .validate()
        .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA service identity"))?;
    if identity.profile_id == 0 || identity.profile_id == HNS_NODE_V1 {
        return Err(HnsrProtocolError::Invalid(
            "invalid named HNSR profile identifier",
        ));
    }
    let service_name = identity.service_name.as_bytes();
    Ok(blake2b_256(&[
        NAMED_ROUTE_KEY_DOMAIN,
        &identity.network_magic.to_le_bytes(),
        &identity.name_hash,
        &[service_name.len() as u8],
        service_name,
        &identity.profile_id.to_le_bytes(),
    ]))
}

pub fn verify_owner_bound_chat_route(
    record: &NamedRouteRecordV2,
    trust: &OwnerBoundChatRouteTrust<'_>,
    now: u64,
) -> Result<(), HnsrProtocolError> {
    if trust.identity.service_name != HNS_CHAT_SERVICE_NAME
        || trust.identity.profile_id != HNS_CHAT_PROFILE_V1
        || record.authorization.service_name != HNS_CHAT_SERVICE_NAME
        || record.profile != HNS_CHAT_PROFILE_V1
    {
        return Err(HnsrProtocolError::Invalid(
            "owner-bound trust is restricted to the hns.chat profile",
        ));
    }
    let verified = verify_current_owner_binding(trust.binding, trust.owner_output)?;
    let authority = owner_authority_record(&verified)?;
    record.verify(
        &NamedRouteTrust {
            authority: &authority,
            identity: trust.identity,
            current_height: trust.current_height,
            policy: trust.policy,
        },
        now,
    )
}

impl NamedRouteRecordV2 {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.profile == 0
            || self.profile == HNS_NODE_V1
            || self.authorization.profile_id != self.profile
            || self.authorization.serial == 0
            || self.authorization.valid_until_height <= self.authorization.valid_from_height
            || !(MIN_ENDPOINT_LIFETIME..=MAX_ENDPOINT_LIFETIME)
                .contains(&self.authorization.max_endpoint_lifetime)
            || self.tickets.is_empty()
            || self.tickets.len() > MAX_TICKETS
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid named HNSR route fields",
            ));
        }
        validate_der_low_s(&self.authorization.root_signature)?;
        validate_der_low_s(&self.delegation.service_signature)?;
        let authorization = self
            .authorization
            .encode()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA service authorization"))?;
        let delegation = self
            .delegation
            .encode()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;
        if authorization.len() > u16::MAX as usize || delegation.len() > u16::MAX as usize {
            return Err(HnsrProtocolError::Invalid(
                "oversized HNSA object in named route",
            ));
        }

        let mut encoded_tickets = Vec::with_capacity(self.tickets.len());
        let mut size = 65_usize
            .saturating_add(authorization.len())
            .saturating_add(delegation.len());
        for ticket in &self.tickets {
            let encoded = ticket.encode()?;
            size = size.saturating_add(encoded.len());
            encoded_tickets.push(encoded);
        }
        if size > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: size,
                maximum: MAX_RECORD_SIZE,
            });
        }

        let mut encoder = Encoder::with_capacity(size);
        encoder.put_u8(NAMED_ROUTE_VERSION);
        encoder.put_u8(HNSA_AUTHORITY_TYPE);
        encoder.put_bytes(&self.route_key);
        encoder.put_u16_le(self.profile);
        encoder.put_u64_le(self.sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u16_le(authorization.len() as u16);
        encoder.put_bytes(&authorization);
        encoder.put_u16_le(delegation.len() as u16);
        encoder.put_bytes(&delegation);
        encoder.put_u8(encoded_tickets.len() as u8);
        for ticket in encoded_tickets {
            encoder.put_bytes(&ticket);
        }
        Ok(encoder.into_bytes())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        self.endpoint_signature = sign(NAMED_ROUTE_RECORD_DOMAIN, &[&unsigned], private_key)?;
        Ok(())
    }

    pub fn verify_untrusted_admission(
        &self,
        now: u64,
        allow_private_relays: bool,
    ) -> Result<(), HnsrProtocolError> {
        self.verify_common(now, MAX_ROUTE_LIFETIME, allow_private_relays)
    }

    pub fn verify(&self, trust: &NamedRouteTrust<'_>, now: u64) -> Result<(), HnsrProtocolError> {
        trust.policy.validate()?;
        if trust.identity.network_magic != self.authorization.network_magic
            || trust.identity.profile_id != self.profile
        {
            return Err(HnsrProtocolError::Invalid(
                "named HNSR route trust context mismatch",
            ));
        }
        self.authorization
            .verify(
                trust.authority,
                trust.identity,
                trust.current_height,
                trust.policy.allowed_authorization_flags,
            )
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA service authorization"))?;
        if self.delegation.capabilities & !trust.policy.allowed_endpoint_capabilities != 0
            || self.delegation.constraints_hash != trust.policy.expected_constraints_hash
            || self.delegation.capabilities & trust.policy.required_endpoint_capabilities
                != trust.policy.required_endpoint_capabilities
        {
            return Err(HnsrProtocolError::Invalid(
                "named HNSR endpoint lacks required capability",
            ));
        }
        self.verify_common(
            now,
            trust.policy.maximum_route_lifetime,
            trust.policy.allow_private_relays,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder =
            Encoder::with_capacity(unsigned.len() + 1 + self.endpoint_signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.endpoint_signature, false)?;
        let output = encoder.into_bytes();
        if output.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: output.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        if input.is_empty() || input.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != NAMED_ROUTE_VERSION {
            return Err(HnsrProtocolError::Invalid(
                "unsupported named HNSR route version",
            ));
        }
        if decoder.read_u8()? != HNSA_AUTHORITY_TYPE {
            return Err(HnsrProtocolError::Invalid(
                "unsupported named HNSR route authority",
            ));
        }
        let route_key = decoder.read_array()?;
        let profile = decoder.read_u16_le()?;
        let sequence = decoder.read_u64_le()?;
        let issued_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let authorization_length = decoder.read_u16_le()? as usize;
        if authorization_length == 0 || authorization_length > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSA authorization length",
            ));
        }
        let authorization =
            ServiceAuthorizationV1::decode(decoder.read_slice(authorization_length)?)
                .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA service authorization"))?;
        let delegation_length = decoder.read_u16_le()? as usize;
        if delegation_length == 0 || delegation_length > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::Invalid("invalid HNSA delegation length"));
        }
        let delegation = EndpointDelegationV1::decode(decoder.read_slice(delegation_length)?)
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;
        let ticket_count = decoder.read_u8()? as usize;
        if !(1..=MAX_TICKETS).contains(&ticket_count) {
            return Err(HnsrProtocolError::Invalid(
                "invalid named HNSR route ticket count",
            ));
        }
        let mut tickets = Vec::with_capacity(ticket_count);
        for _ in 0..ticket_count {
            tickets.push(RelayTicket::read_from(&mut decoder)?);
        }
        let endpoint_signature = decode_signature(&mut decoder, false)?;
        decoder.finish()?;
        let record = Self {
            route_key,
            profile,
            sequence,
            issued_at,
            expires_at,
            authorization,
            delegation,
            tickets,
            endpoint_signature,
        };
        record.encode_unsigned()?;
        Ok(record)
    }

    fn verify_common(
        &self,
        now: u64,
        maximum_route_lifetime: u64,
        allow_private_relays: bool,
    ) -> Result<(), HnsrProtocolError> {
        let identity = self.authorization.identity();
        if self.profile == 0
            || self.profile == HNS_NODE_V1
            || self.authorization.profile_id != self.profile
            || self.route_key != named_route_key(&identity)?
            || self.sequence == 0
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > maximum_route_lifetime
            || now < self.issued_at
            || now >= self.expires_at
            || self.issued_at < self.delegation.issued_at
            || self.expires_at > self.delegation.expires_at
            || self.tickets.is_empty()
            || self.tickets.len() > MAX_TICKETS
        {
            return Err(HnsrProtocolError::Invalid("invalid named HNSR route"));
        }
        validate_der_low_s(&self.authorization.root_signature)?;
        self.delegation
            .verify(
                &self.authorization,
                now,
                u32::MAX,
                self.delegation.constraints_hash,
            )
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;

        let mut ticket_ids = HashSet::with_capacity(self.tickets.len());
        for ticket in &self.tickets {
            if ticket.endpoint_key != self.delegation.endpoint_key
                || ticket.profile != self.profile
                || self.issued_at < ticket.issued_at
                || ticket.expires_at < self.expires_at
            {
                return Err(HnsrProtocolError::Invalid(
                    "named HNSR route ticket binding mismatch",
                ));
            }
            ticket.verify_for_profile(
                self.authorization.network_magic,
                self.profile,
                now,
                allow_private_relays,
            )?;
            if !ticket_ids.insert(ticket.id()?) {
                return Err(HnsrProtocolError::Invalid(
                    "duplicate named HNSR route ticket",
                ));
            }
        }
        let unsigned = self.encode_unsigned()?;
        verify(
            NAMED_ROUTE_RECORD_DOMAIN,
            &[&unsigned],
            &self.endpoint_signature,
            &self.delegation.endpoint_key,
        )
    }
}

fn validate_der_low_s(signature: &[u8]) -> Result<(), HnsrProtocolError> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_SIZE {
        return Err(HnsrProtocolError::Invalid(
            "invalid named HNSR signature length",
        ));
    }
    let signature = Signature::from_der(signature).map_err(|_| HnsrProtocolError::Cryptography)?;
    if signature.normalize_s().is_some() {
        return Err(HnsrProtocolError::Cryptography);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hns_chat_protocol::{
        ChatIdentityBindingV1, ChatKeyMode, ChatProtocolError, HNS_CHAT_PROFILE_V1,
        HNS_CHAT_SERVICE_NAME, xonly_from_compressed_public_key,
    };
    use hns_covenants::{Covenant, CovenantKind};
    use hns_primitives::Dollarydoos;
    use hns_service_authority::{
        AuthorityRecord, EndpointDelegationV1, ServiceAuthorizationV1, ServiceIdentity,
        public_key as authority_public_key,
    };

    use super::*;
    use crate::record::public_key;
    use crate::{RouteStore, RouteStoreLimits};

    const MAGIC: u32 = 2_922_943_951;
    const PROFILE: u16 = 0xff00;

    fn route(now: u64) -> (NamedRouteRecordV2, AuthorityRecord, ServiceIdentity) {
        let root_private = [11; 32];
        let service_private = [12; 32];
        let endpoint_private = [13; 32];
        let relay_private = [14; 32];
        let identity = ServiceIdentity {
            network_magic: MAGIC,
            name_hash: [15; 32],
            service_name: "pool-stats".to_owned(),
            profile_id: PROFILE,
        };
        let authority = AuthorityRecord {
            root_key: authority_public_key(&root_private).expect("root key"),
            epoch: 3,
        };
        let mut authorization = ServiceAuthorizationV1 {
            network_magic: MAGIC,
            name_hash: identity.name_hash,
            authority_epoch: authority.epoch,
            service_name: identity.service_name.clone(),
            profile_id: PROFILE,
            service_key: authority_public_key(&service_private).expect("service key"),
            flags: 0,
            serial: 1,
            valid_from_height: 100,
            valid_until_height: 200,
            max_endpoint_lifetime: 3_600,
            root_signature: Vec::new(),
        };
        authorization.sign(&root_private).expect("authorization");
        let endpoint_key = authority_public_key(&endpoint_private).expect("endpoint key");
        let mut delegation = EndpointDelegationV1 {
            network_magic: MAGIC,
            authorization_id: authorization.id().expect("authorization ID"),
            endpoint_key,
            endpoint_sequence: 1,
            issued_at: now,
            expires_at: now + 1_800,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(&service_private).expect("delegation");
        let mut ticket = RelayTicket {
            network_magic: MAGIC,
            profile: PROFILE,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            relay_key: public_key(&relay_private).expect("relay key"),
            endpoint_key,
            reservation_id: [16; 16],
            issued_at: now,
            expires_at: now + 1_800,
            max_active_circuits: 8,
            max_bytes_per_circuit: 1_048_576,
            max_total_bytes: 8_388_608,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket.sign_relay(&relay_private).expect("relay ticket");
        ticket
            .sign_endpoint(&endpoint_private)
            .expect("ticket confirmation");
        let mut route = NamedRouteRecordV2 {
            route_key: named_route_key(&identity).expect("route key"),
            profile: PROFILE,
            sequence: 1,
            issued_at: now,
            expires_at: now + 900,
            authorization,
            delegation,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        route.sign(&endpoint_private).expect("route signature");
        (route, authority, identity)
    }

    fn trust<'a>(
        authority: &'a AuthorityRecord,
        identity: &'a ServiceIdentity,
    ) -> NamedRouteTrust<'a> {
        NamedRouteTrust {
            authority,
            identity,
            current_height: 150,
            policy: NamedRoutePolicy {
                maximum_route_lifetime: 900,
                allowed_authorization_flags: 0,
                allowed_endpoint_capabilities: 1,
                required_endpoint_capabilities: 1,
                expected_constraints_hash: [0; 32],
                allow_private_relays: true,
            },
        }
    }

    #[test]
    fn hsa1_route_round_trips_and_verifies_complete_chain() {
        let now = 1_700_000_000;
        let (route, authority, identity) = route(now);
        let encoded = route.encode().expect("encode");
        assert_eq!(
            hex::encode(route.route_key),
            "7e1a513c71518f69164fdcc754202a769e8cbd2dd980da3fd231b9b0de90e60b"
        );
        let actual = hex::encode(&encoded);
        let expected = concat!(
            "02017e1a513c71518f69164fdcc754202a769e8cbd2dd980da3fd231b9b0de90e60b",
            "00ff010000000000000000f153650000000084f4536500000000b500",
            "01cf9538ae0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "030000000a706f6f6c2d737461747300ff030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b",
            "9a39ed93346d03d67d412d1770000010000000000000064000000c8000000100e000047",
            "30450221008d3bb1b7ffbd42f4fffcf2620d58dd874a2c26920720616123976ec00dcb4434",
            "022005768bb7694f743094838090c55334cde42a56391fd555b30556a37dd8271fd7ca00",
            "01cf9538aef19dbd98cbc5191b6441d3640c35782f9ab30f598a16b19fe572316d12940c58",
            "022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d010000",
            "000000000000f153650000000008f853650000000001000000000000000000000000000000",
            "0000000000000000000000000000000000000000473045022100f59178b8a2dddf1b17e51b",
            "3bd1c3ced85cc6f43d12610f522d0095af2a44eb450220763015e7a127b4fdd8f6ed7c66eb",
            "b52aa111b97273182d712dd04e9b595f13850101cf9538ae00ff000100000000000000000000",
            "000000000000d7360299c2aa85d2b21a62f396907a802a58e521dafd5bddaccbd72786eea18",
            "9bc4dc9022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d1",
            "010101010101010101010101010101000f153650000000008f85365000000000800000010",
            "000000000000008000000000000000473045022100f5bad583cf4d3901e10aa0e9cc13bbb7",
            "ab4014f1b6bdc722db7d7c0e072f579702203b02b61b1fbe0b64ae38e1a785e17462970e3f",
            "b9f6f2c680621db9612d36c45d473045022100df052129dd75631617c3b9c64bff2046b7d0",
            "b266922d4e0d48f4ec60ed93f18102202f59a11d71bfe6e1070db7f591a6d7c7c4ca6464",
            "b22b1e9a510817a25be7a2b74730450221008e5f905f5278ddf2880ddc8307347f03ec1497",
            "ba6056ebefa1132dc65da5c11102202de430cdfa136e0ea726e6c4be05f9bf445639afae622",
            "6f3a2bbd385d7b61f33"
        );
        assert_eq!(actual, expected);
        let decoded = NamedRouteRecordV2::decode(&encoded).expect("decode");
        decoded
            .verify_untrusted_admission(now, true)
            .expect("bounded admission");
        decoded
            .verify(&trust(&authority, &identity), now)
            .expect("complete validation");
        assert_eq!(decoded, route);
    }

    #[test]
    fn named_route_binds_identity_capability_and_every_ticket() {
        let now = 1_700_000_000;
        let (route, authority, identity) = route(now);
        let mut wrong_identity = identity.clone();
        wrong_identity.service_name = "other".to_owned();
        assert!(
            route
                .verify(&trust(&authority, &wrong_identity), now)
                .is_err()
        );

        let mut wrong_capability = trust(&authority, &identity);
        wrong_capability.policy.required_endpoint_capabilities = 2;
        wrong_capability.policy.allowed_endpoint_capabilities = 3;
        assert!(route.verify(&wrong_capability, now).is_err());

        let mut duplicate = route.clone();
        duplicate.tickets.push(duplicate.tickets[0].clone());
        assert!(
            duplicate
                .verify(&trust(&authority, &identity), now)
                .is_err()
        );
    }

    #[test]
    fn owner_bound_chat_admission_uses_current_owner_parity_and_generation() {
        let now = 1_700_000_000;
        let root_private = [11; 32];
        let service_private = [12; 32];
        let endpoint_private = [13; 32];
        let relay_private = [14; 32];
        let (mut route, authority, mut identity) = route(now);
        identity.service_name = HNS_CHAT_SERVICE_NAME.to_owned();
        identity.profile_id = HNS_CHAT_PROFILE_V1;
        route.authorization.service_name = identity.service_name.clone();
        route.authorization.profile_id = identity.profile_id;
        route.authorization.root_signature.clear();
        route
            .authorization
            .sign(&root_private)
            .expect("chat authorization");
        route.delegation.authorization_id = route.authorization.id().expect("authorization ID");
        route.delegation.service_signature.clear();
        route
            .delegation
            .sign(&service_private)
            .expect("chat delegation");
        route.tickets[0].profile = HNS_CHAT_PROFILE_V1;
        route.tickets[0].relay_signature.clear();
        route.tickets[0].endpoint_signature.clear();
        route.tickets[0]
            .sign_relay(&relay_private)
            .expect("chat relay ticket");
        route.tickets[0]
            .sign_endpoint(&endpoint_private)
            .expect("chat ticket confirmation");
        route.profile = HNS_CHAT_PROFILE_V1;
        route.route_key = named_route_key(&identity).expect("chat route key");
        route.endpoint_signature.clear();
        route.sign(&endpoint_private).expect("chat route");

        let owner_key = authority.root_key;
        let owner_output = Output {
            value: Dollarydoos::new(1),
            address: hns_transaction::Address::from_compressed_public_key(&owner_key)
                .expect("owner address"),
            covenant: Covenant {
                kind: CovenantKind::Update,
                items: Vec::new(),
            },
        };
        let binding = ChatIdentityBindingV1 {
            key_mode: ChatKeyMode::Owner,
            xonly_public_key: xonly_from_compressed_public_key(&owner_key).expect("x-only"),
            generation: authority.epoch,
        };
        let chat_trust = OwnerBoundChatRouteTrust {
            binding: &binding,
            owner_output: &owner_output,
            identity: &identity,
            current_height: 150,
            policy: trust(&authority, &identity).policy,
        };
        verify_owner_bound_chat_route(&route, &chat_trust, now).expect("owner-bound chat route");

        let other_key = authority_public_key(&[21; 32]).expect("other owner key");
        let mut stale_output = owner_output.clone();
        stale_output.address = hns_transaction::Address::from_compressed_public_key(&other_key)
            .expect("other owner address");
        let stale_trust = OwnerBoundChatRouteTrust {
            owner_output: &stale_output,
            ..chat_trust
        };
        assert!(matches!(
            verify_owner_bound_chat_route(&route, &stale_trust, now),
            Err(HnsrProtocolError::OwnerBinding(
                ChatProtocolError::StaleOwner
            ))
        ));
    }

    #[test]
    fn route_key_is_stable_across_endpoint_rotation() {
        let now = 1_700_000_000;
        let (first, _, identity) = route(now);
        let (mut second, _, _) = route(now);
        second.delegation.endpoint_key = authority_public_key(&[17; 32]).expect("new key");
        assert_eq!(
            first.route_key,
            named_route_key(&identity).expect("route key")
        );
        assert_eq!(first.route_key, second.route_key);
    }

    #[test]
    fn named_storage_supports_full_or_bounded_admission_and_never_sampling() {
        let now = 1_700_000_000;
        let (route, authority, identity) = route(now);
        let raw = route.encode().expect("route");
        let mut fully_verified =
            RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        fully_verified
            .put_named(
                route.route_key,
                raw.clone(),
                &trust(&authority, &identity),
                now,
                "peer-a".to_owned(),
            )
            .expect("stored");
        assert_eq!(fully_verified.get(&route.route_key, 8, now).len(), 1);
        assert!(fully_verified.sample(8, &[1; 32], now).is_empty());

        let mut bounded = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        bounded
            .put_named_for_admission(route.route_key, raw, now, "peer-b".to_owned())
            .expect("stored");
        assert_eq!(bounded.get(&route.route_key, 8, now).len(), 1);
        assert!(bounded.sample(8, &[2; 32], now).is_empty());
    }

    #[test]
    fn named_admission_checks_storage_capacity_before_signatures() {
        let now = 1_700_000_000;
        let endpoint_private = [17; 32];
        let service_private = [12; 32];
        let relay_private = [14; 32];
        let (first, _, _) = route(now);
        let mut second = first.clone();
        let endpoint_key = authority_public_key(&endpoint_private).expect("endpoint key");
        second.sequence = 2;
        second.delegation.endpoint_key = endpoint_key;
        second.delegation.endpoint_sequence = 2;
        second.delegation.service_signature.clear();
        second
            .delegation
            .sign(&service_private)
            .expect("delegation");
        second.tickets[0].endpoint_key = endpoint_key;
        second.tickets[0].relay_signature.clear();
        second.tickets[0].endpoint_signature.clear();
        second.tickets[0]
            .sign_relay(&relay_private)
            .expect("relay ticket");
        second.tickets[0]
            .sign_endpoint(&endpoint_private)
            .expect("ticket confirmation");
        second.endpoint_signature.clear();
        second.sign(&endpoint_private).expect("route");

        let limits = RouteStoreLimits {
            records_per_key: 1,
            ..RouteStoreLimits::default()
        };
        let mut store = RouteStore::new(MAGIC, true, limits).expect("store");
        store
            .put_named_for_admission(
                first.route_key,
                first.encode().expect("first route"),
                now,
                "peer-a".to_owned(),
            )
            .expect("stored");

        second.sequence += 1;
        assert!(matches!(
            store.put_named_for_admission(
                second.route_key,
                second.encode().expect("second route"),
                now,
                "peer-b".to_owned(),
            ),
            Err(HnsrProtocolError::Capacity)
        ));
    }

    #[test]
    fn named_admission_limits_global_and_per_source_verification() {
        let now = 1_700_000_000;
        let (mut route, _, _) = route(now);
        route.sequence += 1;
        let raw = route.encode().expect("structurally valid route");
        let limits = RouteStoreLimits {
            verification_attempts_total: 2,
            verification_attempts_per_source: 1,
            verification_window_seconds: 60,
            ..RouteStoreLimits::default()
        };
        let mut store = RouteStore::new(MAGIC, true, limits).expect("store");

        let first =
            store.put_named_for_admission(route.route_key, raw.clone(), now, "peer-a".to_owned());
        assert!(first.is_err());
        assert!(!matches!(
            first,
            Err(HnsrProtocolError::VerificationRateLimited)
        ));
        assert!(matches!(
            store.put_named_for_admission(route.route_key, raw.clone(), now, "peer-a".to_owned(),),
            Err(HnsrProtocolError::VerificationRateLimited)
        ));

        let second_source =
            store.put_named_for_admission(route.route_key, raw.clone(), now, "peer-b".to_owned());
        assert!(second_source.is_err());
        assert!(!matches!(
            second_source,
            Err(HnsrProtocolError::VerificationRateLimited)
        ));
        assert!(matches!(
            store.put_named_for_admission(route.route_key, raw.clone(), now, "peer-c".to_owned(),),
            Err(HnsrProtocolError::VerificationRateLimited)
        ));

        let after_window =
            store.put_named_for_admission(route.route_key, raw, now + 60, "peer-c".to_owned());
        assert!(after_window.is_err());
        assert!(!matches!(
            after_window,
            Err(HnsrProtocolError::VerificationRateLimited)
        ));
    }
}
