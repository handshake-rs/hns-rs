//! HRM/HNSA-backed version-3 named rendezvous routes.
//!
//! Version 3 is intentionally distinct from the retained `hsa1`-backed
//! [`crate::named::NamedRouteRecordV2`]. Admission validation proves bounded
//! internal consistency only.
//! [`NamedRouteRecordV3::verify_current_uncommitted`] adds the required
//! point-in-time binding to an already verified HRM/HNSA service. Production
//! requesters use [`crate::ReconfirmedNamedRouteV3RequesterState`] inside an
//! ordered operation-lease scope so authority and replay state remain durably
//! current together.

use std::collections::HashSet;

use hns_encoding::{Decoder, Encoder};
use hns_service_authority::hrm::{
    EndpointDelegationV1, MAX_ENDPOINT_DELEGATION_SIZE, NamedServiceIdentity, VerifiedNamedService,
};

use crate::record::{
    RelayTicket, blake2b_256, decode_signature, encode_signature, sign, validate_public_key, verify,
};
use crate::{
    HNS_NODE_V1, HnsrProtocolError, MAX_RECORD_SIZE, MAX_RECORDS_PER_KEY, MAX_ROUTE_LIFETIME,
    MAX_SIGNATURE_SIZE,
};

const NAMED_ROUTE_KEY_DOMAIN: &[u8] = b"HNSR-NAMED-ROUTE-V1\0";
const ROUTE_SIGNATURE_DOMAIN: &[u8] = b"HNSR-HRM-HNSA-ROUTE-RECORD-V3\0";
const ROUTE_VERSION: u8 = 3;
const HRM_HNSA_AUTHORITY_TYPE: u8 = 2;
const MAX_TICKETS: usize = 8;
const ROUTE_FIXED_BODY_SIZE: usize = 168;
/// Application-profile and local relay policy applied after current HNSA
/// authority has been established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HrmNamedRoutePolicy {
    pub maximum_route_lifetime: u64,
    pub allowed_service_flags: u16,
    pub required_service_flags: u16,
    pub expected_service_constraints_hash: [u8; 32],
    pub allowed_endpoint_capabilities: u32,
    pub required_endpoint_capabilities: u32,
    pub expected_endpoint_constraints_hash: [u8; 32],
    pub allow_private_relays: bool,
}

impl HrmNamedRoutePolicy {
    fn validate(self) -> Result<(), HnsrProtocolError> {
        if self.maximum_route_lifetime == 0
            || self.maximum_route_lifetime > MAX_ROUTE_LIFETIME
            || self.required_service_flags & !self.allowed_service_flags != 0
            || self.required_endpoint_capabilities & !self.allowed_endpoint_capabilities != 0
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HRM-backed HNSR profile policy",
            ));
        }
        Ok(())
    }
}

/// Complete HRM-backed HNSR version-3 named route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedRouteRecordV3 {
    pub route_key: [u8; 32],
    pub profile_id: u16,
    pub record_sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub service_resource_id: [u8; 32],
    pub service_delegation_id: [u8; 32],
    pub service_generation: u64,
    pub service_controller_key: [u8; 33],
    pub endpoint_delegation: EndpointDelegationV1,
    pub tickets: Vec<RelayTicket>,
    pub endpoint_signature: Vec<u8>,
}

/// Point-in-time current-authority result with the fail-closed cache bound
/// already reduced across HRM/HNSA, endpoint, route, and every relay ticket.
///
/// This value is historical evidence, not a reusable authority capability.
/// Callers must stop using it at [`Self::cache_until`] and must revalidate after
/// either the HNSA authority aggregate or requester replay state advances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNamedRouteV3<'a> {
    record: &'a NamedRouteRecordV3,
    service: &'a VerifiedNamedService,
    cache_until: u64,
}

impl<'a> VerifiedNamedRouteV3<'a> {
    pub const fn record(&self) -> &'a NamedRouteRecordV3 {
        self.record
    }

    pub const fn service(&self) -> &'a VerifiedNamedService {
        self.service
    }

    pub const fn cache_until(&self) -> u64 {
        self.cache_until
    }
}

/// Derive the stable lookup key for one exact HNSA security origin.
pub fn named_route_key_v3(identity: &NamedServiceIdentity) -> Result<[u8; 32], HnsrProtocolError> {
    identity
        .validate()
        .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA named-service identity"))?;
    if identity.application_profile_id == 0 || identity.application_profile_id == HNS_NODE_V1 {
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
        &identity.application_profile_id.to_le_bytes(),
    ]))
}

/// Select the greatest fully valid route for one exact endpoint-key scope.
///
/// Invalid and unrelated candidates cannot create a conflict. Current
/// candidates independently contribute endpoint-delegation and route maxima.
/// Equal greatest sequence with distinct identities/bytes fails closed at
/// either layer, and no route is returned unless one exact record realizes
/// both maxima. Candidate processing is bounded before signature verification.
/// This helper is intentionally stateless and protects only one supplied
/// batch; production requesters need
/// [`crate::ReconfirmedNamedRouteV3RequesterState`] to retain both high-water
/// marks and equivocation observations across responses and restarts. A bare
/// [`VerifiedNamedService`] also cannot prove that its authority aggregate
/// crossed the durable commit boundary or remains the exact current revision,
/// so this is an explicitly uncommitted inspection helper.
#[doc(hidden)]
pub fn select_named_route_v3_uncommitted<'a>(
    candidates: impl IntoIterator<Item = &'a NamedRouteRecordV3>,
    endpoint_key: &[u8; 33],
    service: &'a VerifiedNamedService,
    policy: HrmNamedRoutePolicy,
    now: u64,
) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError> {
    let candidates = candidates
        .into_iter()
        .take(MAX_RECORDS_PER_KEY.saturating_add(1))
        .collect::<Vec<_>>();
    if candidates.len() > MAX_RECORDS_PER_KEY {
        return Err(HnsrProtocolError::TooLarge {
            actual: candidates.len(),
            maximum: MAX_RECORDS_PER_KEY,
        });
    }
    validate_public_key(endpoint_key)?;
    let expected_route_key = named_route_key_v3(service.identity())?;
    let mut valid = Vec::new();
    for candidate in candidates {
        if candidate.route_key != expected_route_key
            || candidate.endpoint_delegation.endpoint_key != *endpoint_key
        {
            continue;
        }
        let Ok(verified) = candidate.verify_current_uncommitted(service, policy, now) else {
            continue;
        };
        let endpoint_id = candidate
            .endpoint_delegation
            .id()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation ID"))?;
        let canonical = candidate.encode()?;
        valid.push((verified, endpoint_id, canonical));
    }
    let greatest_endpoint = valid
        .iter()
        .map(|(verified, _, _)| verified.record.endpoint_delegation.endpoint_sequence)
        .max()
        .ok_or(HnsrProtocolError::Invalid(
            "no current HRM-backed named route",
        ))?;
    let mut greatest_endpoints = valid.iter().filter(|(verified, _, _)| {
        verified.record.endpoint_delegation.endpoint_sequence == greatest_endpoint
    });
    let selected_endpoint_id = greatest_endpoints
        .next()
        .map(|(_, endpoint_id, _)| *endpoint_id)
        .ok_or(HnsrProtocolError::Invalid(
            "no current HRM-backed named route",
        ))?;
    if greatest_endpoints.any(|(_, endpoint_id, _)| *endpoint_id != selected_endpoint_id) {
        return Err(HnsrProtocolError::ConflictingSequence);
    }
    let greatest_route = valid
        .iter()
        .map(|(verified, _, _)| verified.record.record_sequence)
        .max()
        .ok_or(HnsrProtocolError::Invalid(
            "no current HRM-backed named route",
        ))?;
    let mut greatest_records = valid
        .iter()
        .filter(|(verified, _, _)| verified.record.record_sequence == greatest_route);
    let selected_bytes = greatest_records
        .next()
        .map(|(_, _, canonical)| canonical.clone())
        .ok_or(HnsrProtocolError::Invalid(
            "no current HRM-backed named route",
        ))?;
    if greatest_records.any(|(_, _, canonical)| canonical != &selected_bytes) {
        return Err(HnsrProtocolError::ConflictingSequence);
    }
    valid
        .into_iter()
        .find(|(verified, endpoint_id, canonical)| {
            verified.record.endpoint_delegation.endpoint_sequence == greatest_endpoint
                && *endpoint_id == selected_endpoint_id
                && verified.record.record_sequence == greatest_route
                && canonical == &selected_bytes
        })
        .map(|(verified, _, _)| verified)
        .ok_or(HnsrProtocolError::StaleSequence)
}

impl NamedRouteRecordV3 {
    /// Encode the exact bytes covered by the endpoint signature.
    pub fn encode_body(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        self.validate_structural_fields()?;
        let endpoint = self
            .endpoint_delegation
            .encode()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;
        if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_DELEGATION_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: endpoint.len(),
                maximum: MAX_ENDPOINT_DELEGATION_SIZE,
            });
        }

        let mut tickets = Vec::with_capacity(self.tickets.len());
        let mut canonical_tickets = HashSet::with_capacity(self.tickets.len());
        let mut size = ROUTE_FIXED_BODY_SIZE.saturating_add(endpoint.len());
        for ticket in &self.tickets {
            if ticket.network_magic != self.endpoint_delegation.network_magic
                || ticket.profile != self.profile_id
                || ticket.endpoint_key != self.endpoint_delegation.endpoint_key
                || self.issued_at < ticket.issued_at
                || ticket.expires_at < self.expires_at
            {
                return Err(HnsrProtocolError::Invalid(
                    "HRM-backed named route ticket binding mismatch",
                ));
            }
            validate_der_low_s(&ticket.relay_signature)?;
            validate_der_low_s(&ticket.endpoint_signature)?;
            let encoded = ticket.encode()?;
            if !canonical_tickets.insert(encoded.clone()) {
                return Err(HnsrProtocolError::Invalid(
                    "duplicate HRM-backed named route ticket",
                ));
            }
            size = size.saturating_add(encoded.len());
            tickets.push(encoded);
        }
        if size > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: size,
                maximum: MAX_RECORD_SIZE,
            });
        }

        let mut encoder = Encoder::with_capacity(size);
        encoder.put_u8(ROUTE_VERSION);
        encoder.put_u8(HRM_HNSA_AUTHORITY_TYPE);
        encoder.put_bytes(&self.route_key);
        encoder.put_u16_le(self.profile_id);
        encoder.put_u64_le(self.record_sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_bytes(&self.service_resource_id);
        encoder.put_bytes(&self.service_delegation_id);
        encoder.put_u64_le(self.service_generation);
        encoder.put_bytes(&self.service_controller_key);
        encoder.put_u16_le(endpoint.len() as u16);
        encoder.put_bytes(&endpoint);
        encoder.put_u8(tickets.len() as u8);
        for ticket in tickets {
            encoder.put_bytes(&ticket);
        }
        Ok(encoder.into_bytes())
    }

    /// Sign a structurally valid record without proving current HRM/HNSA
    /// authority or the cryptographic validity of its relay tickets.
    ///
    /// This low-level operation exists for deterministic and negative vectors.
    /// Before production use, the caller must atomically reserve and durably
    /// persist a fresh nonzero `record_sequence` for the exact
    /// `(route_key, endpoint_key)` scope. This helper does not do that.
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), HnsrProtocolError> {
        if crate::record::public_key(private_key)? != self.endpoint_delegation.endpoint_key {
            return Err(HnsrProtocolError::Invalid(
                "route signing key is not the delegated endpoint key",
            ));
        }
        let body = self.encode_body()?;
        self.endpoint_signature = sign(ROUTE_SIGNATURE_DOMAIN, &[&body], private_key)?;
        self.encode()?;
        Ok(())
    }

    /// Low-level sign-and-verify helper for deterministic vectors and callers
    /// migrating already durable counters.
    ///
    /// It does not reserve or persist `record_sequence`. Production callers
    /// must reserve and durably persist the exact-scope counter before calling;
    /// crash gaps are safe, but reuse is not. The wallet-backed durable
    /// publisher workflow is intentionally a separate integration layer.
    #[doc(hidden)]
    pub fn sign_current_uncommitted<'a>(
        &'a mut self,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        private_key: &[u8; 32],
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError> {
        let mut candidate = self.clone();
        candidate.sign(private_key)?;
        candidate.verify_current_uncommitted(service, policy, now)?;
        self.endpoint_signature = candidate.endpoint_signature;
        self.verify_current_uncommitted(service, policy, now)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let body = self.encode_body()?;
        validate_der_low_s(&self.endpoint_signature)?;
        let mut encoder = Encoder::with_capacity(body.len() + 1 + self.endpoint_signature.len());
        encoder.put_bytes(&body);
        encode_signature(&mut encoder, &self.endpoint_signature, false)?;
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        if input.is_empty() || input.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != ROUTE_VERSION {
            return Err(HnsrProtocolError::Invalid(
                "unsupported HRM-backed named route version",
            ));
        }
        if decoder.read_u8()? != HRM_HNSA_AUTHORITY_TYPE {
            return Err(HnsrProtocolError::Invalid(
                "unsupported HRM-backed named route authority",
            ));
        }
        let route_key = decoder.read_array()?;
        let profile_id = decoder.read_u16_le()?;
        let record_sequence = decoder.read_u64_le()?;
        let issued_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let service_resource_id = decoder.read_array()?;
        let service_delegation_id = decoder.read_array()?;
        let service_generation = decoder.read_u64_le()?;
        let service_controller_key = decoder.read_array()?;
        let endpoint_length = decoder.read_u16_le()? as usize;
        if !(1..=MAX_ENDPOINT_DELEGATION_SIZE).contains(&endpoint_length) {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSA endpoint delegation length",
            ));
        }
        let endpoint_delegation =
            EndpointDelegationV1::decode(decoder.read_slice(endpoint_length)?)
                .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;
        let ticket_count = decoder.read_u8()? as usize;
        if !(1..=MAX_TICKETS).contains(&ticket_count) {
            return Err(HnsrProtocolError::Invalid(
                "invalid HRM-backed named route ticket count",
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
            profile_id,
            record_sequence,
            issued_at,
            expires_at,
            service_resource_id,
            service_delegation_id,
            service_generation,
            service_controller_key,
            endpoint_delegation,
            tickets,
            endpoint_signature,
        };
        validate_der_low_s(&record.endpoint_signature)?;
        if record.encode()? != input {
            return Err(HnsrProtocolError::Invalid(
                "noncanonical HRM-backed named route",
            ));
        }
        Ok(record)
    }

    /// Verify only canonical bounded parsing, duplicated bindings, transient
    /// signatures, and time limits. This is suitable for rendezvous storage
    /// admission but is not proof of current name authority.
    pub fn verify_admission(
        &self,
        now: u64,
        allow_private_relays: bool,
    ) -> Result<(), HnsrProtocolError> {
        let body = self.validate_for_verification(now, MAX_ROUTE_LIFETIME)?;
        self.endpoint_delegation
            .verify_admission(&self.service_controller_key)
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?;
        self.verify_tickets_and_route(&body, now, allow_private_relays)
    }

    /// Point-in-time verification against a bare HRM/HNSA service value.
    ///
    /// This does not prove that the authority aggregate crossed its durable
    /// commit boundary, that the service remains its exact current revision,
    /// or that requester replay observations were durably committed. It is an
    /// explicitly uncommitted escape hatch for validators, deterministic
    /// vectors, and offline inspection.
    #[doc(hidden)]
    pub fn verify_current_uncommitted<'a>(
        &'a self,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError> {
        policy.validate()?;
        let identity = service.identity();
        if now < service.validated_at()
            || now >= service.cache_until()
            || self.route_key != named_route_key_v3(identity)?
            || self.profile_id != identity.application_profile_id
            || self.service_resource_id != service.resource_id()
            || self.service_delegation_id != service.delegation_id()
            || self.service_generation != service.service_generation()
            || self.service_controller_key != service.service_controller_key()
            || service.profile_flags() & !policy.allowed_service_flags != 0
            || service.profile_flags() & policy.required_service_flags
                != policy.required_service_flags
            || service.profile_constraints_hash() != policy.expected_service_constraints_hash
            || self.endpoint_delegation.capabilities & !policy.allowed_endpoint_capabilities != 0
            || self.endpoint_delegation.capabilities & policy.required_endpoint_capabilities
                != policy.required_endpoint_capabilities
            || self.endpoint_delegation.constraints_hash
                != policy.expected_endpoint_constraints_hash
        {
            return Err(HnsrProtocolError::Invalid(
                "named route does not match current HRM/HNSA state",
            ));
        }
        let body = self.validate_for_verification(now, policy.maximum_route_lifetime)?;
        self.endpoint_delegation
            .verify_uncommitted(service, now, policy.required_endpoint_capabilities)
            .map_err(|_| HnsrProtocolError::Invalid("invalid current HNSA endpoint delegation"))?;
        self.verify_tickets_and_route(&body, now, policy.allow_private_relays)?;
        let cache_until = self.tickets.iter().fold(
            service
                .cache_until()
                .min(self.endpoint_delegation.expires_at)
                .min(self.expires_at),
            |until, ticket| until.min(ticket.expires_at),
        );
        Ok(VerifiedNamedRouteV3 {
            record: self,
            service,
            cache_until,
        })
    }

    fn validate_structural_fields(&self) -> Result<(), HnsrProtocolError> {
        if self.profile_id == 0
            || self.profile_id == HNS_NODE_V1
            || self.record_sequence == 0
            || self.service_generation == 0
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_ROUTE_LIFETIME
            || self.tickets.is_empty()
            || self.tickets.len() > MAX_TICKETS
            || self.service_resource_id != self.endpoint_delegation.service_resource_id
            || self.service_delegation_id != self.endpoint_delegation.service_delegation_id
            || self.service_generation != self.endpoint_delegation.service_generation
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HRM-backed named route fields",
            ));
        }
        validate_public_key(&self.service_controller_key)
    }

    fn validate_for_verification(
        &self,
        now: u64,
        maximum_route_lifetime: u64,
    ) -> Result<Vec<u8>, HnsrProtocolError> {
        // Perform every bounded, canonical, duplicate, and duplicated-binding
        // check before any public-key verification.
        let body = self.encode_body()?;
        validate_der_low_s(&self.endpoint_signature)?;
        let encoded_size = body.len().saturating_add(1 + self.endpoint_signature.len());
        if encoded_size > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: encoded_size,
                maximum: MAX_RECORD_SIZE,
            });
        }
        if maximum_route_lifetime == 0
            || maximum_route_lifetime > MAX_ROUTE_LIFETIME
            || self.expires_at.saturating_sub(self.issued_at) > maximum_route_lifetime
            || now < self.issued_at
            || now >= self.expires_at
            || self.issued_at < self.endpoint_delegation.issued_at
            || self.expires_at > self.endpoint_delegation.expires_at
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HRM-backed named route interval",
            ));
        }
        Ok(body)
    }

    fn verify_tickets_and_route(
        &self,
        body: &[u8],
        now: u64,
        allow_private_relays: bool,
    ) -> Result<(), HnsrProtocolError> {
        for ticket in &self.tickets {
            ticket.verify_for_profile(
                self.endpoint_delegation.network_magic,
                self.profile_id,
                now,
                allow_private_relays,
            )?;
        }

        verify(
            ROUTE_SIGNATURE_DOMAIN,
            &[body],
            &self.endpoint_signature,
            &self.endpoint_delegation.endpoint_key,
        )
    }
}

fn validate_der_low_s(signature_bytes: &[u8]) -> Result<(), HnsrProtocolError> {
    if signature_bytes.is_empty() || signature_bytes.len() > MAX_SIGNATURE_SIZE {
        return Err(HnsrProtocolError::Invalid(
            "invalid HRM-backed named route signature length",
        ));
    }
    let signature = k256::ecdsa::Signature::from_der(signature_bytes)
        .map_err(|_| HnsrProtocolError::Cryptography)?;
    if signature.normalize_s().is_some() || signature.to_der().as_bytes() != signature_bytes {
        return Err(HnsrProtocolError::Cryptography);
    }
    Ok(())
}
