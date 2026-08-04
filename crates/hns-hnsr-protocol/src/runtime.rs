//! Bounded live state machines for HNSR relay reservations and rendezvous
//! publication/lookup.
//!
//! Transport ownership stays with the embedding node or daemon. This module
//! accepts and returns canonical [`HnsrPacket`] values, so the same admission
//! logic can be composed with Handshake P2P, an authenticated overlay, or a
//! deterministic integration harness without inventing another consensus or
//! authority boundary.

use std::collections::{BTreeSet, HashMap};

use zeroize::Zeroizing;

use crate::body::{
    ConfirmBody, ConfirmedBody, GetRouteBody, OpenBody, PutResultBody, PutRouteBody, RenewBody,
    RoutesBody, WithdrawBody,
};
use crate::record::{RelayTicket, ReserveRequest, public_key, validate_host, verify_withdrawal};
use crate::{
    HnsrOpcode, HnsrPacket, HnsrProtocolError, MAX_CIRCUITS, MAX_CONTACTS, MAX_TICKET_LIFETIME,
    RouteStore, RouteStoreLimits,
};

const MAX_RESERVATION_ID_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    pub maximum_reservations: usize,
    pub maximum_reservations_per_source: usize,
    pub maximum_bytes_per_circuit: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            maximum_reservations: 4096,
            maximum_reservations_per_source: 64,
            maximum_bytes_per_circuit: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    pub network_magic: u32,
    pub transport: u8,
    pub host_type: u8,
    pub host: [u8; 16],
    pub port: u16,
    pub allow_private_address: bool,
    pub supported_profiles: BTreeSet<u16>,
    pub limits: RelayLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReservationState {
    source: String,
    context_id: [u8; 8],
    nonce: [u8; 16],
    ticket: RelayTicket,
    replaces: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedReservation {
    pub ticket: RelayTicket,
    pub source: String,
}

pub struct RelayService {
    config: RelayConfig,
    relay_private_key: Zeroizing<[u8; 32]>,
    relay_key: [u8; 33],
    reservations: HashMap<[u8; 16], ReservationState>,
    source_counts: HashMap<String, usize>,
}

impl RelayService {
    pub fn new(
        config: RelayConfig,
        relay_private_key: [u8; 32],
    ) -> Result<Self, HnsrProtocolError> {
        if config.supported_profiles.is_empty()
            || config.supported_profiles.contains(&0)
            || config.limits.maximum_reservations == 0
            || config.limits.maximum_reservations_per_source == 0
            || config.limits.maximum_reservations_per_source > config.limits.maximum_reservations
            || config.limits.maximum_bytes_per_circuit == 0
            || config.transport != 0
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR relay configuration",
            ));
        }
        validate_host(
            config.host_type,
            &config.host,
            config.port,
            config.allow_private_address,
        )?;
        let relay_key = public_key(&relay_private_key)?;
        Ok(Self {
            config,
            relay_private_key: Zeroizing::new(relay_private_key),
            relay_key,
            reservations: HashMap::new(),
            source_counts: HashMap::new(),
        })
    }

    pub const fn relay_key(&self) -> [u8; 33] {
        self.relay_key
    }

    pub fn len(&self) -> usize {
        self.reservations.len()
    }

    pub fn confirmed(&self, reservation_id: &[u8; 16]) -> Option<ConfirmedReservation> {
        self.reservations.get(reservation_id).and_then(|state| {
            (!state.ticket.endpoint_signature.is_empty()).then(|| ConfirmedReservation {
                ticket: state.ticket.clone(),
                source: state.source.clone(),
            })
        })
    }

    /// Admit one circuit open against an exact current confirmed reservation.
    ///
    /// The returned endpoint source is the authenticated outer connection that
    /// owns the reservation. Callers must route circuit traffic only to that
    /// connection and must revoke it when that connection disappears.
    pub fn admit_circuit(
        &self,
        open: &OpenBody,
        now: u64,
    ) -> Result<ConfirmedReservation, HnsrProtocolError> {
        let state = self
            .reservations
            .get(&open.reservation_id)
            .ok_or(HnsrProtocolError::Invalid("unknown HNSR reservation"))?;
        if state.ticket.endpoint_signature.is_empty()
            || state.ticket.expires_at <= now
            || state.ticket.id()? != open.ticket_id
            || state.ticket.endpoint_key != open.endpoint_key
            || state.ticket.profile != open.profile
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSR circuit does not match an active reservation",
            ));
        }
        state.ticket.verify_for_profile(
            self.config.network_magic,
            state.ticket.profile,
            now,
            self.config.allow_private_address,
        )?;
        Ok(ConfirmedReservation {
            ticket: state.ticket.clone(),
            source: state.source.clone(),
        })
    }

    /// Remove every reservation owned by one disconnected outer peer.
    ///
    /// The returned IDs let the embedding runtime revoke matching opaque
    /// circuits without retaining a second reservation index.
    pub fn disconnect(&mut self, source: &str) -> Vec<[u8; 16]> {
        let reservations = self
            .reservations
            .iter()
            .filter_map(|(reservation_id, state)| {
                (state.source == source).then_some(*reservation_id)
            })
            .collect::<Vec<_>>();
        for reservation_id in &reservations {
            self.remove(reservation_id);
        }
        reservations
    }

    pub fn prune(&mut self, now: u64) {
        let expired = self
            .reservations
            .iter()
            .filter_map(|(reservation_id, state)| {
                (state.ticket.expires_at <= now).then_some(*reservation_id)
            })
            .collect::<Vec<_>>();
        for reservation_id in expired {
            self.remove(&reservation_id);
        }
    }

    fn handle(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
    ) -> Result<Option<HnsrPacket>, HnsrProtocolError> {
        match packet.opcode {
            HnsrOpcode::Reserve => {
                let request = ReserveRequest::decode(&packet.body)?;
                let ticket = self.issue(request, packet.context_id, source, now, None)?;
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Offer,
                    packet.context_id,
                    ticket.encode()?,
                )?))
            }
            HnsrOpcode::Renew => {
                let renewal = RenewBody::decode(&packet.body)?;
                let previous = self
                    .reservations
                    .get(&renewal.previous_reservation_id)
                    .cloned()
                    .ok_or(HnsrProtocolError::Invalid("unknown HNSR reservation"))?;
                if previous.source != source
                    || previous.ticket.endpoint_signature.is_empty()
                    || previous.ticket.expires_at <= now
                    || renewal.request.endpoint_key != previous.ticket.endpoint_key
                    || renewal.request.profile != previous.ticket.profile
                {
                    return Err(HnsrProtocolError::Invalid("invalid HNSR renewal state"));
                }
                renewal.request.verify_renewal(
                    self.config.network_magic,
                    &self.relay_key,
                    &packet.context_id,
                    &renewal.previous_reservation_id,
                )?;
                let ticket = self.issue(
                    renewal.request,
                    packet.context_id,
                    source,
                    now,
                    Some(renewal.previous_reservation_id),
                )?;
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Offer,
                    packet.context_id,
                    ticket.encode()?,
                )?))
            }
            HnsrOpcode::Confirm => {
                let confirmation = ConfirmBody::decode(&packet.body)?;
                let state = self
                    .reservations
                    .get_mut(&confirmation.reservation_id)
                    .ok_or(HnsrProtocolError::Invalid("unknown HNSR reservation"))?;
                if state.source != source
                    || state.context_id != packet.context_id
                    || state.ticket.expires_at <= now
                    || !state.ticket.endpoint_signature.is_empty()
                {
                    return Err(HnsrProtocolError::Invalid(
                        "invalid HNSR confirmation state",
                    ));
                }
                state.ticket.endpoint_signature = confirmation.endpoint_signature;
                state.ticket.verify_for_profile(
                    self.config.network_magic,
                    state.ticket.profile,
                    now,
                    self.config.allow_private_address,
                )?;
                let ticket_id = state.ticket.id()?;
                let expires_at = state.ticket.expires_at;
                let replaces = state.replaces;
                if let Some(previous) = replaces {
                    self.remove(&previous);
                }
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Confirmed,
                    packet.context_id,
                    ConfirmedBody {
                        reservation_id: confirmation.reservation_id,
                        ticket_id,
                        expires_at,
                    }
                    .encode()?,
                )?))
            }
            HnsrOpcode::Withdraw => {
                let withdrawal = WithdrawBody::decode(&packet.body)?;
                let state = self
                    .reservations
                    .get(&withdrawal.reservation_id)
                    .ok_or(HnsrProtocolError::Invalid("unknown HNSR reservation"))?;
                if state.source != source
                    || state.context_id != packet.context_id
                    || state.ticket.endpoint_signature.is_empty()
                    || state.ticket.id()? != withdrawal.ticket_id
                {
                    return Err(HnsrProtocolError::Invalid("invalid HNSR withdrawal state"));
                }
                verify_withdrawal(
                    self.config.network_magic,
                    &self.relay_key,
                    &packet.context_id,
                    &withdrawal.reservation_id,
                    &withdrawal.ticket_id,
                    &withdrawal.signature,
                    &state.ticket.endpoint_key,
                )?;
                self.remove(&withdrawal.reservation_id);
                Ok(None)
            }
            _ => Err(HnsrProtocolError::Invalid(
                "unsupported HNSR relay operation",
            )),
        }
    }

    fn issue(
        &mut self,
        request: ReserveRequest,
        context_id: [u8; 8],
        source: &str,
        now: u64,
        replaces: Option<[u8; 16]>,
    ) -> Result<RelayTicket, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR reservation source"));
        }
        self.prune(now);
        request.validate_limits_for_profile(request.profile)?;
        if !self.config.supported_profiles.contains(&request.profile)
            || request.max_circuits > MAX_CIRCUITS
            || request.lifetime as u64 > MAX_TICKET_LIFETIME
            || request.max_bytes == 0
        {
            return Err(HnsrProtocolError::Invalid("disabled HNSR relay profile"));
        }
        if replaces.is_none() {
            request.verify(self.config.network_magic, &self.relay_key, &context_id)?;
        }
        if self.reservations.len() >= self.config.limits.maximum_reservations
            || self.source_counts.get(source).copied().unwrap_or(0)
                >= self.config.limits.maximum_reservations_per_source
        {
            return Err(HnsrProtocolError::Capacity);
        }
        if self.reservations.values().any(|state| {
            state.ticket.expires_at > now
                && state.ticket.endpoint_key == request.endpoint_key
                && state.ticket.profile == request.profile
                && state.nonce == request.nonce
        }) {
            return Err(HnsrProtocolError::Invalid(
                "replayed HNSR reservation nonce",
            ));
        }

        let reservation_id = self.random_reservation_id()?;
        let expires_at = now
            .checked_add(u64::from(request.lifetime))
            .ok_or(HnsrProtocolError::Invalid("HNSR reservation time overflow"))?;
        let mut ticket = RelayTicket {
            network_magic: self.config.network_magic,
            profile: request.profile,
            transport: self.config.transport,
            host_type: self.config.host_type,
            host: self.config.host,
            port: self.config.port,
            relay_key: self.relay_key,
            endpoint_key: request.endpoint_key,
            reservation_id,
            issued_at: now,
            expires_at,
            max_active_circuits: request.max_circuits,
            max_bytes_per_circuit: request
                .max_bytes
                .min(self.config.limits.maximum_bytes_per_circuit),
            max_total_bytes: request.max_bytes,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket.sign_relay(&self.relay_private_key)?;
        self.reservations.insert(
            reservation_id,
            ReservationState {
                source: source.to_owned(),
                context_id,
                nonce: request.nonce,
                ticket: ticket.clone(),
                replaces,
            },
        );
        *self.source_counts.entry(source.to_owned()).or_default() += 1;
        Ok(ticket)
    }

    fn random_reservation_id(&self) -> Result<[u8; 16], HnsrProtocolError> {
        for _ in 0..MAX_RESERVATION_ID_ATTEMPTS {
            let mut reservation_id = [0; 16];
            getrandom::fill(&mut reservation_id).map_err(|_| HnsrProtocolError::Cryptography)?;
            if reservation_id != [0; 16] && !self.reservations.contains_key(&reservation_id) {
                return Ok(reservation_id);
            }
        }
        Err(HnsrProtocolError::Cryptography)
    }

    fn remove(&mut self, reservation_id: &[u8; 16]) {
        let Some(state) = self.reservations.remove(reservation_id) else {
            return;
        };
        if let Some(count) = self.source_counts.get_mut(&state.source) {
            *count -= 1;
            if *count == 0 {
                self.source_counts.remove(&state.source);
            }
        }
    }
}

pub struct RendezvousService {
    routes: RouteStore,
}

impl RendezvousService {
    pub fn new(
        network_magic: u32,
        allow_private_routes: bool,
        limits: RouteStoreLimits,
    ) -> Result<Self, HnsrProtocolError> {
        Ok(Self {
            routes: RouteStore::new(network_magic, allow_private_routes, limits)?,
        })
    }

    pub const fn route_count(&self) -> usize {
        self.routes.len()
    }

    fn handle(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
    ) -> Result<Option<HnsrPacket>, HnsrProtocolError> {
        match packet.opcode {
            HnsrOpcode::PutRoute => {
                let put = PutRouteBody::decode(&packet.body)?;
                let stored_until = match put.record.first() {
                    Some(1) => {
                        self.routes
                            .put(put.route_key, put.record, now, source.to_owned())?
                    }
                    Some(2) => self.routes.put_named_for_admission(
                        put.route_key,
                        put.record,
                        now,
                        source.to_owned(),
                    )?,
                    _ => {
                        return Err(HnsrProtocolError::Invalid(
                            "unsupported HNSR route record version",
                        ));
                    }
                };
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::PutResult,
                    packet.context_id,
                    PutResultBody {
                        status: 0,
                        stored_until,
                    }
                    .encode(),
                )?))
            }
            HnsrOpcode::GetRoute => {
                let get = GetRouteBody::decode(&packet.body)?;
                let records = self.routes.get(
                    &get.route_key,
                    usize::from(get.maximum_records).min(MAX_CONTACTS),
                    now,
                );
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Routes,
                    packet.context_id,
                    RoutesBody { records }.encode()?,
                )?))
            }
            _ => Err(HnsrProtocolError::Invalid(
                "unsupported HNSR rendezvous operation",
            )),
        }
    }
}

pub struct HnsrService {
    relay: Option<RelayService>,
    rendezvous: Option<RendezvousService>,
}

impl HnsrService {
    pub const fn new(relay: Option<RelayService>, rendezvous: Option<RendezvousService>) -> Self {
        Self { relay, rendezvous }
    }

    pub fn relay(&self) -> Option<&RelayService> {
        self.relay.as_ref()
    }

    /// Borrow the relay reservation plane for pruning and disconnect cleanup.
    pub fn relay_mut(&mut self) -> Option<&mut RelayService> {
        self.relay.as_mut()
    }

    pub fn rendezvous(&self) -> Option<&RendezvousService> {
        self.rendezvous.as_ref()
    }

    pub fn handle(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
    ) -> Result<Option<HnsrPacket>, HnsrProtocolError> {
        match packet.opcode {
            HnsrOpcode::Reserve
            | HnsrOpcode::Renew
            | HnsrOpcode::Confirm
            | HnsrOpcode::Withdraw => self
                .relay
                .as_mut()
                .ok_or(HnsrProtocolError::Invalid("HNSR relay role is disabled"))?
                .handle(packet, source, now),
            HnsrOpcode::PutRoute | HnsrOpcode::GetRoute => self
                .rendezvous
                .as_mut()
                .ok_or(HnsrProtocolError::Invalid(
                    "HNSR rendezvous role is disabled",
                ))?
                .handle(packet, source, now),
            _ => Err(HnsrProtocolError::Invalid(
                "unsupported live HNSR operation",
            )),
        }
    }

    pub fn handle_encoded(
        &mut self,
        packet: &[u8],
        source: &str,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HnsrProtocolError> {
        let packet = HnsrPacket::decode(packet)?;
        self.handle(&packet, source, now)?
            .map(|response| response.encode())
            .transpose()
    }
}

pub struct EndpointReservation {
    endpoint_private_key: Zeroizing<[u8; 32]>,
    pub network_magic: u32,
    pub profile: u16,
}

impl EndpointReservation {
    pub fn new(
        network_magic: u32,
        profile: u16,
        endpoint_private_key: [u8; 32],
    ) -> Result<Self, HnsrProtocolError> {
        if profile == 0 {
            return Err(HnsrProtocolError::Invalid("invalid HNSR endpoint profile"));
        }
        let _ = public_key(&endpoint_private_key)?;
        Ok(Self {
            endpoint_private_key: Zeroizing::new(endpoint_private_key),
            network_magic,
            profile,
        })
    }

    pub fn endpoint_key(&self) -> Result<[u8; 33], HnsrProtocolError> {
        public_key(&self.endpoint_private_key)
    }

    pub fn reserve(
        &self,
        relay_key: &[u8; 33],
        context_id: [u8; 8],
        lifetime: u32,
        max_circuits: u16,
        max_bytes: u64,
        nonce: [u8; 16],
    ) -> Result<HnsrPacket, HnsrProtocolError> {
        let mut request = ReserveRequest {
            endpoint_key: self.endpoint_key()?,
            profile: self.profile,
            lifetime,
            max_circuits,
            max_bytes,
            nonce,
            signature: Vec::new(),
        };
        request.validate_limits_for_profile(self.profile)?;
        request.sign(
            self.network_magic,
            relay_key,
            &context_id,
            &self.endpoint_private_key,
        )?;
        HnsrPacket::new(HnsrOpcode::Reserve, context_id, request.encode()?)
    }

    pub fn confirm_offer(
        &self,
        offer: &HnsrPacket,
        expected_relay_key: &[u8; 33],
        now: u64,
        allow_private_relay: bool,
    ) -> Result<(HnsrPacket, RelayTicket), HnsrProtocolError> {
        if offer.opcode != HnsrOpcode::Offer {
            return Err(HnsrProtocolError::Invalid("expected HNSR relay offer"));
        }
        let mut ticket = RelayTicket::decode(&offer.body)?;
        if ticket.network_magic != self.network_magic
            || ticket.profile != self.profile
            || ticket.relay_key != *expected_relay_key
            || ticket.endpoint_key != self.endpoint_key()?
            || !ticket.endpoint_signature.is_empty()
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSR relay offer context mismatch",
            ));
        }
        ticket.sign_endpoint(&self.endpoint_private_key)?;
        ticket.verify_for_profile(self.network_magic, self.profile, now, allow_private_relay)?;
        let confirmation = HnsrPacket::new(
            HnsrOpcode::Confirm,
            offer.context_id,
            ConfirmBody {
                reservation_id: ticket.reservation_id,
                endpoint_signature: ticket.endpoint_signature.clone(),
            }
            .encode()?,
        )?;
        Ok((confirmation, ticket))
    }

    pub fn accept_confirmation(
        &self,
        response: &HnsrPacket,
        ticket: RelayTicket,
    ) -> Result<RelayTicket, HnsrProtocolError> {
        if response.opcode != HnsrOpcode::Confirmed {
            return Err(HnsrProtocolError::Invalid(
                "expected HNSR relay confirmation",
            ));
        }
        let confirmed = ConfirmedBody::decode(&response.body)?;
        if confirmed.reservation_id != ticket.reservation_id
            || confirmed.ticket_id != ticket.id()?
            || confirmed.expires_at != ticket.expires_at
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSR relay confirmation mismatch",
            ));
        }
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use hns_service_authority::{
        AuthorityRecord, EndpointDelegationV1, ServiceAuthorizationV1, ServiceIdentity,
        public_key as authority_public_key,
    };

    use super::*;
    use crate::HNS_NODE_V1;
    use crate::named::{NamedRoutePolicy, NamedRouteRecordV2, NamedRouteTrust, named_route_key};

    const MAGIC: u32 = 0x6d6f_6f6e;
    const PROFILE: u16 = 0xff00;
    const NOW: u64 = 1_700_000_000;

    fn service() -> HnsrService {
        let config = RelayConfig {
            network_magic: MAGIC,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            allow_private_address: true,
            supported_profiles: BTreeSet::from([PROFILE]),
            limits: RelayLimits {
                maximum_reservations: 8,
                maximum_reservations_per_source: 2,
                maximum_bytes_per_circuit: 1_048_576,
            },
        };
        HnsrService::new(
            Some(RelayService::new(config, [4; 32]).expect("relay")),
            Some(
                RendezvousService::new(
                    MAGIC,
                    true,
                    RouteStoreLimits {
                        total_records: 32,
                        records_per_key: 4,
                        records_per_source: 8,
                    },
                )
                .expect("rendezvous"),
            ),
        )
    }

    fn named_route(ticket: RelayTicket) -> (NamedRouteRecordV2, AuthorityRecord, ServiceIdentity) {
        let root_private = [10; 32];
        let service_private = [11; 32];
        let endpoint_private = [3; 32];
        let identity = ServiceIdentity {
            network_magic: MAGIC,
            name_hash: [12; 32],
            service_name: "pool-stats".to_owned(),
            profile_id: PROFILE,
        };
        let authority = AuthorityRecord {
            root_key: authority_public_key(&root_private).expect("root key"),
            epoch: 1,
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
            max_endpoint_lifetime: 3600,
            root_signature: Vec::new(),
        };
        authorization.sign(&root_private).expect("authorization");
        let mut delegation = EndpointDelegationV1 {
            network_magic: MAGIC,
            authorization_id: authorization.id().expect("authorization ID"),
            endpoint_key: ticket.endpoint_key,
            endpoint_sequence: 1,
            issued_at: NOW,
            expires_at: NOW + 1800,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(&service_private).expect("delegation");
        let mut route = NamedRouteRecordV2 {
            route_key: named_route_key(&identity).expect("route key"),
            profile: PROFILE,
            sequence: 1,
            issued_at: NOW,
            expires_at: NOW + 600,
            authorization,
            delegation,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        route.sign(&endpoint_private).expect("route");
        (route, authority, identity)
    }

    #[test]
    fn live_reservation_publication_and_lookup_verify_complete_named_chain() {
        let mut service = service();
        let relay_key = service.relay().expect("relay").relay_key();
        let endpoint = EndpointReservation::new(MAGIC, PROFILE, [3; 32]).expect("endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [1; 8], 1200, 4, 4_194_304, [2; 16])
            .expect("reserve");
        let offer = service
            .handle(&reserve, "operator-a", NOW)
            .expect("offer")
            .expect("response");
        let (confirm, ticket) = endpoint
            .confirm_offer(&offer, &relay_key, NOW, true)
            .expect("confirm");
        let confirmed = service
            .handle(&confirm, "operator-a", NOW)
            .expect("confirmed")
            .expect("response");
        let ticket = endpoint
            .accept_confirmation(&confirmed, ticket)
            .expect("ticket");
        assert!(
            service
                .relay()
                .expect("relay")
                .confirmed(&ticket.reservation_id)
                .is_some()
        );

        let (route, authority, identity) = named_route(ticket);
        let publish = HnsrPacket::new(
            HnsrOpcode::PutRoute,
            [5; 8],
            PutRouteBody {
                route_key: route.route_key,
                record: route.encode().expect("record"),
            }
            .encode()
            .expect("put body"),
        )
        .expect("put packet");
        let put_result = service
            .handle(&publish, "operator-a", NOW)
            .expect("put")
            .expect("response");
        assert_eq!(put_result.opcode, HnsrOpcode::PutResult);
        assert_eq!(
            PutResultBody::decode(&put_result.body)
                .expect("result")
                .status,
            0
        );

        let lookup = HnsrPacket::new(
            HnsrOpcode::GetRoute,
            [6; 8],
            GetRouteBody {
                route_key: route.route_key,
                maximum_records: 4,
            }
            .encode()
            .expect("get body"),
        )
        .expect("get packet");
        let routes = service
            .handle(&lookup, "observer", NOW + 1)
            .expect("lookup")
            .expect("response");
        let routes = RoutesBody::decode(&routes.body).expect("routes");
        assert_eq!(routes.records.len(), 1);
        let discovered = NamedRouteRecordV2::decode(&routes.records[0]).expect("route");
        discovered
            .verify(
                &NamedRouteTrust {
                    authority: &authority,
                    identity: &identity,
                    current_height: 150,
                    policy: NamedRoutePolicy {
                        maximum_route_lifetime: 900,
                        allowed_authorization_flags: 0,
                        allowed_endpoint_capabilities: 1,
                        required_endpoint_capabilities: 1,
                        expected_constraints_hash: [0; 32],
                        allow_private_relays: true,
                    },
                },
                NOW + 1,
            )
            .expect("independently verified route");
    }

    #[test]
    fn reservation_nonce_replay_and_cross_source_confirmation_fail_closed() {
        let mut service = service();
        let relay_key = service.relay().expect("relay").relay_key();
        let endpoint = EndpointReservation::new(MAGIC, PROFILE, [3; 32]).expect("endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [1; 8], 1200, 4, 4_194_304, [2; 16])
            .expect("reserve");
        let offer = service
            .handle(&reserve, "operator-a", NOW)
            .expect("offer")
            .expect("response");
        assert!(service.handle(&reserve, "operator-a", NOW).is_err());
        let (confirm, _) = endpoint
            .confirm_offer(&offer, &relay_key, NOW, true)
            .expect("confirm");
        assert!(service.handle(&confirm, "operator-b", NOW).is_err());
        assert!(service.handle(&confirm, "operator-a", NOW).is_ok());
    }

    #[test]
    fn named_profile_allowlist_does_not_enable_unnamed_hns_nodes() {
        let mut service = service();
        let relay_key = service.relay().expect("relay").relay_key();
        let endpoint = EndpointReservation::new(MAGIC, HNS_NODE_V1, [3; 32]).expect("endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [1; 8], 1200, 4, 4_194_304, [2; 16])
            .expect("reserve");
        assert!(service.handle(&reserve, "node", NOW).is_err());
    }
}
