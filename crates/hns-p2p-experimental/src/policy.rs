use crate::assignment::ExperimentalWireProfile;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsRelayRequesterPolicy {
    #[default]
    Auto,
    Disabled,
    Required,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObliviousDnsPolicy {
    Required,
    #[default]
    Preferred,
    DirectRelayAllowed,
    Disabled,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HnsrPolicy {
    #[default]
    Disabled,
    Client,
    Endpoint,
    Relay,
    Rendezvous,
    EndpointAndClient,
    Full,
}

impl HnsrPolicy {
    pub const fn has_client(self) -> bool {
        matches!(self, Self::Client | Self::EndpointAndClient | Self::Full)
    }

    pub const fn has_endpoint(self) -> bool {
        matches!(self, Self::Endpoint | Self::EndpointAndClient | Self::Full)
    }

    pub const fn has_relay(self) -> bool {
        matches!(self, Self::Relay | Self::Full)
    }

    pub const fn has_rendezvous(self) -> bool {
        matches!(self, Self::Rendezvous | Self::Full)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderRoles {
    pub dns_relay: bool,
    pub odoh_proxy: bool,
    pub odoh_target: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPolicy {
    pub dns_relay_requester: DnsRelayRequesterPolicy,
    pub oblivious_dns: ObliviousDnsPolicy,
    pub allow_direct_relay_fallback: bool,
    pub hnsr: HnsrPolicy,
    pub providers: ProviderRoles,
    pub wire_profile: ExperimentalWireProfile,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            dns_relay_requester: DnsRelayRequesterPolicy::Auto,
            oblivious_dns: ObliviousDnsPolicy::Preferred,
            allow_direct_relay_fallback: true,
            hnsr: HnsrPolicy::Disabled,
            providers: ProviderRoles::default(),
            wire_profile: ExperimentalWireProfile::DenuoV1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyAction {
    StopAdmittingDnsRelayRequests,
    CancelDnsRelayRequests,
    StopAdmittingOdohRequests,
    CancelOdohRequests,
    WithdrawDnsRelayAdvertisement,
    WithdrawOdohProxyAdvertisement,
    WithdrawOdohTargetAdvertisement,
    RevokeOdohTargetConfigurations,
    WithdrawHnsrRoutes,
    CloseHnsrCircuits,
    ClearRequesterSelections,
    DrainProviderWork,
    RefreshStructuredStatus,
    RenegotiateAffectedPeers,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyTransition {
    pub previous_generation: u64,
    pub generation: u64,
    pub previous: TransportPolicy,
    pub current: TransportPolicy,
    pub actions: Vec<PolicyAction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyController {
    policy: TransportPolicy,
    generation: u64,
}

impl Default for PolicyController {
    fn default() -> Self {
        Self {
            policy: TransportPolicy::default(),
            generation: 1,
        }
    }
}

impl PolicyController {
    pub const fn new(policy: TransportPolicy, generation: u64) -> Self {
        Self { policy, generation }
    }

    pub const fn policy(&self) -> TransportPolicy {
        self.policy
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn replace(&mut self, next: TransportPolicy) -> Option<PolicyTransition> {
        if self.policy == next {
            return None;
        }

        let previous = self.policy;
        let previous_generation = self.generation;
        self.generation = self.generation.saturating_add(1);
        self.policy = next;

        let mut actions = Vec::with_capacity(12);
        if next.dns_relay_requester == DnsRelayRequesterPolicy::Disabled {
            actions.push(PolicyAction::StopAdmittingDnsRelayRequests);
            actions.push(PolicyAction::CancelDnsRelayRequests);
        }
        if next.oblivious_dns == ObliviousDnsPolicy::Disabled {
            actions.push(PolicyAction::StopAdmittingOdohRequests);
            actions.push(PolicyAction::CancelOdohRequests);
        }
        if previous.providers.dns_relay && !next.providers.dns_relay {
            actions.push(PolicyAction::WithdrawDnsRelayAdvertisement);
            actions.push(PolicyAction::DrainProviderWork);
        }
        if previous.providers.odoh_proxy && !next.providers.odoh_proxy {
            actions.push(PolicyAction::WithdrawOdohProxyAdvertisement);
            actions.push(PolicyAction::DrainProviderWork);
        }
        if previous.providers.odoh_target && !next.providers.odoh_target {
            actions.push(PolicyAction::WithdrawOdohTargetAdvertisement);
            actions.push(PolicyAction::RevokeOdohTargetConfigurations);
            actions.push(PolicyAction::DrainProviderWork);
        }
        if previous.hnsr != next.hnsr {
            actions.push(PolicyAction::WithdrawHnsrRoutes);
            actions.push(PolicyAction::CloseHnsrCircuits);
        }
        actions.push(PolicyAction::ClearRequesterSelections);
        actions.push(PolicyAction::RefreshStructuredStatus);

        let advertisements_changed = previous.providers != next.providers
            || previous.hnsr.has_relay() != next.hnsr.has_relay()
            || previous.hnsr.has_rendezvous() != next.hnsr.has_rendezvous()
            || previous.wire_profile != next.wire_profile;
        if advertisements_changed {
            actions.push(PolicyAction::RenegotiateAffectedPeers);
        }
        actions.sort_unstable_by_key(|action| *action as u8);
        actions.dedup();

        Some(PolicyTransition {
            previous_generation,
            generation: self.generation,
            previous,
            current: next,
            actions,
        })
    }

    pub const fn accepts_result_generation(&self, generation: u64) -> bool {
        generation == self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requester_defaults_and_provider_opt_in_match_policy() {
        let policy = TransportPolicy::default();
        assert_eq!(policy.dns_relay_requester, DnsRelayRequesterPolicy::Auto);
        assert_eq!(policy.oblivious_dns, ObliviousDnsPolicy::Preferred);
        assert_eq!(policy.hnsr, HnsrPolicy::Disabled);
        assert_eq!(policy.providers, ProviderRoles::default());
    }

    #[test]
    fn disabling_requesters_revokes_stale_work() {
        let mut controller = PolicyController::default();
        let old_generation = controller.generation();
        let mut next = controller.policy();
        next.dns_relay_requester = DnsRelayRequesterPolicy::Disabled;
        next.oblivious_dns = ObliviousDnsPolicy::Disabled;
        let transition = controller.replace(next).expect("policy changed");
        assert_eq!(transition.generation, old_generation + 1);
        assert!(
            transition
                .actions
                .contains(&PolicyAction::CancelDnsRelayRequests)
        );
        assert!(
            transition
                .actions
                .contains(&PolicyAction::CancelOdohRequests)
        );
        assert!(!controller.accepts_result_generation(old_generation));
    }

    #[test]
    fn withdrawing_provider_roles_requires_peer_renegotiation() {
        let initial = TransportPolicy {
            providers: ProviderRoles {
                dns_relay: true,
                odoh_proxy: true,
                odoh_target: true,
            },
            ..TransportPolicy::default()
        };
        let mut controller = PolicyController::new(initial, 9);
        let transition = controller
            .replace(TransportPolicy::default())
            .expect("policy changed");
        assert!(
            transition
                .actions
                .contains(&PolicyAction::RenegotiateAffectedPeers)
        );
        assert!(
            transition
                .actions
                .contains(&PolicyAction::WithdrawDnsRelayAdvertisement)
        );
        assert!(
            transition
                .actions
                .contains(&PolicyAction::RevokeOdohTargetConfigurations)
        );
    }
}
