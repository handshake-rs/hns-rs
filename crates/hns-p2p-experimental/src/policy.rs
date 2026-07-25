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

/// Independent HNSR participation roles.
///
/// Opaque relay participation defaults on and remains independently
/// opt-out. Endpoint/output, requester, and rendezvous roles require separate
/// explicit enablement, so one role can never grant another implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrPolicy {
    client: bool,
    endpoint: bool,
    relay: bool,
    rendezvous: bool,
}

impl HnsrPolicy {
    /// Disable every HNSR role.
    pub const fn disabled() -> Self {
        Self {
            client: false,
            endpoint: false,
            relay: false,
            rendezvous: false,
        }
    }

    /// Default to opaque relay participation only.
    pub const fn relay_default() -> Self {
        Self {
            relay: true,
            ..Self::disabled()
        }
    }

    /// Set requester/client participation independently.
    pub const fn with_client(mut self, enabled: bool) -> Self {
        self.client = enabled;
        self
    }

    /// Set endpoint/output-node participation independently.
    pub const fn with_endpoint(mut self, enabled: bool) -> Self {
        self.endpoint = enabled;
        self
    }

    /// Set opaque relay participation independently.
    pub const fn with_relay(mut self, enabled: bool) -> Self {
        self.relay = enabled;
        self
    }

    /// Set rendezvous-directory participation independently.
    pub const fn with_rendezvous(mut self, enabled: bool) -> Self {
        self.rendezvous = enabled;
        self
    }

    /// Whether requester/client activity is enabled.
    pub const fn has_client(self) -> bool {
        self.client
    }

    /// Whether endpoint/output-node activity is enabled.
    pub const fn has_endpoint(self) -> bool {
        self.endpoint
    }

    /// Whether opaque relay activity is enabled.
    pub const fn has_relay(self) -> bool {
        self.relay
    }

    /// Whether rendezvous-directory activity is enabled.
    pub const fn has_rendezvous(self) -> bool {
        self.rendezvous
    }
}

impl Default for HnsrPolicy {
    fn default() -> Self {
        Self::relay_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRoles {
    pub dns_relay: bool,
    pub odoh_proxy: bool,
    pub odoh_target: bool,
}

impl Default for ProviderRoles {
    fn default() -> Self {
        Self {
            dns_relay: false,
            odoh_proxy: true,
            odoh_target: false,
        }
    }
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
            hnsr: HnsrPolicy::default(),
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
    fn relay_defaults_and_output_roles_require_opt_in() {
        let policy = TransportPolicy::default();
        assert_eq!(policy.dns_relay_requester, DnsRelayRequesterPolicy::Auto);
        assert_eq!(policy.oblivious_dns, ObliviousDnsPolicy::Preferred);
        assert!(!policy.hnsr.has_client());
        assert!(policy.hnsr.has_relay());
        assert!(!policy.hnsr.has_endpoint());
        assert!(!policy.hnsr.has_rendezvous());
        assert!(!policy.providers.dns_relay);
        assert!(policy.providers.odoh_proxy);
        assert!(!policy.providers.odoh_target);
    }

    #[test]
    fn hnsr_roles_never_imply_output_node_consent() {
        let relay_only = HnsrPolicy::default();
        assert!(relay_only.has_relay());
        assert!(!relay_only.has_endpoint());

        let output_and_relay = relay_only.with_endpoint(true);
        assert!(output_and_relay.has_relay());
        assert!(output_and_relay.has_endpoint());
        assert!(!output_and_relay.has_client());

        let output_only = output_and_relay.with_relay(false);
        assert!(!output_only.has_relay());
        assert!(output_only.has_endpoint());
        assert!(!output_only.has_rendezvous());
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
