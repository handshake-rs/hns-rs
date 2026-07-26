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

/// Narrow consent authority for operating a plaintext HIP-76 DNS output.
///
/// This is deliberately not an opaque-relay capability. Constructing
/// [`Self::opted_in`] records the operator decision required before a runtime
/// may advertise or serve HIP-76.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRelayOutputPolicy {
    enabled: bool,
}

impl DnsRelayOutputPolicy {
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    pub const fn opted_in() -> Self {
        Self { enabled: true }
    }

    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

impl Default for DnsRelayOutputPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Opaque forwarding roles that default on with independent opt-out.
///
/// HNSR's opaque relay bit remains in [`HnsrPolicy`] because its other roles
/// share one wire protocol, but follows the same default-on boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueRelayRoles {
    pub odoh_proxy: bool,
}

impl Default for OpaqueRelayRoles {
    fn default() -> Self {
        Self { odoh_proxy: true }
    }
}

/// Output roles that see plaintext and/or perform external DNS work.
///
/// Every field defaults off and requires an explicit operator opt-in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutputRoles {
    pub dns_relay: DnsRelayOutputPolicy,
    pub odoh_target: bool,
}

/// Legacy mixed role bucket retained only for configuration migration.
///
/// New admission and policy APIs use [`OpaqueRelayRoles`] and [`OutputRoles`]
/// so opaque relay defaults cannot grant output authority.
#[deprecated(
    note = "split this value into OpaqueRelayRoles and OutputRoles; it is not an admission authority"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRoles {
    pub dns_relay: bool,
    pub odoh_proxy: bool,
    pub odoh_target: bool,
}

#[allow(deprecated)]
impl Default for ProviderRoles {
    fn default() -> Self {
        Self {
            dns_relay: false,
            odoh_proxy: true,
            odoh_target: false,
        }
    }
}

#[allow(deprecated)]
impl ProviderRoles {
    pub const fn split(self) -> (OpaqueRelayRoles, OutputRoles) {
        (
            OpaqueRelayRoles {
                odoh_proxy: self.odoh_proxy,
            },
            OutputRoles {
                dns_relay: if self.dns_relay {
                    DnsRelayOutputPolicy::opted_in()
                } else {
                    DnsRelayOutputPolicy::disabled()
                },
                odoh_target: self.odoh_target,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPolicy {
    pub dns_relay_requester: DnsRelayRequesterPolicy,
    pub oblivious_dns: ObliviousDnsPolicy,
    pub allow_direct_relay_fallback: bool,
    pub hnsr: HnsrPolicy,
    pub opaque_relays: OpaqueRelayRoles,
    pub outputs: OutputRoles,
    pub wire_profile: ExperimentalWireProfile,
}

impl TransportPolicy {
    /// Import the former mixed provider bucket without making it authoritative.
    #[allow(deprecated)]
    #[deprecated(note = "migrate configuration to opaque_relays and outputs")]
    pub const fn with_legacy_provider_roles(mut self, roles: ProviderRoles) -> Self {
        let (opaque_relays, outputs) = roles.split();
        self.opaque_relays = opaque_relays;
        self.outputs = outputs;
        self
    }
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            dns_relay_requester: DnsRelayRequesterPolicy::Auto,
            oblivious_dns: ObliviousDnsPolicy::Preferred,
            allow_direct_relay_fallback: true,
            hnsr: HnsrPolicy::default(),
            opaque_relays: OpaqueRelayRoles::default(),
            outputs: OutputRoles::default(),
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
    DrainOpaqueRelayWork,
    DrainOutputWork,
    #[deprecated(note = "use DrainOpaqueRelayWork or DrainOutputWork")]
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

        let mut actions = Vec::with_capacity(16);
        if next.dns_relay_requester == DnsRelayRequesterPolicy::Disabled {
            actions.push(PolicyAction::StopAdmittingDnsRelayRequests);
            actions.push(PolicyAction::CancelDnsRelayRequests);
        }
        if next.oblivious_dns == ObliviousDnsPolicy::Disabled {
            actions.push(PolicyAction::StopAdmittingOdohRequests);
            actions.push(PolicyAction::CancelOdohRequests);
        }
        if previous.outputs.dns_relay.is_enabled() && !next.outputs.dns_relay.is_enabled() {
            actions.push(PolicyAction::WithdrawDnsRelayAdvertisement);
            actions.push(PolicyAction::DrainOutputWork);
        }
        if previous.opaque_relays.odoh_proxy && !next.opaque_relays.odoh_proxy {
            actions.push(PolicyAction::WithdrawOdohProxyAdvertisement);
            actions.push(PolicyAction::DrainOpaqueRelayWork);
        }
        if previous.outputs.odoh_target && !next.outputs.odoh_target {
            actions.push(PolicyAction::WithdrawOdohTargetAdvertisement);
            actions.push(PolicyAction::RevokeOdohTargetConfigurations);
            actions.push(PolicyAction::DrainOutputWork);
        }
        if previous.hnsr != next.hnsr {
            actions.push(PolicyAction::WithdrawHnsrRoutes);
            actions.push(PolicyAction::CloseHnsrCircuits);
            if previous.hnsr.has_relay() && !next.hnsr.has_relay() {
                actions.push(PolicyAction::DrainOpaqueRelayWork);
            }
            if previous.hnsr.has_endpoint() && !next.hnsr.has_endpoint() {
                actions.push(PolicyAction::DrainOutputWork);
            }
        }
        actions.push(PolicyAction::ClearRequesterSelections);
        actions.push(PolicyAction::RefreshStructuredStatus);

        let advertisements_changed = previous.opaque_relays != next.opaque_relays
            || previous.outputs != next.outputs
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
        assert!(policy.opaque_relays.odoh_proxy);
        assert!(!policy.outputs.dns_relay.is_enabled());
        assert!(!policy.outputs.odoh_target);
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
    fn opaque_relay_and_output_authorities_never_imply_each_other() {
        let mut policy = TransportPolicy::default();
        policy.opaque_relays.odoh_proxy = false;
        policy.hnsr = policy.hnsr.with_relay(false);
        assert!(!policy.outputs.dns_relay.is_enabled());
        assert!(!policy.outputs.odoh_target);

        policy.outputs.dns_relay = DnsRelayOutputPolicy::opted_in();
        policy.outputs.odoh_target = true;
        assert!(!policy.opaque_relays.odoh_proxy);
        assert!(!policy.hnsr.has_relay());
        assert!(policy.outputs.dns_relay.is_enabled());
        assert!(policy.outputs.odoh_target);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_provider_roles_split_without_cross_granting() {
        let (opaque_relays, outputs) = ProviderRoles {
            dns_relay: true,
            odoh_proxy: false,
            odoh_target: false,
        }
        .split();
        assert!(!opaque_relays.odoh_proxy);
        assert!(outputs.dns_relay.is_enabled());
        assert!(!outputs.odoh_target);
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
    fn withdrawing_opaque_and_output_roles_uses_separate_drains() {
        let initial = TransportPolicy {
            outputs: OutputRoles {
                dns_relay: DnsRelayOutputPolicy::opted_in(),
                odoh_target: true,
            },
            ..TransportPolicy::default()
        };
        let next = TransportPolicy {
            opaque_relays: OpaqueRelayRoles { odoh_proxy: false },
            hnsr: HnsrPolicy::default().with_relay(false),
            ..TransportPolicy::default()
        };
        let mut controller = PolicyController::new(initial, 9);
        let transition = controller.replace(next).expect("policy changed");
        assert!(!controller.policy().opaque_relays.odoh_proxy);
        assert!(!controller.policy().hnsr.has_relay());
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
        assert!(
            transition
                .actions
                .contains(&PolicyAction::DrainOpaqueRelayWork)
        );
        assert!(transition.actions.contains(&PolicyAction::DrainOutputWork));
        #[allow(deprecated)]
        let legacy_mixed_drain = PolicyAction::DrainProviderWork;
        assert!(!transition.actions.contains(&legacy_mixed_drain));
    }
}
