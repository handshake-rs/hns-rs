//! Profile-neutral, current-state HRM authorization validation.
//!
//! Retrieval and profile semantics remain caller-owned interfaces. This module
//! supplies the invariant checks, recursive delegation walk, cycle and budget
//! limits, proof-chain output, and explicit rollback observations needed by an
//! operational adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::commitment::{CommitmentError, CommitmentLimits, HrmCommitment, select_commitment};
use crate::model::{
    Controller, Delegation, Envelope, HrmModelError, ResourceAuthority, ResourceEntry,
};

pub const MAX_PARENT_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    pub maximum_parent_depth: usize,
    pub maximum_fetched_objects: usize,
    pub maximum_fetched_bytes: usize,
    pub maximum_cache_lifetime: u64,
    /// Maximum redirects a retrieval adapter may follow for one object.
    pub maximum_redirects_per_object: usize,
    /// Maximum wall-clock time for the complete authorization decision.
    pub maximum_validation_milliseconds: u64,
    pub commitment: CommitmentLimits,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            maximum_parent_depth: 16,
            maximum_fetched_objects: 64,
            maximum_fetched_bytes: 8 * 1_048_576,
            maximum_cache_lifetime: 86_400,
            maximum_redirects_per_object: 4,
            maximum_validation_milliseconds: 10_000,
            commitment: CommitmentLimits::default(),
        }
    }
}

impl ValidationLimits {
    fn validate(self) -> Result<(), ValidationError> {
        if self.maximum_parent_depth == 0 || self.maximum_parent_depth > MAX_PARENT_DEPTH {
            return Err(ValidationError::InvalidLimits(
                "maximum_parent_depth must be in 1..=32",
            ));
        }
        if self.maximum_fetched_objects == 0
            || self.maximum_fetched_bytes == 0
            || self.maximum_cache_lifetime == 0
            || self.maximum_validation_milliseconds == 0
        {
            return Err(ValidationError::InvalidLimits(
                "fetch, byte, and cache lifetime limits must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Current HNS state authenticated by a full node, header-rooted proof, or
/// locally accepted DNSSEC trust path before entering this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedNameState {
    pub network_magic: u32,
    pub subject: [u8; 32],
    pub has_current_owner: bool,
    pub revoked: bool,
    pub expired: bool,
    pub finality_accepted: bool,
    pub chain_height: u32,
    /// Unsigned big-endian active-chain work used only for lexical comparison.
    pub chain_work: [u8; 32],
    pub chain_anchor: [u8; 32],
    /// Exact event-scoped evidence supplied only after local finality policy
    /// accepts a reorganization between the prior and current observations.
    pub accepted_reorganization: Option<AcceptedReorganization>,
    pub commitment_records: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedManifest {
    pub name_state: AuthenticatedNameState,
    pub envelope: Vec<u8>,
}

/// Untrusted object returned by an external-proof retrieval implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalProof {
    pub bytes: Vec<u8>,
}

/// Remaining retrieval budget that an adapter MUST enforce before allocating,
/// following redirects, or returning an object to HRM Core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchBudget {
    pub remaining_objects: usize,
    pub remaining_bytes: usize,
    pub maximum_redirects: usize,
    /// Time remaining in the complete authorization decision.
    pub remaining_milliseconds: u64,
}

/// Total retrieval work consumed while producing one successful result,
/// including failed locator attempts and redirects. A successful adapter must
/// report at least one object and no fewer bytes than the returned body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchUsage {
    pub objects: usize,
    pub bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchOutcome<T> {
    pub value: T,
    pub usage: FetchUsage,
}

/// Retrieval implementations are trusted to enforce `budget` before response
/// allocation, across URI attempts and redirects, and against elapsed time.
pub trait ManifestResolver {
    fn resolve_current(
        &self,
        subject: [u8; 32],
        budget: FetchBudget,
    ) -> Result<FetchOutcome<ResolvedManifest>, String>;
}

pub trait ExternalProofResolver {
    fn fetch(
        &self,
        proof_profile: &str,
        proof_hash: [u8; 32],
        proof_uris: &[String],
        budget: FetchBudget,
    ) -> Result<FetchOutcome<ExternalProof>, String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourcePolicy {
    pub permits_hns_local_origin: bool,
    pub permits_external_origin: bool,
    pub permits_parent_delegation: bool,
    /// Whether a resource authorized at this link may issue a child delegation.
    pub permits_subdelegation: bool,
    pub cache_until: u64,
}

/// Expiry derived by the profile from authenticated proof contents and its
/// current revocation policy, never from untrusted transport metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedExternalProof {
    pub cache_until: u64,
}

/// Time remaining in the complete authorization decision. Profile adapters
/// are trusted to stop their own work within this bound; HRM Core checks the
/// same monotonic deadline before and after every callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionBudget {
    pub remaining_milliseconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ResourceValidationContext<'a> {
    pub network_magic: u32,
    pub subject: [u8; 32],
    pub controller: &'a Controller,
    pub resource: &'a ResourceEntry,
    pub action: &'a str,
    pub now: u64,
    pub budget: DecisionBudget,
}

/// Complete expected authority context supplied to an external-proof profile.
/// The proof must cryptographically bind these values as required by its
/// profile rather than trusting a retrieval server to select them.
#[derive(Clone, Copy, Debug)]
pub struct ExternalProofContext<'a> {
    pub network_magic: u32,
    pub subject: [u8; 32],
    pub controller: &'a Controller,
    pub resource: &'a ResourceEntry,
    pub proof_profile: &'a str,
    pub action: &'a str,
    pub now: u64,
    pub budget: DecisionBudget,
}

#[derive(Clone, Copy, Debug)]
pub struct DelegationValidationContext<'a> {
    pub parent: &'a ResourceEntry,
    pub child: &'a ResourceEntry,
    pub delegation: &'a Delegation,
    pub action: &'a str,
    pub now: u64,
    pub budget: DecisionBudget,
}

/// Dispatcher for profile-specific identifiers, resource IDs, origins,
/// external proof formats, containment, rights, and constraints.
pub trait ProfilePolicy {
    fn validate_resource(
        &self,
        context: ResourceValidationContext<'_>,
    ) -> Result<ResourcePolicy, String>;

    fn validate_external_proof(
        &self,
        context: ExternalProofContext<'_>,
        proof: &[u8],
    ) -> Result<ValidatedExternalProof, String>;

    fn validate_delegation(&self, context: DelegationValidationContext<'_>) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackState {
    pub network_magic: u32,
    pub subject: [u8; 32],
    pub sequence: u64,
    pub envelope_hash: [u8; 32],
    pub chain_height: u32,
    pub chain_work: [u8; 32],
    pub chain_anchor: [u8; 32],
}

/// Persisted rollback observations indexed by both active network and subject.
pub type RollbackObservations = BTreeMap<(u32, [u8; 32]), RollbackState>;

/// Event-scoped accepted-reorganization evidence. Exact previous and current
/// anchors, heights, and work values prevent a generic boolean from disabling
/// rollback checks for unrelated observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedReorganization {
    pub previous_chain_height: u32,
    pub previous_chain_work: [u8; 32],
    pub previous_chain_anchor: [u8; 32],
    pub current_chain_height: u32,
    pub current_chain_work: [u8; 32],
    pub current_chain_anchor: [u8; 32],
}

impl AcceptedReorganization {
    fn matches(self, previous: RollbackState, current: RollbackState) -> bool {
        self.previous_chain_height == previous.chain_height
            && self.previous_chain_work == previous.chain_work
            && self.previous_chain_anchor == previous.chain_anchor
            && self.current_chain_height == current.chain_height
            && self.current_chain_work == current.chain_work
            && self.current_chain_anchor == current.chain_anchor
            && self.previous_chain_anchor != self.current_chain_anchor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofLink {
    HnsLocal {
        subject: [u8; 32],
        resource_id: [u8; 32],
    },
    External {
        subject: [u8; 32],
        resource_id: [u8; 32],
        proof_profile: String,
        proof_hash: [u8; 32],
    },
    ParentDelegation {
        parent_subject: [u8; 32],
        parent_resource_id: [u8; 32],
        child_subject: [u8; 32],
        child_resource_id: [u8; 32],
        delegation_id: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAuthorization {
    pub network_magic: u32,
    pub subject: [u8; 32],
    pub resource_id: [u8; 32],
    pub profile: String,
    pub action: String,
    pub expires_at: u64,
    pub proof_chain: Vec<ProofLink>,
    /// Every observation must be persisted atomically before operational use.
    pub rollback_observations: Vec<RollbackState>,
    pub fetched_objects: usize,
    pub fetched_bytes: usize,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid HRM validation limits: {0}")]
    InvalidLimits(&'static str),
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
    #[error(transparent)]
    Model(#[from] HrmModelError),
    #[error("authenticated current HNS name state is not usable")]
    NameState,
    #[error("resolved parent belongs to the wrong Handshake network or subject")]
    ResolverContext,
    #[error("retrieved HRM envelope does not match the current commitment")]
    EnvelopeHash,
    #[error("requested HRM resource is missing")]
    MissingResource,
    #[error("HRM profile validation failed: {0}")]
    Profile(String),
    #[error("HRM external proof retrieval failed: {0}")]
    ExternalRetrieval(String),
    #[error("HRM parent retrieval failed: {0}")]
    ParentRetrieval(String),
    #[error("HRM resource origin is forbidden by its profile")]
    Origin,
    #[error("HRM parent delegation is missing or does not match the child")]
    ParentDelegation,
    #[error("HRM delegation does not authorize the requested action")]
    Right,
    #[error("HRM delegation graph contains a cycle")]
    Cycle,
    #[error("HRM delegation graph exceeds the parent-depth limit")]
    Depth,
    #[error("HRM validation exceeds its fetched-object or byte budget")]
    Budget,
    #[error("HRM validation exceeds its wall-clock decision deadline")]
    Deadline,
    #[error("HRM sequence rollback was not justified by an accepted reorganization")]
    Rollback,
}

/// Validate current authorization for one resource and action.
#[allow(clippy::too_many_arguments)]
pub fn validate_authorization<P, M, X>(
    root: ResolvedManifest,
    expected_network_magic: u32,
    expected_subject: [u8; 32],
    resource_id: [u8; 32],
    action: &str,
    now: u64,
    limits: ValidationLimits,
    previous_observations: &RollbackObservations,
    profiles: &P,
    manifests: &M,
    external_proofs: &X,
) -> Result<ValidatedAuthorization, ValidationError>
where
    P: ProfilePolicy,
    M: ManifestResolver,
    X: ExternalProofResolver,
{
    limits.validate()?;
    let started_at = Instant::now();
    if action.is_empty() || action.len() > 128 || !action.is_ascii() {
        return Err(ValidationError::Right);
    }
    if root.name_state.subject != expected_subject {
        return Err(ValidationError::ResolverContext);
    }
    let mut context = Context {
        expected_network_magic,
        now,
        action,
        limits,
        previous_observations,
        profiles,
        manifests,
        external_proofs,
        fetched_objects: 0,
        fetched_bytes: 0,
        active: BTreeSet::new(),
        started_at,
    };
    let authorized = context.authorize(root, resource_id, 0, true)?;
    context.check_deadline()?;
    let expires_at = authorized
        .expires_at
        .min(now.saturating_add(limits.maximum_cache_lifetime));
    Ok(ValidatedAuthorization {
        network_magic: expected_network_magic,
        subject: expected_subject,
        resource_id,
        profile: authorized.resource.profile,
        action: action.to_owned(),
        expires_at,
        proof_chain: authorized.proof_chain,
        rollback_observations: authorized.observations,
        fetched_objects: context.fetched_objects,
        fetched_bytes: context.fetched_bytes,
    })
}

/// Apply the draft rollback rule to one persisted high-water observation.
pub fn validate_rollback(
    previous: RollbackState,
    current: RollbackState,
    accepted_reorganization: Option<&AcceptedReorganization>,
) -> Result<(), ValidationError> {
    if previous.network_magic != current.network_magic || previous.subject != current.subject {
        return Err(ValidationError::Rollback);
    }
    let rolls_back = current.sequence < previous.sequence
        || (current.sequence == previous.sequence
            && current.envelope_hash != previous.envelope_hash)
        || current.chain_work < previous.chain_work;
    if rolls_back
        && !accepted_reorganization.is_some_and(|evidence| evidence.matches(previous, current))
    {
        return Err(ValidationError::Rollback);
    }
    Ok(())
}

struct AuthorizedResource {
    resource: ResourceEntry,
    delegations: Vec<Delegation>,
    expires_at: u64,
    permits_subdelegation: bool,
    proof_chain: Vec<ProofLink>,
    observations: Vec<RollbackState>,
}

struct Context<'a, P, M, X> {
    expected_network_magic: u32,
    now: u64,
    action: &'a str,
    limits: ValidationLimits,
    previous_observations: &'a RollbackObservations,
    profiles: &'a P,
    manifests: &'a M,
    external_proofs: &'a X,
    fetched_objects: usize,
    fetched_bytes: usize,
    active: BTreeSet<([u8; 32], [u8; 32])>,
    started_at: Instant,
}

impl<P, M, X> Context<'_, P, M, X>
where
    P: ProfilePolicy,
    M: ManifestResolver,
    X: ExternalProofResolver,
{
    fn authorize(
        &mut self,
        resolved: ResolvedManifest,
        resource_id: [u8; 32],
        depth: usize,
        charge_resolved: bool,
    ) -> Result<AuthorizedResource, ValidationError> {
        self.check_deadline()?;
        if depth > self.limits.maximum_parent_depth {
            return Err(ValidationError::Depth);
        }
        let subject = resolved.name_state.subject;
        if !self.active.insert((subject, resource_id)) {
            return Err(ValidationError::Cycle);
        }
        let result = self.authorize_inner(resolved, resource_id, depth, charge_resolved);
        self.active.remove(&(subject, resource_id));
        self.check_deadline()?;
        result
    }

    fn authorize_inner(
        &mut self,
        resolved: ResolvedManifest,
        resource_id: [u8; 32],
        depth: usize,
        charge_resolved: bool,
    ) -> Result<AuthorizedResource, ValidationError> {
        if charge_resolved {
            self.charge_object(resolved.envelope.len())?;
        }
        let state = &resolved.name_state;
        if state.network_magic != self.expected_network_magic
            || !state.has_current_owner
            || state.revoked
            || state.expired
            || !state.finality_accepted
        {
            return Err(ValidationError::NameState);
        }
        let commitment = select_commitment(&state.commitment_records, &self.limits.commitment)?;
        self.check_deadline()?;
        if Sha256::digest(&resolved.envelope).as_slice() != commitment.envelope_hash {
            return Err(ValidationError::EnvelopeHash);
        }
        let envelope = Envelope::decode(&resolved.envelope)?;
        envelope.validate_context(
            state.network_magic,
            state.subject,
            commitment.sequence,
            self.now,
            0,
        )?;
        self.check_deadline()?;
        let observation = rollback_observation(state, &commitment);
        if let Some(previous) = self
            .previous_observations
            .get(&(state.network_magic, state.subject))
        {
            validate_rollback(
                *previous,
                observation,
                state.accepted_reorganization.as_ref(),
            )?;
        }
        let resource = envelope
            .payload
            .resources
            .iter()
            .find(|resource| resource.resource_id == resource_id)
            .cloned()
            .ok_or(ValidationError::MissingResource)?;
        if !time_active(resource.not_before, resource.expires_at, self.now) {
            return Err(ValidationError::Profile(
                "resource is not currently valid".to_owned(),
            ));
        }
        let policy = self
            .profiles
            .validate_resource(ResourceValidationContext {
                network_magic: state.network_magic,
                subject: state.subject,
                controller: &envelope.payload.controller,
                resource: &resource,
                action: self.action,
                now: self.now,
                budget: self.decision_budget()?,
            })
            .map_err(ValidationError::Profile)?;
        self.check_deadline()?;
        if self.now >= policy.cache_until {
            return Err(ValidationError::Profile(
                "profile authorization is not currently cacheable".to_owned(),
            ));
        }
        let mut expires_at = envelope
            .payload
            .expires_at
            .min(resource.expires_at)
            .min(policy.cache_until);
        let mut observations = vec![observation];
        let (proof_chain, inherited_subdelegation) = match &resource.authority {
            ResourceAuthority::HnsLocal => {
                if !policy.permits_hns_local_origin {
                    return Err(ValidationError::Origin);
                }
                (
                    vec![ProofLink::HnsLocal {
                        subject: state.subject,
                        resource_id,
                    }],
                    true,
                )
            }
            ResourceAuthority::External {
                proof_profile,
                proof_hash,
                proof_uris,
            } => {
                if !policy.permits_external_origin {
                    return Err(ValidationError::Origin);
                }
                let fetched = self
                    .external_proofs
                    .fetch(proof_profile, *proof_hash, proof_uris, self.fetch_budget()?)
                    .map_err(ValidationError::ExternalRetrieval)?;
                self.check_deadline()?;
                self.charge_fetch(fetched.usage, fetched.value.bytes.len())?;
                let proof = fetched.value;
                if Sha256::digest(&proof.bytes).as_slice() != *proof_hash {
                    return Err(ValidationError::Origin);
                }
                let validated_proof = self
                    .profiles
                    .validate_external_proof(
                        ExternalProofContext {
                            network_magic: state.network_magic,
                            subject: state.subject,
                            controller: &envelope.payload.controller,
                            resource: &resource,
                            proof_profile,
                            action: self.action,
                            now: self.now,
                            budget: self.decision_budget()?,
                        },
                        &proof.bytes,
                    )
                    .map_err(ValidationError::Profile)?;
                self.check_deadline()?;
                if self.now >= validated_proof.cache_until {
                    return Err(ValidationError::Origin);
                }
                expires_at = expires_at.min(validated_proof.cache_until);
                (
                    vec![ProofLink::External {
                        subject: state.subject,
                        resource_id,
                        proof_profile: proof_profile.clone(),
                        proof_hash: *proof_hash,
                    }],
                    true,
                )
            }
            ResourceAuthority::ParentDelegation {
                parent_subject,
                parent_resource_id,
                delegation_id,
            } => {
                if !policy.permits_parent_delegation {
                    return Err(ValidationError::Origin);
                }
                let fetched = self
                    .manifests
                    .resolve_current(*parent_subject, self.fetch_budget()?)
                    .map_err(ValidationError::ParentRetrieval)?;
                self.check_deadline()?;
                self.charge_fetch(fetched.usage, fetched.value.envelope.len())?;
                let parent_resolved = fetched.value;
                if parent_resolved.name_state.network_magic != self.expected_network_magic
                    || parent_resolved.name_state.subject != *parent_subject
                {
                    return Err(ValidationError::ResolverContext);
                }
                let parent =
                    self.authorize(parent_resolved, *parent_resource_id, depth + 1, false)?;
                if !parent.permits_subdelegation {
                    return Err(ValidationError::ParentDelegation);
                }
                let delegation = parent
                    .delegations
                    .iter()
                    .find(|delegation| delegation.delegation_id == *delegation_id)
                    .cloned()
                    .ok_or(ValidationError::ParentDelegation)?;
                validate_child_binding(
                    &parent.resource,
                    &resource,
                    &delegation,
                    state,
                    &envelope.payload.controller,
                    self.action,
                    self.now,
                )?;
                self.profiles
                    .validate_delegation(DelegationValidationContext {
                        parent: &parent.resource,
                        child: &resource,
                        delegation: &delegation,
                        action: self.action,
                        now: self.now,
                        budget: self.decision_budget()?,
                    })
                    .map_err(ValidationError::Profile)?;
                self.check_deadline()?;
                expires_at = expires_at.min(parent.expires_at).min(delegation.expires_at);
                observations.extend(parent.observations);
                let mut chain = parent.proof_chain;
                chain.push(ProofLink::ParentDelegation {
                    parent_subject: *parent_subject,
                    parent_resource_id: *parent_resource_id,
                    child_subject: state.subject,
                    child_resource_id: resource_id,
                    delegation_id: *delegation_id,
                });
                (chain, delegation.may_subdelegate)
            }
        };
        Ok(AuthorizedResource {
            resource,
            delegations: envelope.payload.delegations,
            expires_at,
            permits_subdelegation: policy.permits_subdelegation && inherited_subdelegation,
            proof_chain,
            observations,
        })
    }

    fn charge_object(&mut self, bytes: usize) -> Result<(), ValidationError> {
        self.charge_fetch(FetchUsage { objects: 1, bytes }, bytes)
    }

    fn charge_fetch(
        &mut self,
        usage: FetchUsage,
        minimum_body_bytes: usize,
    ) -> Result<(), ValidationError> {
        if usage.objects == 0 || usage.bytes < minimum_body_bytes {
            return Err(ValidationError::Budget);
        }
        self.fetched_objects = self.fetched_objects.saturating_add(usage.objects);
        self.fetched_bytes = self.fetched_bytes.saturating_add(usage.bytes);
        if self.fetched_objects > self.limits.maximum_fetched_objects
            || self.fetched_bytes > self.limits.maximum_fetched_bytes
        {
            return Err(ValidationError::Budget);
        }
        Ok(())
    }

    fn fetch_budget(&self) -> Result<FetchBudget, ValidationError> {
        let remaining_objects = self
            .limits
            .maximum_fetched_objects
            .checked_sub(self.fetched_objects)
            .ok_or(ValidationError::Budget)?;
        let remaining_bytes = self
            .limits
            .maximum_fetched_bytes
            .checked_sub(self.fetched_bytes)
            .ok_or(ValidationError::Budget)?;
        if remaining_objects == 0 || remaining_bytes == 0 {
            return Err(ValidationError::Budget);
        }
        Ok(FetchBudget {
            remaining_objects,
            remaining_bytes,
            maximum_redirects: self.limits.maximum_redirects_per_object,
            remaining_milliseconds: self.decision_budget()?.remaining_milliseconds,
        })
    }

    fn decision_budget(&self) -> Result<DecisionBudget, ValidationError> {
        let maximum = u128::from(self.limits.maximum_validation_milliseconds);
        let elapsed = self.started_at.elapsed().as_millis();
        let remaining = maximum
            .checked_sub(elapsed)
            .filter(|remaining| *remaining != 0)
            .ok_or(ValidationError::Deadline)?;
        Ok(DecisionBudget {
            remaining_milliseconds: u64::try_from(remaining).unwrap_or(u64::MAX),
        })
    }

    fn check_deadline(&self) -> Result<(), ValidationError> {
        self.decision_budget().map(|_| ())
    }
}

fn validate_child_binding(
    parent: &ResourceEntry,
    child: &ResourceEntry,
    delegation: &Delegation,
    child_state: &AuthenticatedNameState,
    child_controller: &Controller,
    action: &str,
    now: u64,
) -> Result<(), ValidationError> {
    if delegation.parent_resource_id != parent.resource_id
        || delegation.child_profile != child.profile
        || delegation.child_resource_id != child.resource_id
        || delegation.child_identifier != child.identifier
        || delegation.child_subject != child_state.subject
        || delegation.child_controller != *child_controller
        || !delegation.rights.iter().any(|right| right == action)
        || now < delegation.not_before
        || now >= delegation.expires_at
        || delegation.not_before < parent.not_before
        || delegation.expires_at > parent.expires_at
        || child.not_before < delegation.not_before
        || child.expires_at > delegation.expires_at
    {
        return Err(ValidationError::ParentDelegation);
    }
    Ok(())
}

fn rollback_observation(
    state: &AuthenticatedNameState,
    commitment: &HrmCommitment,
) -> RollbackState {
    RollbackState {
        network_magic: state.network_magic,
        subject: state.subject,
        sequence: commitment.sequence,
        envelope_hash: commitment.envelope_hash,
        chain_height: state.chain_height,
        chain_work: state.chain_work,
        chain_anchor: state.chain_anchor,
    }
}

fn time_active(not_before: u64, expires_at: u64, now: u64) -> bool {
    now >= not_before && now < expires_at
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;
    use crate::model::{Payload, VERSION, public_key};

    const MAGIC: u32 = 0xae38_95cf;
    const NOW: u64 = 1_700_000_100;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SeenExternalContext {
        network_magic: u32,
        subject: [u8; 32],
        controller: Controller,
        resource_id: [u8; 32],
        proof_profile: String,
        action: String,
        now: u64,
        remaining_milliseconds: u64,
        proof: Vec<u8>,
    }

    struct Profiles {
        subdelegating_resources: BTreeSet<[u8; 32]>,
        delegation_valid: bool,
        external_cache_until: u64,
        delay: Option<Duration>,
        seen_external: RefCell<Vec<SeenExternalContext>>,
    }

    impl Default for Profiles {
        fn default() -> Self {
            Self {
                subdelegating_resources: BTreeSet::new(),
                delegation_valid: true,
                external_cache_until: NOW + 500,
                delay: None,
                seen_external: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProfilePolicy for Profiles {
        fn validate_resource(
            &self,
            context: ResourceValidationContext<'_>,
        ) -> Result<ResourcePolicy, String> {
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }
            if context.resource.profile != "test.local/v1" || context.action != "operate" {
                return Err("unknown profile".to_owned());
            }
            Ok(ResourcePolicy {
                permits_hns_local_origin: true,
                permits_external_origin: true,
                permits_parent_delegation: true,
                permits_subdelegation: self
                    .subdelegating_resources
                    .contains(&context.resource.resource_id),
                cache_until: context.resource.expires_at,
            })
        }

        fn validate_external_proof(
            &self,
            context: ExternalProofContext<'_>,
            proof: &[u8],
        ) -> Result<ValidatedExternalProof, String> {
            self.seen_external.borrow_mut().push(SeenExternalContext {
                network_magic: context.network_magic,
                subject: context.subject,
                controller: context.controller.clone(),
                resource_id: context.resource.resource_id,
                proof_profile: context.proof_profile.to_owned(),
                action: context.action.to_owned(),
                now: context.now,
                remaining_milliseconds: context.budget.remaining_milliseconds,
                proof: proof.to_vec(),
            });
            Ok(ValidatedExternalProof {
                cache_until: self.external_cache_until,
            })
        }

        fn validate_delegation(
            &self,
            _context: DelegationValidationContext<'_>,
        ) -> Result<(), String> {
            if self.delegation_valid {
                Ok(())
            } else {
                Err("child is not contained by parent".to_owned())
            }
        }
    }

    #[derive(Default)]
    struct ManifestMap {
        manifests: BTreeMap<[u8; 32], ResolvedManifest>,
        usage: Option<FetchUsage>,
        budgets: RefCell<Vec<FetchBudget>>,
    }

    impl ManifestResolver for ManifestMap {
        fn resolve_current(
            &self,
            subject: [u8; 32],
            budget: FetchBudget,
        ) -> Result<FetchOutcome<ResolvedManifest>, String> {
            self.budgets.borrow_mut().push(budget);
            let value = self
                .manifests
                .get(&subject)
                .cloned()
                .ok_or_else(|| "not available".to_owned())?;
            let usage = self.usage.unwrap_or(FetchUsage {
                objects: 1,
                bytes: value.envelope.len(),
            });
            Ok(FetchOutcome { value, usage })
        }
    }

    struct ProofResolver {
        proof: Result<Vec<u8>, String>,
        usage: Option<FetchUsage>,
        budgets: RefCell<Vec<FetchBudget>>,
    }

    impl ExternalProofResolver for ProofResolver {
        fn fetch(
            &self,
            _proof_profile: &str,
            _proof_hash: [u8; 32],
            _proof_uris: &[String],
            budget: FetchBudget,
        ) -> Result<FetchOutcome<ExternalProof>, String> {
            self.budgets.borrow_mut().push(budget);
            let bytes = self.proof.clone()?;
            let usage = self.usage.unwrap_or(FetchUsage {
                objects: 1,
                bytes: bytes.len(),
            });
            Ok(FetchOutcome {
                value: ExternalProof { bytes },
                usage,
            })
        }
    }

    fn no_manifests() -> ManifestMap {
        ManifestMap::default()
    }

    fn no_proofs() -> ProofResolver {
        ProofResolver {
            proof: Err("not available".to_owned()),
            usage: None,
            budgets: RefCell::new(Vec::new()),
        }
    }

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn subject(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn resource_id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn resource(
        id: u8,
        authority: ResourceAuthority,
        not_before: u64,
        expires_at: u64,
    ) -> ResourceEntry {
        ResourceEntry {
            profile: "test.local/v1".to_owned(),
            resource_id: resource_id(id),
            identifier: vec![id],
            authority,
            not_before,
            expires_at,
            attributes: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn delegation(
        id: u8,
        parent_resource: u8,
        child_resource: u8,
        child_subject: u8,
        child_key: u8,
        rights: &[&str],
        not_before: u64,
        expires_at: u64,
        may_subdelegate: bool,
    ) -> Delegation {
        Delegation {
            delegation_id: resource_id(id),
            parent_resource_id: resource_id(parent_resource),
            child_profile: "test.local/v1".to_owned(),
            child_resource_id: resource_id(child_resource),
            child_identifier: vec![child_resource],
            child_subject: subject(child_subject),
            child_controller: Controller::secp256k1(public_key(&key(child_key)).expect("key"))
                .expect("controller"),
            rights: rights.iter().map(|right| (*right).to_owned()).collect(),
            not_before,
            expires_at,
            may_subdelegate,
            constraints: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest(
        subject_byte: u8,
        private_key_byte: u8,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        resources: Vec<ResourceEntry>,
        delegations: Vec<Delegation>,
    ) -> ResolvedManifest {
        let subject = subject(subject_byte);
        let private_key = key(private_key_byte);
        let payload = Payload {
            version: VERSION,
            subject,
            sequence,
            issued_at,
            expires_at,
            controller: Controller::secp256k1(public_key(&private_key).expect("key"))
                .expect("controller"),
            resources,
            delegations,
            extensions: None,
        };
        let envelope = Envelope::sign(payload, MAGIC, &private_key)
            .expect("sign")
            .encode()
            .expect("encode");
        let digest: [u8; 32] = Sha256::digest(&envelope).into();
        let record = vec![
            "hrm1".to_owned(),
            format!("seq={sequence}"),
            format!("hash=sha256:{}", URL_SAFE_NO_PAD.encode(digest)),
            "uri=https://example.test/hrm".to_owned(),
        ];
        ResolvedManifest {
            name_state: AuthenticatedNameState {
                network_magic: MAGIC,
                subject,
                has_current_owner: true,
                revoked: false,
                expired: false,
                finality_accepted: true,
                chain_height: 10,
                chain_work: [3; 32],
                chain_anchor: [4; 32],
                accepted_reorganization: None,
                commitment_records: vec![record],
            },
            envelope,
        }
    }

    fn root(private_key: &[u8; 32], sequence: u64) -> ResolvedManifest {
        let private_key_byte = private_key[0];
        manifest(
            1,
            private_key_byte,
            sequence,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                2,
                ResourceAuthority::HnsLocal,
                NOW - 50,
                NOW + 500,
            )],
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize(
        root: ResolvedManifest,
        expected_subject: [u8; 32],
        id: u8,
        action: &str,
        now: u64,
        limits: ValidationLimits,
        previous: &RollbackObservations,
        profiles: &Profiles,
        manifests: &ManifestMap,
        proofs: &ProofResolver,
    ) -> Result<ValidatedAuthorization, ValidationError> {
        validate_authorization(
            root,
            MAGIC,
            expected_subject,
            resource_id(id),
            action,
            now,
            limits,
            previous,
            profiles,
            manifests,
            proofs,
        )
    }

    fn one_level(rights: &[&str], may_subdelegate: bool) -> (ResolvedManifest, ResolvedManifest) {
        let parent = manifest(
            10,
            10,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                11,
                ResourceAuthority::HnsLocal,
                NOW - 60,
                NOW + 600,
            )],
            vec![delegation(
                12,
                11,
                21,
                20,
                20,
                rights,
                NOW - 50,
                NOW + 500,
                may_subdelegate,
            )],
        );
        let child = manifest(
            20,
            20,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                21,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(10),
                    parent_resource_id: resource_id(11),
                    delegation_id: resource_id(12),
                },
                NOW - 40,
                NOW + 400,
            )],
            Vec::new(),
        );
        (child, parent)
    }

    #[test]
    fn validates_current_hns_local_authority_and_emits_rollback_state() {
        let result = validate_authorization(
            root(&[1; 32], 7),
            MAGIC,
            [1; 32],
            [2; 32],
            "operate",
            NOW,
            ValidationLimits::default(),
            &BTreeMap::new(),
            &Profiles::default(),
            &no_manifests(),
            &no_proofs(),
        )
        .expect("authorization");
        assert_eq!(result.resource_id, [2; 32]);
        assert_eq!(result.proof_chain.len(), 1);
        assert_eq!(result.rollback_observations[0].sequence, 7);
        assert_eq!(result.fetched_objects, 1);
    }

    #[test]
    fn hash_name_state_budget_and_rollback_fail_closed() {
        let mut wrong_hash = root(&[1; 32], 7);
        wrong_hash.envelope[0] ^= 1;
        assert!(matches!(
            validate_authorization(
                wrong_hash,
                MAGIC,
                [1; 32],
                [2; 32],
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::EnvelopeHash)
        ));

        let mut unowned = root(&[1; 32], 7);
        unowned.name_state.has_current_owner = false;
        assert!(matches!(
            validate_authorization(
                unowned,
                MAGIC,
                [1; 32],
                [2; 32],
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::NameState)
        ));

        let current = root(&[1; 32], 7);
        let commitment = select_commitment(
            &current.name_state.commitment_records,
            &CommitmentLimits::default(),
        )
        .expect("commitment");
        let mut previous = BTreeMap::new();
        previous.insert(
            (current.name_state.network_magic, current.name_state.subject),
            RollbackState {
                sequence: 8,
                ..rollback_observation(&current.name_state, &commitment)
            },
        );
        assert!(matches!(
            validate_authorization(
                current,
                MAGIC,
                [1; 32],
                [2; 32],
                "operate",
                NOW,
                ValidationLimits::default(),
                &previous,
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::Rollback)
        ));
    }

    #[test]
    fn rejects_invalid_direct_actions_and_expected_subject_mismatch() {
        for action in ["", "é", &"a".repeat(129)] {
            assert!(matches!(
                authorize(
                    root(&key(1), 7),
                    subject(1),
                    2,
                    action,
                    NOW,
                    ValidationLimits::default(),
                    &BTreeMap::new(),
                    &Profiles::default(),
                    &no_manifests(),
                    &no_proofs(),
                ),
                Err(ValidationError::Right)
            ));
        }
        assert!(matches!(
            authorize(
                root(&key(1), 7),
                subject(99),
                2,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::ResolverContext)
        ));
    }

    #[test]
    fn external_proof_binds_full_context_and_accounts_cache_and_budget() {
        let proof = b"authenticated external proof".to_vec();
        let proof_hash: [u8; 32] = Sha256::digest(&proof).into();
        let root = manifest(
            30,
            30,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                31,
                ResourceAuthority::External {
                    proof_profile: "test.proof/v1".to_owned(),
                    proof_hash,
                    proof_uris: vec!["https://proof.test/object".to_owned()],
                },
                NOW - 50,
                NOW + 500,
            )],
            Vec::new(),
        );
        let root_len = root.envelope.len();
        let profiles = Profiles {
            external_cache_until: NOW + 25,
            ..Profiles::default()
        };
        let proofs = ProofResolver {
            proof: Ok(proof.clone()),
            usage: Some(FetchUsage {
                objects: 2,
                bytes: proof.len() + 7,
            }),
            budgets: RefCell::new(Vec::new()),
        };
        let result = authorize(
            root,
            subject(30),
            31,
            "operate",
            NOW,
            ValidationLimits::default(),
            &BTreeMap::new(),
            &profiles,
            &no_manifests(),
            &proofs,
        )
        .expect("external authorization");
        assert_eq!(result.expires_at, NOW + 25);
        assert_eq!(result.fetched_objects, 3);
        assert_eq!(result.fetched_bytes, root_len + proof.len() + 7);
        assert_eq!(
            profiles.seen_external.borrow().as_slice(),
            &[SeenExternalContext {
                network_magic: MAGIC,
                subject: subject(30),
                controller: Controller::secp256k1(public_key(&key(30)).expect("key"))
                    .expect("controller"),
                resource_id: resource_id(31),
                proof_profile: "test.proof/v1".to_owned(),
                action: "operate".to_owned(),
                now: NOW,
                remaining_milliseconds: profiles.seen_external.borrow()[0].remaining_milliseconds,
                proof,
            }]
        );
        let budget = proofs.budgets.borrow()[0];
        assert_eq!(budget.remaining_objects, 63);
        assert_eq!(budget.remaining_bytes, 8 * 1_048_576 - root_len);
        assert_eq!(budget.maximum_redirects, 4);
        assert!((1..=10_000).contains(&budget.remaining_milliseconds));
    }

    #[test]
    fn external_proof_rejects_bad_usage_hash_and_expired_cache() {
        let bytes = b"proof".to_vec();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let make_root = || {
            manifest(
                30,
                30,
                1,
                NOW - 100,
                NOW + 1_000,
                vec![resource(
                    31,
                    ResourceAuthority::External {
                        proof_profile: "test.proof/v1".to_owned(),
                        proof_hash: hash,
                        proof_uris: Vec::new(),
                    },
                    NOW - 50,
                    NOW + 500,
                )],
                Vec::new(),
            )
        };
        for usage in [
            FetchUsage {
                objects: 0,
                bytes: bytes.len(),
            },
            FetchUsage {
                objects: 1,
                bytes: bytes.len() - 1,
            },
            FetchUsage {
                objects: 64,
                bytes: bytes.len(),
            },
        ] {
            let resolver = ProofResolver {
                proof: Ok(bytes.clone()),
                usage: Some(usage),
                budgets: RefCell::new(Vec::new()),
            };
            assert!(matches!(
                authorize(
                    make_root(),
                    subject(30),
                    31,
                    "operate",
                    NOW,
                    ValidationLimits::default(),
                    &BTreeMap::new(),
                    &Profiles::default(),
                    &no_manifests(),
                    &resolver,
                ),
                Err(ValidationError::Budget)
            ));
        }

        let wrong = ProofResolver {
            proof: Ok(b"wrong".to_vec()),
            usage: None,
            budgets: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            authorize(
                make_root(),
                subject(30),
                31,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &wrong,
            ),
            Err(ValidationError::Origin)
        ));

        let expired_profiles = Profiles {
            external_cache_until: NOW,
            ..Profiles::default()
        };
        let valid = ProofResolver {
            proof: Ok(bytes),
            usage: None,
            budgets: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            authorize(
                make_root(),
                subject(30),
                31,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &expired_profiles,
                &no_manifests(),
                &valid,
            ),
            Err(ValidationError::Origin)
        ));
    }

    #[test]
    fn validates_one_level_and_multi_level_delegation() {
        let (child, parent) = one_level(&["operate"], true);
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(11)]),
            ..Profiles::default()
        };
        let result = authorize(
            child,
            subject(20),
            21,
            "operate",
            NOW,
            ValidationLimits::default(),
            &BTreeMap::new(),
            &profiles,
            &manifests,
            &no_proofs(),
        )
        .expect("one level");
        assert_eq!(result.proof_chain.len(), 2);
        assert_eq!(result.rollback_observations.len(), 2);
        assert_eq!(result.fetched_objects, 2);

        let top = manifest(
            40,
            40,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                41,
                ResourceAuthority::HnsLocal,
                NOW - 80,
                NOW + 800,
            )],
            vec![delegation(
                42,
                41,
                51,
                50,
                50,
                &["operate"],
                NOW - 70,
                NOW + 700,
                true,
            )],
        );
        let middle = manifest(
            50,
            50,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                51,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(40),
                    parent_resource_id: resource_id(41),
                    delegation_id: resource_id(42),
                },
                NOW - 60,
                NOW + 600,
            )],
            vec![delegation(
                52,
                51,
                61,
                60,
                60,
                &["operate"],
                NOW - 50,
                NOW + 500,
                true,
            )],
        );
        let bottom = manifest(
            60,
            60,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                61,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(50),
                    parent_resource_id: resource_id(51),
                    delegation_id: resource_id(52),
                },
                NOW - 40,
                NOW + 400,
            )],
            Vec::new(),
        );
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(40), top);
        manifests.manifests.insert(subject(50), middle);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(41), resource_id(51)]),
            ..Profiles::default()
        };
        let result = authorize(
            bottom,
            subject(60),
            61,
            "operate",
            NOW,
            ValidationLimits::default(),
            &BTreeMap::new(),
            &profiles,
            &manifests,
            &no_proofs(),
        )
        .expect("multi level");
        assert_eq!(result.proof_chain.len(), 3);
        assert_eq!(result.rollback_observations.len(), 3);
    }

    #[test]
    fn rejects_rights_escalation_containment_failure_and_forbidden_subdelegation() {
        let (child, parent) = one_level(&["observe"], true);
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(11)]),
            ..Profiles::default()
        };
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::ParentDelegation)
        ));

        let (child, parent) = one_level(&["operate"], true);
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        let containment_failure = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(11)]),
            delegation_valid: false,
            ..Profiles::default()
        };
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &containment_failure,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::Profile(_))
        ));

        let (child, parent) = one_level(&["operate"], true);
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::ParentDelegation)
        ));
    }

    #[test]
    fn rejects_missing_removed_and_revoked_parent() {
        let (child, _) = one_level(&["operate"], true);
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::ParentRetrieval(_))
        ));

        let (child, mut parent) = one_level(&["operate"], true);
        let decoded = Envelope::decode(&parent.envelope).expect("decode");
        parent = manifest(
            10,
            10,
            2,
            decoded.payload.issued_at,
            decoded.payload.expires_at,
            decoded.payload.resources,
            Vec::new(),
        );
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(11)]),
            ..Profiles::default()
        };
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::ParentDelegation)
        ));

        let (child, mut parent) = one_level(&["operate"], true);
        parent.name_state.revoked = true;
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::NameState)
        ));
    }

    #[test]
    fn rejects_delegation_cycles_and_depth_overflow() {
        let a = manifest(
            70,
            70,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                71,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(80),
                    parent_resource_id: resource_id(81),
                    delegation_id: resource_id(82),
                },
                NOW - 40,
                NOW + 400,
            )],
            vec![delegation(
                72,
                71,
                81,
                80,
                80,
                &["operate"],
                NOW - 50,
                NOW + 500,
                true,
            )],
        );
        let b = manifest(
            80,
            80,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                81,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(70),
                    parent_resource_id: resource_id(71),
                    delegation_id: resource_id(72),
                },
                NOW - 40,
                NOW + 400,
            )],
            vec![delegation(
                82,
                81,
                71,
                70,
                70,
                &["operate"],
                NOW - 50,
                NOW + 500,
                true,
            )],
        );
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(70), a.clone());
        manifests.manifests.insert(subject(80), b);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(71), resource_id(81)]),
            ..Profiles::default()
        };
        assert!(matches!(
            authorize(
                a,
                subject(70),
                71,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::Cycle)
        ));

        let top = manifest(
            40,
            40,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                41,
                ResourceAuthority::HnsLocal,
                NOW - 80,
                NOW + 800,
            )],
            vec![delegation(
                42,
                41,
                51,
                50,
                50,
                &["operate"],
                NOW - 70,
                NOW + 700,
                true,
            )],
        );
        let middle = manifest(
            50,
            50,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                51,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(40),
                    parent_resource_id: resource_id(41),
                    delegation_id: resource_id(42),
                },
                NOW - 60,
                NOW + 600,
            )],
            vec![delegation(
                52,
                51,
                61,
                60,
                60,
                &["operate"],
                NOW - 50,
                NOW + 500,
                true,
            )],
        );
        let bottom = manifest(
            60,
            60,
            1,
            NOW - 100,
            NOW + 1_000,
            vec![resource(
                61,
                ResourceAuthority::ParentDelegation {
                    parent_subject: subject(50),
                    parent_resource_id: resource_id(51),
                    delegation_id: resource_id(52),
                },
                NOW - 40,
                NOW + 400,
            )],
            Vec::new(),
        );
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(40), top);
        manifests.manifests.insert(subject(50), middle);
        let limits = ValidationLimits {
            maximum_parent_depth: 1,
            ..ValidationLimits::default()
        };
        assert!(matches!(
            authorize(
                bottom,
                subject(60),
                61,
                "operate",
                NOW,
                limits,
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::Depth)
        ));
    }

    #[test]
    fn rollback_requires_exact_event_scoped_reorganization_evidence() {
        let previous = RollbackState {
            network_magic: MAGIC,
            subject: subject(1),
            sequence: 9,
            envelope_hash: [1; 32],
            chain_height: 20,
            chain_work: [9; 32],
            chain_anchor: [2; 32],
        };
        let unchanged = previous;
        validate_rollback(previous, unchanged, None).expect("equal hash is not rollback");
        let advanced = RollbackState {
            sequence: 10,
            envelope_hash: [3; 32],
            chain_height: 21,
            chain_work: [10; 32],
            chain_anchor: [4; 32],
            ..previous
        };
        validate_rollback(previous, advanced, None).expect("advance");

        let rolled_back = RollbackState {
            sequence: 8,
            envelope_hash: [5; 32],
            chain_height: 18,
            chain_work: [8; 32],
            chain_anchor: [6; 32],
            ..previous
        };
        let evidence = AcceptedReorganization {
            previous_chain_height: previous.chain_height,
            previous_chain_work: previous.chain_work,
            previous_chain_anchor: previous.chain_anchor,
            current_chain_height: rolled_back.chain_height,
            current_chain_work: rolled_back.chain_work,
            current_chain_anchor: rolled_back.chain_anchor,
        };
        validate_rollback(previous, rolled_back, Some(&evidence)).expect("accepted reorg");
        let wrong_event = AcceptedReorganization {
            current_chain_anchor: [7; 32],
            ..evidence
        };
        assert!(matches!(
            validate_rollback(previous, rolled_back, Some(&wrong_event)),
            Err(ValidationError::Rollback)
        ));
        assert!(matches!(
            validate_rollback(
                previous,
                RollbackState {
                    envelope_hash: [8; 32],
                    ..previous
                },
                None,
            ),
            Err(ValidationError::Rollback)
        ));
    }

    #[test]
    fn all_validity_and_cache_expiries_are_exclusive() {
        let resource_expired = manifest(
            1,
            1,
            1,
            NOW - 100,
            NOW + 100,
            vec![resource(2, ResourceAuthority::HnsLocal, NOW - 50, NOW)],
            Vec::new(),
        );
        assert!(matches!(
            authorize(
                resource_expired,
                subject(1),
                2,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::Profile(_))
        ));

        let payload_expired = manifest(
            1,
            1,
            1,
            NOW - 100,
            NOW,
            vec![resource(2, ResourceAuthority::HnsLocal, NOW - 50, NOW)],
            Vec::new(),
        );
        assert!(matches!(
            authorize(
                payload_expired,
                subject(1),
                2,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &Profiles::default(),
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::Model(_))
        ));

        let (child, parent) = one_level(&["operate"], true);
        let decoded = Envelope::decode(&parent.envelope).expect("decode");
        let mut expired_delegation = decoded.payload.delegations[0].clone();
        expired_delegation.expires_at = NOW;
        let parent = manifest(
            10,
            10,
            2,
            NOW - 100,
            NOW + 1_000,
            decoded.payload.resources,
            vec![expired_delegation],
        );
        let mut manifests = ManifestMap::default();
        manifests.manifests.insert(subject(10), parent);
        let profiles = Profiles {
            subdelegating_resources: BTreeSet::from([resource_id(11)]),
            ..Profiles::default()
        };
        assert!(matches!(
            authorize(
                child,
                subject(20),
                21,
                "operate",
                NOW,
                ValidationLimits::default(),
                &BTreeMap::new(),
                &profiles,
                &manifests,
                &no_proofs(),
            ),
            Err(ValidationError::ParentDelegation)
        ));
    }

    #[test]
    fn complete_decision_deadline_includes_profile_work() {
        let profiles = Profiles {
            delay: Some(Duration::from_millis(5)),
            ..Profiles::default()
        };
        let limits = ValidationLimits {
            maximum_validation_milliseconds: 1,
            ..ValidationLimits::default()
        };
        assert!(matches!(
            authorize(
                root(&key(1), 7),
                subject(1),
                2,
                "operate",
                NOW,
                limits,
                &BTreeMap::new(),
                &profiles,
                &no_manifests(),
                &no_proofs(),
            ),
            Err(ValidationError::Deadline)
        ));
    }
}
