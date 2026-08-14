//! Scoped, fenced operation-lease capabilities for durable HNSA consumers.
//!
//! A compare-and-swap orders durable writes but cannot keep an independently
//! restored tab, worker, or process current after the write returns. Production
//! authority and requester operations therefore run inside an embedding-owned
//! namespace-wide lease. The embedding is part of the trusted computing base:
//! it must acquire real exclusion and atomically reject stale fencing tokens in
//! every storage transaction.

use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;
use std::ops::AsyncFnOnce;

use thiserror::Error;

/// Stable identity of one authenticated durable-storage namespace.
///
/// This identifies the physical logical lineage shared by every tab, worker,
/// process, or device that can access the state. It is not an HNSA origin and
/// must not be derived from an untrusted serving URL.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageNamespaceId([u8; 32]);

impl StorageNamespaceId {
    /// Construct a nonzero durable-storage namespace identity.
    pub fn new(value: [u8; 32]) -> Result<Self, LeaseError> {
        if value == [0; 32] {
            return Err(LeaseError::ZeroStorageNamespace);
        }
        Ok(Self(value))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Monotonic, nonzero token assigned by the namespace lease broker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    pub fn new(value: u64) -> Result<Self, LeaseError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(LeaseError::ZeroFencingToken)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact subject-wide authority namespace protected by one lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityLeaseKey {
    storage_namespace_id: StorageNamespaceId,
    network_magic: u32,
    subject: [u8; 32],
}

impl AuthorityLeaseKey {
    pub const fn new(
        storage_namespace_id: StorageNamespaceId,
        network_magic: u32,
        subject: [u8; 32],
    ) -> Self {
        Self {
            storage_namespace_id,
            network_magic,
            subject,
        }
    }

    pub const fn storage_namespace_id(&self) -> StorageNamespaceId {
        self.storage_namespace_id
    }

    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    pub const fn subject(&self) -> &[u8; 32] {
        &self.subject
    }
}

/// Fail-closed lease validation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseError {
    #[error("durable-storage namespace identity must be nonzero")]
    ZeroStorageNamespace,
    #[error("fencing token must be nonzero")]
    ZeroFencingToken,
    #[error("lease guard belongs to a different namespace")]
    KeyMismatch,
    #[error("lease guard fencing token changed")]
    FenceChanged,
    #[error("operation lease was lost, expired, or revoked")]
    Lost,
}

/// Security-critical embedding contract for one acquired fenced lease.
///
/// The protocol crates deliberately provide no no-op/default/test guard. A real
/// implementation must be non-cloneable as an ownership capability, retain
/// namespace-wide exclusion for its lifetime, and make [`Self::ensure_held`]
/// fail after loss, expiry, revocation, or fencing-token replacement. Its
/// persistence adapter must atomically validate the same token while applying
/// every compare-and-swap; a pointwise `ensure_held` call is not a substitute
/// for a fenced storage transaction. A guard that can expire or be revoked
/// silently must not use point checks to authorize irreversible publication.
/// Such an adapter must use broker-owned fenced session/result promotion, or a
/// genuinely nonrevocable callback-scoped lock, before publishing the result.
///
/// This is a safe trait because violating the contract is a protocol-security
/// failure, not Rust memory unsafety. Implementations remain part of the trusted
/// embedding boundary.
pub trait FencedLeaseGuard<K>: fmt::Debug {
    fn key(&self) -> &K;
    fn fencing_token(&self) -> FencingToken;
    fn ensure_held(&self) -> Result<(), LeaseError>;
}

/// An embedding acquisition failure or an invalid guard returned by it.
#[derive(Debug)]
pub enum LeaseAcquireError<E> {
    Backend(E),
    Lease(LeaseError),
}

impl<E: fmt::Display> fmt::Display for LeaseAcquireError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => {
                write!(formatter, "operation-lease acquisition failed: {error}")
            }
            Self::Lease(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for LeaseAcquireError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::Lease(error) => Some(error),
        }
    }
}

/// A scoped operation failure or lease loss detected at its release boundary.
#[derive(Debug)]
pub enum LeaseScopeError<E> {
    Operation(E),
    Lease(LeaseError),
}

impl<E: fmt::Display> fmt::Display for LeaseScopeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for LeaseScopeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Operation(error) => Some(error),
            Self::Lease(error) => Some(error),
        }
    }
}

/// Opaque borrow of one exact held lease.
///
/// Fields and construction are private. The witness is neither `Clone` nor
/// `Copy` and is issued only inside [`HeldFencedLease::run`] or
/// [`HeldFencedLease::run_async`].
#[derive(Debug)]
pub struct LeaseWitness<'a, K> {
    key: K,
    fence: FencingToken,
    guard: &'a dyn FencedLeaseGuard<K>,
}

impl<K: Eq> LeaseWitness<'_, K> {
    pub const fn key(&self) -> &K {
        &self.key
    }

    pub const fn fencing_token(&self) -> FencingToken {
        self.fence
    }

    pub fn ensure_held(&self) -> Result<(), LeaseError> {
        self.guard.ensure_held()?;
        if self.guard.key() != &self.key {
            return Err(LeaseError::KeyMismatch);
        }
        if self.guard.fencing_token() != self.fence {
            return Err(LeaseError::FenceChanged);
        }
        Ok(())
    }
}

/// Owned, non-cloneable RAII lease awaiting one scoped operation.
#[derive(Debug)]
pub struct HeldFencedLease<K, G> {
    key: K,
    fence: FencingToken,
    guard: G,
}

impl<K, G> HeldFencedLease<K, G>
where
    K: Copy + Eq,
    G: FencedLeaseGuard<K>,
{
    /// Acquire and validate a guard through a trusted embedding callback.
    pub fn acquire<E, F>(key: K, acquire: F) -> Result<Self, LeaseAcquireError<E>>
    where
        F: FnOnce(&K) -> Result<G, E>,
    {
        let guard = acquire(&key).map_err(LeaseAcquireError::Backend)?;
        Self::from_acquired(key, guard).map_err(LeaseAcquireError::Lease)
    }

    /// Await an owned guard without requiring it or its future to be `Send`.
    pub async fn acquire_async<E, F, Fut>(key: K, acquire: F) -> Result<Self, LeaseAcquireError<E>>
    where
        F: FnOnce(K) -> Fut,
        Fut: Future<Output = Result<G, E>>,
    {
        let guard = acquire(key).await.map_err(LeaseAcquireError::Backend)?;
        Self::from_acquired(key, guard).map_err(LeaseAcquireError::Lease)
    }

    fn from_acquired(key: K, guard: G) -> Result<Self, LeaseError> {
        guard.ensure_held()?;
        if guard.key() != &key {
            return Err(LeaseError::KeyMismatch);
        }
        let fence = guard.fencing_token();
        Ok(Self { key, fence, guard })
    }

    pub fn ensure_held(&self) -> Result<(), LeaseError> {
        self.guard.ensure_held()?;
        if self.guard.key() != &self.key {
            return Err(LeaseError::KeyMismatch);
        }
        if self.guard.fencing_token() != self.fence {
            return Err(LeaseError::FenceChanged);
        }
        Ok(())
    }

    /// Run one operation while withholding its outcome until the lease has
    /// passed both entry and release-boundary checks.
    ///
    /// `R` is necessarily independent of the scoped witness. It must also be
    /// an owned, lease-independent result in the protocol sense: callbacks
    /// must not smuggle an externally publishable capability through interior
    /// state. Irreversible publication still requires the fenced promotion
    /// described on [`FencedLeaseGuard`].
    ///
    /// The HRTB prevents the opaque witness—and therefore any current guard
    /// borrowing it—from being returned:
    ///
    /// ```compile_fail
    /// use hns_service_authority::lease::{FencedLeaseGuard, HeldFencedLease};
    ///
    /// fn escape<K, G>(held: HeldFencedLease<K, G>)
    /// where
    ///     K: Copy + Eq,
    ///     G: FencedLeaseGuard<K>,
    /// {
    ///     let _escaped = held.run(|witness| Ok::<_, ()>(witness)).unwrap();
    /// }
    /// ```
    pub fn run<R, E, F>(self, operation: F) -> Result<R, LeaseScopeError<E>>
    where
        F: for<'op> FnOnce(&'op LeaseWitness<'op, K>) -> Result<R, E>,
    {
        self.ensure_held().map_err(LeaseScopeError::Lease)?;
        let witness = LeaseWitness {
            key: self.key,
            fence: self.fence,
            guard: &self.guard,
        };
        let result = operation(&witness);
        self.ensure_held().map_err(LeaseScopeError::Lease)?;
        result.map_err(LeaseScopeError::Operation)
    }

    /// Await one task-local scoped operation. Cancellation drops the owned
    /// guard; no `Send` bound is imposed for browser or mobile adapters.
    pub async fn run_async<R, E, F>(self, operation: F) -> Result<R, LeaseScopeError<E>>
    where
        F: for<'op> AsyncFnOnce(&'op LeaseWitness<'op, K>) -> Result<R, E>,
    {
        self.ensure_held().map_err(LeaseScopeError::Lease)?;
        let witness = LeaseWitness {
            key: self.key,
            fence: self.fence,
            guard: &self.guard,
        };
        let result = operation(&witness).await;
        self.ensure_held().map_err(LeaseScopeError::Lease)?;
        result.map_err(LeaseScopeError::Operation)
    }
}

pub type AuthorityLeaseWitness<'a> = LeaseWitness<'a, AuthorityLeaseKey>;
pub type HeldAuthorityLease<G> = HeldFencedLease<AuthorityLeaseKey, G>;

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use super::*;

    #[derive(Debug)]
    struct TestGuard {
        key: AuthorityLeaseKey,
        fence: Rc<Cell<u64>>,
        held: Rc<Cell<bool>>,
    }

    impl FencedLeaseGuard<AuthorityLeaseKey> for TestGuard {
        fn key(&self) -> &AuthorityLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            FencingToken::new(self.fence.get()).expect("nonzero test fence")
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    fn key(namespace: u8) -> AuthorityLeaseKey {
        AuthorityLeaseKey::new(
            StorageNamespaceId::new([namespace; 32]).expect("nonzero namespace"),
            0x1234_5678,
            [9; 32],
        )
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn rejects_zero_identifiers_and_wrong_acquired_key() {
        assert_eq!(
            StorageNamespaceId::new([0; 32]),
            Err(LeaseError::ZeroStorageNamespace)
        );
        assert_eq!(FencingToken::new(0), Err(LeaseError::ZeroFencingToken));

        let requested = key(1);
        let result = HeldAuthorityLease::acquire(requested, |_| {
            Ok::<_, ()>(TestGuard {
                key: key(2),
                fence: Rc::new(Cell::new(1)),
                held: Rc::new(Cell::new(true)),
            })
        });
        assert!(matches!(
            result,
            Err(LeaseAcquireError::Lease(LeaseError::KeyMismatch))
        ));
    }

    #[test]
    fn detects_loss_and_fence_replacement_at_release_boundary() {
        let fence = Rc::new(Cell::new(7));
        let held = Rc::new(Cell::new(true));
        let lease = HeldAuthorityLease::acquire(key(1), |_| {
            Ok::<_, ()>(TestGuard {
                key: key(1),
                fence: Rc::clone(&fence),
                held: Rc::clone(&held),
            })
        })
        .expect("lease");
        let result = lease.run(|witness| {
            witness.ensure_held().expect("entry held");
            fence.set(8);
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(LeaseScopeError::Lease(LeaseError::FenceChanged))
        ));

        fence.set(9);
        held.set(true);
        let lease = HeldAuthorityLease::acquire(key(1), |_| {
            Ok::<_, ()>(TestGuard {
                key: key(1),
                fence: Rc::clone(&fence),
                held: Rc::clone(&held),
            })
        })
        .expect("lease");
        let result = lease.run(|_| {
            held.set(false);
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(LeaseScopeError::Lease(LeaseError::Lost))
        ));
    }

    #[test]
    fn task_local_async_scope_accepts_non_send_guard_and_future() {
        let marker = Rc::new(Cell::new(false));
        let lease = HeldAuthorityLease::acquire(key(3), |_| {
            Ok::<_, ()>(TestGuard {
                key: key(3),
                fence: Rc::new(Cell::new(1)),
                held: Rc::new(Cell::new(true)),
            })
        })
        .expect("lease");
        let result = block_on(lease.run_async(async |witness| {
            witness.ensure_held().expect("held");
            marker.set(true);
            Ok::<_, ()>(41_u8)
        }));
        assert_eq!(result.expect("scope"), 41);
        assert!(marker.get());
    }
}
