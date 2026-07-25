use std::collections::{BTreeSet, VecDeque};

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestTracker {
    generation: u64,
    maximum_live: usize,
    live: BTreeSet<u64>,
    completed_order: VecDeque<u64>,
    completed: BTreeSet<u64>,
}

impl RequestTracker {
    pub fn new(generation: u64, maximum_live: usize) -> Result<Self, RequestTrackerError> {
        if maximum_live == 0 {
            return Err(RequestTrackerError::ZeroCapacity);
        }
        Ok(Self {
            generation,
            maximum_live,
            live: BTreeSet::new(),
            completed_order: VecDeque::with_capacity(maximum_live),
            completed: BTreeSet::new(),
        })
    }

    pub fn admit(&mut self, request_id: u64, generation: u64) -> Result<(), RequestTrackerError> {
        if request_id == 0 {
            return Err(RequestTrackerError::ZeroRequestId);
        }
        if generation != self.generation {
            return Err(RequestTrackerError::StaleGeneration {
                expected: self.generation,
                actual: generation,
            });
        }
        if self.live.contains(&request_id) || self.completed.contains(&request_id) {
            return Err(RequestTrackerError::DuplicateRequestId(request_id));
        }
        if self.live.len() >= self.maximum_live {
            return Err(RequestTrackerError::CapacityExceeded(self.maximum_live));
        }
        self.live.insert(request_id);
        Ok(())
    }

    pub fn complete(&mut self, request_id: u64) -> Result<(), RequestTrackerError> {
        if !self.live.remove(&request_id) {
            return Err(RequestTrackerError::UnknownRequestId(request_id));
        }
        self.completed.insert(request_id);
        self.completed_order.push_back(request_id);
        while self.completed_order.len() > self.maximum_live {
            if let Some(expired) = self.completed_order.pop_front() {
                self.completed.remove(&expired);
            }
        }
        Ok(())
    }

    pub fn revoke_and_advance(&mut self, generation: u64) -> Result<(), RequestTrackerError> {
        if generation <= self.generation {
            return Err(RequestTrackerError::NonIncreasingGeneration {
                previous: self.generation,
                next: generation,
            });
        }
        self.generation = generation;
        self.live.clear();
        self.completed.clear();
        self.completed_order.clear();
        Ok(())
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestTrackerError {
    #[error("request tracker capacity must be nonzero")]
    ZeroCapacity,
    #[error("request ID must be nonzero")]
    ZeroRequestId,
    #[error("request generation {actual} is stale; current generation is {expected}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("duplicate or replayed request ID {0}")]
    DuplicateRequestId(u64),
    #[error("live request capacity {0} exceeded")]
    CapacityExceeded(usize),
    #[error("request ID {0} is not live")]
    UnknownRequestId(u64),
    #[error("generation must increase from {previous}; got {next}")]
    NonIncreasingGeneration { previous: u64, next: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_duplicates_replays_and_capacity_exhaustion() {
        let mut tracker = RequestTracker::new(7, 2).expect("valid");
        assert_eq!(tracker.admit(0, 7), Err(RequestTrackerError::ZeroRequestId));
        tracker.admit(1, 7).expect("first request");
        assert_eq!(
            tracker.admit(1, 7),
            Err(RequestTrackerError::DuplicateRequestId(1))
        );
        tracker.admit(2, 7).expect("second request");
        assert_eq!(
            tracker.admit(3, 7),
            Err(RequestTrackerError::CapacityExceeded(2))
        );
        tracker.complete(1).expect("live request");
        assert_eq!(
            tracker.admit(1, 7),
            Err(RequestTrackerError::DuplicateRequestId(1))
        );
    }

    #[test]
    fn policy_generation_revokes_all_in_flight_work() {
        let mut tracker = RequestTracker::new(4, 2).expect("valid");
        tracker.admit(1, 4).expect("live");
        tracker.revoke_and_advance(5).expect("advances");
        assert_eq!(tracker.live_count(), 0);
        assert_eq!(
            tracker.admit(2, 4),
            Err(RequestTrackerError::StaleGeneration {
                expected: 5,
                actual: 4
            })
        );
        tracker.admit(2, 5).expect("current generation");
    }
}
