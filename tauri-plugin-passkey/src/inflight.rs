//! Single-flight guard: at most one `register`/`authenticate` ceremony runs at a
//! time. Every backend keeps per-ceremony state (a PIN channel, a pending
//! ASAuthorizationController, a Credential Manager call) that a second
//! concurrent ceremony would clobber, so the second one is rejected with
//! [`crate::Error::Busy`] instead. `cancel` deliberately does not take the
//! guard: it must work while a ceremony is running.

use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub(crate) struct InFlight(AtomicBool);

/// Held for the duration of a ceremony; clears the flag on drop.
#[derive(Debug)]
pub(crate) struct InFlightGuard<'a>(&'a InFlight);

impl InFlight {
    /// Claim the single ceremony slot, or fail with [`crate::Error::Busy`] if a
    /// ceremony already holds it.
    pub fn acquire(&self) -> crate::Result<InFlightGuard<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| InFlightGuard(self))
            .map_err(|_| crate::Error::Busy)
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0 .0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_while_held_is_busy() {
        let inflight = InFlight::default();
        let _guard = inflight.acquire().unwrap();
        let err = inflight.acquire().unwrap_err();
        assert_eq!(err.kind(), "busy");
    }

    #[test]
    fn acquire_succeeds_again_after_guard_drops() {
        let inflight = InFlight::default();
        drop(inflight.acquire().unwrap());
        assert!(inflight.acquire().is_ok());
    }
}
