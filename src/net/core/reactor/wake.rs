//! The core half of the wake path: arming the wake-eventfd `READ` and the
//! drain-quiescence check. The role wrapper owns what a wake *delivers*
//! (draining injected work, the graceful-drain state machine).

use super::Reactor;
use crate::errno;
use crate::net::core::conn::{pack, Op};
use std::sync::atomic::Ordering;

impl<U> Reactor<U> {
    /// If a graceful drain has fully quiesced (no live connections), stop.
    pub(crate) fn maybe_finish_drain(&mut self) {
        if self.draining && self.table.active() == 0 {
            self.engine.shared.stop.store(true, Ordering::Release);
        }
    }

    /// Arm the wake-eventfd `READ` under the stream wake tag (the mechanics —
    /// and why a direct counter read beats a poll — live in
    /// [`crate::uring::engine::Engine::arm_wake`]).
    pub(crate) fn arm_wake(&mut self) -> errno::Result<()> {
        self.engine.arm_wake(pack(Op::Wake, 0, 0))
    }
}
