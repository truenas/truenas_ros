//! The core half of the wake path: arming the wake-eventfd `READ` and the drain-quiescence check. The role wrapper owns
//! what a wake *delivers* (draining injected work, the graceful-drain state machine).

use super::Reactor;
use crate::errno;
use crate::net::core::conn::{Op, pack};

impl<U> Reactor<U> {
    /// If a graceful drain has fully quiesced, stop.
    ///
    /// Quiescence counts `pending_tasks` as well as connections, since a task on the embedded fs reactor can outlive
    /// the connection that spawned it and be pending with no op in flight. A task that never finishes holds the drain
    /// open until the grace period ends it.
    ///
    /// Freeing a slot (`reclaim_slot`) re-runs this only for the connection term, so the role loop also re-reads it
    /// once per pass, or a drain whose last blocker is a task would sit out its whole grace period.
    pub(crate) fn maybe_finish_drain(&mut self) {
        if self.draining && self.table.active() == 0 && self.pending_tasks.get() == 0 {
            self.engine.shared.request_stop();
        }
    }

    /// Arm the wake-eventfd `READ` under the stream wake tag (the mechanics -- and why a direct counter read beats a
    /// poll - live in [`crate::uring::engine::Engine::arm_wake`]).
    pub(crate) fn arm_wake(&mut self) -> errno::Result<()> {
        self.engine.arm_wake(pack(Op::Wake, 0, 0))
    }
}
