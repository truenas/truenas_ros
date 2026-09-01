//! The core half of the wake path: arming the wake-eventfd `READ` and the
//! drain-quiescence check. The role wrapper owns what a wake *delivers*
//! (draining injected work, the graceful-drain state machine).

use super::Reactor;
use crate::errno;
use crate::net::core::conn::{Op, pack};

impl<U> Reactor<U> {
    /// If a graceful drain has fully quiesced, stop.
    ///
    /// Quiescence is not "no live connections" alone. A task on the
    /// embedded fs reactor outlives the connection that spawned it -
    /// an owner gone mid-chain is explicitly tolerated - and can be
    /// pending with no op in flight, so a check that counts
    /// connections would stop the loop with that work unfinished and
    /// drop it at teardown. `pending_tasks` is zero for a server with
    /// no fs reactor, so this is the same test it always was there.
    ///
    /// A task that never finishes therefore holds a drain open; the
    /// grace period remains the backstop that ends it regardless.
    pub(crate) fn maybe_finish_drain(&mut self) {
        if self.draining
            && self.table.active() == 0
            && self.pending_tasks.get() == 0
        {
            self.engine.shared.request_stop();
        }
    }

    /// Arm the wake-eventfd `READ` under the stream wake tag (the mechanics --
    /// and why a direct counter read beats a poll - live in
    /// [`crate::uring::engine::Engine::arm_wake`]).
    pub(crate) fn arm_wake(&mut self) -> errno::Result<()> {
        self.engine.arm_wake(pack(Op::Wake, 0, 0))
    }
}
