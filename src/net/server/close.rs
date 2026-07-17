//! The one piece of teardown that reaches back into the server's listeners:
//! re-arming a listener parked on a full pool once a slot frees. The teardown
//! *mechanics* — close reasons, the SHUTDOWN-then-CLOSE FIN forcing, the CLOSE
//! itself, op-count draining, and slot reclamation — are role-agnostic and live
//! on [`Reactor`](crate::net::core::reactor); reclamation raises `pool_freed`,
//! and the loop calls this to consume it.

use super::Server;
use crate::errno;

// This path runs no handler code, so it needs no closure bounds — it works on
// any `Server`.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// A pool slot just freed (`Reactor::pool_freed`): re-arm any listener whose
    /// multishot accept was parked on a full pool. Never while shutting down or
    /// draining — the re-arm guards leave the listener down (the drain path
    /// relies on this, so a `pool_freed` set during `cancel_and_reap_all` is
    /// safely ignored).
    pub(super) fn rearm_parked_accepts(&mut self) -> errno::Result<()> {
        if !self.core.stopping() && !self.core.draining {
            for lidx in 0..self.listeners.len() as u32 {
                if self.listeners[lidx as usize].awaiting_slot {
                    self.arm_accept(lidx)?;
                }
            }
        }
        Ok(())
    }
}
