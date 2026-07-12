//! The core half of the wake path: arming the wake-eventfd `READ` and the
//! drain-quiescence check. The role wrapper owns what a wake *delivers*
//! (draining injected work, the graceful-drain state machine).

use super::Reactor;
use crate::errno;
use crate::net::core::conn::{pack, Op};
use crate::net::core::sys::*;
use std::sync::atomic::Ordering;

impl<U> Reactor<U> {
    /// If a graceful drain has fully quiesced (no live connections), stop.
    pub(crate) fn maybe_finish_drain(&mut self) {
        if self.draining && self.table.active() == 0 {
            self.shared.stop.store(true, Ordering::Release);
        }
    }

    pub(crate) fn arm_wake(&mut self) -> errno::Result<()> {
        let fd = self.shared.wake.as_raw_fd();
        // Read the eventfd's 8-byte counter directly rather than polling it: the
        // READ auto-arms io_uring's internal fast-poll (exactly as our socket
        // recvs do) and completes only once the fd is readable, draining the
        // counter to 0 in the same op — no separate poll SQE, no follow-up
        // read() syscall.
        let buf = std::ptr::addr_of_mut!(self.pads.wake_buf) as u64;
        self.stage(pack(Op::Wake, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_READ;
            sqe.fd = fd;
            sqe.addr = buf;
            sqe.len = 8;
        })
    }
}
