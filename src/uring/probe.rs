//! Generic opcode-support probing. `IORING_REGISTER_PROBE` is a control
//! syscall on an already-built ring (available far below every kernel floor
//! this crate imposes) that reports per-opcode support without executing
//! anything — the construction-time alternative to discovering a missing
//! opcode as a mysterious per-op `-EINVAL` at runtime. Domain-specific probes
//! (socket commands, the TLS ULP) live with their domains; this is the shared
//! mechanism.

use crate::uring::ring::Ring;
use crate::uring::sys::*;

/// Whether this kernel's io_uring supports `opcode`. Any register failure
/// reads as "unsupported" — fail closed; callers turn `false` into a clear
/// validation error (or record it and degrade, where the op is optional).
pub(crate) fn probe_op_supported(ring: &Ring, opcode: u8) -> bool {
    #[repr(C)]
    struct ProbeBuf {
        header: IoUringProbeHeader,
        ops: [IoUringProbeOp; 256],
    }
    // SAFETY: all-integer plain data; zeroed is a valid initial value (the
    // kernel requires the probe argument zeroed and fills it).
    let mut buf: Box<ProbeBuf> = Box::new(unsafe { std::mem::zeroed() });
    // SAFETY: `buf` is a valid, zeroed probe argument sized for 256 op
    // entries, live across the call; the ring fd is live.
    let rc = unsafe {
        io_uring_register(
            ring.raw_fd(),
            IORING_REGISTER_PROBE,
            (&mut *buf as *mut ProbeBuf).cast(),
            buf.ops.len() as u32,
        )
    };
    if rc.is_err() {
        return false;
    }
    buf.header.last_op >= opcode
        && buf.ops[opcode as usize].flags & IO_URING_OP_SUPPORTED != 0
}
