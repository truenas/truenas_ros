//! A ring's fixed-buffer table: slots the kernel pins once, so
//! `READ_FIXED`/`WRITE_FIXED` skip the per-call page walk and cannot name
//! unregistered memory.
//!
//! Registered sparse at the owner's size and filled slot by slot
//! ([`install`](FixedTable::install), [`clear`](FixedTable::clear)). Slot
//! ownership is the owner's business. The table holds the ring's fd
//! number, not a reference: the owner must stop using it before the ring
//! closes (`BodyPool::detach_table`), and the ring's close unregisters
//! everything still installed.

use std::os::fd::RawFd;

use super::aligned::AlignedBuf;
use super::sys::{
    IORING_MAX_REG_BUFFERS, register_buffer_update, register_buffers_sparse,
};
use crate::errno::{self, Errno};

/// Whether this process holds `CAP_IPC_LOCK` (effective set). A ring made
/// with it has its registered buffers uncharged to `RLIMIT_MEMLOCK`
/// (`io_uring_create`); without it every install is charged and an
/// unprivileged limit refuses them, so the owner registers no table.
pub(crate) fn ipc_lock_held() -> bool {
    const CAP_IPC_LOCK: u32 = 14;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << CAP_IPC_LOCK) != 0)
}

/// A registered, sparse fixed-buffer table on one ring.
pub(crate) struct FixedTable {
    ring: RawFd,
    slots: u32,
}

impl FixedTable {
    /// Register `slots` empty slots on `ring_fd`; `EINVAL` for 0 or
    /// above the kernel's ceiling.
    pub(crate) fn register(
        ring_fd: RawFd,
        slots: u32,
    ) -> errno::Result<FixedTable> {
        if slots == 0 || slots > IORING_MAX_REG_BUFFERS {
            return Err(Errno::EINVAL);
        }
        register_buffers_sparse(ring_fd, slots)?;
        Ok(FixedTable {
            ring: ring_fd,
            slots,
        })
    }

    /// How many slots the table has.
    pub(crate) fn slots(&self) -> u32 {
        self.slots
    }

    /// Pin `buf`'s whole capacity behind `slot`. The buffer must stay
    /// mapped and unmoved until [`clear`](FixedTable::clear) or the
    /// ring's close.
    pub(crate) fn install(
        &self,
        slot: u16,
        buf: &AlignedBuf,
    ) -> errno::Result<()> {
        if u32::from(slot) >= self.slots {
            return Err(Errno::EINVAL);
        }
        register_buffer_update(
            self.ring,
            u32::from(slot),
            buf.base(),
            buf.capacity(),
        )
    }

    /// Empty `slot`, unpinning whatever it named.
    pub(crate) fn clear(&self, slot: u16) -> errno::Result<()> {
        if u32::from(slot) >= self.slots {
            return Err(Errno::EINVAL);
        }
        register_buffer_update(self.ring, u32::from(slot), std::ptr::null(), 0)
    }
}

impl std::fmt::Debug for FixedTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedTable")
            .field("slots", &self.slots)
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::uring::ring::RingFd;

    fn ring() -> Option<RingFd> {
        // No ring under Miri: `io_uring_setup` is an unsupported foreign
        // call that aborts the interpreter, not an errno to skip on.
        if cfg!(miri) {
            return None;
        }
        match RingFd::setup(8) {
            Ok(r) => Some(r),
            Err(e) if crate::uring::setup_unavailable(e) => None,
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    #[test]
    fn a_table_installs_clears_and_bounds_its_slots() {
        let Some(r) = ring() else {
            return;
        };
        let t = FixedTable::register(r.raw_fd(), 4).expect("registers");
        assert_eq!(t.slots(), 4);
        let buf = AlignedBuf::new(1 << 16).expect("allocates");
        t.install(2, &buf).expect("installs");
        // Re-install over a live slot is a replace, not an error.
        t.install(2, &buf).expect("replaces");
        t.clear(2).expect("clears");
        assert_eq!(t.install(4, &buf), Err(Errno::EINVAL), "past the table");
        assert_eq!(t.clear(9), Err(Errno::EINVAL));
    }

    #[test]
    fn the_table_refuses_the_kernels_ceiling_itself() {
        let Some(r) = ring() else {
            return;
        };
        assert_eq!(
            FixedTable::register(r.raw_fd(), IORING_MAX_REG_BUFFERS + 1).err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(
            FixedTable::register(r.raw_fd(), 0).err(),
            Some(Errno::EINVAL)
        );
    }
}
