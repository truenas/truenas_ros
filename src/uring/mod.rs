//! The shared io_uring engine: the raw UAPI surface ([`sys`]), the mmap'd ring ([`ring`]), SQE staging with in-flight
//! accounting and the cancel-everything teardown ([`engine`]), the wake eventfd and cross-thread loop flags ([`wake`]),
//! the generation-guarded slot entry ([`slots`]), the `user_data` routing codec ([`user_data`]), and opcode-support
//! probing ([`probe`]).
//!
//! Domain stacks build on this, each bringing its own op-tag vocabulary and completion dispatch. The engine knows
//! neither, since tags and per-completion policy are passed in ([`engine::Engine::arm_wake`],
//! [`engine::Engine::cancel_and_reap_all`]), so one ring can serve several domains' ops on a shared submission batch.

// Which items a build uses depends on the enabled domains, so an unused item here is expected, not dead code to prune.
#![allow(dead_code)]

/// Whether a ring that would not start is this environment rather than a defect - and, where CI arms
/// `TRUENAS_ROS_REQUIRE_IO_URING`, not even that.
///
/// `EPERM`/`ENOSYS`/`EACCES` mean there is no io_uring here (an old kernel, seccomp, `kernel.io_uring_disabled`).
/// `ENOMEM` means both allocation paths in [`RingFd::setup`](ring::RingFd::setup) failed, from `RLIMIT_MEMLOCK` or a
/// host too fragmented even for the retry, so raising `ulimit -l` is not always the answer. **Everything else is a
/// defect**, `EINVAL` above all, and the caller must panic rather than skip every assertion behind it.
///
/// Every skip helper calls this, since a local copy of the list is how a skip stops being visible to CI.
#[cfg(all(test, not(loom)))]
pub(crate) fn setup_unavailable(e: crate::errno::Errno) -> bool {
    use crate::errno::Errno;
    let environmental = matches!(e, Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM);
    if environmental {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
    }
    environmental
}

/// The system page size, or 4096 if `sysconf` somehow refuses.
///
/// One definition for the `uring` modules: ring, SQE and buffer-ring regions are all sized in whole pages, and a wrong
/// answer here is a short mapping.
pub(crate) fn page_size() -> usize {
    // SAFETY: `sysconf` with a valid name reads no memory and returns a long.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as usize } else { 4096 }
}

#[cfg(feature = "net-server")]
pub(crate) mod bufring;
pub(crate) mod engine;
pub(crate) mod force_async;
pub(crate) mod personality;
pub(crate) mod probe;
pub(crate) mod ring;
pub(crate) mod slots;
pub(crate) mod sys;
pub(crate) mod user_data;
pub(crate) mod wake;
