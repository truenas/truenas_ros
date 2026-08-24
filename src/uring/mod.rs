//! The shared io_uring engine: the raw UAPI surface ([`sys`]), the mmap'd
//! ring ([`ring`]), SQE staging with in-flight accounting and the
//! cancel-everything teardown ([`engine`]), the wake eventfd and cross-thread
//! loop flags ([`wake`]), the generation-guarded slot entry ([`slots`]), the
//! `user_data` routing codec ([`user_data`]), and opcode-support probing
//! ([`probe`]).
//!
//! Domain stacks build on this - `net` (the stream server/client roles)
//! today, the async fs reactor next - each bringing its own op-tag vocabulary
//! and completion dispatch. The engine deliberately knows neither: tags and
//! per-completion policy are passed in ([`engine::Engine::arm_wake`],
//! [`engine::Engine::cancel_and_reap_all`]), so one ring can serve several
//! domains' ops on a shared submission batch.

// Like `sys`, the engine keeps a deliberate superset surface: which items a
// build uses depends on the enabled domains (a lone role - or the engine
// feature by itself - leaves shared primitives unused, and domain tag space
// is declared before its domain lands). That asymmetry is expected, not dead
// code to prune.
#![allow(dead_code)]

/// Whether a ring that would not start is this environment rather than a
/// defect - and, where CI arms `TRUENAS_ROS_REQUIRE_IO_URING`, not even
/// that.
///
/// `EPERM`/`ENOSYS`/`EACCES` mean there is no io_uring here (an old kernel,
/// seccomp, `kernel.io_uring_disabled`). `ENOMEM` is the memlock ceiling:
/// every ring pins pages against `RLIMIT_MEMLOCK`, so a box running many
/// test binaries at once exhausts it. **Everything else is a defect** -
/// `EINVAL` above all, which is a rejected setup argument - and the caller
/// must panic rather than skip every assertion behind it.
///
/// One definition, because the alternative is what it replaced: three
/// unit-test skip helpers with three different ideas of "unavailable", one
/// of which swallowed the lot with `.ok()` and took twenty-one tests with
/// it.
#[cfg(all(test, not(loom)))]
pub(crate) fn setup_unavailable(e: crate::errno::Errno) -> bool {
    use crate::errno::Errno;
    let environmental = matches!(
        e,
        Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM
    );
    if environmental {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
    }
    environmental
}

#[cfg(feature = "net-server")]
pub(crate) mod bufring;
pub(crate) mod engine;
pub(crate) mod probe;
pub(crate) mod ring;
pub(crate) mod slots;
pub(crate) mod sys;
pub(crate) mod user_data;
pub(crate) mod wake;
