//! The "is this run privileged" gate shared by the live suites
//! (`test/uring_fs.rs`, `test/net_server.rs`).
//!
//! A root-only assertion that returns early on an unprivileged runner tests
//! nothing, and libtest reports that early return as a pass - there is no
//! signal distinguishing it from a real one. `TRUENAS_ROS_REQUIRE_ROOT` turns
//! the skip into a failure where CI arms it: the QEMU job, which runs as root
//! over ssh and is the only place these paths execute at all. The
//! unprivileged `ci.yml` lane leaves it unset and skips, which is correct -
//! it cannot become another uid.

/// True when the process is root. Callers that merely *branch* on privilege
/// (asserting a refusal only an unprivileged caller can provoke, say) want
/// this; callers about to skip their assertions want [`root_or_skip`].
#[allow(dead_code)] // each including binary uses the half it needs
pub fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Whether a root-only test may proceed. `false` means the caller returns
/// without asserting; under `TRUENAS_ROS_REQUIRE_ROOT` that skip is a test
/// failure instead. `what` names the capability the test needed, so a red
/// run says which privilege the runner turned out not to have.
#[allow(dead_code)] // see `is_root`
pub fn root_or_skip(what: &str) -> bool {
    if is_root() {
        return true;
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
        "TRUENAS_ROS_REQUIRE_ROOT is set but this process is not root: {what}"
    );
    false
}
