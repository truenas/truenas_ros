//! `secrets` through its public surface, across a real `fork(2)`.
//!
//! The unit tests in `src/secrets.rs` drive the mapping directly. These drive
//! the shape a consumer has, and the one the `Send`/`Sync` impls exist for: a
//! credential snapshot behind a shared `Arc`, a process that forks after
//! building it, and a child whose teardown runs its own destructors.
//!
//! Skips when the kernel has no `memfd_secret`; the QEMU job sets
//! `TRUENAS_ROS_REQUIRE_SECRETMEM` so a skip there is a failure.
#![cfg(all(target_os = "linux", feature = "secrets"))]

use std::sync::Arc;

use truenas_ros::secrets::{Secret, SecretMem};

const KEY: &[u8; 31] = b"AKIAIOSFODNN7EXAMPLE/wJalrXUtnF";

fn secretmem_or_skip() -> bool {
    if SecretMem::available() {
        return true;
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
        "memfd_secret unavailable but TRUENAS_ROS_REQUIRE_SECRETMEM is set"
    );
    false
}

/// Fork, returning 0 in the child as `fork(2)` does.
///
/// Each child branch is inline rather than passed in as a closure: the child
/// has to own the handles to drop them, and a `move` closure would take them
/// from the parent. A branch ending in `_exit` diverges, so the parent's
/// copies survive it.
fn fork_now() -> libc::pid_t {
    // SAFETY: `fork` in a test binary; each child below only drops its own
    // values, or reads one address, and then `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    pid
}

fn wait_for(pid: libc::pid_t) -> libc::c_int {
    let mut status = 0;
    // SAFETY: waiting on our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    status
}

fn key_region() -> Arc<SecretMem> {
    let mut mem = SecretMem::with_capacity(KEY.len()).expect("secret region");
    mem.as_mut_slice().copy_from_slice(KEY);
    Arc::new(mem)
}

/// The credential-snapshot pattern: a signing key behind an `Arc`, a worker
/// holding a second handle, a fork, and then the child's last handle going
/// out of scope. The parent must still hold the key it signs with.
#[test]
fn a_child_dropping_its_last_handle_leaves_the_parent_signing() {
    if !secretmem_or_skip() {
        return;
    }
    let key = key_region();
    let worker = Arc::clone(&key);

    let pid = fork_now();
    if pid == 0 {
        // Both handles go here, so the child's refcount reaches zero and
        // `SecretMem::drop` runs — the teardown of a forked worker.
        drop(worker);
        drop(key);
        // SAFETY: async-signal-safe exit; nothing buffered to flush.
        unsafe { libc::_exit(0) };
    }
    let status = wait_for(pid);

    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the child's teardown did not exit cleanly: status {status}"
    );
    assert_eq!(
        key.as_slice(),
        &KEY[..],
        "a forked child's teardown reached the parent's key"
    );
    // Still a working region, not just intact bytes.
    assert_eq!(key.len(), KEY.len());
    assert_eq!(Arc::strong_count(&key), 2, "the parent lost a handle");
}

/// The other half: the address the child inherited is not mapped there, so
/// reading it faults instead of yielding key material.
#[test]
fn a_forked_child_cannot_read_the_key() {
    if !secretmem_or_skip() {
        return;
    }
    let key = key_region();
    let addr = key.as_slice().as_ptr() as usize;

    let pid = fork_now();
    if pid == 0 {
        // SAFETY: deliberately reading an address this process should not
        // have. Faulting is the pass condition; the parent checks the signal.
        let first = unsafe { std::ptr::read_volatile(addr as *const u8) };
        // Reached only if the mapping was inherited, which is the failure —
        // exit non-zero, and make the read observable so it is not elided.
        unsafe { libc::_exit(if first == KEY[0] { 2 } else { 3 }) };
    }
    let status = wait_for(pid);

    assert!(
        libc::WIFSIGNALED(status),
        "the child read the parent's secret instead of faulting (status \
         {status}, exit {})",
        libc::WEXITSTATUS(status)
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSEGV,
        "expected SIGSEGV on the unmapped region"
    );
    assert_eq!(key.as_slice(), &KEY[..], "the parent's key changed");
}

/// `Secret` wraps the same region, and is what a caller reaches for first.
#[test]
fn a_secret_survives_a_childs_teardown() {
    if !secretmem_or_skip() {
        return;
    }
    let secret = Arc::new(Secret::new(KEY).expect("secret"));
    let handed_off = Arc::clone(&secret);

    let pid = fork_now();
    if pid == 0 {
        drop(handed_off);
        drop(secret);
        // SAFETY: as above.
        unsafe { libc::_exit(0) };
    }
    let status = wait_for(pid);

    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status}"
    );
    assert_eq!(secret.as_bytes(), &KEY[..]);
    assert_eq!(format!("{secret:?}"), "Secret(..)");
}
