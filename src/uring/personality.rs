//! [`Personality`]: a registered io_uring credential snapshot, named per-SQE, and [`SelfRegistrar`]: the handle that
//! mints one from any thread while the ring's owner runs its loop.

use crate::errno::Errno;
use crate::sync::{Arc, Mutex};
use crate::uring::sys::{register_personality, unregister_personality};
use std::os::fd::RawFd;
use std::sync::PoisonError;

/// A registered io_uring personality: a kernel-held snapshot of one identity's credentials (fsuid/fsgid, supplementary
/// groups, capabilities, LSM label), stamped into an SQE's `personality` field. The kernel - not the library - performs
/// that operation's permission checks under it.
///
/// Mint one for the calling process with [`UringFs::register_self`](crate::uring_fs::UringFs::register_self), or for
/// another identity through the credential broker ([`CredHandle::register`](crate::uring_fs::CredHandle::register)).
/// Ids are never 0 (the kernel's allocator starts at 1), so a `Personality` always names a real registration on the
/// ring it came from. An id this ring never registered fails the operation with `EINVAL` at submission.
///
/// # An id is only meaningful on the ring that issued it
///
/// **A `Personality` carries no ring tag, and using one on the wrong ring does not fail - it runs the operation as a
/// different identity.** Each ring's id space starts at 1 (`XA_FLAGS_ALLOC1`, `io_uring.c:367`), and submission
/// resolves the id against that ring's table alone (`io_uring.c:2269-2273`), so two rings that have each registered
/// one identity both hold id 1.
///
/// A process driving more than one reactor must keep each `Personality` with the ring that minted it. Pairing a broker
/// handle to its ring where both are created, rather than by position in two lists, keeps them from drifting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Personality(pub(crate) u16);

impl Personality {
    /// The raw kernel id.
    pub fn id(self) -> u16 {
        self.0
    }

    /// Name an id registered elsewhere on **this** ring - the form a credential broker's reply takes once it has
    /// registered an identity on the reactor's behalf. Returns `None` for `0`, which is not a valid personality:
    /// **`sqe.personality == 0` means "no credential override", so an op stamped with it runs under the reactor
    /// thread's ambient credentials (the root daemon), bypassing the kernel's per-op identity check entirely.**
    ///
    /// A nonzero id this ring never registered is refused by the kernel with `EINVAL`. An id from a *different* ring
    /// is likely to name a **live registration here** and run the op under it (see [`Personality`]).
    pub fn from_raw(id: u16) -> Option<Personality> {
        (id != 0).then_some(Personality(id))
    }
}

/// The ring a [`SelfRegistrar`] registers on, for as long as that ring lives.
///
/// The ring closes it in its `Drop`, before its descriptor closes. A call holds the lock across its syscall, so the
/// descriptor cannot close, and its number cannot come to name another file, under a call in flight. **Do not copy
/// the descriptor out of the lock**: the syscall would then race the close, and a number that another ring took
/// since would get the registration.
#[derive(Debug)]
pub(crate) struct RingGate {
    /// The ring descriptor, `None` once the ring has dropped.
    fd: Mutex<Option<RawFd>>,
}

impl RingGate {
    pub(crate) fn new(fd: RawFd) -> Arc<RingGate> {
        Arc::new(RingGate {
            fd: Mutex::new(Some(fd)),
        })
    }

    /// The ring is about to close its descriptor: every later call fails `EBADF`.
    pub(crate) fn close(&self) {
        *self.fd.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Run `f` on the ring descriptor, which stays open for the whole call.
    fn with_fd<T>(&self, f: impl FnOnce(RawFd) -> crate::errno::Result<T>) -> crate::Result<T> {
        let fd = self.fd.lock().unwrap_or_else(PoisonError::into_inner);
        match *fd {
            Some(fd) => Ok(f(fd)?),
            None => Err(Errno::EBADF.into()),
        }
    }
}

/// A `Clone + Send + Sync` handle that registers the **calling thread's** credentials as a [`Personality`] on one
/// ring, from any thread, while the ring's owner runs its loop.
///
/// The kernel snapshots the credentials of the task that makes the call (`get_current_cred` in
/// `io_register_personality`, `io_uring/register.c`), and the raw `setresuid` family changes those of the calling
/// thread alone (`__sys_setresuid` commits to `current`, `kernel/sys.c`). So a thread that holds an identity registers
/// it here, and the loop then runs operations as that identity with no thread changing credentials again. The
/// snapshot is frozen at the call.
///
/// The handle grants no authority the caller lacks, since it registers only what the calling thread already is. A
/// call from a thread other than the loop's is sound because these rings are never `IORING_SETUP_SINGLE_ISSUER`,
/// which makes `__io_uring_register` refuse every task but the submitter with `EEXIST`. It serialises with the loop on
/// the ring's `uring_lock`, as every `io_uring_register(2)` does.
///
/// A [`Personality`] it returns belongs to this handle's ring alone (see [`Personality`] on why a crossed id does not
/// fail). Once the ring has dropped, every call fails with `EBADF`.
#[derive(Clone, Debug)]
pub struct SelfRegistrar {
    gate: Arc<RingGate>,
}

impl SelfRegistrar {
    pub(crate) fn new(gate: Arc<RingGate>) -> SelfRegistrar {
        SelfRegistrar { gate }
    }

    /// Register the calling thread's **current** credentials on the ring and return their id.
    pub fn register_self(&self) -> crate::Result<Personality> {
        let id = self.gate.with_fd(register_personality)?;
        Ok(Personality(id))
    }

    /// Unregister `who`, which this ring issued. Operations already submitted under it keep their credential
    /// reference, and a later one that names it fails `EINVAL` at submission. An id this ring does not hold fails
    /// `EINVAL` (`io_unregister_personality`, `io_uring/register.c`).
    pub fn unregister(&self, who: Personality) -> crate::Result<()> {
        self.gate.with_fd(|fd| unregister_personality(fd, who.0))
    }

    /// Whether the ring has dropped.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn ring_gone(&self) -> bool {
        self.gate.fd.lock().unwrap_or_else(PoisonError::into_inner).is_none()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// A closed gate refuses with `EBADF` and runs nothing: by then the number may name another file.
    #[test]
    fn a_closed_gate_runs_nothing() {
        let gate = RingGate::new(7);
        assert_eq!(gate.with_fd(Ok).unwrap(), 7);
        gate.close();
        let ran = gate.with_fd(|_| -> crate::errno::Result<()> { panic!("the call ran on a closed gate") });
        assert!(matches!(ran, Err(crate::Error::Errno(Errno::EBADF))));
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use crate::sync::atomic::{AtomicBool, Ordering};

    /// A call through the gate never runs once `close` has returned, in any interleaving of a registering thread and
    /// the ring's drop. `open` stands for the descriptor, which the ring closes only after `close` returns.
    #[test]
    fn loom_a_gated_call_never_runs_after_close_returns() {
        loom::model(|| {
            let gate = RingGate::new(7);
            let open = Arc::new(AtomicBool::new(true));
            let (g, o) = (Arc::clone(&gate), Arc::clone(&open));
            let caller = loom::thread::spawn(move || {
                let _ = g.with_fd(|_| {
                    assert!(o.load(Ordering::Acquire), "the call ran on a closed descriptor");
                    Ok(())
                });
            });
            gate.close();
            open.store(false, Ordering::Release);
            caller.join().unwrap();
        });
    }
}
