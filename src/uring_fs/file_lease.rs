//! Read leases on files a ring holds, and the breaks of them that reach the ring.
//!
//! A read lease (`F_SETLEASE`, `fcntl(2)`) asks the kernel to warn its holder when anyone else opens the file for
//! writing or truncates it, any process at all (`__break_lease` in `fs/locks.c`). The kernel refuses one with `EAGAIN`
//! while the file is open for writing anywhere. The one who broke it waits until the holder gives the lease back, for
//! at most `/proc/sys/fs/lease-break-time` seconds, after which the kernel drops a lease held from user space and lets
//! them go on. One who opens with `O_NONBLOCK` is answered `EWOULDBLOCK` at once, once the break has begun, and every
//! open on the ring does, through the special-file guard ([`SpecialFiles::Guard`](super::SpecialFiles::Guard)), which
//! strips the flag again once the open is done.
//!
//! The warning is a signal. A ring takes a lease with `F_SETSIG` set to [`signal`], a realtime signal, which carries
//! the number of the leased descriptor, and with `F_SETOWN_EX` naming its own thread, so the signal goes to that thread
//! alone. A realtime signal the kernel cannot queue comes as `SIGIO` instead, with no descriptor (`send_sigio_to_task`
//! in `fs/fcntl.c`). Either one ends the process on a thread that has not blocked it, so [`block_signals`] blocks both
//! on the main thread before any other thread exists, as [`crate::signal::block`] blocks the daemon's signals, and a
//! ring refuses a lease while its own thread has them unblocked.
//!
//! The ring reads them from a `signalfd(2)` it polls, with a plain read on its own thread, since a signalfd takes the
//! signals of the thread that reads it (`signalfd_read` in `fs/signalfd.c`), and a read on an io-wq worker would find
//! none of the ring's. A signal names only a descriptor's number, which may belong to a newer lease by the time the
//! ring reads it. So a break is reported only for a lease of the ring's whose descriptor `F_GETLEASE` answers
//! `F_UNLCK`, as it does while a lease is broken and once the kernel dropped it (`target_leasetype` in `fs/locks.c`),
//! and a `SIGIO` has the ring ask so of every lease it holds. Each break reaches the handler the host was given, once.

use std::collections::HashMap;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use crate::errno::{Errno, retry_on_eintr};
use crate::sync::Arc;
use crate::uring::engine::Engine;
use crate::uring::sys::IORING_OP_POLL_ADD;
use crate::uring::user_data::pack_raw;

use super::core::{FsConn, TAG_FILE_LEASE};

/// The `fcntl(2)` commands and the owner the libc crate lacks for this target, as `include/uapi/asm-generic/fcntl.h`
/// defines them.
const F_SETSIG: libc::c_int = 10;
const F_SETOWN_EX: libc::c_int = 15;
const F_OWNER_TID: libc::c_int = 0;

/// `struct f_owner_ex` of the same header.
#[repr(C)]
struct OwnerEx {
    kind: libc::c_int,
    pid: libc::pid_t,
}

/// The realtime signal a break of a lease comes as, the first that glibc leaves free (`SIGRTMIN`, past the two its
/// threads keep).
pub fn signal() -> libc::c_int {
    libc::SIGRTMIN()
}

/// The two signals a break comes as, [`signal`] and `SIGIO`.
fn signals() -> libc::sigset_t {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `sigemptyset` initializes the set, and both signals are valid numbers, so neither call can fail.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), signal());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGIO);
        set.assume_init()
    }
}

/// Block the two signals a break of a lease comes as on the calling thread, and so on every thread it starts
/// afterwards, which inherits the mask.
///
/// Call it on the main thread before any other thread exists, as [`crate::signal::block`] is called, since either
/// signal ends the process on a thread that has it unblocked. A ring refuses a lease while its own thread has them
/// unblocked ([`FsConn::file_lease`]).
pub fn block_signals() -> crate::Result<()> {
    let set = signals();
    // SAFETY: a valid set, and the old mask may be null.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) };
    if rc != 0 {
        return Err(Errno::from_raw(rc).into());
    }
    Ok(())
}

/// Whether the calling thread has both signals blocked.
fn blocked_here() -> bool {
    let mut old = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: a null set changes nothing and writes the current mask.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), old.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: written by the call that succeeded above.
    let old = unsafe { old.assume_init() };
    // SAFETY: a valid set and valid numbers.
    unsafe { libc::sigismember(&old, signal()) == 1 && libc::sigismember(&old, libc::SIGIO) == 1 }
}

/// A read lease a ring holds, as [`FsConn::file_lease`] gave it, which a break names and [`FsConn::release_file_lease`]
/// gives back.
///
/// It is the descriptor's number and a serial, so a lease taken again on a descriptor of the same number is another.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileLeaseId {
    fd: RawFd,
    serial: u64,
}

/// The handler a break reaches, with the lease and a facade on the ring.
pub(crate) type BreakHandler = Box<dyn FnMut(FileLeaseId, &mut FsConn<'_>)>;

/// One lease the ring holds, with the descriptor it is on, kept open so its number names nothing else while the lease
/// lasts.
struct Held {
    serial: u64,
    file: Arc<OwnedFd>,
    /// Whether its break was reported, so it is reported once.
    broken: bool,
}

/// The leases a ring holds, by the number of their descriptors, and the signalfd their breaks arrive on.
#[derive(Default)]
pub(crate) struct FileLeases {
    held: HashMap<RawFd, Held>,
    serial: u64,
    signalfd: Option<OwnedFd>,
    /// Whether the poll of the signalfd waits to be armed again, since staging it failed. The next completion of the
    /// ring arms it.
    unarmed: bool,
    handler: Option<BreakHandler>,
    /// Whether a handler was set, which stays true while it runs and is taken out of `handler`.
    heard: bool,
    /// How many signals the ring has read, which a test waits on.
    #[cfg(all(test, not(loom)))]
    pub(crate) read: u64,
    /// How many of them were `SIGIO`.
    #[cfg(all(test, not(loom)))]
    pub(crate) sigio: u64,
}

impl FileLeases {
    /// Set the handler every break reaches. Only the net server's host gives one.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn set_handler(&mut self, handler: BreakHandler) {
        self.handler = Some(handler);
        self.heard = true;
    }

    /// Whether the ring holds no lease.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn held_none(&self) -> bool {
        self.held.is_empty()
    }

    /// Take a read lease on `file`, as [`FsConn::file_lease`] says.
    pub(crate) fn take(&mut self, eng: &mut Engine, file: &Arc<OwnedFd>) -> crate::Result<FileLeaseId> {
        if !self.heard || !blocked_here() {
            return Err(Errno::EINVAL.into());
        }
        let fd = file.as_raw_fd();
        if self.held.contains_key(&fd) {
            return Err(Errno::EBUSY.into());
        }
        if self.signalfd.is_none() {
            let set = signals();
            let flags = libc::SFD_CLOEXEC | libc::SFD_NONBLOCK;
            // SAFETY: a valid set, and -1 asks for a new descriptor.
            let raw = retry_on_eintr(|| unsafe { libc::signalfd(-1, &set, flags) })?;
            // SAFETY: a new descriptor no one else owns.
            self.signalfd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            self.unarmed = true;
        }
        self.arm(eng);
        let owner = OwnerEx {
            kind: F_OWNER_TID,
            // SAFETY: gettid has no preconditions.
            pid: unsafe { libc::gettid() },
        };
        // SAFETY: `fd` is open for the call, since `file` holds it, and `owner` outlives the call that reads it. The
        // signal and the owner come first, so a break right after F_SETLEASE finds them, and since F_SETLEASE makes the
        // whole process the owner where none is set (`lease_setup` in `fs/locks.c`), whose signal any thread that has
        // it unblocked would take, and die of.
        unsafe {
            retry_on_eintr(|| libc::fcntl(fd, F_SETSIG, signal()))?;
            let owner: *const OwnerEx = &owner;
            retry_on_eintr(|| libc::fcntl(fd, F_SETOWN_EX, owner))?;
            retry_on_eintr(|| libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK))?;
        }
        self.serial += 1;
        let serial = self.serial;
        let held = Held {
            serial,
            file: Arc::clone(file),
            broken: false,
        };
        self.held.insert(fd, held);
        Ok(FileLeaseId { fd, serial })
    }

    /// Give back the lease `id`, as [`FsConn::release_file_lease`] says.
    pub(crate) fn release(&mut self, id: FileLeaseId) -> crate::Result<()> {
        match self.held.get(&id.fd) {
            Some(held) if held.serial == id.serial => {}
            _ => return Err(Errno::ENOENT.into()),
        }
        // SAFETY: the held descriptor is open for the call. A lease the kernel dropped answers EAGAIN, and is given
        // back all the same.
        let rc = retry_on_eintr(|| unsafe { libc::fcntl(id.fd, libc::F_SETLEASE, libc::F_UNLCK) });
        self.held.remove(&id.fd);
        match rc {
            Ok(_) | Err(Errno::EAGAIN) => Ok(()),
            Err(errno) => Err(errno.into()),
        }
    }

    /// Stage the poll of the signalfd, unless it waits on none or one is staged. A failure leaves it for the next
    /// completion.
    pub(crate) fn arm(&mut self, eng: &mut Engine) {
        let Some(signalfd) = &self.signalfd else {
            return;
        };
        if !self.unarmed {
            return;
        }
        let raw = signalfd.as_raw_fd();
        let staged = eng.stage(pack_raw(TAG_FILE_LEASE, 0, 0), |sqe| {
            sqe.opcode = IORING_OP_POLL_ADD;
            sqe.fd = raw;
            // `poll32_events` overlays `op_flags`.
            sqe.op_flags = libc::POLLIN as u32;
        });
        self.unarmed = staged.is_err();
    }

    /// Read every signal the signalfd holds, arm its poll again, and give back the leases they found broken, as the
    /// module says.
    pub(crate) fn on_readable(&mut self, eng: &mut Engine) -> Vec<FileLeaseId> {
        self.unarmed = true;
        let mut broken = Vec::new();
        let Some(signalfd) = &self.signalfd else {
            return broken;
        };
        let raw = signalfd.as_raw_fd();
        let mut every = false;
        let mut infos = [MaybeUninit::<libc::signalfd_siginfo>::uninit(); 16];
        loop {
            let len = size_of::<libc::signalfd_siginfo>() * infos.len();
            // SAFETY: the buffer holds `len` bytes, and the signalfd is open and non-blocking, so the read returns at
            // once.
            let n = retry_on_eintr(|| unsafe { libc::read(raw, infos.as_mut_ptr().cast(), len) });
            let Ok(n) = n else { break };
            let count = n as usize / size_of::<libc::signalfd_siginfo>();
            for info in &infos[..count] {
                // SAFETY: the kernel wrote the first `count` entries.
                let info = unsafe { info.assume_init_ref() };
                #[cfg(all(test, not(loom)))]
                {
                    self.read += 1;
                }
                if info.ssi_signo as libc::c_int == libc::SIGIO {
                    #[cfg(all(test, not(loom)))]
                    {
                        self.sigio += 1;
                    }
                    every = true;
                } else {
                    Self::check(&mut self.held, info.ssi_fd, &mut broken);
                }
            }
            if count < infos.len() {
                break;
            }
        }
        if every {
            let fds: Vec<RawFd> = self.held.keys().copied().collect();
            for fd in fds {
                Self::check(&mut self.held, fd, &mut broken);
            }
        }
        self.arm(eng);
        broken
    }

    /// Note the lease on `fd` as broken in `broken`, if the ring holds one there not yet reported and `F_GETLEASE`
    /// shows it broken.
    fn check(held: &mut HashMap<RawFd, Held>, fd: RawFd, broken: &mut Vec<FileLeaseId>) {
        let Some(lease) = held.get_mut(&fd) else {
            return;
        };
        if lease.broken {
            return;
        }
        // SAFETY: the held descriptor is open for the call.
        let kind = unsafe { libc::fcntl(lease.file.as_raw_fd(), libc::F_GETLEASE) };
        if kind == libc::F_UNLCK {
            lease.broken = true;
            broken.push(FileLeaseId {
                fd,
                serial: lease.serial,
            });
        }
    }

    /// Hand each lease of `broken` to the handler, with a facade on the ring that no connection owns.
    pub(crate) fn deliver(fs: &mut super::core::FsCore, eng: &mut Engine, broken: Vec<FileLeaseId>) {
        let Some(mut handler) = fs.file_leases.handler.take() else {
            return;
        };
        for id in broken {
            let mut conn = FsConn::new(fs, eng, None);
            handler(id, &mut conn);
        }
        if fs.file_leases.handler.is_none() {
            fs.file_leases.handler = Some(handler);
        }
    }
}
