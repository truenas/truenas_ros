//! Process signals for a daemon: block them once, then receive them as
//! values on one thread.
//!
//! No handler is ever installed. The process blocks the signals it acts on
//! ([`block`]) on its main thread **before any other thread exists** - every
//! thread created afterwards inherits the mask - and then exactly one thread
//! receives them, either by waiting ([`Blocked::wait`],
//! [`Blocked::wait_timeout`]) or through a [`SignalFd`] it can poll next to
//! other descriptors. Nothing here runs in signal context, so there is no
//! async-signal-safety to reason about, no handler chaining, and no
//! process-global handler state; the reactors never see a signal at all.
//! That is the daemon shape the net server documents and relies on: its
//! loop is woken only by completions, and a shutdown is an eventfd poke.
//!
//! The one mutation of process-global state, the mask, happens only when
//! asked and on the thread that asks. A signal that arrives at a thread
//! which has it unblocked takes its default action - for `SIGTERM` that is
//! the process ending - which is why the order matters: block first, then
//! spawn. The mask is copied into every task created from the thread that
//! holds it, a forked process as much as a thread (`CLONE_CLEAR_SIGHAND`
//! resets handlers, not the mask), so a child forked after [`block`] with
//! no thread of its own waiting on the set never takes those signals'
//! default action either. For the credential broker that is the point: it
//! ignores a cgroup-wide `SIGTERM` and keeps minting identities while the
//! daemon drains, dying when the daemon drops it.
//!
//! ```no_run
//! use std::time::Duration;
//! use truenas_ros::signal::{SigSet, Signal, block};
//!
//! // First statement of main: nothing else has had a chance to spawn.
//! let blocked = block(SigSet::of([Signal::Term, Signal::Int, Signal::Hup]))?;
//! // ... build the reactors, fork the broker, spawn the threads ...
//! std::thread::spawn(move || {
//!     loop {
//!         match blocked.wait_timeout(Duration::from_secs(1)) {
//!             Ok(Some(d)) if d.signal == Signal::Hup => { /* reload */ }
//!             Ok(Some(_)) => { /* drain and stop */ break; }
//!             Ok(None) => { /* the timeout: a place for reload hysteresis */ }
//!             Err(_) => break,
//!         }
//!     }
//! });
//! # Ok::<(), truenas_ros::Errno>(())
//! ```

use crate::errno::{Errno, Result, retry_on_eintr};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::Duration;

/// The signals a daemon acts on.
///
/// Deliberately the daemon vocabulary and nothing more, and closed: the
/// realtime range and the fault signals have no place in a set a thread
/// waits on, and `SIGCHLD` is displaced by the pidfd every child here is
/// forked with. A [`Blocked`] yields only signals its own set named.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// `SIGHUP` - reload.
    Hup = libc::SIGHUP,
    /// `SIGINT` - stop, from a terminal.
    Int = libc::SIGINT,
    /// `SIGQUIT` - stop with a core, from a terminal.
    Quit = libc::SIGQUIT,
    /// `SIGTERM` - stop, from the service manager.
    Term = libc::SIGTERM,
    /// `SIGUSR1` - application-defined.
    Usr1 = libc::SIGUSR1,
    /// `SIGUSR2` - application-defined.
    Usr2 = libc::SIGUSR2,
}

impl Signal {
    /// The signal number.
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// The signal for a number, if it is one this module names.
    pub const fn from_raw(n: i32) -> Option<Signal> {
        match n {
            libc::SIGHUP => Some(Signal::Hup),
            libc::SIGINT => Some(Signal::Int),
            libc::SIGQUIT => Some(Signal::Quit),
            libc::SIGTERM => Some(Signal::Term),
            libc::SIGUSR1 => Some(Signal::Usr1),
            libc::SIGUSR2 => Some(Signal::Usr2),
            _ => None,
        }
    }
}

impl TryFrom<i32> for Signal {
    type Error = Errno;

    /// `EINVAL` for a number this module does not name.
    fn try_from(n: i32) -> Result<Signal> {
        Signal::from_raw(n).ok_or(Errno::EINVAL)
    }
}

/// A set of signals (`sigset_t`), built only from [`Signal`]s.
///
/// Equality is membership: every set starts from the all-zero pattern and
/// `sigaddset`/`sigdelset` only flip single bits, so two sets with the same
/// members are the same bytes.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigSet(libc::sigset_t);

impl Default for SigSet {
    fn default() -> SigSet {
        SigSet::empty()
    }
}

impl SigSet {
    /// The empty set.
    pub fn empty() -> SigSet {
        let mut set = MaybeUninit::<libc::sigset_t>::zeroed();
        // SAFETY: `zeroed` already initialized every byte (all-zero is the
        // empty set); `sigemptyset` rewrites the words the kernel reads and
        // cannot fail for a valid pointer.
        unsafe {
            libc::sigemptyset(set.as_mut_ptr());
            SigSet(set.assume_init())
        }
    }

    /// The set of exactly these signals.
    pub fn of(signals: impl IntoIterator<Item = Signal>) -> SigSet {
        let mut set = SigSet::empty();
        for s in signals {
            set.add(s);
        }
        set
    }

    /// Add `signal`.
    pub fn add(&mut self, signal: Signal) -> &mut SigSet {
        // SAFETY: a valid set and a valid signal number; cannot fail.
        unsafe { libc::sigaddset(&mut self.0, signal.as_raw()) };
        self
    }

    /// Remove `signal`.
    pub fn remove(&mut self, signal: Signal) -> &mut SigSet {
        // SAFETY: a valid set and a valid signal number; cannot fail.
        unsafe { libc::sigdelset(&mut self.0, signal.as_raw()) };
        self
    }

    /// Whether `signal` is in the set.
    pub fn contains(&self, signal: Signal) -> bool {
        // SAFETY: a valid set and a valid signal number; returns 0 or 1.
        unsafe { libc::sigismember(&self.0, signal.as_raw()) == 1 }
    }

    const ALL: [Signal; 6] = [
        Signal::Hup,
        Signal::Int,
        Signal::Quit,
        Signal::Term,
        Signal::Usr1,
        Signal::Usr2,
    ];
}

impl std::fmt::Debug for SigSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(Self::ALL.iter().filter(|s| self.contains(**s)))
            .finish()
    }
}

/// Who sent a signal, as the siginfo reports it. For `kill(2)` and
/// `tgkill(2)` (`SI_USER`, `SI_TKILL`) the kernel stamps the sender's pid
/// and real uid itself. For `SI_QUEUE` it relays what the sender wrote:
/// `sigqueue(3)` fills its own pid and real uid, but `rt_sigqueueinfo(2)`
/// accepts any values there, so under `SI_QUEUE` this is the sender's
/// claim. Informational in every case, never an authorization input. A
/// signal the kernel raised itself has no sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    /// The sending process.
    pub pid: libc::pid_t,
    /// The sending process's real uid.
    pub uid: libc::uid_t,
}

/// One received signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Which signal.
    pub signal: Signal,
    /// Who sent it, where the siginfo carries a sender; see [`Sender`] for
    /// which origins the kernel vouches for.
    pub sender: Option<Sender>,
}

fn sender_of(code: i32, pid: libc::pid_t, uid: libc::uid_t) -> Option<Sender> {
    // Only these origins fill the sender fields; for the rest the same
    // bytes mean something else and must not be read as a pid.
    matches!(code, libc::SI_USER | libc::SI_QUEUE | libc::SI_TKILL)
        .then_some(Sender { pid, uid })
}

impl Delivered {
    fn from_siginfo(info: &libc::siginfo_t) -> Result<Delivered> {
        let signal = Signal::try_from(info.si_signo)?;
        // SAFETY: the call filled every byte of `info`, so the two union
        // fields hold initialized integers whatever `si_code` is, which is
        // all the getters need. The values name a sender only for the codes
        // `sender_of` keeps: `SI_USER` (the `_kill` layout) and
        // `SI_QUEUE`/`SI_TKILL` (the `_rt` layout) both begin with
        // `_pid, _uid`, the offsets the getters read.
        let (pid, uid) = unsafe { (info.si_pid(), info.si_uid()) };
        Ok(Delivered {
            signal,
            sender: sender_of(info.si_code, pid, uid),
        })
    }

    fn from_signalfd(info: &libc::signalfd_siginfo) -> Result<Delivered> {
        let signal = Signal::try_from(info.ssi_signo as i32)?;
        Ok(Delivered {
            signal,
            sender: sender_of(
                info.ssi_code,
                info.ssi_pid as libc::pid_t,
                info.ssi_uid as libc::uid_t,
            ),
        })
    }
}

/// Block `set` on the calling thread.
///
/// Call this on the main thread before any other thread exists: a thread
/// inherits its creator's mask, so that one call covers the whole process,
/// and a thread created earlier would keep the set unblocked and take a
/// signal's default action on the whole process. The returned [`Blocked`]
/// is the proof the set is blocked here and the handle to receive from it.
pub fn block(set: SigSet) -> Result<Blocked> {
    // SAFETY: a valid set; the old-mask pointer may be null.
    let rc = unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &set.0, ptr::null_mut())
    };
    // `pthread_sigmask` returns the error number directly.
    if rc != 0 {
        return Err(Errno::from_raw(rc));
    }
    Ok(Blocked { set })
}

/// A set of signals blocked on this thread (and on every thread created
/// after [`block`] ran), and the ways to receive one of them.
///
/// Receiving is for one thread: two threads waiting on overlapping sets race
/// for each delivery.
#[derive(Clone, Copy, Debug)]
pub struct Blocked {
    set: SigSet,
}

impl Blocked {
    /// The blocked set.
    pub fn set(&self) -> &SigSet {
        &self.set
    }

    /// Wait for one signal in the set.
    ///
    /// `sigwaitinfo(2)`: the signal is dequeued, never delivered, so no
    /// handler runs anywhere. Retries `EINTR`.
    pub fn wait(&self) -> Result<Delivered> {
        let mut info = MaybeUninit::<libc::siginfo_t>::uninit();
        // SAFETY: a valid set and a writable siginfo the call fills on
        // success.
        retry_on_eintr(|| unsafe {
            libc::sigwaitinfo(&self.set.0, info.as_mut_ptr())
        })?;
        // SAFETY: a non-negative return means the call filled `info`.
        Delivered::from_siginfo(unsafe { info.assume_init_ref() })
    }

    /// [`Blocked::wait`] with a deadline: `None` when `timeout` passes with
    /// nothing pending. A timeout is the natural place for reload hysteresis
    /// or a periodic liveness check, without a second thread.
    ///
    /// `sigtimedwait(2)`; an `EINTR` restarts the full timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<Option<Delivered>> {
        let ts = timespec_of(timeout);
        let mut info = MaybeUninit::<libc::siginfo_t>::uninit();
        // SAFETY: a valid set, a writable siginfo, and a timespec that lives
        // for the call.
        let r = retry_on_eintr(|| unsafe {
            libc::sigtimedwait(&self.set.0, info.as_mut_ptr(), &ts)
        });
        match r {
            Ok(_) => {
                // SAFETY: a non-negative return means the call filled `info`.
                Delivered::from_siginfo(unsafe { info.assume_init_ref() })
                    .map(Some)
            }
            Err(Errno::EAGAIN) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A descriptor that becomes readable when a signal in the set is
    /// pending, for a thread that waits on several things at once.
    pub fn signal_fd(&self) -> Result<SignalFd> {
        SignalFd::new(&self.set)
    }
}

/// A `signalfd(2)` over a blocked set: readable when one of its signals is
/// pending, so a thread can `poll` it beside a pidfd or an eventfd instead
/// of blocking in [`Blocked::wait`]. Non-blocking and close-on-exec.
#[derive(Debug)]
pub struct SignalFd {
    fd: OwnedFd,
}

impl SignalFd {
    fn new(set: &SigSet) -> Result<SignalFd> {
        // SAFETY: a valid set; -1 asks for a new descriptor.
        let fd = Errno::result(unsafe {
            libc::signalfd(-1, &set.0, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK)
        })?;
        // SAFETY: a fresh descriptor this process owns.
        Ok(SignalFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Take one pending signal, or `None` when none is pending.
    ///
    /// Like [`Blocked::wait`], this dequeues the signal and no handler runs.
    pub fn read(&self) -> Result<Option<Delivered>> {
        let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        let want = std::mem::size_of::<libc::signalfd_siginfo>();
        // SAFETY: a live fd and a writable buffer of exactly one record.
        let r = retry_on_eintr(|| unsafe {
            libc::read(self.fd.as_raw_fd(), info.as_mut_ptr().cast(), want)
        });
        match r {
            Ok(n) if n as usize == want => {
                // SAFETY: the kernel wrote one whole record.
                Delivered::from_signalfd(unsafe { info.assume_init_ref() })
                    .map(Some)
            }
            // A signalfd read is whole records or nothing.
            Ok(_) => Err(Errno::EIO),
            Err(Errno::EAGAIN) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait up to `timeout` (forever for `None`) for a signal, then take
    /// it. `None` when the timeout passes first. Retries `EINTR`, which
    /// restarts the full timeout.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<Option<Delivered>> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // `ppoll(2)` rather than `poll(2)`: a timespec reaches as far as
        // `sigtimedwait`'s does, where poll's int milliseconds stop at
        // about 24 days and would report a timeout that never passed.
        let ts = timeout.map(timespec_of);
        let tsp = ts.as_ref().map_or(ptr::null(), |t| t as *const _);
        // SAFETY: one valid pollfd and a timespec (or null) that live for
        // the call; a null sigmask leaves the mask alone.
        let n = retry_on_eintr(|| unsafe {
            libc::ppoll(&mut pfd, 1, tsp, ptr::null())
        })?;
        if n == 0 {
            return Ok(None);
        }
        self.read()
    }
}

impl AsFd for SignalFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn timespec_of(d: Duration) -> libc::timespec {
    libc::timespec {
        // Clamp rather than wrap: a negative tv_sec is EINVAL, and
        // time_t::MAX seconds is "never" for any practical purpose.
        tv_sec: d.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
        // Below 1e9, so it fits whatever width tv_nsec has.
        tv_nsec: d.subsec_nanos() as libc::c_long,
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// Raise `s` at the calling thread only (`tgkill`), so a test never
    /// sends a process-directed signal that another test's thread, with the
    /// set unblocked, would take at its default action.
    fn raise_here(s: Signal) {
        // SAFETY: the calling thread's own id and a valid signal number.
        let rc =
            unsafe { libc::pthread_kill(libc::pthread_self(), s.as_raw()) };
        assert_eq!(rc, 0, "pthread_kill");
    }

    /// The sender fields are read out of a union, so which `si_code`
    /// values are allowed to name a sender is a memory-safety-adjacent
    /// question and not a formatting one: for anything else the same bytes
    /// are `si_status`/`si_utime` (a `SIGCHLD`) or `si_addr` (a kernel
    /// fault), and reporting them as a pid/uid fabricates an origin out of
    /// unrelated data. `Delivered::sender` is what a caller authorizes on.
    ///
    /// Only the three accepted codes are reachable through the public API
    /// (a raised signal is `SI_TKILL`), so the refusals are pinned on the
    /// predicate directly.
    #[test]
    fn only_the_codes_that_carry_a_sender_report_one() {
        for code in [libc::SI_USER, libc::SI_QUEUE, libc::SI_TKILL] {
            assert_eq!(
                sender_of(code, 42, 7),
                Some(Sender { pid: 42, uid: 7 }),
                "si_code {code} fills the sender fields"
            );
        }
        // A kernel-raised fault carries `si_addr` in those bytes; a timer
        // carries `si_timerid`/`si_overrun`; a child carries `si_status`
        // and `si_utime`. None of them is a pid.
        for code in [
            libc::SI_KERNEL,
            libc::SI_TIMER,
            libc::SI_MESGQ,
            libc::SI_ASYNCIO,
            libc::SI_SIGIO,
            libc::CLD_EXITED,
            libc::CLD_KILLED,
        ] {
            assert_eq!(
                sender_of(code, 42, 7),
                None,
                "si_code {code} does not name a sender"
            );
        }
    }

    fn me() -> Sender {
        // SAFETY: pure getters.
        unsafe {
            Sender {
                pid: libc::getpid(),
                uid: libc::getuid(),
            }
        }
    }

    #[test]
    fn signal_round_trips_its_number() {
        for s in SigSet::ALL {
            assert_eq!(Signal::try_from(s.as_raw()), Ok(s));
        }
        assert_eq!(Signal::try_from(libc::SIGKILL), Err(Errno::EINVAL));
        assert_eq!(Signal::try_from(0), Err(Errno::EINVAL));
    }

    #[test]
    fn sigset_membership() {
        let mut set = SigSet::of([Signal::Term, Signal::Hup]);
        assert!(set.contains(Signal::Term));
        assert!(set.contains(Signal::Hup));
        assert!(!set.contains(Signal::Int));
        set.remove(Signal::Hup).add(Signal::Int);
        assert!(!set.contains(Signal::Hup));
        assert!(set.contains(Signal::Int));
        assert_eq!(format!("{set:?}"), "{Int, Term}");
        assert_eq!(format!("{:?}", SigSet::empty()), "{}");
        assert_eq!(set, SigSet::of([Signal::Int, Signal::Term]));
        assert_eq!(SigSet::default(), SigSet::empty());
        assert_ne!(set, SigSet::empty());
    }

    /// The calling thread's mask. A null new set leaves the mask alone and
    /// `how` unread, so this is a pure query.
    fn mask_here() -> SigSet {
        let mut out = MaybeUninit::<libc::sigset_t>::zeroed();
        // SAFETY: no new set; `out` is writable and filled on a zero return.
        let rc = unsafe {
            libc::pthread_sigmask(
                libc::SIG_BLOCK,
                ptr::null(),
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "pthread_sigmask");
        // SAFETY: a zero return means the call filled `out`.
        SigSet(unsafe { out.assume_init() })
    }

    /// A signal raised at this thread after blocking is dequeued by `wait`
    /// as a value, with the kernel's record of who sent it, and no handler
    /// ran (there is none to run: the process is still here).
    #[test]
    fn wait_receives_a_signal_raised_at_this_thread() {
        let blocked = block(SigSet::of([Signal::Usr1])).expect("block");
        raise_here(Signal::Usr1);
        let d = blocked.wait().expect("wait");
        assert_eq!(d.signal, Signal::Usr1);
        assert_eq!(d.sender, Some(me()), "tgkill records the sender");
    }

    /// Nothing pending: the timeout returns `None`; then a raise is seen.
    #[test]
    fn wait_timeout_is_none_until_something_is_pending() {
        let blocked = block(SigSet::of([Signal::Usr2])).expect("block");
        assert_eq!(
            blocked
                .wait_timeout(Duration::from_millis(10))
                .expect("wait"),
            None
        );
        raise_here(Signal::Usr2);
        let d = blocked
            .wait_timeout(Duration::from_secs(5))
            .expect("wait")
            .expect("the raised signal");
        assert_eq!(d.signal, Signal::Usr2);
    }

    /// The fd form: nothing to read, then readable after a raise, then
    /// nothing again once taken.
    #[test]
    fn signalfd_reads_a_pending_signal_once() {
        let blocked = block(SigSet::of([Signal::Hup])).expect("block");
        let fd = blocked.signal_fd().expect("signalfd");
        assert_eq!(fd.read().expect("read"), None, "nothing pending yet");
        assert_eq!(
            fd.wait(Some(Duration::from_millis(10))).expect("wait"),
            None,
            "the poll times out with nothing pending"
        );
        raise_here(Signal::Hup);
        let d = fd
            .wait(Some(Duration::from_secs(5)))
            .expect("wait")
            .expect("the raised signal");
        assert_eq!(d.signal, Signal::Hup);
        assert_eq!(d.sender, Some(me()));
        assert_eq!(fd.read().expect("read"), None, "taken exactly once");
    }

    /// The mask is per thread and inherited at spawn: a thread created
    /// after `block` can receive the set without blocking it again.
    #[test]
    fn a_thread_spawned_after_block_inherits_the_mask() {
        let blocked = block(SigSet::of([Signal::Int])).expect("block");
        let t = std::thread::spawn(move || {
            // Checked before raising: were the mask not inherited, the
            // raise would end the whole test process rather than fail
            // this test.
            assert!(
                mask_here().contains(Signal::Int),
                "the spawned thread inherits the blocked set"
            );
            raise_here(Signal::Int);
            blocked.wait().expect("wait").signal
        });
        assert_eq!(t.join().unwrap(), Signal::Int);
    }

    #[test]
    fn timeouts_clamp_instead_of_wrapping() {
        let ts = timespec_of(Duration::MAX);
        assert_eq!(ts.tv_sec, libc::time_t::MAX);
        assert_eq!(ts.tv_nsec, 999_999_999);
        let ts = timespec_of(Duration::from_millis(1_500));
        assert_eq!((ts.tv_sec, ts.tv_nsec), (1, 500_000_000));
    }
}
