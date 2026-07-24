//! The credential broker: a tiny forked process that mints personalities
//! for *other* identities.
//!
//! Registering a personality snapshots the **caller's** credentials, so
//! minting one for user X means some task must first become X. Doing that
//! inside the reactor process is a trap: glibc's `setuid` family signals
//! every thread (`SIGSETXID`), so one call re-identifies the reactor thread
//! mid-flight, and io-wq workers — kernel clones, invisible to the
//! broadcast — are left on the old identity, giving one process two
//! identities depending on which path an op took.
//!
//! So the reactor process never changes credentials at all. A broker
//! process does, and it is deliberately minimal: it holds the ring fds, and
//! its whole job is *three syscalls and a register*.
//!
//! ```text
//! main (single-threaded)            broker (cloned child, keeps CAP_SETUID)
//! ──────────────────────            ──────────────────────────────────────
//! AsyncFs::new()  → ring fd
//! socketpair(SEQPACKET)
//! clone3() ─────────────────────►   inherits the ring fds; closes all else
//! drop CAP_SETUID/CAP_SETGID        loop: recv
//! … spawn threads, serve …
//! … session authenticates …
//! register(AsUser) ─────────────►   SYS_setgroups + SYS_setresgid +
//!                                   SYS_setresuid (RAW), REGISTER_PERSONALITY,
//!                                   SYS_setresuid(0,0,0)      (revert)
//! Personality ◄─────────────────    reply {id}
//! ```
//!
//! **`clone3`, not `fork`, and every credential syscall in the child is
//! raw** — both load-bearing, not stylistic:
//!
//! - `clone3(CLONE_CLEAR_SIGHAND)` resets the child's inherited signal
//!   handlers to `SIG_DFL`. A `fork`ed child keeps main's handlers, so a
//!   signal delivered *inside the impersonation window* would run main's
//!   handler code at the impersonated identity — a soundness hole. It also
//!   takes `CLONE_PIDFD` (race-free supervision/reap) and `exit_signal = 0`
//!   (the library's broker death sends no `SIGCHLD` to the host). See
//!   [`crate::clone3`].
//! - The window uses **`SYS_setgroups`/`SYS_setresgid`/`SYS_setresuid`
//!   directly**, never glibc's wrappers: the wrappers implement POSIX
//!   process-wide semantics by SIGSETXID-broadcasting to every thread, and in
//!   a `clone3` child (no glibc fork cleanup, a stale copied thread list) that
//!   broadcast can deadlock. The raw syscall changes only this single task's
//!   credentials, which is exactly what a one-thread broker wants. Even the
//!   reads (`raw_geteuid`/`raw_getegid`/`SYS_getgroups`) go raw so no glibc
//!   state sits in the credential path. (`truens_pos` `acl_check.c` hit and
//!   documented this same trap.)
//!
//! **The ring fds are inherited across `fork`, never sent.** The obvious
//! alternative — keep a broker alive from the start and pass each ring over
//! the socket with `SCM_RIGHTS` — *cannot work*: since Linux 6.8 the kernel
//! refuses to attach an io_uring file to a unix socket at all
//! (`scm_fp_copy` → `-EINVAL`, kernel commit `a4104821ad65`, which removed
//! io_uring's own socket-GC handling). Inheritance is why every ring must
//! exist before [`CredBroker::spawn`] is called.
//!
//! `pidfd_getfd(2)` *would* lift that ordering rule — it installs through
//! `receive_fd`, which has no io_uring exclusion — and is deliberately not
//! used: it is gated on `PTRACE_MODE_ATTACH_REALCREDS`, and since the
//! broker is main's *child* it is on the wrong side of Yama's default
//! ancestor-only rule, so it would need `CAP_SYS_PTRACE` — an unscoped
//! authority to read and write any process's memory, held for life, to
//! serve a startup-only operation. The full rationale is in the
//! fs-reactor design, §6.5.
//!
//! Two properties make this worth the process boundary:
//!
//! - **After [`CredBroker::spawn`] the reactor process can never obtain a
//!   `uid == 0` (root) personality.** It permanently drops
//!   `CAP_SETUID`/`CAP_SETGID`, so it cannot change identity itself; and the
//!   broker refuses to mint a personality for uid 0. Note the precise
//!   boundary: a *compromised* main still holds a [`CredHandle`] and can ask
//!   the broker to mint a personality for any **non-root** identity, and can
//!   free any id ([`CredHandle::unregister`] takes no ownership proof). That
//!   is acceptable under the stated model — main runs as root, so a
//!   compromised main is already root-equivalent — but the guarantee is "no
//!   forged *root* identity," not "no forging."
//! - **A minted personality carries no elevated capability.** Dropping to
//!   the user's uid clears the effective capability set (the kernel's
//!   setuid fixup), so the snapshot has the user's authority and no
//!   `CAP_DAC_OVERRIDE` — the kernel's own permission checks then bind the
//!   daemon exactly as they would bind the user.

use super::{AsyncFs, Personality};
use crate::errno::{self, retry_on_eintr, Errno};
use std::ffi::c_void;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

/// The largest supplementary-group list a registration may carry.
///
/// Sized against what winbindd/Samba actually produces for Active Directory
/// users, not against a guess. Samba imposes no fixed ceiling of its own —
/// `getgroups_unix_user` tries a 128-entry stack buffer and, on overflow,
/// *reallocates on the heap and retries* `[V samba source3/lib/system_smbd.c]`,
/// so it serves users far past any small cap; its real limit is
/// `sysconf(_SC_NGROUPS_MAX)` (65536 on Linux). The practical ceiling comes
/// from AD itself: a Kerberos PAC carries roughly 1015 group SIDs before
/// `MaxTokenSize` problems begin. **4096** therefore clears real-world AD by
/// several times over while keeping one request inside a single SEQPACKET
/// datagram (16 KiB — the transport is measured good to ~16k groups, and
/// fails only past 65536).
///
/// A longer list is **rejected, never truncated**: dropping groups silently
/// changes what the identity may do, which is a permission bug that would
/// surface as a mysterious `EACCES` far from its cause.
///
/// Note the cost is paid per *registration* and scales with the actual list
/// length — measured ~93 µs at 256 groups, ~320 µs at 1024, ~1.4 ms at 4096
/// (`setgroups` twice, plus copying the credential). Large AD identities are
/// exactly why [`IdentityCache`] exists: registering once per identity rather
/// than once per connection keeps that off the connection path.
pub const MAX_GROUPS: usize = 4096;

/// How many rings one broker will serve.
pub const MAX_RINGS: usize = 8;

/// The child's IPC socket, after `tidy_child_fds` normalizes descriptors.
const SOCK_FD: RawFd = 3;
/// Ring `i`'s fd in the child: descriptors are renumbered at startup so the
/// mapping needs no bookkeeping.
const RING_FD_BASE: RawFd = 4;

// Wire opcodes.
const OP_REGISTER: u8 = 1;
const OP_UNREGISTER: u8 = 2;

/// Request header: `op`, `ring`, `ngroups`, `uid`, `gid`, then `ngroups`
/// group ids. (`uid` doubles as the personality id for `OP_UNREGISTER`.)
const HDR_LEN: usize = 12;
const MAX_REQ: usize = HDR_LEN + 4 * MAX_GROUPS;

/// The identity to impersonate: everything the kernel consults for a
/// filesystem permission check.
///
/// `groups` is the full supplementary list. Getting it wrong is a
/// permission bug in either direction — a missing group denies access the
/// user should have, an extra one grants access they should not — so the
/// caller is expected to pass exactly what the directory service reports.
///
/// The list is stored **sorted and deduplicated**, because group membership
/// is a set: `[27, 4]` and `[4, 27, 4]` describe the same identity, and
/// equality here decides whether [`IdentityCache`] reuses a personality or
/// mints a redundant one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsUser {
    /// Filesystem user id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    groups: Vec<u32>,
}

impl AsUser {
    /// A new identity with no supplementary groups.
    pub fn new(uid: u32, gid: u32) -> AsUser {
        AsUser {
            uid,
            gid,
            groups: Vec::new(),
        }
    }

    /// Set the supplementary groups (normalized to a sorted, deduplicated
    /// set — see the type docs).
    pub fn groups(mut self, mut groups: Vec<u32>) -> AsUser {
        groups.sort_unstable();
        groups.dedup();
        self.groups = groups;
        self
    }

    /// The supplementary groups, sorted and deduplicated.
    pub fn group_list(&self) -> &[u32] {
        &self.groups
    }
}

struct BrokerInner {
    /// Serialized: one request at a time (registration is a rare,
    /// session-setup operation — see the fs-reactor design §16.4).
    sock: Mutex<OwnedFd>,
    pid: libc::pid_t,
    /// The broker's pidfd (from `clone3(CLONE_PIDFD)`): race-free death
    /// detection ([`CredBroker::is_alive`]), signalling, and reaping.
    pidfd: OwnedFd,
    rings: usize,
}

impl Drop for BrokerInner {
    fn drop(&mut self) {
        // Dropping the last `CredBroker`: no more requests will come, so kill
        // and reap the broker. `SIGKILL` via the pidfd is PID-reuse-safe and
        // uncatchable, so a wedged broker cannot linger holding `CAP_SETUID`;
        // the `waitpid` clears the zombie (`exit_signal == 0` means nothing
        // auto-reaps it). `ECHILD` (already reaped, e.g. by a consumer's
        // wildcard reaper) or any non-`EINTR` error ends the loop.
        // SAFETY: `pidfd_send_signal` on our owned pidfd; NULL siginfo / 0
        // flags per the man page.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::c_void>(),
                0u32,
            );
        }
        loop {
            // SAFETY: waitpid on our child pid; a NULL status pointer is
            // allowed.
            let r = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
            if r >= 0 || Errno::last() != Errno::EINTR {
                break;
            }
        }
        // `pidfd` and `sock` (OwnedFd) close after this body.
    }
}

/// A handle to the broker process. `Send + Sync + Clone` — registration
/// happens on whichever thread authenticates a session, never on the
/// reactor loop.
#[derive(Clone)]
pub struct CredBroker {
    inner: Arc<BrokerInner>,
}

impl std::fmt::Debug for CredBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredBroker")
            .field("pid", &self.inner.pid)
            .field("rings", &self.inner.rings)
            .finish_non_exhaustive()
    }
}

/// A broker bound to one ring: what a consumer actually calls to mint and
/// retire identities. Obtain it from [`CredBroker::handle`].
#[derive(Clone, Debug)]
pub struct CredHandle {
    broker: CredBroker,
    ring: u8,
}

impl CredHandle {
    /// Mint a [`Personality`] for `who` — the broker impersonates that
    /// identity just long enough to snapshot it.
    ///
    /// Requires the broker to hold `CAP_SETUID`/`CAP_SETGID` (i.e. the
    /// process was privileged when [`CredBroker::spawn`] ran) unless `who`
    /// already *is* the broker's own identity, which needs no privilege and
    /// is the unprivileged path.
    ///
    /// Registering `uid == 0` is refused: the daemon's own identity comes
    /// from [`AsyncFs::register_self`], and a root personality — which
    /// would carry the daemon's capabilities — is exactly what this design
    /// exists to avoid.
    pub fn register(&self, who: &AsUser) -> crate::Result<Personality> {
        if who.uid == 0 {
            return Err(crate::Error::Validation(
                "refusing to register a personality for uid 0; use \
                 AsyncFs::register_self for the daemon's own identity"
                    .into(),
            ));
        }
        // `(uid_t)-1`/`(gid_t)-1` are the kernel's "leave unchanged" sentinel
        // for setres*id; they must never reach the impersonation window (the
        // broker verifies the drop server-side too, but reject them here for a
        // clear error rather than a bare EINVAL).
        if who.uid == u32::MAX || who.gid == u32::MAX {
            return Err(crate::Error::Validation(
                "uid/gid 0xFFFFFFFF is the setres*id no-change sentinel and \
                 cannot be impersonated"
                    .into(),
            ));
        }
        if who.groups.len() > MAX_GROUPS {
            return Err(crate::Error::Validation(format!(
                "too many supplementary groups ({} > {MAX_GROUPS})",
                who.groups.len()
            )));
        }
        let id = self.broker.request(OP_REGISTER, self.ring, who)?;
        u16::try_from(id)
            .map(Personality)
            .map_err(|_| Errno::EINVAL.into())
    }

    /// Retire a personality, freeing its kernel-held credential and its id.
    ///
    /// Call this when a session ends: ids are a `u16` space and each pins a
    /// credential plus its group list, so leaking them is a real exhaustion
    /// vector. In-flight operations that already resolved the id complete
    /// normally; new SQEs naming it fail `EINVAL`.
    ///
    /// Takes no proof of ownership over `who`, so it can free *any* live id
    /// on the ring — a compromised main can retire other sessions' identities
    /// (a DoS within its existing power; see the module boundary note).
    /// Prefer the ref-counted [`IdentityCache`], which frees an id only once
    /// its last [`Lease`] drops.
    pub fn unregister(&self, who: Personality) -> crate::Result<()> {
        let msg = AsUser::new(u32::from(who.0), 0);
        self.broker.request(OP_UNREGISTER, self.ring, &msg)?;
        Ok(())
    }
}

/// A registered identity, kept alive by its leases.
///
/// The kernel id is freed by `Drop`, so the `Arc` count *is* the reference
/// count: the personality outlives the cache entry itself when a lease is
/// still held, which is exactly the "in-flight work finishes under the old
/// id" behaviour re-registration needs.
#[derive(Debug)]
struct IdEntry {
    id: Personality,
    creds: CredHandle,
}

impl Drop for IdEntry {
    fn drop(&mut self) {
        // Best-effort: a dead broker means the ids are gone with it.
        let _ = self.creds.unregister(self.id);
    }
}

/// A live borrow of a cached identity.
///
/// A lease keeps its personality registered, but dropping the last one does
/// **not** retire it: the cache entry holds a reference of its own, so a
/// cached identity stays registered until
/// [`invalidate`](IdentityCache::invalidate) (or dropping the whole cache)
/// releases that one *and* every lease is gone. That is the point of the cache
/// — the next connection for the same identity reuses the id instead of paying
/// another mint. Retiring ids is therefore the consumer's call: invalidate on a
/// directory-services change or a TTL, or ids accumulate in the per-ring `u16`
/// space (see [`IdentityCache`]).
#[derive(Clone, Debug)]
pub struct Lease(Arc<IdEntry>);

impl Lease {
    /// The personality to stamp on operations for this identity.
    pub fn personality(&self) -> Personality {
        self.0.id
    }
}

/// Registers each distinct identity once and hands out reference-counted
/// [`Lease`]s — the "register on connect, but only if the credentials are
/// new" pattern.
///
/// Minting is not free (an IPC round trip plus an impersonation window:
/// order of tens of microseconds), and every live id pins a kernel
/// credential inside a **`u16`** space that is per-ring. Registering per
/// *connection* rather than per *identity* therefore caps concurrent
/// connections at ~65k per ring and does needless work; this collapses both
/// to per-identity.
///
/// ```no_run
/// # use truenas_ros::async_fs::{AsUser, AsyncFs, CredBroker, FsConfig, IdentityCache};
/// # let afs = AsyncFs::new(FsConfig::default())?;
/// # let broker = CredBroker::spawn(&[&afs])?;
/// let cache = IdentityCache::new(broker.handle(0)?);
///
/// // On each connection, after authenticating:
/// let lease = cache.acquire(&AsUser::new(1000, 1000).groups(vec![4, 27]))?;
/// let who = lease.personality();
/// // … serve the connection, stamping `who` …
/// drop(lease); // the identity stays cached (and registered) for the next one
/// # Ok::<(), truenas_ros::Error>(())
/// ```
///
/// **Snapshots are frozen, and nothing expires on its own.** A personality
/// captures group membership at registration, so a cached identity will not
/// notice a later directory change — and because the cache holds its own
/// reference, no id is retired just because its last [`Lease`] dropped. Call
/// [`invalidate`](Self::invalidate) on a change event, or on a TTL of your
/// choosing, or [`invalidate_all`](Self::invalidate_all) wholesale: the entry
/// is removed so the next `acquire` registers fresh, the old id is retired
/// once the leases already handed out drop, and those leases keep working
/// meanwhile (in-flight work finishes under the identity it started with).
/// A daemon that never invalidates accumulates one id per distinct identity it
/// has ever served, against the per-ring `u16` space.
#[derive(Clone, Debug)]
pub struct IdentityCache {
    inner: Arc<CacheInner>,
}

#[derive(Debug)]
struct CacheInner {
    creds: CredHandle,
    live: Mutex<std::collections::HashMap<AsUser, Arc<IdSlot>>>,
}

/// One identity's cache slot: the registered entry once minted, plus a gate
/// that single-flights the mint so concurrent callers for the *same* identity
/// register it once — without holding the shared map lock across the broker
/// round-trip.
#[derive(Debug)]
struct IdSlot {
    cell: OnceLock<Arc<IdEntry>>,
    gate: Mutex<()>,
}

impl IdentityCache {
    /// Build a cache over one ring's broker handle.
    pub fn new(creds: CredHandle) -> IdentityCache {
        IdentityCache {
            inner: Arc::new(CacheInner {
                creds,
                live: Mutex::new(std::collections::HashMap::new()),
            }),
        }
    }

    /// A lease on `who`'s personality, registering it only if this is the
    /// first live use of exactly these credentials.
    ///
    /// Concurrent callers asking for the *same* new identity collapse into one
    /// registration (they serialize on that identity's gate), but the shared
    /// map lock is held only for an O(1) slot lookup — never across the broker
    /// round-trip — so cache hits and registrations of *other* identities are
    /// not blocked behind one mint.
    pub fn acquire(&self, who: &AsUser) -> crate::Result<Lease> {
        // Brief map lock: find or create this identity's slot, then release.
        let slot = {
            let mut live = self.inner.live.lock().map_err(|_| Errno::EIO)?;
            live.entry(who.clone())
                .or_insert_with(|| {
                    Arc::new(IdSlot {
                        cell: OnceLock::new(),
                        gate: Mutex::new(()),
                    })
                })
                .clone()
        };
        // Fast path: already registered — no lock, no broker call.
        if let Some(entry) = slot.cell.get() {
            return Ok(Lease(entry.clone()));
        }
        // Slow path: single-flight the mint on this identity's gate (the map
        // lock is not held, so other identities and hits proceed). Re-check
        // under the gate — a racing caller may have just filled the cell.
        let _mint = slot.gate.lock().map_err(|_| Errno::EIO)?;
        if let Some(entry) = slot.cell.get() {
            return Ok(Lease(entry.clone()));
        }
        let id = match self.inner.creds.register(who) {
            Ok(id) => id,
            Err(e) => {
                // A failed mint must not leave its slot behind: nothing ever
                // fills or removes an empty slot, so a daemon whose broker is
                // down (or which is handed identities the broker refuses) would
                // otherwise grow the map by one entry per attempt, forever.
                // Remove only if the map still holds *this* slot — a concurrent
                // `invalidate` + `acquire` may already have replaced it.
                if let Ok(mut live) = self.inner.live.lock() {
                    if live.get(who).is_some_and(|s| Arc::ptr_eq(s, &slot)) {
                        live.remove(who);
                    }
                }
                return Err(e);
            }
        };
        let entry = Arc::new(IdEntry {
            id,
            creds: self.inner.creds.clone(),
        });
        // Set can't fail: we hold the gate, so no one else filled it.
        let _ = slot.cell.set(entry.clone());
        Ok(Lease(entry))
    }

    /// Forget the cached personality for `who`, so the next
    /// [`acquire`](Self::acquire) mints a fresh one. Outstanding leases are
    /// unaffected and retire the old id when they drop.
    pub fn invalidate(&self, who: &AsUser) {
        if let Ok(mut live) = self.inner.live.lock() {
            live.remove(who);
        }
    }

    /// Forget every cached identity (a wholesale directory-services
    /// change). Existing leases keep working, as in
    /// [`invalidate`](Self::invalidate).
    pub fn invalidate_all(&self) {
        if let Ok(mut live) = self.inner.live.lock() {
            live.clear();
        }
    }

    /// How many distinct identities are currently cached and registered. An
    /// identity whose mint is still in flight does not count (one that failed
    /// leaves nothing behind at all).
    pub fn len(&self) -> usize {
        self.inner
            .live
            .lock()
            .map(|m| m.values().filter(|s| s.cell.get().is_some()).count())
            .unwrap_or(0)
    }

    /// Whether no identity is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A reactor whose io_uring ring a [`CredBroker`] registers personalities on.
///
/// Implemented by the standalone [`AsyncFs`] and by a `net` server built with
/// an fs pool — so a server can act as *authenticated peers* on its own ring,
/// the fs ops and net ops interleaving there (fs ops carry a registered
/// personality, net ops carry 0).
pub trait BrokerReactor {
    /// The ring descriptor the broker inherits at `fork` and registers on.
    ///
    /// Hidden by design: a ring fd plus its personality xarray is a credential
    /// capability (anyone holding it can register creds on the ring), not a
    /// handle to pass around — [`CredBroker::spawn`] is the only intended
    /// consumer.
    #[doc(hidden)]
    fn broker_ring_fd(&self) -> RawFd;
}

impl BrokerReactor for AsyncFs {
    fn broker_ring_fd(&self) -> RawFd {
        self.ring_fd()
    }
}

impl CredBroker {
    /// Fork the broker process — which inherits `reactors`' ring
    /// descriptors — then permanently drop `CAP_SETUID`/`CAP_SETGID` from
    /// **this** process.
    ///
    /// # Ordering requirements
    ///
    /// 1. **Every ring must already exist.** The broker registers on the
    ///    fds it inherits at `fork`, and there is no way to hand it one
    ///    afterwards: since Linux 6.8 an io_uring fd cannot be sent over a
    ///    unix socket (`SCM_RIGHTS` → `EINVAL`). Build every [`AsyncFs`]
    ///    first, then spawn one broker with all of them.
    /// 2. **Call this before starting any threads.** Not a style
    ///    preference — a `fork` without `exec` keeps only the calling
    ///    thread, and any lock another thread held at that instant (glibc's
    ///    malloc arena above all) stays locked forever in the child, which
    ///    would deadlock the broker at its first allocation. This is not
    ///    checked (a process cannot usefully prove it): the child is written
    ///    to survive a violation — its three scratch buffers are allocated
    ///    here, in the parent, and its request loop then allocates nothing and
    ///    calls only raw syscalls — but that is defence in depth, not a
    ///    licence. Anything added to the child that allocates, takes a lock,
    ///    or calls into glibc's stateful machinery makes the rule load-bearing
    ///    again.
    ///
    /// The capability drop is the point of the whole exercise, so it is not
    /// optional: from here on this process can *use* personalities but
    /// never mint them. (A process that was already unprivileged simply has
    /// nothing to drop; the broker can then still register its own
    /// identity.)
    ///
    /// **Failure is fatal.** An `Err` means the security setup did not
    /// complete — on a `fork` failure the caps are dropped and no broker
    /// exists; on a `capset` failure the caps may still be held. Either way
    /// the caller must abort, never continue serving.
    pub fn spawn<R: BrokerReactor + ?Sized>(
        reactors: &[&R],
    ) -> crate::Result<CredBroker> {
        if reactors.is_empty() || reactors.len() > MAX_RINGS {
            return Err(crate::Error::Validation(format!(
                "a broker serves 1..={MAX_RINGS} rings, got {}",
                reactors.len()
            )));
        }
        let ring_fds: Vec<RawFd> =
            reactors.iter().map(|r| r.broker_ring_fd()).collect();

        let mut sv = [0 as RawFd; 2];
        // SAFETY: `sv` is a valid 2-element array for socketpair to fill.
        Errno::result(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        })?;
        // SAFETY: fresh owned fds from socketpair.
        let parent_end = unsafe { crate::fd::owned_from_raw(sv[0]) };
        let child_end = unsafe { crate::fd::owned_from_raw(sv[1]) };

        // Fork the broker via `clone3`, not `fork()`, for three reasons —
        // one of them load-bearing for the privileged window:
        //   * CLONE_CLEAR_SIGHAND resets the child's inherited signal handlers
        //     to SIG_DFL, so a signal can never run main's handler code inside
        //     the impersonation window, at the impersonated identity (a
        //     fork-without-exec soundness hazard);
        //   * CLONE_PIDFD gives a race-free pidfd for supervision/reap;
        //   * exit_signal 0 means the broker's death sends NO SIGCHLD to the
        //     host — async_fs is a library and must not disturb the consumer's
        //     own child reaping (the pidfd carries death instead).
        // Same single-threaded-at-spawn precondition as fork (sharper, even:
        // a raw clone3 has no glibc atfork net — see `crate::clone3`).
        // Allocate the broker's scratch buffers HERE, before the fork: the
        // child inherits them, so its request loop never allocates. A raw
        // clone3 bypasses glibc's atfork malloc mitigation, so a child that
        // allocated after the fork could deadlock on an arena lock a concurrent
        // thread held at fork time — the reason `spawn` must run before any
        // threads (and why this hardens the test harness, which is not).
        let req = vec![0u8; MAX_REQ];
        let groups = vec![0u32; MAX_GROUPS];
        let scratch = vec![0 as libc::gid_t; MAX_GROUPS];

        let mut pidfd: RawFd = -1;
        // SAFETY: `clone3_fork` requires that the child do nothing that a
        // fork-copied lock could block. That holds by construction here, not by
        // trusting the caller's ordering: `broker_main` runs only raw syscalls
        // over the buffers allocated just above, and ends in `_exit`. The
        // documented before-any-threads rule is what keeps it that way.
        let fork_ret = unsafe { crate::clone3::clone3_fork(0, 0, &mut pidfd) };
        let pid = match fork_ret {
            Ok(pid) => pid,
            Err(e) => {
                // Shed the mint privilege even on failure: no broker exists,
                // so main has no use for CAP_SETUID/SETGID. `spawn` failure is
                // fatal (see the doc).
                let _ = drop_setid_caps();
                return Err(e.into());
            }
        };
        if pid == 0 {
            // The child must not run any destructor belonging to the parent
            // (they would free memory the parent still owns and flush its
            // buffers a second time), so `broker_main` ends in `_exit`.
            broker_main(child_end.as_raw_fd(), &ring_fds, req, groups, scratch);
        }
        // SAFETY: `CLONE_PIDFD` wrote a fresh owned pidfd for the child.
        let pidfd = unsafe { crate::fd::owned_from_raw(pidfd) };
        drop(child_end);
        // If this fails the broker is already running but main still holds the
        // mint caps — an unsafe state. The `?` surfaces it; `spawn` failure is
        // fatal (see the doc), so the caller aborts rather than serves.
        drop_setid_caps()?;
        Ok(CredBroker {
            inner: Arc::new(BrokerInner {
                sock: Mutex::new(parent_end),
                pid,
                pidfd,
                rings: ring_fds.len(),
            }),
        })
    }

    /// The handle for ring `index` — the position of that [`AsyncFs`] in
    /// the slice passed to [`CredBroker::spawn`].
    pub fn handle(&self, index: u8) -> crate::Result<CredHandle> {
        if usize::from(index) >= self.inner.rings {
            return Err(crate::Error::Validation(format!(
                "ring index {index} out of range (broker serves {})",
                self.inner.rings
            )));
        }
        Ok(CredHandle {
            broker: self.clone(),
            ring: index,
        })
    }

    /// The broker process's pid (for supervision: if it dies, existing
    /// personalities keep working — the kernel refcounts them — but no new
    /// identity can be minted until the process is restarted).
    pub fn pid(&self) -> i32 {
        self.inner.pid
    }

    /// Whether the broker process is still alive. A dead broker cannot mint
    /// **new** identities (already-registered personalities keep working —
    /// the kernel refcounts them), so a supervisor can poll this to restart
    /// it. Race-free against PID reuse: it polls the pidfd, which becomes
    /// readable only when *this* child exits. A poll error is reported as
    /// not-alive (conservative).
    pub fn is_alive(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.inner.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll over one owned pidfd, 0 timeout (non-blocking). Retry
        // on EINTR so a signal delivered to the daemon can't make a live
        // broker look dead.
        let r = retry_on_eintr(|| unsafe { libc::poll(&mut pfd, 1, 0) });
        // Ok(0) = timed out, not readable → still running. Ok(>0) (POLLIN) →
        // exited. A non-EINTR error is treated conservatively as not-alive.
        matches!(r, Ok(0))
    }

    fn request(&self, op: u8, ring: u8, who: &AsUser) -> crate::Result<i64> {
        // Sized to this request, not to MAX_GROUPS: a large cap must not
        // put a 16 KiB array on the caller's stack for a two-group user.
        let len = HDR_LEN + 4 * who.groups.len();
        let mut req = vec![0u8; len];
        req[0] = op;
        req[1] = ring;
        req[2..4].copy_from_slice(&(who.groups.len() as u16).to_le_bytes());
        req[4..8].copy_from_slice(&who.uid.to_le_bytes());
        req[8..12].copy_from_slice(&who.gid.to_le_bytes());
        for (i, g) in who.groups.iter().enumerate() {
            let at = HDR_LEN + 4 * i;
            req[at..at + 4].copy_from_slice(&g.to_le_bytes());
        }

        let sock = self.inner.sock.lock().map_err(|_| Errno::EIO)?;
        let n = retry_on_eintr(|| {
            // SAFETY: `req[..len]` is a valid initialized buffer.
            unsafe {
                libc::send(
                    sock.as_raw_fd(),
                    req.as_ptr().cast::<c_void>(),
                    len,
                    libc::MSG_NOSIGNAL,
                )
            }
        })?;
        if n as usize != len {
            return Err(Errno::EIO.into());
        }
        let reply = recv_reply(sock.as_raw_fd())?;
        if reply < 0 {
            return Err(Errno::from_raw(-reply as i32).into());
        }
        Ok(reply)
    }
}

fn recv_reply(sock: RawFd) -> errno::Result<i64> {
    let mut buf = [0u8; 8];
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid 8-byte destination.
        unsafe {
            libc::recv(sock, buf.as_mut_ptr().cast::<c_void>(), buf.len(), 0)
        }
    })?;
    if n as usize != buf.len() {
        // A short or empty read means the broker died mid-request.
        return Err(Errno::ECONNRESET);
    }
    Ok(i64::from_le_bytes(buf))
}

/// Drop `CAP_SETUID`/`CAP_SETGID` from every capability set of the calling
/// process. Succeeds trivially where they were not held.
fn drop_setid_caps() -> errno::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
    const VERSION_3: u32 = 0x2008_0522;
    // `<linux/capability.h>`; `libc` exposes neither constant.
    const CAP_SETGID: u32 = 6;
    const CAP_SETUID: u32 = 7;
    let mask = !((1u32 << CAP_SETUID) | (1u32 << CAP_SETGID));

    let mut hdr = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget fills two CapData words for VERSION_3.
    Errno::result(unsafe {
        libc::syscall(
            libc::SYS_capget,
            std::ptr::addr_of_mut!(hdr),
            data.as_mut_ptr(),
        )
    })?;
    // CAP_SETGID (6) and CAP_SETUID (7) both live in the low word.
    data[0].effective &= mask;
    data[0].permitted &= mask;
    data[0].inheritable &= mask;
    // SAFETY: capset reads the same two-word layout back.
    Errno::result(unsafe {
        libc::syscall(
            libc::SYS_capset,
            std::ptr::addr_of_mut!(hdr),
            data.as_ptr(),
        )
    })?;
    Ok(())
}

// -------------------------------------------------------------------------
// The broker process
// -------------------------------------------------------------------------

/// The forked child's whole life. Never returns.
///
/// Deliberately allocation-free and panic-free in the request loop: the
/// scratch buffers are allocated by the parent and moved in, every other
/// buffer is a fixed-size stack array, and every failure becomes an errno in
/// the reply. Errors are never logged — writing a log line inside an
/// impersonation window would perform file I/O as the impersonated user.
fn broker_main(
    sock: RawFd,
    ring_fds: &[RawFd],
    req: Vec<u8>,
    groups: Vec<u32>,
    scratch: Vec<libc::gid_t>,
) -> ! {
    let nrings = tidy_child_fds(sock, ring_fds);
    // A panic inside request handling must not unwind past `_exit` and run the
    // parent's `Drop` handlers / flush its buffers on the shared copy-on-write
    // image. Contain it here and exit non-zero; under `panic = "abort"` the
    // child aborts instead, which is equally safe.
    let ok = std::panic::catch_unwind(move || {
        broker_loop(nrings, req, groups, scratch)
    })
    .is_ok();
    // SAFETY: `_exit` never runs atexit handlers or destructors — exactly what
    // a forked child sharing the parent's heap image must do.
    unsafe { libc::_exit(if ok { 0 } else { 1 }) }
}

/// The broker's request loop, split out so a panic in it is catchable at the
/// `_exit` boundary (see [`broker_main`]).
///
/// The three scratch buffers are allocated by the **parent** before the fork
/// and moved in here: a raw `clone3` bypasses glibc's atfork malloc mitigation,
/// so allocating in the child could deadlock on an arena lock a concurrent
/// thread held at fork time. The loop is then truly allocation-free.
fn broker_loop(
    nrings: usize,
    mut req: Vec<u8>,
    mut groups: Vec<u32>,
    mut scratch: Vec<libc::gid_t>,
) {
    loop {
        let n = match recv_request(SOCK_FD, &mut req) {
            Ok(0) | Err(_) => break, // parent closed, or a fatal IPC error
            Ok(n) => n,
        };
        if n < HDR_LEN {
            let _ = reply(SOCK_FD, -(libc::EINVAL as i64));
            continue;
        }
        let op = req[0];
        let ring = usize::from(req[1]);
        let ngroups = usize::from(u16::from_le_bytes([req[2], req[3]]));
        let uid = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
        let gid = u32::from_le_bytes([req[8], req[9], req[10], req[11]]);

        if ring >= nrings || ngroups > MAX_GROUPS || n < HDR_LEN + 4 * ngroups {
            let _ = reply(SOCK_FD, -(libc::EINVAL as i64));
            continue;
        }
        let ring_fd = RING_FD_BASE + ring as RawFd;

        let res: i64 = match op {
            OP_REGISTER if uid != 0 => {
                for (i, g) in groups.iter_mut().take(ngroups).enumerate() {
                    let at = HDR_LEN + 4 * i;
                    *g = u32::from_le_bytes([
                        req[at],
                        req[at + 1],
                        req[at + 2],
                        req[at + 3],
                    ]);
                }
                register_as(ring_fd, uid, gid, &groups[..ngroups], &mut scratch)
            }
            OP_UNREGISTER => match u16::try_from(uid) {
                // The id rides in the uid field; freeing needs no creds.
                Ok(id) => {
                    match crate::uring::sys::unregister_personality(ring_fd, id)
                    {
                        Ok(()) => 0,
                        Err(e) => -(e as i32 as i64),
                    }
                }
                Err(_) => -(libc::EINVAL as i64),
            },
            _ => -(libc::EINVAL as i64),
        };
        if reply(SOCK_FD, res).is_err() {
            break;
        }
    }
    // Returns to `broker_main`, which `_exit`s (0 on this clean shutdown).
}

/// Renumber the child's descriptors to a fixed layout — the IPC socket at
/// [`SOCK_FD`], ring `i` at `RING_FD_BASE + i` — then close everything else
/// it inherited. Returns the ring count.
///
/// The moves go through a scratch range first, because a source descriptor
/// may already sit in a destination slot, and a direct `dup2` would clobber
/// a descriptor not yet copied.
fn tidy_child_fds(sock: RawFd, ring_fds: &[RawFd]) -> usize {
    let n = ring_fds.len();
    // The scratch range must sit above BOTH the highest inherited source fd
    // AND the final target range [SOCK_FD, RING_FD_BASE + n): copying down
    // into the target must never clobber a source or a not-yet-copied ring.
    // A fixed base would collide once the daemon had opened enough fds (TLS
    // certs, many listeners) before creating the rings.
    let max_src = ring_fds.iter().copied().fold(sock, |a, b| a.max(b));
    let scratch_base = max_src.max(RING_FD_BASE + n as RawFd) + 1;
    // SAFETY: dup2/close_range on descriptors this forked child owns. A failed
    // dup2 would leave a wrong layout (serving requests off a stray fd, or a
    // missing ring), so `dup2_or_die` aborts the child instead.
    unsafe {
        dup2_or_die(sock, scratch_base);
        for (i, &fd) in ring_fds.iter().enumerate() {
            dup2_or_die(fd, scratch_base + 1 + i as RawFd);
        }
        // The target range now holds nothing we still need; copy down.
        dup2_or_die(scratch_base, SOCK_FD);
        for i in 0..n {
            dup2_or_die(
                scratch_base + 1 + i as RawFd,
                RING_FD_BASE + i as RawFd,
            );
        }
        // Keep ONLY the socket (SOCK_FD) and the rings; scrub everything else
        // the child inherited — the scratch copies AND fds 0/1/2, where a
        // daemon that closed stdio could have let a ring or the parent IPC end
        // land (a leaked ring fd is a credential capability; a leaked parent
        // end keeps the socket from ever reaching EOF, stranding a CAP_SETUID
        // broker). The broker never uses stdio and never execs. A pre-5.9
        // kernel without close_range leaves them open — best-effort; the fds
        // are CLOEXEC-marked.
        libc::syscall(
            libc::SYS_close_range,
            0u32,
            (SOCK_FD - 1) as libc::c_uint,
            0,
        );
        libc::syscall(
            libc::SYS_close_range,
            (RING_FD_BASE + n as RawFd) as libc::c_uint,
            libc::c_uint::MAX,
            0,
        );
    }
    n
}

/// `dup2(from, to)` retrying `EINTR`, aborting the (forked) child on any
/// other failure — a wrong descriptor layout must never go on to serve
/// requests.
///
/// # Safety
///
/// Runs in the forked child; `from` and `to` are descriptors it owns.
unsafe fn dup2_or_die(from: RawFd, to: RawFd) {
    loop {
        // SAFETY: dup2 on owned descriptors.
        let r = unsafe { libc::dup2(from, to) };
        if r >= 0 {
            return;
        }
        // SAFETY: errno is valid after a failed syscall.
        if unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        }
        // SAFETY: _exit in the forked child.
        unsafe { libc::_exit(3) };
    }
}

/// Receive one request. Returns 0 when the parent has closed the socket.
fn recv_request(sock: RawFd, buf: &mut [u8]) -> errno::Result<usize> {
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid destination for its own length.
        unsafe {
            libc::recv(sock, buf.as_mut_ptr().cast::<c_void>(), buf.len(), 0)
        }
    })?;
    Ok(n as usize)
}

fn reply(sock: RawFd, value: i64) -> errno::Result<()> {
    let buf = value.to_le_bytes();
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid 8-byte source.
        unsafe {
            libc::send(
                sock,
                buf.as_ptr().cast::<c_void>(),
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        }
    })?;
    if n as usize != buf.len() {
        return Err(Errno::EIO);
    }
    Ok(())
}

/// Raw `geteuid`/`getegid` — the whole credential path in the cloned broker
/// child must use raw syscalls, never glibc's wrappers. The *setters* would
/// otherwise SIGSETXID-broadcast across glibc's stale (fork-copied) thread
/// list and can deadlock (this is why `register_as` uses `SYS_setres*id`
/// directly; cf. `truens_pos` `acl_check.c`). These reads don't broadcast,
/// but going raw keeps the security post-condition from trusting glibc not to
/// proxy/cache the effective id after a raw `setresuid` — no glibc state in
/// the loop, by construction.
fn raw_geteuid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_geteuid) as u32 }
}

fn raw_getegid() -> u32 {
    // SAFETY: `getegid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_getegid) as u32 }
}

/// **The impersonation window.** Become `uid`/`gid`/`groups`, snapshot
/// those credentials into a personality, and revert.
///
/// Every credential call is a *raw* syscall: glibc's wrappers implement
/// POSIX process-wide semantics by signalling every thread, which is both
/// unnecessary here (the broker is single-threaded) and precisely the
/// behaviour that makes in-process impersonation unsound.
///
/// Ordering is load-bearing. Groups and gids are set while still
/// privileged; the uid drop comes last and keeps **saved-uid 0** so the
/// window can be closed again. As euid leaves 0 the kernel's setuid fixup
/// clears the effective capability set — which is what guarantees the
/// snapshot carries the user's authority and no `CAP_DAC_OVERRIDE`.
/// Nothing else runs inside the window: no allocation, no logging, no
/// fallible work that could unwind.
fn register_as(
    ring_fd: RawFd,
    uid: u32,
    gid: u32,
    groups: &[u32],
    scratch: &mut [libc::gid_t],
) -> i64 {
    // Registering credentials identical to the broker's own needs no
    // privilege transition at all — and this is the path an unprivileged
    // process takes, where `setgroups` would fail even for an unchanged
    // list (it always demands CAP_SETGID).
    if !needs_impersonation(uid, gid, groups, scratch) {
        return match crate::uring::sys::register_personality(ring_fd) {
            Ok(id) => i64::from(id),
            Err(e) => -(e as i32 as i64),
        };
    }

    // --- window opens ---
    // SAFETY: raw setgroups/setresgid/setresuid on a single-threaded
    // process; each is checked, and every exit path closes the window via
    // `revert`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            groups.len() as libc::size_t,
            groups.as_ptr(),
        )
    };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }
    // Keep saved-gid unchanged (-1) so the revert can restore it.
    // SAFETY: as above.
    let rc = unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, u32::MAX) };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }
    // Saved-uid stays 0: the only way back.
    // SAFETY: as above.
    let rc = unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, 0) };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }

    // Fail CLOSED: confirm the drop actually took effect before snapshotting.
    // The kernel treats a `(uid_t)-1`/`(gid_t)-1` argument to setres*id as
    // "leave unchanged" and returns success, so a request for uid/gid
    // `0xFFFFFFFF` slips past the `uid != 0` guards yet leaves the broker fully
    // root — `REGISTER_PERSONALITY` would then snapshot root creds with
    // `CAP_DAC_OVERRIDE`. Re-reading the effective ids closes that and every
    // future no-op/sentinel hole: a mismatch means we are not the requested
    // identity, so refuse rather than mint a forged personality. Raw reads
    // (see `raw_geteuid`) — no glibc between the raw `setresuid` and this
    // check.
    if raw_geteuid() != uid || raw_getegid() != gid {
        revert();
        return -(libc::EINVAL as i64);
    }

    let out = match crate::uring::sys::register_personality(ring_fd) {
        Ok(id) => i64::from(id),
        Err(e) => -(e as i32 as i64),
    };
    // --- window closes ---
    revert();
    out
}

/// Does `who` differ from the broker's current credentials?
fn needs_impersonation(
    uid: u32,
    gid: u32,
    groups: &[u32],
    scratch: &mut [libc::gid_t],
) -> bool {
    // Compare against the EFFECTIVE ids: `REGISTER_PERSONALITY` snapshots the
    // effective/fs identity, so the skip-the-window fast path is sound only
    // when the effective ids already match (a broker running ruid != euid —
    // e.g. launched setuid — must not treat a real-uid match as sufficient).
    // Raw reads only (see `raw_geteuid`).
    if uid != raw_geteuid() || gid != raw_getegid() {
        return true;
    }
    // SAFETY: raw `getgroups` into `scratch`; its length bounds the write.
    let n = unsafe {
        libc::syscall(
            libc::SYS_getgroups,
            scratch.len() as libc::c_long,
            scratch.as_mut_ptr(),
        )
    };
    if n < 0 {
        return true;
    }
    let cur = &scratch[..n as usize];
    if cur.len() != groups.len() {
        return true;
    }
    groups.iter().any(|g| !cur.contains(g))
}

/// Close the impersonation window. uid first — that is what restores the
/// privilege the remaining two calls need.
fn revert() {
    // SAFETY: restoring credentials via saved-uid 0. Each call is attempted
    // unconditionally: a failure here is unrecoverable and must not be
    // masked by a later success.
    unsafe {
        libc::syscall(libc::SYS_setresuid, 0, 0, 0);
        libc::syscall(libc::SYS_setresgid, 0, 0, 0);
        libc::syscall(
            libc::SYS_setgroups,
            0 as libc::size_t,
            std::ptr::null::<u32>(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uring::ring::Ring;
    use std::mem::size_of;

    /// The server-side fail-closed check in `register_as`: even if a caller
    /// bypassed the input guards, a `(uid_t)-1` request must NOT mint a
    /// personality — the kernel no-ops the setres*id drop, so the euid
    /// post-condition rejects it — and the broker must be left back at root.
    /// (Root-only: impersonation needs `CAP_SETUID`.)
    #[test]
    fn register_as_rejects_the_no_change_sentinel() {
        if raw_geteuid() != 0 {
            return;
        }
        let Ok(ring) = Ring::new(4) else { return };
        let mut scratch = [0 as libc::gid_t; 8];
        let out =
            register_as(ring.raw_fd(), u32::MAX, u32::MAX, &[], &mut scratch);
        assert!(out < 0, "sentinel uid/gid must be refused, got id {out}");
        // The window was reverted: we are root again, able to impersonate a
        // real (non-sentinel) uid on the same ring.
        assert_eq!(raw_geteuid(), 0, "euid restored after refusal");
        let ok = register_as(ring.raw_fd(), 65534, 65534, &[], &mut scratch);
        assert!(ok > 0, "a real uid still registers after the refusal: {ok}");
    }

    /// Pin the kernel behaviour that shapes this whole module: an io_uring
    /// descriptor **cannot** be passed over a unix socket. `scm_fp_copy`
    /// rejects it with `EINVAL` (kernel commit `a4104821ad65`, Linux 6.8,
    /// which dropped io_uring's unix-socket GC support).
    ///
    /// If this ever starts succeeding, a broker could be forked before any
    /// ring exists and receive rings later; until then the fds must be
    /// inherited across `fork`, which is why [`CredBroker::spawn`] takes
    /// the reactors themselves.
    #[test]
    fn io_uring_fd_cannot_cross_scm_rights() {
        let Ok(ring) = Ring::new(4) else {
            return; // io_uring unavailable (sandbox/old kernel)
        };
        let mut sv = [0 as RawFd; 2];
        // SAFETY: valid 2-element array.
        Errno::result(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        })
        .unwrap();
        // SAFETY: fresh fds from socketpair.
        let (a, b) = unsafe {
            (
                crate::fd::owned_from_raw(sv[0]),
                crate::fd::owned_from_raw(sv[1]),
            )
        };

        let payload = [0u8; 4];
        let mut cmsg_buf = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut c_void,
            iov_len: payload.len(),
        };
        // SAFETY: a zeroed msghdr is valid; every field used is set below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<c_void>();
        // SAFETY: CMSG_SPACE is pure arithmetic.
        msg.msg_controllen =
            unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) }
                as libc::size_t;
        let fd = ring.raw_fd();
        // SAFETY: the control buffer holds one SCM_RIGHTS cmsg for one fd.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(size_of::<RawFd>() as u32) as libc::size_t;
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!(fd).cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                size_of::<RawFd>(),
            );
        }
        // SAFETY: `msg` is fully initialized and outlives the call.
        let rc = unsafe { libc::sendmsg(a.as_raw_fd(), &msg, 0) };
        assert_eq!(rc, -1, "the kernel must refuse an io_uring fd here");
        assert_eq!(
            Errno::last(),
            Errno::EINVAL,
            "refusal is EINVAL from scm_fp_copy"
        );
        drop(b);
    }
}
