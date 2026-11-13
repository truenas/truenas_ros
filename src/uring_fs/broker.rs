//! The credential broker: a tiny forked process that mints personalities for *other* identities.
//!
//! Registering a personality snapshots the **caller's** credentials, so minting one for user X means some task must
//! first become X. The reactor process never does that itself, since glibc's `setuid` family signals every thread
//! (`SIGSETXID`) while io-wq workers, invisible to the broadcast, keep the old identity. A forked broker does it
//! instead, and its whole job is *three syscalls and a register*.
//!
//! ```text
//! main (single-threaded)            broker (cloned child, keeps CAP_SETUID)
//! ----------------------            --------------------------------------
//! UringFs::new()  -> ring fd
//! socketpair(SEQPACKET)
//! clone3() --------------------->   inherits the ring fds; closes all else
//! drop CAP_SETUID/CAP_SETGID        loop: recv
//! ... spawn threads, serve ...
//! ... session authenticates ...
//! register(AsUser) ------------->   SYS_setgroups + SYS_setresgid +
//!                                   SYS_setresuid (RAW), REGISTER_PERSONALITY,
//!                                   SYS_setresuid(0,0,0)      (revert)
//! Personality <-----------------    reply {id}
//! ```
//!
//! **`clone3`, not `fork`, and every credential syscall in the child is raw.** `CLONE_CLEAR_SIGHAND` keeps main's
//! signal handlers from running at the impersonated identity, `CLONE_PIDFD` gives race-free reaping, and
//! `exit_signal = 0` sends the host no `SIGCHLD` (see [`crate::clone3`]). glibc's credential wrappers broadcast
//! `SIGSETXID` across a thread list the clone copied stale, which can deadlock, so the window uses
//! `SYS_setgroups`/`SYS_setresgid`/`SYS_setresuid` and raw reads.
//!
//! **The ring fds are inherited across `fork`, never sent.** Since Linux 6.8 the kernel refuses to attach an io_uring
//! file to a unix socket (`scm_fp_copy` -> `-EINVAL`, kernel commit `a4104821ad65`), so every ring must exist before
//! [`CredBroker::spawn`]. A [`RingFd`] from `UringFs::setup_ring` or `net::server::setup_ring` is enough, so a reactor
//! that will live on its own thread is built after the fork, on that thread. `pidfd_getfd(2)` would lift that rule but
//! needs `CAP_SYS_PTRACE` for life, so it is not used.
//!
//! After [`CredBroker::spawn`] the reactor process holds no `CAP_SETUID`/`CAP_SETGID`, and the broker mints uid 0 only
//! within the root limit [`spawn_with_root`](CredBroker::spawn_with_root) fixed. A compromised main can still ask for
//! any non-root identity and free any id, so the guarantee is "no forged identity beyond the limits fixed at spawn",
//! not "no forging". A minted personality's effective set is empty unless [`Caps`] were allowed at spawn and asked for,
//! so the kernel's own permission checks bind it as they would bind the user.

use super::{Personality, UringFs};
use crate::errno::{self, Errno, retry_on_eintr};
use crate::sync::{Arc, Mutex};
use crate::uring::ring::RingFd;
use std::ffi::c_void;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::single_flight::SingleFlight;
use child::{broker_main, group_set_differs};
#[cfg(all(test, not(loom)))]
use child::{register_as, set_effective_caps};

/// The largest supplementary-group list a registration may carry.
///
/// A Kerberos PAC carries roughly 1015 group SIDs before `MaxTokenSize` problems begin, so **4096** clears Active
/// Directory several times over while one request stays inside a single 16 KiB SEQPACKET datagram. A longer list is
/// **rejected, never truncated**, since dropping groups silently changes what the identity may do. The cost is paid per
/// registration and grows with the list, which is why [`IdentityCache`] exists.
pub const MAX_GROUPS: usize = 4096;

/// How many rings one broker will serve.
///
/// A policy bound that catches a caller handing the broker a slice it did not mean to, at the one moment that cannot be
/// retried. It clears a ring on every core of a 128-core machine plus rings that serve no listener, since a personality
/// id is valid only on the ring it was minted against. Each ring costs the child one descriptor, and the renumbering
/// one more (`child_fd_high_water`).
pub const MAX_RINGS: usize = 128;

/// The child's IPC socket, after `tidy_child_fds` normalizes descriptors.
const SOCK_FD: RawFd = 3;
/// Ring `i`'s fd in the child: descriptors are renumbered at startup so the mapping needs no bookkeeping.
const RING_FD_BASE: RawFd = 4;

// Wire opcodes.
const OP_REGISTER: u8 = 1;
const OP_UNREGISTER: u8 = 2;

/// Request header: `op`, `ring`, `ngroups`, `uid`, `gid`, `caps`, then `ngroups` group ids. (`uid` doubles as the
/// personality id for `OP_UNREGISTER`.) Both ends compile from this crate, so the layout is an in-tree detail, not a
/// stable ABI.
const HDR_LEN: usize = 16;
const MAX_REQ: usize = HDR_LEN + 4 * MAX_GROUPS;

tn_bitflags! {
    /// Capabilities a minted [`Personality`] may carry, on top of the identity's own authority.
    ///
    /// Empty by default, and anything else is an escalation, so it must be allowed twice, once by the mask given to
    /// [`CredBroker::spawn_with_caps`] (fixed before the privilege drop) and again per request via [`AsUser::caps`].
    /// The bit values are the kernel's own capability numbers, so a mask is exactly the low word of `cap_effective`.
    ///
    /// The write-side bits are defensible only where the caller confines every path op, since they bound what may be
    /// done *within* a tree and say nothing about *which* tree. Add a bit only with its precise kernel semantics,
    /// verified against the source, written down.
    pub struct Caps: u32 {
        /// `CAP_DAC_READ_SEARCH` - **read the whole filesystem**.
        ///
        /// Grants search and `readdir` on any directory when the request carries no write bit (`fs/namei.c:478`), and
        /// file read only when the request is *exactly* read (`fs/namei.c:492`), so `O_RDWR` on a mode-`0000` file
        /// still fails `EACCES`. It never grants execute, write or delete, nor a way past a read-only mount, an
        /// immutable flag, quarantine or LSM policy. **On ZFS with NFSv4 ACLs it overrides an explicit DENY entry.** It
        /// satisfies the `linkat(AT_EMPTY_PATH)` check (`fs/namei.c:2632`), lifting the one-[`Lease`]-per-create rule
        /// on [`FsHandle::linkat_file`](crate::uring_fs::FsHandle::linkat_file). ZFS tests it in the initial user
        /// namespace, so it would diverge from the VFS under an idmapped mount (see [`crate::mount::idmap`]).
        DAC_READ_SEARCH = 0x0000_0004;

        /// `CAP_DAC_OVERRIDE` - **read and write the whole filesystem**, within whatever the caller's path resolution
        /// confines it to.
        ///
        /// On ZFS with NFSv4 ACLs it grants create, unlink and rename past an explicit DENY ACE, and it answers the
        /// VFS's NFSv4 `chmod`/`chown` retry (`fs/attr.c:188-196`, `:229-236`), so it rewrites a mode or ACL it does
        /// not own and, where the ACL is non-trivial, changes the owner (see [`Caps::FOWNER`]). It does not defeat a
        /// DENY `ACE_DELETE`, a read-only dataset, `ZFS_IMMUTABLE`, `ZFS_NOUNLINK` or quarantine.
        ///
        /// **This bit requires confinement.** Unconfined it could create, unlink and rename anywhere the reactor can
        /// name. `RESOLVE_BENEATH` bounds it whatever the capability (`fs/namei.c:1045`, `:2108`), so a consumer must
        /// resolve every user-supplied name from a per-tenant anchor.
        DAC_OVERRIDE = 0x0000_0002;

        /// `CAP_FOWNER` - **act as the owner of every file**, within whatever the caller's path resolution confines it
        /// to.
        ///
        /// Grants `chmod` and ACL rewrite, and on a file whose NFSv4 ACL is non-trivial it grants `chown`, since ZFS
        /// asks for this bit there and not `CAP_CHOWN`. Over [`Caps::DAC_OVERRIDE`] it adds **delete past an explicit
        /// DENY `ACE_DELETE`**. It does not defeat a read-only dataset, `ZFS_IMMUTABLE`, `ZFS_NOUNLINK` or quarantine,
        /// nor widen [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs).
        ///
        /// **An ownership change outlives the request that made it**, and becomes authoritative if the tree is later
        /// served under a policy where the filesystem decides. Declining this bit alone does not close that, since
        /// [`Caps::DAC_OVERRIDE`] reaches the same state.
        FOWNER = 0x0000_0008;

        /// `CAP_CHOWN` - **change the owner and group of any file**, for uid 0 alone (see [`Caps::ROOT_ONLY`]).
        ///
        /// The VFS checks it before any filesystem sees a chown (`chown_ok` and `chgrp_ok` in `fs/attr.c`). Without it
        /// only the owner may change the group, and only to a group it is in. On ZFS a chown then also needs
        /// [`Caps::FOWNER`], which `zfs_setattr` asks for through `secpolicy_vnode_chown`, so a root personality that
        /// is to chown carries both.
        CHOWN = 0x0000_0001;

        /// `CAP_FSETID` - **keep the set-user-ID and set-group-ID bits**, for uid 0 alone (see [`Caps::ROOT_ONLY`]).
        ///
        /// Without it the kernel drops them when a regular file is written or changes owner
        /// (`setattr_should_drop_suidgid` in `fs/attr.c`), and keeps set-group-ID on a chmod or a create only for a
        /// member of the group (`in_group_or_capable` and `mode_strip_sgid` in `fs/inode.c`). ZFS asks for it in the
        /// same cases (`secpolicy_vnode_setid_retain`, `secpolicy_vnode_setids_setgids` and
        /// `secpolicy_vnode_setid_modify`).
        FSETID = 0x0000_0010;

        /// `CAP_MKNOD` - **make a character or block device**, for uid 0 alone (see [`Caps::ROOT_ONLY`]).
        ///
        /// `vfs_mknod` (`fs/namei.c`) refuses a device without it. A FIFO and a socket need nothing.
        MKNOD = 0x0800_0000;
    }
}

impl Caps {
    /// The capabilities a root personality may carry and no other may, [`Caps::CHOWN`], [`Caps::FSETID`] and
    /// [`Caps::MKNOD`]. [`CredBroker::spawn_with_caps`] refuses them in the limit for identities other than root, so
    /// only the limit for uid 0 that [`CredBroker::spawn_with_root`] fixes may name them.
    pub const ROOT_ONLY: Caps = Caps::CHOWN.union(Caps::FSETID).union(Caps::MKNOD);
}

/// The identity to impersonate: everything the kernel consults for a filesystem permission check.
///
/// `groups` is the full supplementary list, exactly as the directory service reports it, since a missing group denies
/// access and an extra one grants it. It is stored **sorted and deduplicated**, so [`IdentityCache`] reuses a
/// personality for the same set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsUser {
    /// Filesystem user id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    groups: Vec<u32>,
    caps: Caps,
}

impl AsUser {
    /// A new identity with no supplementary groups and no capability.
    pub fn new(uid: u32, gid: u32) -> AsUser {
        AsUser {
            uid,
            gid,
            groups: Vec::new(),
            caps: Caps::empty(),
        }
    }

    /// Set the supplementary groups (normalized to a sorted, deduplicated set - see the type docs).
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

    /// Request capabilities on top of this identity's own authority - see [`Caps`], and note that the broker's
    /// spawn-time mask is the ceiling.
    pub fn caps(mut self, caps: Caps) -> AsUser {
        self.caps = caps;
        self
    }

    /// The capabilities requested for this identity.
    pub fn cap_set(&self) -> Caps {
        self.caps
    }
}

/// The parent's end of the broker socket, with the mark that says a reply is owed on it and nobody is going to claim
/// it.
///
/// The two travel under one lock because the mark is only meaningful to whoever is about to use the socket: a reply
/// carries nothing naming the request it answers, so a thread that finds the mark set must not send.
struct BrokerSock {
    fd: OwnedFd,
    /// Set when a request was delivered and its reply was not received. See [`round_trip`].
    desynced: bool,
}

struct BrokerInner {
    /// One request at a time.
    sock: Mutex<BrokerSock>,
    pid: libc::pid_t,
    /// The broker's pidfd (from `clone3(CLONE_PIDFD)`): race-free death detection ([`CredBroker::is_alive`]),
    /// signalling, and reaping.
    pidfd: OwnedFd,
    /// The ring descriptors this broker was spawned over, in the order the child renumbered them (ring `i` is the
    /// child's `RING_FD_BASE + i`). Kept so a handle can be asked for by *ring* rather than by position - see
    /// [`CredBroker::handle_for`].
    ring_fds: Vec<RawFd>,
    /// Whether the broker was spawned with a root limit, so that [`CredHandle::register`] can refuse uid 0 with a clear
    /// error before the broker refuses it with `EPERM`.
    root: bool,
}

impl Drop for BrokerInner {
    fn drop(&mut self) {
        // Kill and reap the broker. The pidfd makes `SIGKILL` PID-reuse-safe, and `__WALL` is needed because
        // `exit_signal == 0` makes the child a "clone child" to `eligible_child` (`kernel/exit.c:1163`), so a plain
        // `waitpid` answers `ECHILD` and leaves the zombie.
        // SAFETY: `pidfd_send_signal` on our owned pidfd; NULL siginfo / 0 flags per the man page.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::c_void>(),
                0u32,
            );
        }
        // SAFETY: waitpid on our child pid; a NULL status pointer is allowed.
        let _ = retry_on_eintr(|| unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), libc::__WALL) });
    }
}

/// A handle to the broker process. `Send + Sync + Clone` - registration happens on whichever thread authenticates a
/// session, never on the reactor loop.
#[derive(Clone)]
pub struct CredBroker {
    inner: Arc<BrokerInner>,
}

impl std::fmt::Debug for CredBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredBroker")
            .field("pid", &self.inner.pid)
            .field("rings", &self.inner.ring_fds.len())
            .finish_non_exhaustive()
    }
}

/// A broker bound to one ring: what a consumer actually calls to mint and retire identities. Obtain it from
/// [`CredBroker::handle`].
#[derive(Clone, Debug)]
pub struct CredHandle {
    broker: CredBroker,
    ring: u8,
}

impl CredHandle {
    /// Which ring this handle mints on - its position in the slice [`CredBroker::spawn`] was given. A [`Personality`]
    /// minted here is meaningful on that ring and no other.
    pub fn ring(&self) -> u8 {
        self.ring
    }

    /// Mint a [`Personality`] for `who` - the broker impersonates that identity just long enough to snapshot it.
    ///
    /// Requires the broker to hold `CAP_SETUID`/`CAP_SETGID` unless `who` already *is* the broker's own identity.
    /// Registering `uid == 0` is refused unless the broker was spawned with [`CredBroker::spawn_with_root`], and then
    /// it carries no capability outside the root limit fixed there. The daemon's own identity comes from
    /// [`UringFs::register_self`].
    pub fn register(&self, who: &AsUser) -> crate::Result<Personality> {
        if who.uid == 0 && !self.broker.inner.root {
            return Err(crate::Error::Validation(
                "refusing to register a personality for uid 0, since the \
                 broker was not spawned with a root limit; use \
                 UringFs::register_self for the daemon's own identity"
                    .into(),
            ));
        }
        // `(uid_t)-1`/`(gid_t)-1` are the kernel's "leave unchanged" sentinel for setres*id; they must never reach the
        // impersonation window (the broker verifies the drop server-side too, but reject them here for a clear error
        // rather than a bare EINVAL).
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
        // Through `Personality::from_raw`, whose `!= 0` refusal exists for data that crossed a process boundary. Id 0
        // means *no credential override*, so an op stamped with it would run as the root daemon, and the kernel never
        // allocates it (`XA_FLAGS_ALLOC1`).
        u16::try_from(id)
            .ok()
            .and_then(Personality::from_raw)
            .ok_or_else(|| Errno::EINVAL.into())
    }

    /// Retire a personality, freeing its kernel-held credential and its id.
    ///
    /// Call this when a session ends, since ids are a per-ring `u16` space. In-flight operations that already resolved
    /// the id complete normally, and new SQEs naming it fail `EINVAL`. It takes no proof of ownership, so prefer the
    /// ref-counted [`IdentityCache`], which frees an id only once its last [`Lease`] drops.
    pub fn unregister(&self, who: Personality) -> crate::Result<()> {
        let msg = AsUser::new(u32::from(who.0), 0);
        self.broker.request(OP_UNREGISTER, self.ring, &msg)?;
        Ok(())
    }
}

/// A registered identity, kept alive by its leases.
///
/// The kernel id is freed by `Drop`, so the `Arc` count *is* the reference count, and in-flight work finishes under the
/// old id after the cache entry is gone.
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
/// A lease keeps its personality registered, but dropping the last one does **not** retire it, since the cache entry
/// holds a reference of its own. A cached identity stays registered until [`invalidate`](IdentityCache::invalidate) (or
/// dropping the cache) and every lease have released it.
#[derive(Clone, Debug)]
pub struct Lease(Arc<IdEntry>);

impl Lease {
    /// The personality to stamp on operations for this identity.
    pub fn personality(&self) -> Personality {
        self.0.id
    }
}

/// Registers each distinct identity once and hands out reference-counted [`Lease`]s - the "register on connect, but
/// only if the credentials are new" pattern.
///
/// Every live id pins a kernel credential inside a per-ring **`u16`** space, so registering per connection rather than
/// per identity would cap concurrent connections near 65k per ring.
///
/// ```no_run
/// # use truenas_ros::uring_fs::{AsUser, UringFs, CredBroker, FsConfig, IdentityCache};
/// # let afs = UringFs::new(FsConfig::default())?;
/// # let broker = CredBroker::spawn(&[&afs])?;
/// let cache = IdentityCache::new(broker.handle(0)?);
///
/// // On each connection, after authenticating:
/// let lease = cache.acquire(&AsUser::new(1000, 1000).groups(vec![4, 27]))?;
/// let who = lease.personality();
/// // ... serve the connection, stamping `who` ...
/// drop(lease); // the identity stays cached (and registered) for the next one
/// # Ok::<(), truenas_ros::Error>(())
/// ```
///
/// **Snapshots are frozen, and nothing expires on its own.** A cached identity will not notice a later directory
/// change. Call [`invalidate`](Self::invalidate) on a change event or a TTL, or
/// [`invalidate_all`](Self::invalidate_all), and leases already handed out keep working until they drop. A daemon that
/// never invalidates accumulates one id per distinct identity it has served.
#[derive(Clone, Debug)]
pub struct IdentityCache {
    inner: Arc<CacheInner>,
}

#[derive(Debug)]
struct CacheInner {
    creds: CredHandle,
    live: SingleFlight<AsUser, Arc<IdEntry>>,
}

impl IdentityCache {
    /// Build a cache over one ring's broker handle.
    pub fn new(creds: CredHandle) -> IdentityCache {
        IdentityCache {
            inner: Arc::new(CacheInner {
                creds,
                live: SingleFlight::new(),
            }),
        }
    }

    /// A lease on `who`'s personality, registering it only if this is the first live use of exactly these credentials.
    ///
    /// Concurrent callers asking for the same new identity collapse into one registration, and the map lock is never
    /// held across the broker round trip (see `SingleFlight`).
    pub fn acquire(&self, who: &AsUser) -> crate::Result<Lease> {
        let creds = &self.inner.creds;
        let entry = self.inner.live.get_or_try_init(who, || {
            Ok(Arc::new(IdEntry {
                id: creds.register(who)?,
                creds: creds.clone(),
            }))
        })?;
        Ok(Lease(entry))
    }

    /// Forget the cached personality for `who`, so the next [`acquire`](Self::acquire) mints a fresh one. Outstanding
    /// leases are unaffected and retire the old id when they drop.
    pub fn invalidate(&self, who: &AsUser) {
        self.inner.live.invalidate(who);
    }

    /// Forget every cached identity (a wholesale directory-services change). Existing leases keep working, as in
    /// [`invalidate`](Self::invalidate).
    pub fn invalidate_all(&self) {
        self.inner.live.clear();
    }

    /// How many distinct identities are currently cached and registered. An identity whose mint is still in flight does
    /// not count (one that failed leaves nothing behind at all).
    pub fn len(&self) -> usize {
        self.inner.live.len()
    }

    /// Whether no identity is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A reactor whose io_uring ring a [`CredBroker`] registers personalities on.
///
/// Implemented by the standalone [`UringFs`] and by a `net` server built with an fs pool - so a server can act as
/// *authenticated peers* on its own ring, the fs ops and net ops interleaving there (fs ops carry a registered
/// personality, net ops carry 0).
pub trait BrokerReactor {
    /// The ring descriptor the broker inherits at `fork` and registers on.
    ///
    /// Hidden by design: a ring fd plus its personality xarray is a credential capability (anyone holding it can
    /// register creds on the ring), not a handle to pass around - [`CredBroker::spawn`] is the only intended consumer.
    #[doc(hidden)]
    fn broker_ring_fd(&self) -> RawFd;
}

impl BrokerReactor for UringFs {
    fn broker_ring_fd(&self) -> RawFd {
        self.ring_fd()
    }
}

// A ring created ahead of the reactor that will run it (`UringFs::setup_ring`, `net::server::setup_ring`). The broker
// needs only the descriptor, which exists from `io_uring_setup` on; mapping and driving it happen later, on the thread
// that receives the `RingFd`.
impl BrokerReactor for RingFd {
    fn broker_ring_fd(&self) -> RawFd {
        self.raw_fd()
    }
}

impl CredBroker {
    /// Fork the broker process - which inherits `reactors`' ring descriptors - then permanently drop
    /// `CAP_SETUID`/`CAP_SETGID` from **this** process.
    ///
    /// # Ordering requirements
    ///
    /// 1. **Every ring must already exist.** The broker registers on the fds it inherits, and an io_uring fd cannot be
    ///    sent to it later. For reactors that will run on their own threads, create the rings with
    ///    `UringFs::setup_ring` or `net::server::setup_ring`, spawn the broker over the [`RingFd`]s, and build each
    ///    reactor on its thread with `with_ring`.
    /// 2. **Call this before starting any threads.** A raw `clone3` skips glibc's atfork malloc mitigation, so a lock
    ///    another thread held at the fork (a malloc arena above all) stays locked in the child. The child survives a
    ///    violation only because its scratch buffers are allocated here and its request loop allocates nothing and
    ///    makes only raw syscalls. Anything added to the child that allocates, locks, or calls stateful glibc makes the
    ///    rule load-bearing again.
    ///
    /// A process that was already unprivileged has nothing to drop, and its broker can still register its own identity.
    ///
    /// **Failure is fatal.** An `Err` means the security setup did not complete (on a `capset` failure the caps may
    /// still be held), so the caller must abort, never continue serving.
    pub fn spawn<R: BrokerReactor + ?Sized>(reactors: &[&R]) -> crate::Result<CredBroker> {
        CredBroker::spawn_with_caps(reactors, Caps::empty())
    }

    /// [`spawn`](Self::spawn), but permitting brokered personalities to carry capabilities from `allowed`.
    ///
    /// `allowed` is a **ceiling fixed here**, before the privilege drop, and a registration asking for anything outside
    /// it fails `EPERM`. A compromised main can already ask for any non-root identity, so pass the smallest set the
    /// deployment needs. A request whose identity matches the broker's own is refused `EPERM` when it asks for any
    /// capability. [`Caps::ROOT_ONLY`] in `allowed` is a `Validation` error.
    ///
    /// **Impersonation is available to the first broker in a process, and only that one.** A broker spawned later
    /// inherits the stripped capability set, so it serves the process's own identity and refuses every other with
    /// `EPERM`.
    pub fn spawn_with_caps<R: BrokerReactor + ?Sized>(reactors: &[&R], allowed: Caps) -> crate::Result<CredBroker> {
        CredBroker::spawn_policy(reactors, allowed, None)
    }

    /// [`spawn_with_caps`](Self::spawn_with_caps), and also permitting a root personality, `uid == 0`, carrying
    /// capabilities from `root`.
    ///
    /// `root` is a second ceiling fixed here, and it binds uid 0 alone. Only `root` may hold [`Caps::ROOT_ONLY`].
    ///
    /// The window cannot lean on the kernel here. A root personality keeps uid 0, and the kernel clears the effective
    /// set only when the euid leaves root (`cap_emulate_setxuid`, `security/commoncap.c`), so the window sets both
    /// words of the effective set to exactly what the request asked for, and its revert gives the broker its own set
    /// back before it clears the groups, since `setgroups` needs `CAP_SETGID`. A root request never takes the path that
    /// registers the broker's own credentials.
    ///
    /// A root personality takes the gid and the groups of the request, as the kernel's own file server does
    /// (`nfsd_setuser`, `fs/nfsd/auth.c`).
    pub fn spawn_with_root<R: BrokerReactor + ?Sized>(
        reactors: &[&R],
        allowed: Caps,
        root: Caps,
    ) -> crate::Result<CredBroker> {
        CredBroker::spawn_policy(reactors, allowed, Some(root))
    }

    /// The body of [`spawn_with_caps`](Self::spawn_with_caps) and [`spawn_with_root`](Self::spawn_with_root), with the
    /// root limit, if any.
    fn spawn_policy<R: BrokerReactor + ?Sized>(
        reactors: &[&R],
        allowed: Caps,
        root: Option<Caps>,
    ) -> crate::Result<CredBroker> {
        if allowed.intersects(Caps::ROOT_ONLY) {
            return Err(crate::Error::Validation(format!(
                "{:?} are for uid 0 alone, and belong in the root limit of \
                 spawn_with_root",
                allowed & Caps::ROOT_ONLY
            )));
        }
        if reactors.is_empty() || reactors.len() > MAX_RINGS {
            return Err(crate::Error::Validation(format!(
                "a broker serves 1..={MAX_RINGS} rings, got {}",
                reactors.len()
            )));
        }
        let ring_fds: Vec<RawFd> = reactors.iter().map(|r| r.broker_ring_fd()).collect();

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

        // The child renumbers through a scratch range above its highest inherited fd (`tidy_child_fds`), and a `dup3`
        // past `RLIMIT_NOFILE` kills it after `CAP_SETUID` is shed. Check here, where a `Validation` error lets the
        // caller retry with fewer rings.
        let max_src = ring_fds.iter().copied().fold(child_end.as_raw_fd(), |a, b| a.max(b));
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` over a stack `rlimit` this thread owns.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
            let top = child_fd_high_water(max_src, ring_fds.len());
            if u64::from(top.unsigned_abs()) >= lim.rlim_cur {
                return Err(crate::Error::Validation(format!(
                    "not enough descriptor headroom to renumber {} ring(s): \
                     the child would need descriptors up to {top}, but \
                     RLIMIT_NOFILE is {}",
                    ring_fds.len(),
                    lim.rlim_cur
                )));
            }
        }

        // Both directions are bounded, or a stalled child wedges every caller behind the socket mutex (see
        // `RECV_TIMEOUT`).
        set_timeout(parent_end.as_raw_fd(), libc::SO_RCVTIMEO, RECV_TIMEOUT)?;
        set_timeout(parent_end.as_raw_fd(), libc::SO_SNDTIMEO, RECV_TIMEOUT)?;

        // Allocate the broker's scratch buffers here, before the fork, so the child's request loop never allocates
        // (see `spawn`).
        let req = vec![0u8; MAX_REQ];
        let groups = vec![0u32; MAX_GROUPS];
        let scratch = vec![0 as libc::gid_t; MAX_GROUPS];

        let mut pidfd: RawFd = -1;
        // SAFETY: the child does nothing a fork-copied lock could block, since `broker_main` runs only raw syscalls
        // over the buffers allocated above and ends in `_exit`.
        let fork_ret = unsafe { crate::clone3::clone3_fork(0, 0, &mut pidfd) };
        let pid = match fork_ret {
            Ok(pid) => pid,
            Err(e) => {
                // Shed the mint privilege even on failure: no broker exists, so main has no use for CAP_SETUID/SETGID.
                // `spawn` failure is fatal (see the doc).
                let _ = drop_setid_caps();
                return Err(e.into());
            }
        };
        if pid == 0 {
            // The child must not run any destructor belonging to the parent (they would free memory the parent still
            // owns and flush its buffers a second time), so `broker_main` ends in `_exit`.
            broker_main(child_end.as_raw_fd(), &ring_fds, allowed, root, req, groups, scratch);
        }
        // SAFETY: `CLONE_PIDFD` wrote a fresh owned pidfd for the child.
        let pidfd = unsafe { crate::fd::owned_from_raw(pidfd) };
        drop(child_end);
        // If this fails the broker is already running but main still holds the mint caps - an unsafe state. The `?`
        // surfaces it; `spawn` failure is fatal (see the doc), so the caller aborts rather than serves.
        drop_setid_caps()?;
        let broker = CredBroker {
            inner: Arc::new(BrokerInner {
                sock: Mutex::new(BrokerSock {
                    fd: parent_end,
                    desynced: false,
                }),
                pid,
                pidfd,
                ring_fds,
                root: root.is_some(),
            }),
        };
        // Take the child's ready datagram first, so a child that died renumbering fails `spawn` here rather than at the
        // first `register`, after the mint capabilities are gone. Dropping `broker` kills and reaps it.
        {
            let sock = broker.inner.sock.lock().map_err(|_| Errno::EIO)?;
            recv_reply(sock.fd.as_raw_fd())?;
        }
        Ok(broker)
    }

    /// The handle for the ring `reactor` runs on.
    ///
    /// Prefer this to [`handle`](Self::handle). A [`Personality`] is meaningful only on the ring that minted it, and
    /// crossing two rings runs the operation under another identity rather than failing. A reactor this broker was not
    /// spawned over is a `Validation` error. The match is on the ring descriptor, so keep the spawn slice alive for the
    /// broker's life.
    pub fn handle_for<R: BrokerReactor + ?Sized>(&self, reactor: &R) -> crate::Result<CredHandle> {
        let fd = reactor.broker_ring_fd();
        let index =
            self.inner.ring_fds.iter().position(|&r| r == fd).ok_or_else(|| {
                crate::Error::Validation("that reactor's ring is not one this broker serves".to_owned())
            })?;
        self.handle(index as u8)
    }

    /// The handle for ring `index` - the position of that [`UringFs`] in the slice passed to [`CredBroker::spawn`].
    ///
    /// Positional, so a personality minted through the wrong index runs as another ring's identity without failing.
    /// [`handle_for`](Self::handle_for) takes the reactor instead.
    pub fn handle(&self, index: u8) -> crate::Result<CredHandle> {
        if usize::from(index) >= self.inner.ring_fds.len() {
            return Err(crate::Error::Validation(format!(
                "ring index {index} out of range (broker serves {})",
                self.inner.ring_fds.len()
            )));
        }
        Ok(CredHandle {
            broker: self.clone(),
            ring: index,
        })
    }

    /// The broker process's pid (for supervision: if it dies, existing personalities keep working - the kernel
    /// refcounts them - but no new identity can be minted until the process is restarted).
    pub fn pid(&self) -> i32 {
        self.inner.pid
    }

    /// Whether the broker process is still alive. Race-free against PID reuse, since it polls the pidfd, and a poll
    /// error reads as not-alive. Personalities already registered keep working after the broker dies.
    ///
    /// **Alive is not the same as able to mint every identity.** A broker spawned after the first in a process holds no
    /// `CAP_SETUID`, so it serves only the process's own identity
    /// ([`UringFs::register_self`](crate::uring_fs::UringFs::register_self)) and answers `EPERM` for the rest.
    /// Recovering impersonation needs a fresh process.
    pub fn is_alive(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.inner.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll over one owned pidfd, 0 timeout (non-blocking). Retry on EINTR so a signal delivered to the
        // daemon can't make a live broker look dead.
        let r = retry_on_eintr(|| unsafe { libc::poll(&mut pfd, 1, 0) });
        matches!(r, Ok(0))
    }

    fn request(&self, op: u8, ring: u8, who: &AsUser) -> crate::Result<i64> {
        // Sized to this request, not to MAX_GROUPS: a large cap must not put a 16 KiB array on the caller's stack for a
        // two-group user.
        let len = HDR_LEN + 4 * who.groups.len();
        let mut req = vec![0u8; len];
        req[0] = op;
        req[1] = ring;
        req[2..4].copy_from_slice(&(who.groups.len() as u16).to_le_bytes());
        req[4..8].copy_from_slice(&who.uid.to_le_bytes());
        req[8..12].copy_from_slice(&who.gid.to_le_bytes());
        req[12..16].copy_from_slice(&who.caps.bits().to_le_bytes());
        for (i, g) in who.groups.iter().enumerate() {
            let at = HDR_LEN + 4 * i;
            req[at..at + 4].copy_from_slice(&g.to_le_bytes());
        }

        let mut sock = self.inner.sock.lock().map_err(|_| Errno::EIO)?;
        let reply = round_trip(&mut sock, &req)?;
        if reply < 0 {
            return Err(Errno::from_raw(-reply as i32).into());
        }
        Ok(reply)
    }
}

/// One request/reply exchange, and the whole of the socket's state machine.
///
/// **SECURITY.** A reply names no request, so a recv that gives up leaves the broker's answer queued for the *next*
/// caller, which would be handed another identity's personality with every later reply shifted. There is no
/// resynchronising without a sequence number, so any recv failure once the request is on the wire marks the socket, and
/// every later request answers `EPROTO`.
///
/// A failed *send* delivered nothing (`unix_dgram_sendmsg` fails before `skb_queue_tail`), and `ECONNRESET` consumed
/// the queue (EOF, or a datagram read and discarded), so neither marks.
fn round_trip(sock: &mut BrokerSock, req: &[u8]) -> errno::Result<i64> {
    if sock.desynced {
        return Err(Errno::EPROTO);
    }
    let n = retry_on_eintr(|| {
        // SAFETY: `req` is a valid initialized buffer of `req.len()`.
        unsafe {
            libc::send(
                sock.fd.as_raw_fd(),
                req.as_ptr().cast::<c_void>(),
                req.len(),
                libc::MSG_NOSIGNAL,
            )
        }
    })?;
    if n as usize != req.len() {
        return Err(Errno::EIO);
    }
    // Delivered. From here a reply is owed on this socket, and anything but taking it - bar the one ending that proves
    // none is coming - leaves that reply for whoever sends next.
    recv_reply(sock.fd.as_raw_fd()).inspect_err(|e| {
        if *e != Errno::ECONNRESET {
            sock.desynced = true;
        }
    })
}

fn recv_reply(sock: RawFd) -> errno::Result<i64> {
    let mut buf = [0u8; 8];
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid 8-byte destination.
        unsafe { libc::recv(sock, buf.as_mut_ptr().cast::<c_void>(), buf.len(), 0) }
    })?;
    if n as usize != buf.len() {
        // A short or empty read means the broker died mid-request.
        return Err(Errno::ECONNRESET);
    }
    Ok(i64::from_le_bytes(buf))
}

/// How long a broker round trip may take before the caller gives up.
///
/// Broker death already fails closed, but a stall would not. The socket mutex spans send and recv, and `IdEntry::drop`
/// unregisters, so one wedged request would block every thread dropping a last `Lease`, the reactor thread included.
/// This is a ceiling on the pathological (a cgroup freeze, or a child wedged in a fork-copied malloc arena), not a
/// latency budget, since giving up spends the socket ([`round_trip`]).
const RECV_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound how long `recv` or `send` on `sock` may block (`opt` is `SO_RCVTIMEO` or `SO_SNDTIMEO`; both take a
/// `timeval`).
fn set_timeout(sock: RawFd, opt: libc::c_int, d: Duration) -> errno::Result<()> {
    let tv = libc::timeval {
        tv_sec: d.as_secs() as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: `tv` is a live `timeval` of the length passed.
    Errno::result(unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            opt,
            std::ptr::addr_of!(tv).cast::<c_void>(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
const VERSION_3: u32 = 0x2008_0522;

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

/// Give the calling process's effective set back the whole of its permitted set, both words, as returning to euid 0
/// from another uid does (`cap_emulate_setxuid`, `security/commoncap.c`). A root window never leaves uid 0, so nothing
/// else gives it back, and `capset` raises effective within permitted with no capability of its own (`cap_capset`).
fn restore_effective_caps() -> errno::Result<()> {
    let mut hdr = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget fills two CapData words for VERSION_3.
    Errno::result(unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(hdr), data.as_mut_ptr()) })?;
    for word in &mut data {
        word.effective = word.permitted;
    }
    // SAFETY: capset reads the same two-word layout back.
    Errno::result(unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of_mut!(hdr), data.as_ptr()) })?;
    Ok(())
}

/// Drop `CAP_SETUID`/`CAP_SETGID` from every capability set of the calling process. Succeeds trivially where they were
/// not held.
fn drop_setid_caps() -> errno::Result<()> {
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
    Errno::result(unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(hdr), data.as_mut_ptr()) })?;
    // CAP_SETGID (6) and CAP_SETUID (7) both live in the low word.
    data[0].effective &= mask;
    data[0].permitted &= mask;
    data[0].inheritable &= mask;
    // SAFETY: capset reads the same two-word layout back.
    Errno::result(unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of_mut!(hdr), data.as_ptr()) })?;
    // A uid-0 process regains its bounding set into permitted on `execve` (`handle_privileged_root`,
    // `security/commoncap.c`), so drop the caps from the bounding set too. `PR_CAPBSET_DROP` needs `CAP_SETPCAP` and an
    // ordinary bounding set is full, so a refused drop is tolerated for a non-root reactor, which has nothing to
    // regain. A root reactor that cannot drop has lost the guarantee, and `spawn` fails.
    const PR_CAPBSET_DROP: libc::c_long = 24;
    let is_root = raw_getuid() == 0 || raw_geteuid() == 0;
    for cap in [CAP_SETUID, CAP_SETGID] {
        // SAFETY: prctl with scalar arguments.
        let rc = unsafe { libc::syscall(libc::SYS_prctl, PR_CAPBSET_DROP, cap as libc::c_long) };
        if rc != 0 {
            let e = Errno::last();
            if is_root || e != Errno::EPERM {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// One validated broker request header.
///
/// `Copy` and free of owned fields, since the broker loop allocates nothing. `pub` only so the `__fuzz` seam in the
/// parent module can re-export it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Req {
    /// `OP_REGISTER` or `OP_UNREGISTER`; anything else is rejected downstream.
    pub op: u8,
    /// Ring index, already checked against the broker's ring count.
    pub ring: usize,
    /// Supplementary group count, already checked against `MAX_GROUPS` and against the datagram's exact length.
    pub ngroups: usize,
    /// The identity's uid - or, for `OP_UNREGISTER`, the personality id.
    pub uid: u32,
    /// The identity's gid.
    pub gid: u32,
    /// Requested capabilities, already checked to be a subset of the spawn-time ceiling, the root limit for a
    /// registration of uid 0.
    pub caps: Caps,
}

/// Decode and validate one request datagram, or return the negated errno the broker replies with.
///
/// This is the privilege boundary, so every field is checked before it reaches `register_as`, and it allocates nothing.
/// A registration of uid 0 is held to `root`, the limit [`CredBroker::spawn_with_root`] fixed, and refused `EPERM` when
/// the broker has none. Every other request is held to `allowed`.
pub fn decode_request(req: &[u8], nrings: usize, allowed: Caps, root: Option<Caps>) -> std::result::Result<Req, i64> {
    if req.len() < HDR_LEN {
        return Err(-(libc::EINVAL as i64));
    }
    let op = req[0];
    let ring = usize::from(req[1]);
    let ngroups = usize::from(u16::from_le_bytes([req[2], req[3]]));
    let uid = u32::from_le_bytes([req[4], req[5], req[6], req[7]]);
    let gid = u32::from_le_bytes([req[8], req[9], req[10], req[11]]);
    let caps_bits = u32::from_le_bytes([req[12], req[13], req[14], req[15]]);

    // Exact length, not a lower bound: a datagram truncated by the fixed-size receive buffer must be refused, never
    // read as though the missing tail were zeroes.
    if ring >= nrings || ngroups > MAX_GROUPS || req.len() != HDR_LEN + 4 * ngroups {
        return Err(-(libc::EINVAL as i64));
    }
    // An unknown bit is refused rather than masked off, or the caller gets a weaker personality than it asked for. The
    // id of `OP_UNREGISTER` rides in the uid field and asks for no capability, so it stays with `allowed`.
    let ceiling = match (op, root) {
        (OP_REGISTER, Some(root)) if uid == 0 => root,
        (OP_REGISTER, None) if uid == 0 => return Err(-(libc::EPERM as i64)),
        _ => allowed,
    };
    let caps = match Caps::from_bits(caps_bits) {
        Some(c) if ceiling.contains(c) => c,
        // Outside the spawn-time ceiling, or not a capability this build knows how to mint.
        _ => return Err(-(libc::EPERM as i64)),
    };
    Ok(Req {
        op,
        ring,
        ngroups,
        uid,
        gid,
        caps,
    })
}

/// Copy the request's `ngroups` supplementary gids into `out`.
///
/// `req` must be a datagram [`decode_request`] accepted with this `ngroups`, which fixes its length at `HDR_LEN + 4 *
/// ngroups`. Writes into the caller's scratch buffer rather than returning a `Vec`, so the broker loop stays
/// allocation-free.
pub fn decode_groups(req: &[u8], ngroups: usize, out: &mut [u32]) {
    for (i, g) in out.iter_mut().take(ngroups).enumerate() {
        let at = HDR_LEN + 4 * i;
        *g = u32::from_le_bytes([req[at], req[at + 1], req[at + 2], req[at + 3]]);
    }
}

/// The highest descriptor number [`tidy_child_fds`] will name for a child inheriting `n` rings whose highest inherited
/// descriptor is `max_src`.
///
/// Split out so `spawn` can check it against `RLIMIT_NOFILE` before the fork, since in the child a refused `dup3` is an
/// `_exit`.
fn child_fd_high_water(max_src: RawFd, n: usize) -> RawFd {
    let scratch_base = max_src.max(RING_FD_BASE + n as RawFd) + 1;
    scratch_base + n as RawFd
}

/// Receive one request. Returns 0 when the parent has closed the socket.
fn recv_request(sock: RawFd, buf: &mut [u8]) -> errno::Result<usize> {
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid destination for its own length.
        unsafe { libc::recv(sock, buf.as_mut_ptr().cast::<c_void>(), buf.len(), 0) }
    })?;
    Ok(n as usize)
}

fn reply(sock: RawFd, value: i64) -> errno::Result<()> {
    let buf = value.to_le_bytes();
    let n = retry_on_eintr(|| {
        // SAFETY: `buf` is a valid 8-byte source.
        unsafe { libc::send(sock, buf.as_ptr().cast::<c_void>(), buf.len(), libc::MSG_NOSIGNAL) }
    })?;
    if n as usize != buf.len() {
        return Err(Errno::EIO);
    }
    Ok(())
}

/// Raw `geteuid`, since the credential path in the cloned broker child keeps clear of glibc (see the module docs). A
/// read does not broadcast, but going raw keeps the post-condition check from trusting glibc not to cache the effective
/// id after a raw `setresuid`.
fn raw_geteuid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_geteuid) as u32 }
}

fn raw_getuid() -> u32 {
    // SAFETY: `getuid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_getuid) as u32 }
}

fn raw_getegid() -> u32 {
    // SAFETY: `getegid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_getegid) as u32 }
}

/// Does `who` differ from the broker's current credentials?
fn needs_impersonation(uid: u32, gid: u32, groups: &[u32], scratch: &mut [libc::gid_t]) -> bool {
    // Compare against the EFFECTIVE ids: `REGISTER_PERSONALITY` snapshots the effective/fs identity, so the
    // skip-the-window fast path is sound only when the effective ids already match (a broker running ruid != euid --
    // e.g. launched setuid - must not treat a real-uid match as sufficient). Raw reads only (see `raw_geteuid`).
    if uid != raw_geteuid() || gid != raw_getegid() {
        return true;
    }
    // SAFETY: raw `getgroups` into `scratch`; its length bounds the write.
    let n = unsafe { libc::syscall(libc::SYS_getgroups, scratch.len() as libc::c_long, scratch.as_mut_ptr()) };
    if n < 0 {
        return true;
    }
    group_set_differs(&scratch[..n as usize], groups)
}

/// Close the impersonation window. The effective capability set first, since a root window narrowed it without leaving
/// uid 0 and `setgroups` needs `CAP_SETGID`. Done later, the gid would still come back through saved gid 0 and nothing
/// would fail, but the broker would keep the groups of the root personality it had just minted. Then the uid, which is
/// what restores the privilege a window that left root dropped, and then the gid and the groups.
fn revert() {
    // Each call is attempted unconditionally, since a failure here is unrecoverable and must not be masked by a later
    // success.
    let _ = restore_effective_caps();
    // SAFETY: restoring credentials via saved-uid 0.
    unsafe {
        libc::syscall(libc::SYS_setresuid, 0, 0, 0);
        libc::syscall(libc::SYS_setresgid, 0, 0, 0);
        libc::syscall(libc::SYS_setgroups, 0 as libc::size_t, std::ptr::null::<u32>());
    }
}

#[cfg(all(test, not(loom)))]
mod tests;

mod child;
