//! Idmapped-mount user namespaces.
//!
//! [`create_idmap_userns`] builds a user namespace populated with the given
//! uid/gid maps and returns an owning fd that pins it — suitable for
//! `mount_setattr(MOUNT_ATTR_IDMAP)`. [`IdmapCache`] adds a caller-owned cache
//! so the (relatively expensive) namespace creation happens at most once per
//! distinct map set.
//!
//! Creation uses a plain `clone3` fork (no `CLONE_VM`): the parent writes the
//! privileged `/proc/<pid>/{setgroups,uid_map,gid_map}` files (the new-userns
//! child lacks `CAP_SETUID` in the parent namespace) and then grabs the
//! namespace via `PIDFD_GET_USER_NAMESPACE`. All allocation and formatting
//! happen in the parent; the child only `pause()`s (async-signal-safe) until it
//! is killed.

use crate::errno::{self, retry_on_eintr, Errno};
use crate::error::{Error, Result};
use crate::fd::owned_from_raw;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Write as _;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::Mutex;

// clone3 flags (defined here as libc lacks CLONE_CLEAR_SIGHAND).
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;

// PIDFD_GET_USER_NAMESPACE = _IO(0xFF, 9). Requires Linux >= 6.9.
const PIDFD_GET_USER_NAMESPACE: libc::c_ulong = 0xFF09;

/// A single uid/gid mapping range: `length` consecutive ids starting at
/// `outside` in the parent namespace map to `inside` in the new namespace.
///
/// Field ordering matches a `/proc/<pid>/uid_map` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdmapEntry {
    inside: u32,
    outside: u32,
    length: u32,
}

impl IdmapEntry {
    /// Construct a validated mapping. `length` must be at least 1, and neither
    /// `inside + length` nor `outside + length` may exceed 2³².
    pub fn new(inside: u32, outside: u32, length: u32) -> Result<Self> {
        if length == 0 {
            return Err(Error::Validation("length must be >= 1".into()));
        }
        let end = |base: u32| base as u64 + length as u64;
        if end(inside) > u32::MAX as u64 + 1 {
            return Err(Error::Validation(
                "inside + length overflows the u32 id range".into(),
            ));
        }
        if end(outside) > u32::MAX as u64 + 1 {
            return Err(Error::Validation(
                "outside + length overflows the u32 id range".into(),
            ));
        }
        Ok(IdmapEntry {
            inside,
            outside,
            length,
        })
    }

    /// Starting id inside the new user namespace.
    pub fn inside(&self) -> u32 {
        self.inside
    }
    /// Starting id in the parent user namespace.
    pub fn outside(&self) -> u32 {
        self.outside
    }
    /// Length of the contiguous mapping range.
    pub fn length(&self) -> u32 {
        self.length
    }
}

/// Kernel `struct clone_args` (VER2, 88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const _: () = assert!(core::mem::size_of::<CloneArgs>() == 88);

/// Create a new user namespace populated with `uid_map` / `gid_map` and return
/// an owning fd that pins it.
///
/// Both maps must be non-empty. Writing arbitrary (non-identity) maps requires
/// `CAP_SETUID`/`CAP_SETGID` in the parent user namespace (root in the initial
/// namespace qualifies).
pub fn create_idmap_userns(
    uid_map: &[IdmapEntry],
    gid_map: &[IdmapEntry],
) -> Result<OwnedFd> {
    if uid_map.is_empty() {
        return Err(Error::Validation("uid_map must be non-empty".into()));
    }
    if gid_map.is_empty() {
        return Err(Error::Validation("gid_map must be non-empty".into()));
    }
    // Format the maps in the parent, before forking.
    let uid_text = format_map(uid_map);
    let gid_text = format_map(gid_map);
    create_userns_fd(&uid_text, &gid_text)
}

fn format_map(entries: &[IdmapEntry]) -> String {
    let mut s = String::new();
    for e in entries {
        // Infallible: writing to a String never errors.
        let _ = writeln!(s, "{} {} {}", e.inside, e.outside, e.length);
    }
    s
}

fn create_userns_fd(uid_text: &str, gid_text: &str) -> Result<OwnedFd> {
    let mut pidfd: libc::c_int = -1;
    let mut ca = CloneArgs {
        flags: CLONE_NEWUSER | CLONE_PIDFD | CLONE_CLEAR_SIGHAND,
        pidfd: &mut pidfd as *mut libc::c_int as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };

    // SAFETY: clone3 with a valid, correctly-sized clone_args.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut ca as *mut CloneArgs,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    if pid < 0 {
        return Err(Errno::last().into());
    }
    if pid == 0 {
        // CHILD: async-signal-safe only — no allocation, no locks, no panics.
        // Block until the parent SIGKILLs us (uncatchable, bypasses pause()).
        loop {
            // SAFETY: pause() is async-signal-safe.
            unsafe { libc::pause() };
        }
    }

    let pid = pid as libc::pid_t;
    // PARENT: writes the privileged maps, then extracts the namespace fd.
    let result = (|| -> Result<OwnedFd> {
        write_proc(pid, "setgroups", b"deny")?;
        write_proc(pid, "uid_map", uid_text.as_bytes())?;
        write_proc(pid, "gid_map", gid_text.as_bytes())?;
        // The third ioctl arg must be a literal 0 (the kernel rejects non-zero).
        let nsfd = retry_on_eintr(|| unsafe {
            libc::ioctl(pidfd, PIDFD_GET_USER_NAMESPACE, 0)
        })?;
        // SAFETY: the ioctl returned a fresh owned namespace fd.
        Ok(unsafe { owned_from_raw(nsfd as RawFd) })
    })();

    // Tear the child down regardless of outcome. pidfd_send_signal is
    // PID-reuse-safe; SIGKILL is uncatchable.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            ptr::null::<libc::c_void>(),
            0u32,
        );
    }
    loop {
        let r = unsafe { libc::waitpid(pid, ptr::null_mut(), 0) };
        if r >= 0 || Errno::last() != Errno::EINTR {
            break;
        }
    }
    // SAFETY: closing our owned pidfd.
    unsafe { libc::close(pidfd) };

    result
}

/// Open `/proc/<pid>/<file>` write-only and write `data` in full.
fn write_proc(pid: libc::pid_t, file: &str, data: &[u8]) -> errno::Result<()> {
    let path = CString::new(format!("/proc/{pid}/{file}"))
        .map_err(|_| Errno::EINVAL)?;
    let fd = retry_on_eintr(|| unsafe {
        libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
    })?;
    // SAFETY: `open` returned a fresh owned fd.
    let fd = unsafe { owned_from_raw(fd as RawFd) };
    let raw = fd.as_raw_fd();
    let mut off = 0;
    while off < data.len() {
        let n = retry_on_eintr(|| unsafe {
            libc::write(raw, data[off..].as_ptr().cast(), data.len() - off)
        })?;
        off += n as usize;
    }
    Ok(())
}

type MapKey = Vec<(u32, u32, u32)>;
type CacheKey = (MapKey, MapKey);

fn key_of(map: &[IdmapEntry]) -> MapKey {
    map.iter()
        .map(|e| (e.inside, e.outside, e.length))
        .collect()
}

fn dup(fd: &OwnedFd) -> Result<OwnedFd> {
    fd.try_clone().map_err(|e| {
        Errno::from_raw(e.raw_os_error().unwrap_or(libc::EBADF)).into()
    })
}

/// A caller-owned cache of idmapped user namespaces, keyed by their
/// `(uid_map, gid_map)`.
///
/// Creating a user namespace is comparatively expensive; an `IdmapCache` runs
/// [`create_idmap_userns`] at most once per distinct map set and hands out
/// independent `dup`s of the pinned namespace fd. A returned fd therefore
/// outlives its cache entry — dropping it never affects the cache or other
/// callers, and [`IdmapCache::clear`] (or dropping the whole cache) releases the
/// originals without disturbing fds already handed out.
#[derive(Debug, Default)]
pub struct IdmapCache {
    entries: Mutex<HashMap<CacheKey, OwnedFd>>,
}

impl IdmapCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return an idmapped user-namespace fd for `(uid_map, gid_map)`, creating
    /// and caching it via [`create_idmap_userns`] on first use.
    ///
    /// The returned fd is an independent `dup` of the cached one.
    pub fn get_or_create(
        &self,
        uid_map: &[IdmapEntry],
        gid_map: &[IdmapEntry],
    ) -> Result<OwnedFd> {
        let key = (key_of(uid_map), key_of(gid_map));
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(fd) = guard.get(&key) {
            return dup(fd);
        }
        let fd = create_idmap_userns(uid_map, gid_map)?;
        let out = dup(&fd)?;
        guard.insert(key, fd);
        Ok(out)
    }

    /// Drop every cached namespace. Fds returned earlier stay valid; the next
    /// [`IdmapCache::get_or_create`] for a given map set recreates it.
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}
