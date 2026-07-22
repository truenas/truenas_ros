//! Raw io_uring UAPI: the `#[repr(C)]` structs, the constants `libc` does not
//! expose, and the three syscall wrappers (`io_uring_setup`/`enter`/`register`).
//!
//! Every struct here mirrors `include/uapi/linux/io_uring.h` byte-for-byte; the
//! `const _: () = assert!(size_of…)` guards catch any layout drift at compile
//! time. This is the crate's only direct contact with the io_uring kernel ABI —
//! the analogue of the local `#[repr(C)]` structs + raw `libc::syscall` in
//! `namespace.rs`.

// A raw-ABI module: some constants document the kernel interface without being
// referenced, and several kernel-struct fields are reserved/unused by us.
#![allow(dead_code)]

use crate::errno::{self, retry_on_eintr, Errno};
use crate::fd::owned_from_raw;
use std::ffi::c_void;
use std::os::fd::{OwnedFd, RawFd};
use std::ptr;

// -------------------------------------------------------------------------
// Structs (offsets/sizes verified against io_uring.h; identical on 6.12–6.18)
// -------------------------------------------------------------------------

/// `struct io_uring_sqe` — a submission-queue entry (64 bytes).
///
/// The kernel struct is a stack of same-sized unions; we flatten it to one
/// field per union (the overlay we actually use). Every field lands at its
/// natural offset, so a plain `#[repr(C)]` reproduces the ABI with no `packed`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringSqe {
    pub opcode: u8,       // @0
    pub flags: u8,        // @1   IOSQE_*
    pub ioprio: u16,      // @2   also accept/recv op-flags
    pub fd: i32,          // @4
    pub off_addr2: u64,   // @8   off / addr2 / accept socklen*
    pub addr: u64,        // @16  msghdr* / sockaddr* / iovec*
    pub len: u32,         // @24
    pub op_flags: u32, // @28  msg_flags / poll32_events / accept_flags / cancel
    pub user_data: u64, // @32  echoed back in the CQE
    pub buf_index: u16, // @40
    pub personality: u16, // @42
    pub file_index: u32, // @44  IORING_FILE_INDEX_ALLOC / slot+1
    pub addr3: u64,    // @48
    pub pad2: u64,     // @56
}
const _: () = assert!(core::mem::size_of::<IoUringSqe>() == 64);
const _: () = assert!(core::mem::align_of::<IoUringSqe>() == 8);

/// `struct io_uring_cqe` — a completion-queue entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringCqe {
    pub user_data: u64, // @0  echoed sqe.user_data
    pub res: i32,       // @8  bytes / new slot / -errno
    pub flags: u32,     // @12 IORING_CQE_F_*
}
const _: () = assert!(core::mem::size_of::<IoUringCqe>() == 16);

/// `struct io_sqring_offsets` (40 bytes) — byte offsets into the SQ mmap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}
const _: () = assert!(core::mem::size_of::<IoSqringOffsets>() == 40);

/// `struct io_cqring_offsets` (40 bytes) — byte offsets into the CQ mmap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}
const _: () = assert!(core::mem::size_of::<IoCqringOffsets>() == 40);

/// `struct io_uring_params` (120 bytes) — in/out argument to `io_uring_setup`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}
const _: () = assert!(core::mem::size_of::<IoUringParams>() == 120);

/// `struct io_uring_rsrc_register` (32 bytes) — arg for `IORING_REGISTER_FILES2`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringRsrcRegister {
    pub nr: u32,
    pub flags: u32,
    pub resv2: u64,
    pub data: u64, // __aligned_u64 == u64 on 64-bit
    pub tags: u64,
}
const _: () = assert!(core::mem::size_of::<IoUringRsrcRegister>() == 32);

/// `struct io_uring_file_index_range` (16 bytes) — arg for
/// `IORING_REGISTER_FILE_ALLOC_RANGE`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringFileIndexRange {
    pub off: u32,
    pub len: u32,
    pub resv: u64,
}
const _: () = assert!(core::mem::size_of::<IoUringFileIndexRange>() == 16);

/// `struct io_uring_rsrc_update` (16 bytes) — arg for
/// `IORING_REGISTER_FILES_UPDATE`. `data` points to an array of `nr_args` fds to
/// install starting at registered-file slot `offset`; the kernel `fget`s its own
/// reference to each, so the caller may close the fd after the call returns.
#[cfg(any(feature = "net-client", feature = "async-fs"))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoUringRsrcUpdate {
    pub offset: u32,
    pub resv: u32,
    pub data: u64, // pointer to the fd array (__aligned_u64 == u64 on 64-bit)
}
#[cfg(any(feature = "net-client", feature = "async-fs"))]
const _: () = assert!(core::mem::size_of::<IoUringRsrcUpdate>() == 16);

/// `struct __kernel_timespec` — the 16-byte timespec io_uring timeout ops read
/// from `sqe.addr`. The kernel copies it at prep time, so it need only be valid
/// at submission.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct KernelTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
const _: () = assert!(core::mem::size_of::<KernelTimespec>() == 16);

// -------------------------------------------------------------------------
// Constants (values verified against io_uring.h)
// -------------------------------------------------------------------------

// Operation opcodes (`enum io_uring_op` ordinals).
/// Vectored read from an fd at an offset (`sqe.addr` = iovec array,
/// `sqe.len` = vector count, `sqe.off` = file offset). The fs reactor's read
/// primitive (single-buffer reads are the k=1 case).
pub(crate) const IORING_OP_READV: u8 = 1;
/// Vectored write; field layout mirrors `READV`.
pub(crate) const IORING_OP_WRITEV: u8 = 2;
/// `fsync`/`fdatasync` on an fd; `sqe.fsync_flags` (`op_flags`) may carry
/// [`IORING_FSYNC_DATASYNC`], `sqe.off`+`sqe.len` bound the range (0 = whole
/// file). Always punted to io-wq (`REQ_F_FORCE_ASYNC`).
pub(crate) const IORING_OP_FSYNC: u8 = 3;
/// Preallocate/punch/zero a range of an fd. Note the kernel's field
/// packing: `sqe.off` = offset, **`sqe.addr` = length**, **`sqe.len` =
/// mode** (`FALLOC_FL_*`). Always io-wq (`REQ_F_FORCE_ASYNC`).
pub(crate) const IORING_OP_FALLOCATE: u8 = 17;
/// `statx` — **path-based only**: `sqe.fd` is a real dirfd (the prep
/// rejects fixed files) and the path is `getname`d at prep, so there is no
/// statx of a registered-table file. `AT_EMPTY_PATH` with an empty path
/// stats the dirfd itself. `sqe.len` = mask, `sqe.statx_flags`
/// (`op_flags`) = `AT_*`, `sqe.addr2` = the `struct statx` the kernel
/// writes **at completion** (so the buffer must live until the CQE).
pub(crate) const IORING_OP_STATX: u8 = 21;
pub(crate) const IORING_OP_SENDMSG: u8 = 9;
pub(crate) const IORING_OP_RECVMSG: u8 = 10;
/// One-shot readiness poll. Used to wait for a splice's non-blocking pool
/// socket to become readable again after `IORING_OP_SPLICE` returned `-EAGAIN`
/// (io_uring forces splice async and never poll-retries it, unlike `RECV`).
pub(crate) const IORING_OP_POLL_ADD: u8 = 6;
pub(crate) const IORING_OP_TIMEOUT: u8 = 11;
pub(crate) const IORING_OP_ACCEPT: u8 = 13;
pub(crate) const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub(crate) const IORING_OP_LINK_TIMEOUT: u8 = 15;
/// Connect an outbound stream socket (client). `sqe.fd` is the (fixed) socket,
/// `sqe.addr`@16 the target sockaddr, `sqe.addr2`@8 (`off_addr2`) its length;
/// `len`/`op_flags`/`buf_index`/`file_index` must be 0 (`io_connect_prep` rejects
/// otherwise). The kernel copies the sockaddr at prep, so it need only live until
/// submission.
#[cfg(feature = "net-client")]
pub(crate) const IORING_OP_CONNECT: u8 = 16;
pub(crate) const IORING_OP_CLOSE: u8 = 19;
pub(crate) const IORING_OP_READ: u8 = 22;
/// `openat2(2)` as a ring op: `fd` = dirfd (a REAL fd — the prep rejects
/// fixed dirfds with `-EBADF`), `addr` = path, `addr2` = `&open_how`,
/// `len` = `sizeof(open_how)` (24), and `file_index` = slot+1 installs the
/// opened file directly into the registered table (CQE `res` = 0 on an
/// explicit-index install). `open_how` must not carry `O_CLOEXEC` when
/// `file_index` is set (kernel `-EINVAL`).
pub(crate) const IORING_OP_OPENAT2: u8 = 28;
pub(crate) const IORING_OP_SEND: u8 = 26;
pub(crate) const IORING_OP_RECV: u8 = 27;
/// Move bytes between a pipe and another fd without a userspace copy — used to
/// splice a framed message body straight from the socket to a consumer pipe.
pub(crate) const IORING_OP_SPLICE: u8 = 30;
pub(crate) const IORING_OP_SHUTDOWN: u8 = 34;
pub(crate) const IORING_OP_URING_CMD: u8 = 46;
/// Materialize a real (installed) fd from a direct/registered descriptor
/// (Linux ≥ 6.8). The new fd rides in the CQE `res`; flags go in
/// `install_fd_flags`, which overlays `op_flags` (the @28 union) here — left
/// zero for the default `O_CLOEXEC`.
pub(crate) const IORING_OP_FIXED_FD_INSTALL: u8 = 54;

// kTLS: values `libc` may not expose. The library only *probes* kTLS
// availability (`TCP_ULP`) and reads the record-type control message on kTLS
// recvs (`SOL_TLS`/`TLS_GET_RECORD_TYPE`); it never installs kTLS (the
// consumer's handshake does that on a furnished fd).
/// `setsockopt(SOL_TCP, TCP_ULP, "tls")` attaches the kernel-TLS ULP.
pub(crate) const TCP_ULP: i32 = 31;
/// `getsockopt`/cmsg level for kernel TLS.
pub(crate) const SOL_TLS: i32 = 282;
/// `cmsg_type` (level `SOL_TLS`) whose one-byte payload is the record's TLS
/// content type.
pub(crate) const TLS_GET_RECORD_TYPE: i32 = 2;
/// TLS record content type for `application_data` (the only type a kTLS recv
/// delivers as plain bytes; anything else is a control record we shed on).
pub(crate) const TLS_RECORD_TYPE_DATA: u8 = 23;

/// `SOCKET_URING_OP_SIOCOUTQ` — `URING_CMD` sub-op: bytes queued to send
/// (`prot->ioctl(sk, SIOCOUTQ)`); takes no operands, CQE `res` = the count or
/// `-errno`. Used only as a construction-time capability probe: it answers
/// "does this kernel route socket `URING_CMD`s for this protocol?" with no
/// bind/connect needed.
pub(crate) const SOCKET_URING_OP_SIOCOUTQ: u32 = 1;

/// `SOCKET_URING_OP_GETSOCKOPT` — `URING_CMD` sub-op on a socket (`cmd_net.c`;
/// `SOL_SOCKET` only). The cmd SQE overlays fields we already declare:
/// `cmd_op` @8 (`off_addr2` low half), `level` @16 / `optname` @20 (`addr` low/
/// high halves on LE), `optlen` @44 (`file_index`), `optval` @48 (`addr3`).
/// The CQE `res` is the returned optlen, or `-errno`.
pub(crate) const SOCKET_URING_OP_GETSOCKOPT: u32 = 2;

// Directory-entry ops. Every one takes its dirfd(s) as **real** fds in
// `sqe.fd` (and `sqe.len` for the second, where there is one): each prep
// rejects `REQ_F_FIXED_FILE` with `-EBADF`, so a registered-table slot can
// never be a dirfd. All are `REQ_F_FORCE_ASYNC`.
/// `fd` = old dirfd, `addr` = old path, `addr2` = new path,
/// **`len` = new dirfd**, `op_flags` = `RENAME_*`.
pub(crate) const IORING_OP_RENAMEAT: u8 = 35;
/// `fd` = dirfd, `addr` = path, `op_flags` = `AT_REMOVEDIR` (the only bit
/// the prep accepts).
pub(crate) const IORING_OP_UNLINKAT: u8 = 36;
/// `fd` = dirfd, `addr` = path, `len` = mode.
pub(crate) const IORING_OP_MKDIRAT: u8 = 37;
/// `fd` = dirfd of the new link, `addr` = target (free-form link content,
/// never resolved at creation), `addr2` = link path.
pub(crate) const IORING_OP_SYMLINKAT: u8 = 38;
/// `fd` = old dirfd, `addr` = old path, `addr2` = new path,
/// **`len` = new dirfd**, `op_flags` = `AT_SYMLINK_FOLLOW`/`AT_EMPTY_PATH`.
pub(crate) const IORING_OP_LINKAT: u8 = 39;

// Extended attributes. The `f*` forms take `needs_file` and **do** accept
// registered-table files (`IOSQE_FIXED_FILE`) — while still performing a
// full per-op credential check in `xattr_permission`. The path-based forms
// (`SETXATTR = 42`, `GETXATTR = 44`) are deliberately absent: the kernel
// hardcodes their resolution to `AT_FDCWD` + `LOOKUP_FOLLOW`, which cannot
// be anchored. All are `REQ_F_FORCE_ASYNC`.
/// `fd` = file, `addr` = name, `addr2` = value, `len` = size,
/// `op_flags` = `XATTR_CREATE`/`XATTR_REPLACE`.
pub(crate) const IORING_OP_FSETXATTR: u8 = 41;
/// `fd` = file, `addr` = name, `addr2` = value buffer (written at issue —
/// must live to the CQE), `len` = size; `op_flags` must be 0. CQE `res` is
/// the attribute's size.
pub(crate) const IORING_OP_FGETXATTR: u8 = 43;
/// Truncate an fd (**`sqe.off` = the new length**; every other operand
/// must be zero). Linux ≥ 6.9 — the one op above this crate's other
/// io_uring floors, so it is probed individually.
pub(crate) const IORING_OP_FTRUNCATE: u8 = 55;

/// `sqe.fsync_flags` (the `op_flags` overlay) for `FSYNC`: `fdatasync`
/// semantics (skip flushing non-essential metadata).
pub(crate) const IORING_FSYNC_DATASYNC: u32 = 1;

/// `sqe.flags`: `fd` is an index into the registered-file table.
pub(crate) const IOSQE_FIXED_FILE: u8 = 1 << 0;

/// `sqe.flags`: link the following SQE to this one, so it runs only after this
/// completes — used to attach a trailing `IORING_OP_LINK_TIMEOUT` that bounds
/// this op's lifetime.
pub(crate) const IOSQE_IO_LINK: u8 = 1 << 2;

/// `sqe.ioprio` for ACCEPT: arm a persistent multishot accept.
pub(crate) const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;

/// `sqe.file_index` sentinel: auto-allocate a free registered-file slot.
pub(crate) const IORING_FILE_INDEX_ALLOC: u32 = u32::MAX;

/// `sqe.op_flags` for ASYNC_CANCEL. `ANY` matches every outstanding request;
/// `ALL` cancels all matches, not just the first; `FD`+`FD_FIXED` key the match
/// on the SQE's `fd` read as a registered (fixed) descriptor index — so a
/// single cancel reaps a connection's recv and send together, whatever their
/// opcode.
pub(crate) const IORING_ASYNC_CANCEL_ALL: u32 = 1 << 0;
pub(crate) const IORING_ASYNC_CANCEL_FD: u32 = 1 << 1;
pub(crate) const IORING_ASYNC_CANCEL_ANY: u32 = 1 << 2;
pub(crate) const IORING_ASYNC_CANCEL_FD_FIXED: u32 = 1 << 3;

/// `splice(2)` flags in `sqe.op_flags` (the `splice_flags` overlay) for
/// `IORING_OP_SPLICE`: `MOVE` moves pages rather than copying, and `FD_IN_FIXED`
/// marks the **input** fd (`splice_fd_in`, overlaying `file_index`) as a
/// registered/fixed descriptor — set when splicing FROM the connection's pool
/// socket.
pub(crate) const SPLICE_F_MOVE: u32 = 1;
pub(crate) const SPLICE_F_FD_IN_FIXED: u32 = 1 << 31;

// `cqe.flags`.
pub(crate) const IORING_CQE_F_MORE: u32 = 1 << 1; // more CQEs follow (multishot)
pub(crate) const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;

/// `io_uring_enter` flag: also wait for completions.
pub(crate) const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

// `io_uring_params.features` (kernel-reported).
pub(crate) const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub(crate) const IORING_FEAT_NODROP: u32 = 1 << 1;

// `mmap` magic offsets.
pub(crate) const IORING_OFF_SQ_RING: i64 = 0;
pub(crate) const IORING_OFF_CQ_RING: i64 = 0x0800_0000;
pub(crate) const IORING_OFF_SQES: i64 = 0x1000_0000;

// `io_uring_register` opcodes + flags.
/// Install fds into an already-registered file table at chosen slots — a client
/// places a freshly-`connect`ed socket into its pool this way (the server's pool
/// is auto-allocated by multishot accept; a client must update explicitly).
#[cfg(any(feature = "net-client", feature = "async-fs"))]
pub(crate) const IORING_REGISTER_FILES_UPDATE: u32 = 6;
pub(crate) const IORING_REGISTER_PROBE: u32 = 8;
/// Snapshot the **calling task's** credentials (fsuid/fsgid, groups,
/// capabilities, keyrings, LSM label) into a ring-local personality; the
/// syscall's return value **is** the id (`u16`, never 0 — the personalities
/// xarray is `XA_FLAGS_ALLOC1`, allocated cyclically with no immediate
/// reuse). Stamped into `sqe.personality`, it runs that op under the
/// snapshot via `override_creds` (inline and io-wq alike).
pub(crate) const IORING_REGISTER_PERSONALITY: u32 = 9;
/// Free a personality id (`nr_args` = id, `arg` must be NULL).
pub(crate) const IORING_UNREGISTER_PERSONALITY: u32 = 10;
pub(crate) const IORING_REGISTER_FILES2: u32 = 13;
pub(crate) const IORING_REGISTER_FILE_ALLOC_RANGE: u32 = 25;
pub(crate) const IORING_RSRC_REGISTER_SPARSE: u32 = 1 << 0;

/// `io_uring_setup` flag: restrict submission — and `io_uring_register`, via
/// the `-EEXIST` gate in `register.c` — to the creating task. **Never set by
/// this crate's rings**: the fs reactor's credential broker must be able to
/// register personalities on a ring from outside (fs-reactor design §6.3).
/// Declared for the regression probe that pins the gate's behavior.
pub(crate) const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;

// `io_uring_probe_op.flags`: the opcode is supported by this kernel.
pub(crate) const IO_URING_OP_SUPPORTED: u16 = 1 << 0;

/// `struct io_uring_probe_op` (8 bytes) — one per-opcode entry filled by
/// `IORING_REGISTER_PROBE`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct IoUringProbeOp {
    pub op: u8,
    pub resv: u8,
    pub flags: u16,
    pub resv2: u32,
}

/// `struct io_uring_probe` header (16 bytes), followed by `nr_args`
/// [`IoUringProbeOp`] entries. `last_op` is the highest opcode the kernel
/// knows (`IORING_OP_LAST - 1`); entry `i` describes opcode `i`.
#[repr(C)]
#[derive(Default)]
pub(crate) struct IoUringProbeHeader {
    pub last_op: u8,
    pub ops_len: u8,
    pub resv: u16,
    pub resv2: [u32; 3],
}

// -------------------------------------------------------------------------
// Syscall wrappers (modeled on src/namespace.rs / src/mount/open_tree.rs)
// -------------------------------------------------------------------------

/// `io_uring_setup(2)`: create a ring and return its owning fd. `params` is
/// read for the requested flags and written back with the negotiated geometry.
pub(crate) fn io_uring_setup(
    entries: u32,
    params: &mut IoUringParams,
) -> errno::Result<OwnedFd> {
    // SAFETY: `params` is a valid, writable IoUringParams for the whole call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            entries as libc::c_long,
            params as *mut IoUringParams,
        )
    };
    let fd = Errno::result(ret)?;
    // SAFETY: io_uring_setup returns a fresh owned fd on success.
    Ok(unsafe { owned_from_raw(fd as RawFd) })
}

/// `io_uring_enter(2)`: submit `to_submit` staged SQEs and, with
/// `IORING_ENTER_GETEVENTS`, wait for `min_complete` completions. Returns the
/// number of SQEs the kernel consumed.
///
/// Retrying `EINTR` is safe here: when `to_submit > 0` the kernel returns the
/// submitted count and swallows any wait-interruption (so a retry never
/// re-submits), and a pure wait (`to_submit == 0`) is idempotent to repeat.
pub(crate) fn io_uring_enter(
    ring_fd: RawFd,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
) -> errno::Result<u32> {
    let ret = retry_on_eintr(|| unsafe {
        // SAFETY: `ring_fd` is a live io_uring fd; argp is null / argsz 0, the
        // documented "no extra argument" form.
        libc::syscall(
            libc::SYS_io_uring_enter,
            ring_fd as libc::c_long,
            to_submit as libc::c_long,
            min_complete as libc::c_long,
            flags as libc::c_long,
            ptr::null::<c_void>(),
            0_usize,
        )
    })?;
    Ok(ret as u32)
}

/// `io_uring_register(2)`: raw form returning the syscall's value. Most
/// register opcodes return 0 on success, but a few return data —
/// `REGISTER_PERSONALITY`'s return *is* the personality id.
///
/// # Safety
///
/// `arg` must point to a valid argument of the size/shape required by
/// `opcode`, live for the duration of the call.
pub(crate) unsafe fn io_uring_register_ret(
    ring_fd: RawFd,
    opcode: u32,
    arg: *const c_void,
    nr_args: u32,
) -> errno::Result<libc::c_long> {
    retry_on_eintr(|| unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring_fd as libc::c_long,
            opcode as libc::c_long,
            arg,
            nr_args as libc::c_long,
        )
    })
}

/// `io_uring_register(2)`: value-discarding form for the (majority of)
/// opcodes whose success return carries no information.
///
/// # Safety
///
/// As [`io_uring_register_ret`].
pub(crate) unsafe fn io_uring_register(
    ring_fd: RawFd,
    opcode: u32,
    arg: *const c_void,
    nr_args: u32,
) -> errno::Result<()> {
    // SAFETY: forwarded contract.
    unsafe { io_uring_register_ret(ring_fd, opcode, arg, nr_args) }.map(|_| ())
}

/// Register the calling task's current credentials as a ring personality and
/// return its id. The kernel guarantees a nonzero id (`XA_FLAGS_ALLOC1` on
/// the personalities xarray) — 0 remains the "submitter's ambient creds" SQE
/// sentinel; a 0 return is refused here so the invariant is load-bearing.
pub(crate) fn register_personality(ring_fd: RawFd) -> errno::Result<u16> {
    // SAFETY: REGISTER_PERSONALITY takes no argument (NULL, nr_args 0); the
    // payload is the calling task's credentials.
    let id = unsafe {
        io_uring_register_ret(
            ring_fd,
            IORING_REGISTER_PERSONALITY,
            ptr::null(),
            0,
        )
    }?;
    if id <= 0 || id > libc::c_long::from(u16::MAX) {
        return Err(Errno::EINVAL);
    }
    Ok(id as u16)
}

/// Unregister a personality id minted by [`register_personality`]. In-flight
/// ops that already resolved the id keep their cred reference; new SQEs
/// naming it fail `-EINVAL` at submission.
pub(crate) fn unregister_personality(
    ring_fd: RawFd,
    id: u16,
) -> errno::Result<()> {
    // SAFETY: UNREGISTER_PERSONALITY takes the id in `nr_args`, NULL `arg`.
    unsafe {
        io_uring_register(
            ring_fd,
            IORING_UNREGISTER_PERSONALITY,
            ptr::null(),
            u32::from(id),
        )
    }
}

/// Register a sparse (all-`-1`) file table of `count` slots — the connection
/// "pool" that multishot accept auto-allocates into.
pub(crate) fn register_files_sparse(
    ring_fd: RawFd,
    count: u32,
) -> errno::Result<()> {
    let reg = IoUringRsrcRegister {
        nr: count,
        flags: IORING_RSRC_REGISTER_SPARSE,
        ..Default::default()
    };
    // SAFETY: FILES2 reads one `io_uring_rsrc_register`; the kernel requires
    // `nr_args == sizeof(rr)` (rsrc.c: `if (size != sizeof(rr)) -EINVAL`).
    unsafe {
        io_uring_register(
            ring_fd,
            IORING_REGISTER_FILES2,
            &reg as *const IoUringRsrcRegister as *const c_void,
            core::mem::size_of::<IoUringRsrcRegister>() as u32,
        )
    }
}

/// Confine `IORING_FILE_INDEX_ALLOC` auto-allocation to slots `[off, off+len)`.
pub(crate) fn register_file_alloc_range(
    ring_fd: RawFd,
    off: u32,
    len: u32,
) -> errno::Result<()> {
    let range = IoUringFileIndexRange { off, len, resv: 0 };
    // SAFETY: FILE_ALLOC_RANGE reads one `io_uring_file_index_range` via its
    // own sizeof; the kernel requires `nr_args == 0` (register.c: `if (!arg ||
    // nr_args) break` → -EINVAL).
    unsafe {
        io_uring_register(
            ring_fd,
            IORING_REGISTER_FILE_ALLOC_RANGE,
            &range as *const IoUringFileIndexRange as *const c_void,
            0,
        )
    }
}

/// Install `fd` into registered-file slot `slot` (`IORING_REGISTER_FILES_UPDATE`).
/// The kernel takes its own reference (`fget`), so the caller may close `fd`
/// afterward. Used by a client to place a freshly-`connect`ed socket into its
/// pool at a chosen index (the server auto-allocates via multishot accept).
#[cfg(any(feature = "net-client", feature = "async-fs"))]
pub(crate) fn register_file_update(
    ring_fd: RawFd,
    slot: u32,
    fd: RawFd,
) -> errno::Result<()> {
    let fds = [fd];
    let update = IoUringRsrcUpdate {
        offset: slot,
        resv: 0,
        data: fds.as_ptr() as u64,
    };
    // SAFETY: FILES_UPDATE reads one `io_uring_rsrc_update` from `arg`; `nr_args`
    // (1) is the number of fds `data` points at. `fds` outlives the call.
    unsafe {
        io_uring_register(
            ring_fd,
            IORING_REGISTER_FILES_UPDATE,
            &update as *const IoUringRsrcUpdate as *const c_void,
            1,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Assert each SQE field lands at its kernel-ABI byte offset. Computed via
    // pointer arithmetic so it works on the crate MSRV (1.75, pre-`offset_of!`).
    #[test]
    fn sqe_field_offsets() {
        let s = IoUringSqe::default();
        let base = &s as *const _ as usize;
        let off = |a: usize| a - base;
        assert_eq!(off(&s.opcode as *const _ as usize), 0);
        assert_eq!(off(&s.flags as *const _ as usize), 1);
        assert_eq!(off(&s.ioprio as *const _ as usize), 2);
        assert_eq!(off(&s.fd as *const _ as usize), 4);
        assert_eq!(off(&s.off_addr2 as *const _ as usize), 8);
        assert_eq!(off(&s.addr as *const _ as usize), 16);
        assert_eq!(off(&s.len as *const _ as usize), 24);
        assert_eq!(off(&s.op_flags as *const _ as usize), 28);
        assert_eq!(off(&s.user_data as *const _ as usize), 32);
        assert_eq!(off(&s.buf_index as *const _ as usize), 40);
        assert_eq!(off(&s.personality as *const _ as usize), 42);
        assert_eq!(off(&s.file_index as *const _ as usize), 44);
        assert_eq!(off(&s.addr3 as *const _ as usize), 48);
        assert_eq!(off(&s.pad2 as *const _ as usize), 56);
    }

    #[test]
    fn cqe_field_offsets() {
        let c = IoUringCqe::default();
        let base = &c as *const _ as usize;
        assert_eq!(&c.user_data as *const _ as usize - base, 0);
        assert_eq!(&c.res as *const _ as usize - base, 8);
        assert_eq!(&c.flags as *const _ as usize - base, 12);
    }
}
