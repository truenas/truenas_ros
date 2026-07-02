//! The [`Errno`] error-number type and its `errno`-based [`Result`] (Linux-only).
//!
//! Low-level syscall wrappers in this crate return [`Result<T>`] — an alias for
//! `Result<T, Errno>`. The rich crate-level [`crate::Error`] wraps `Errno` via
//! `From` so `?` bridges the two layers.

use libc::c_void;
use std::{error, fmt, io};

/// The result type used by low-level syscall wrappers: `Ok(value)` or a raw
/// [`Errno`].
pub type Result<T> = std::result::Result<T, Errno>;

/// A platform error number.
///
/// The variants are the standard Linux `errno` values. [`Errno::UnknownErrno`]
/// is used for any value not otherwise recognised.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[non_exhaustive]
#[allow(missing_docs)] // the variant names are the canonical errno symbols
pub enum Errno {
    /// Unknown / unrecognised error number.
    UnknownErrno = 0,
    EPERM = libc::EPERM,
    ENOENT = libc::ENOENT,
    ESRCH = libc::ESRCH,
    EINTR = libc::EINTR,
    EIO = libc::EIO,
    ENXIO = libc::ENXIO,
    E2BIG = libc::E2BIG,
    ENOEXEC = libc::ENOEXEC,
    EBADF = libc::EBADF,
    ECHILD = libc::ECHILD,
    EAGAIN = libc::EAGAIN,
    ENOMEM = libc::ENOMEM,
    EACCES = libc::EACCES,
    EFAULT = libc::EFAULT,
    ENOTBLK = libc::ENOTBLK,
    EBUSY = libc::EBUSY,
    EEXIST = libc::EEXIST,
    EXDEV = libc::EXDEV,
    ENODEV = libc::ENODEV,
    ENOTDIR = libc::ENOTDIR,
    EISDIR = libc::EISDIR,
    EINVAL = libc::EINVAL,
    ENFILE = libc::ENFILE,
    EMFILE = libc::EMFILE,
    ENOTTY = libc::ENOTTY,
    ETXTBSY = libc::ETXTBSY,
    EFBIG = libc::EFBIG,
    ENOSPC = libc::ENOSPC,
    ESPIPE = libc::ESPIPE,
    EROFS = libc::EROFS,
    EMLINK = libc::EMLINK,
    EPIPE = libc::EPIPE,
    EDOM = libc::EDOM,
    ERANGE = libc::ERANGE,
    EDEADLK = libc::EDEADLK,
    ENAMETOOLONG = libc::ENAMETOOLONG,
    ENOLCK = libc::ENOLCK,
    ENOSYS = libc::ENOSYS,
    ENOTEMPTY = libc::ENOTEMPTY,
    ELOOP = libc::ELOOP,
    ENOMSG = libc::ENOMSG,
    EIDRM = libc::EIDRM,
    ECHRNG = libc::ECHRNG,
    EL2NSYNC = libc::EL2NSYNC,
    EL3HLT = libc::EL3HLT,
    EL3RST = libc::EL3RST,
    ELNRNG = libc::ELNRNG,
    EUNATCH = libc::EUNATCH,
    ENOCSI = libc::ENOCSI,
    EL2HLT = libc::EL2HLT,
    EBADE = libc::EBADE,
    EBADR = libc::EBADR,
    EXFULL = libc::EXFULL,
    ENOANO = libc::ENOANO,
    EBADRQC = libc::EBADRQC,
    EBADSLT = libc::EBADSLT,
    EBFONT = libc::EBFONT,
    ENOSTR = libc::ENOSTR,
    ENODATA = libc::ENODATA,
    ETIME = libc::ETIME,
    ENOSR = libc::ENOSR,
    ENONET = libc::ENONET,
    ENOPKG = libc::ENOPKG,
    EREMOTE = libc::EREMOTE,
    ENOLINK = libc::ENOLINK,
    EADV = libc::EADV,
    ESRMNT = libc::ESRMNT,
    ECOMM = libc::ECOMM,
    EPROTO = libc::EPROTO,
    EMULTIHOP = libc::EMULTIHOP,
    EDOTDOT = libc::EDOTDOT,
    EBADMSG = libc::EBADMSG,
    EOVERFLOW = libc::EOVERFLOW,
    ENOTUNIQ = libc::ENOTUNIQ,
    EBADFD = libc::EBADFD,
    EREMCHG = libc::EREMCHG,
    ELIBACC = libc::ELIBACC,
    ELIBBAD = libc::ELIBBAD,
    ELIBSCN = libc::ELIBSCN,
    ELIBMAX = libc::ELIBMAX,
    ELIBEXEC = libc::ELIBEXEC,
    EILSEQ = libc::EILSEQ,
    ERESTART = libc::ERESTART,
    ESTRPIPE = libc::ESTRPIPE,
    EUSERS = libc::EUSERS,
    ENOTSOCK = libc::ENOTSOCK,
    EDESTADDRREQ = libc::EDESTADDRREQ,
    EMSGSIZE = libc::EMSGSIZE,
    EPROTOTYPE = libc::EPROTOTYPE,
    ENOPROTOOPT = libc::ENOPROTOOPT,
    EPROTONOSUPPORT = libc::EPROTONOSUPPORT,
    ESOCKTNOSUPPORT = libc::ESOCKTNOSUPPORT,
    EOPNOTSUPP = libc::EOPNOTSUPP,
    EPFNOSUPPORT = libc::EPFNOSUPPORT,
    EAFNOSUPPORT = libc::EAFNOSUPPORT,
    EADDRINUSE = libc::EADDRINUSE,
    EADDRNOTAVAIL = libc::EADDRNOTAVAIL,
    ENETDOWN = libc::ENETDOWN,
    ENETUNREACH = libc::ENETUNREACH,
    ENETRESET = libc::ENETRESET,
    ECONNABORTED = libc::ECONNABORTED,
    ECONNRESET = libc::ECONNRESET,
    ENOBUFS = libc::ENOBUFS,
    EISCONN = libc::EISCONN,
    ENOTCONN = libc::ENOTCONN,
    ESHUTDOWN = libc::ESHUTDOWN,
    ETOOMANYREFS = libc::ETOOMANYREFS,
    ETIMEDOUT = libc::ETIMEDOUT,
    ECONNREFUSED = libc::ECONNREFUSED,
    EHOSTDOWN = libc::EHOSTDOWN,
    EHOSTUNREACH = libc::EHOSTUNREACH,
    EALREADY = libc::EALREADY,
    EINPROGRESS = libc::EINPROGRESS,
    ESTALE = libc::ESTALE,
    EUCLEAN = libc::EUCLEAN,
    ENOTNAM = libc::ENOTNAM,
    ENAVAIL = libc::ENAVAIL,
    EISNAM = libc::EISNAM,
    EREMOTEIO = libc::EREMOTEIO,
    EDQUOT = libc::EDQUOT,
    ENOMEDIUM = libc::ENOMEDIUM,
    EMEDIUMTYPE = libc::EMEDIUMTYPE,
    ECANCELED = libc::ECANCELED,
    ENOKEY = libc::ENOKEY,
    EKEYEXPIRED = libc::EKEYEXPIRED,
    EKEYREVOKED = libc::EKEYREVOKED,
    EKEYREJECTED = libc::EKEYREJECTED,
    EOWNERDEAD = libc::EOWNERDEAD,
    ENOTRECOVERABLE = libc::ENOTRECOVERABLE,
    ERFKILL = libc::ERFKILL,
    EHWPOISON = libc::EHWPOISON,
}

impl Errno {
    /// `EWOULDBLOCK` is an alias for [`Errno::EAGAIN`] on Linux.
    pub const EWOULDBLOCK: Errno = Errno::EAGAIN;
    /// `EDEADLOCK` is an alias for [`Errno::EDEADLK`] on Linux.
    pub const EDEADLOCK: Errno = Errno::EDEADLK;
    /// `ENOTSUP` is an alias for [`Errno::EOPNOTSUPP`] on Linux.
    pub const ENOTSUP: Errno = Errno::EOPNOTSUPP;

    /// Returns the current value of `errno`.
    pub fn last() -> Self {
        Self::from_raw(Self::last_raw())
    }

    /// Returns the current raw `i32` value of `errno`.
    pub fn last_raw() -> i32 {
        // SAFETY: `__errno_location` returns a valid pointer to the
        // thread-local errno.
        unsafe { *libc::__errno_location() }
    }

    /// Sets the value of `errno`.
    pub fn set(self) {
        Self::set_raw(self as i32)
    }

    /// Sets the raw `i32` value of `errno`.
    pub fn set_raw(errno: i32) {
        // SAFETY: `__errno_location` returns a valid pointer to the
        // thread-local errno.
        unsafe {
            *libc::__errno_location() = errno;
        }
    }

    /// Clears `errno` (sets it to zero).
    pub fn clear() {
        Self::set_raw(0)
    }

    /// Maps a raw `i32` to an [`Errno`], returning [`Errno::UnknownErrno`] for
    /// unrecognised values.
    pub const fn from_raw(err: i32) -> Errno {
        from_raw(err)
    }

    /// Returns `Ok(value)` unless `value` equals the failure sentinel for its
    /// type (usually `-1`), in which case the current `errno` is returned as
    /// the error.
    #[inline]
    pub fn result<S: ErrnoSentinel + PartialEq<S>>(value: S) -> Result<S> {
        if value == S::sentinel() {
            Err(Self::last())
        } else {
            Ok(value)
        }
    }
}

/// A value that a fallible libc/syscall function returns to signal failure.
pub trait ErrnoSentinel: Sized {
    /// The sentinel value that means "an error occurred; consult `errno`".
    fn sentinel() -> Self;
}

impl ErrnoSentinel for isize {
    fn sentinel() -> Self {
        -1
    }
}

impl ErrnoSentinel for i32 {
    fn sentinel() -> Self {
        -1
    }
}

impl ErrnoSentinel for i64 {
    fn sentinel() -> Self {
        -1
    }
}

impl ErrnoSentinel for *mut c_void {
    fn sentinel() -> Self {
        -1isize as *mut c_void
    }
}

/// Runs `f`, retrying while it fails with [`Errno::EINTR`].
///
/// This mirrors the syscall loop in the `truenas_os` C extension. Unlike those
/// Python bindings we have no interpreter signal check to poll, so — like the
/// Rust standard library — we simply retry `EINTR` unconditionally.
#[inline]
#[allow(dead_code)] // unused only when no feature module is compiled
pub(crate) fn retry_on_eintr<S, F>(mut f: F) -> Result<S>
where
    S: ErrnoSentinel + PartialEq<S> + Copy,
    F: FnMut() -> S,
{
    loop {
        match Errno::result(f()) {
            Err(Errno::EINTR) => continue,
            other => return other,
        }
    }
}

impl error::Error for Errno {}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // e.g. "EIO: Input/output error (os error 5)"
        write!(f, "{:?}: {}", self, io::Error::from(*self))
    }
}

impl From<Errno> for io::Error {
    fn from(err: Errno) -> Self {
        io::Error::from_raw_os_error(err as i32)
    }
}

impl TryFrom<io::Error> for Errno {
    type Error = io::Error;

    fn try_from(ioerror: io::Error) -> std::result::Result<Self, io::Error> {
        ioerror.raw_os_error().map(Errno::from_raw).ok_or(ioerror)
    }
}

const fn from_raw(e: i32) -> Errno {
    use self::Errno::*;

    match e {
        libc::EPERM => EPERM,
        libc::ENOENT => ENOENT,
        libc::ESRCH => ESRCH,
        libc::EINTR => EINTR,
        libc::EIO => EIO,
        libc::ENXIO => ENXIO,
        libc::E2BIG => E2BIG,
        libc::ENOEXEC => ENOEXEC,
        libc::EBADF => EBADF,
        libc::ECHILD => ECHILD,
        libc::EAGAIN => EAGAIN,
        libc::ENOMEM => ENOMEM,
        libc::EACCES => EACCES,
        libc::EFAULT => EFAULT,
        libc::ENOTBLK => ENOTBLK,
        libc::EBUSY => EBUSY,
        libc::EEXIST => EEXIST,
        libc::EXDEV => EXDEV,
        libc::ENODEV => ENODEV,
        libc::ENOTDIR => ENOTDIR,
        libc::EISDIR => EISDIR,
        libc::EINVAL => EINVAL,
        libc::ENFILE => ENFILE,
        libc::EMFILE => EMFILE,
        libc::ENOTTY => ENOTTY,
        libc::ETXTBSY => ETXTBSY,
        libc::EFBIG => EFBIG,
        libc::ENOSPC => ENOSPC,
        libc::ESPIPE => ESPIPE,
        libc::EROFS => EROFS,
        libc::EMLINK => EMLINK,
        libc::EPIPE => EPIPE,
        libc::EDOM => EDOM,
        libc::ERANGE => ERANGE,
        libc::EDEADLK => EDEADLK,
        libc::ENAMETOOLONG => ENAMETOOLONG,
        libc::ENOLCK => ENOLCK,
        libc::ENOSYS => ENOSYS,
        libc::ENOTEMPTY => ENOTEMPTY,
        libc::ELOOP => ELOOP,
        libc::ENOMSG => ENOMSG,
        libc::EIDRM => EIDRM,
        libc::ECHRNG => ECHRNG,
        libc::EL2NSYNC => EL2NSYNC,
        libc::EL3HLT => EL3HLT,
        libc::EL3RST => EL3RST,
        libc::ELNRNG => ELNRNG,
        libc::EUNATCH => EUNATCH,
        libc::ENOCSI => ENOCSI,
        libc::EL2HLT => EL2HLT,
        libc::EBADE => EBADE,
        libc::EBADR => EBADR,
        libc::EXFULL => EXFULL,
        libc::ENOANO => ENOANO,
        libc::EBADRQC => EBADRQC,
        libc::EBADSLT => EBADSLT,
        libc::EBFONT => EBFONT,
        libc::ENOSTR => ENOSTR,
        libc::ENODATA => ENODATA,
        libc::ETIME => ETIME,
        libc::ENOSR => ENOSR,
        libc::ENONET => ENONET,
        libc::ENOPKG => ENOPKG,
        libc::EREMOTE => EREMOTE,
        libc::ENOLINK => ENOLINK,
        libc::EADV => EADV,
        libc::ESRMNT => ESRMNT,
        libc::ECOMM => ECOMM,
        libc::EPROTO => EPROTO,
        libc::EMULTIHOP => EMULTIHOP,
        libc::EDOTDOT => EDOTDOT,
        libc::EBADMSG => EBADMSG,
        libc::EOVERFLOW => EOVERFLOW,
        libc::ENOTUNIQ => ENOTUNIQ,
        libc::EBADFD => EBADFD,
        libc::EREMCHG => EREMCHG,
        libc::ELIBACC => ELIBACC,
        libc::ELIBBAD => ELIBBAD,
        libc::ELIBSCN => ELIBSCN,
        libc::ELIBMAX => ELIBMAX,
        libc::ELIBEXEC => ELIBEXEC,
        libc::EILSEQ => EILSEQ,
        libc::ERESTART => ERESTART,
        libc::ESTRPIPE => ESTRPIPE,
        libc::EUSERS => EUSERS,
        libc::ENOTSOCK => ENOTSOCK,
        libc::EDESTADDRREQ => EDESTADDRREQ,
        libc::EMSGSIZE => EMSGSIZE,
        libc::EPROTOTYPE => EPROTOTYPE,
        libc::ENOPROTOOPT => ENOPROTOOPT,
        libc::EPROTONOSUPPORT => EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT => ESOCKTNOSUPPORT,
        libc::EOPNOTSUPP => EOPNOTSUPP,
        libc::EPFNOSUPPORT => EPFNOSUPPORT,
        libc::EAFNOSUPPORT => EAFNOSUPPORT,
        libc::EADDRINUSE => EADDRINUSE,
        libc::EADDRNOTAVAIL => EADDRNOTAVAIL,
        libc::ENETDOWN => ENETDOWN,
        libc::ENETUNREACH => ENETUNREACH,
        libc::ENETRESET => ENETRESET,
        libc::ECONNABORTED => ECONNABORTED,
        libc::ECONNRESET => ECONNRESET,
        libc::ENOBUFS => ENOBUFS,
        libc::EISCONN => EISCONN,
        libc::ENOTCONN => ENOTCONN,
        libc::ESHUTDOWN => ESHUTDOWN,
        libc::ETOOMANYREFS => ETOOMANYREFS,
        libc::ETIMEDOUT => ETIMEDOUT,
        libc::ECONNREFUSED => ECONNREFUSED,
        libc::EHOSTDOWN => EHOSTDOWN,
        libc::EHOSTUNREACH => EHOSTUNREACH,
        libc::EALREADY => EALREADY,
        libc::EINPROGRESS => EINPROGRESS,
        libc::ESTALE => ESTALE,
        libc::EUCLEAN => EUCLEAN,
        libc::ENOTNAM => ENOTNAM,
        libc::ENAVAIL => ENAVAIL,
        libc::EISNAM => EISNAM,
        libc::EREMOTEIO => EREMOTEIO,
        libc::EDQUOT => EDQUOT,
        libc::ENOMEDIUM => ENOMEDIUM,
        libc::EMEDIUMTYPE => EMEDIUMTYPE,
        libc::ECANCELED => ECANCELED,
        libc::ENOKEY => ENOKEY,
        libc::EKEYEXPIRED => EKEYEXPIRED,
        libc::EKEYREVOKED => EKEYREVOKED,
        libc::EKEYREJECTED => EKEYREJECTED,
        libc::EOWNERDEAD => EOWNERDEAD,
        libc::ENOTRECOVERABLE => ENOTRECOVERABLE,
        libc::ERFKILL => ERFKILL,
        libc::EHWPOISON => EHWPOISON,
        _ => UnknownErrno,
    }
}
