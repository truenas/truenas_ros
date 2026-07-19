//! Socket setup for the three stream families, plus pure `sockaddr`
//! builders/parsers. The builders/parsers do no syscalls, so they are unit
//! tested directly without privilege.

use super::protocol::{ClientAddr, ServerAddr};
use crate::errno::Errno;
use crate::error::Error;
use std::ffi::c_void;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

/// A built kernel socket address plus its valid length.
pub(crate) struct SockAddr {
    pub storage: libc::sockaddr_storage,
    pub len: libc::socklen_t,
}

/// `offsetof(struct sockaddr_un, sun_path)` — `sun_family` is the only field
/// before it, so this is `sizeof(sockaddr_un) - sizeof(sun_path)` (== 2).
fn sun_path_offset() -> usize {
    size_of::<libc::sockaddr_un>() - 108
}

/// Build a kernel `sockaddr` for `addr`.
pub(crate) fn build_sockaddr(addr: &ServerAddr) -> crate::Result<SockAddr> {
    // SAFETY: `sockaddr_storage` is plain data; all-zero is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let len = match addr {
        ServerAddr::Tcp(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: copy the 16-byte sockaddr_in into the larger storage.
            unsafe {
                ptr::copy_nonoverlapping(
                    (&sin as *const libc::sockaddr_in).cast::<u8>(),
                    (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
                    size_of::<libc::sockaddr_in>(),
                );
            }
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        ServerAddr::Tcp6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                // Verbatim, matching std: `SocketAddrV6::flowinfo` IS the
                // wire-order `__be32` value (std's to-C/from-C conversions
                // never swap it), so swapping here would make the kernel see
                // a different flow label than the same SocketAddrV6 given to
                // std::net, and peer addresses disagree with `peer_addr()`.
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: copy the 28-byte sockaddr_in6 into the larger storage.
            unsafe {
                ptr::copy_nonoverlapping(
                    (&sin6 as *const libc::sockaddr_in6).cast::<u8>(),
                    (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
                    size_of::<libc::sockaddr_in6>(),
                );
            }
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
        ServerAddr::Unix(path) => {
            let bytes = path.as_os_str().as_bytes();
            let base = sun_path_offset();
            if bytes.len() + 1 > 108 {
                return Err(Error::Validation(format!(
                    "unix socket path too long: {} bytes (max {})",
                    bytes.len(),
                    107
                )));
            }
            if bytes.contains(&0) {
                return Err(Error::Validation(
                    "unix socket path contains an interior NUL".into(),
                ));
            }
            // storage is zeroed, so sun_path is already NUL-filled.
            let su = (&mut storage as *mut libc::sockaddr_storage)
                .cast::<libc::sockaddr_un>();
            // SAFETY: storage is >= sizeof(sockaddr_un) and correctly aligned;
            // `bytes.len() < 108` leaves room for the trailing NUL.
            unsafe {
                (*su).sun_family = libc::AF_UNIX as libc::sa_family_t;
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (*su).sun_path.as_mut_ptr().cast::<u8>(),
                    bytes.len(),
                );
            }
            (base + bytes.len() + 1) as libc::socklen_t
        }
    };

    Ok(SockAddr { storage, len })
}

/// Decode an `AF_INET`/`AF_INET6` `sockaddr_storage` — dispatched on its own
/// `ss_family` — into a `SocketAddr`. `None` for any other family. The one
/// unsafe sockaddr decoder: `parse_peer`, `peer_from_fd`, and `local_addr`
/// all funnel through here.
pub(crate) fn parse_inet(
    storage: &libc::sockaddr_storage,
) -> Option<SocketAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: ss_family says AF_INET, so storage holds a sockaddr_in;
            // sockaddr_storage is over-aligned for it.
            let sin = unsafe {
                &*(storage as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
            };
            let o = sin.sin_addr.s_addr.to_ne_bytes();
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(o[0], o[1], o[2], o[3]),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family says AF_INET6, so storage holds a sockaddr_in6.
            let sin6 = unsafe {
                &*(storage as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                // Verbatim (no swap) — see `build_sockaddr`: std treats
                // `sin6_flowinfo` as an opaque pass-through in both
                // directions, and interop (comparing against std's
                // `peer_addr()`) requires matching that.
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Parse the peer address captured by an accept into a [`ClientAddr`].
pub(crate) fn parse_peer(
    storage: &libc::sockaddr_storage,
    kind: &ServerAddr,
) -> Option<ClientAddr> {
    match kind {
        // Unix stream clients are unnamed; credentials (if enabled) are fetched
        // separately by the server before the accept handler runs.
        ServerAddr::Unix(_) => Some(ClientAddr::Unix { cred: None }),
        // TCP listeners: decode by the address's own family. A pad that does
        // not parse as `AF_INET`/`AF_INET6` — a short or rewritten peer-name
        // result, e.g. from a cgroup getsockopt BPF program — yields `None` so
        // the caller sheds, rather than fabricating a local `Unix` identity for
        // a remote peer (fail closed, matching `peer_from_fd`).
        ServerAddr::Tcp(_) | ServerAddr::Tcp6(_) => {
            parse_inet(storage).map(ClientAddr::Inet)
        }
    }
}

/// The peer address of a connected socket via `getpeername(2)` — used for
/// kTLS connections, whose peer is read from the furnished real fd rather
/// than an accept buffer. kTLS listeners are validated TCP, so the peer MUST
/// parse as `AF_INET`/`AF_INET6`; a getpeername failure (e.g. `ENOTCONN`
/// after an early RST) or any other family returns `None` and the caller
/// sheds — fail CLOSED, like the `SO_PEERNAME` accept path. Returning a
/// fabricated identity here (the old `Unix { cred: None }` fallback) let a
/// remote TCP peer read as a local unix one to per-listener policy and audit
/// hooks.
pub(crate) fn peer_from_fd(fd: RawFd) -> Option<ClientAddr> {
    // SAFETY: sockaddr_storage is plain data; zeroed is a valid initial value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: getpeername writes up to `len` bytes into `storage` and updates
    // `len`; both point at valid, sized stack storage.
    let rc = unsafe {
        libc::getpeername(fd, std::ptr::addr_of_mut!(storage).cast(), &mut len)
    };
    if rc != 0 {
        return None;
    }
    parse_inet(&storage).map(ClientAddr::Inet)
}

/// `setsockopt` an integer-valued option.
pub(crate) fn set_opt(
    fd: &OwnedFd,
    level: libc::c_int,
    opt: libc::c_int,
    val: libc::c_int,
) -> crate::Result<()> {
    // SAFETY: optval points to a valid c_int of the given length.
    Errno::result(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            opt,
            (&val as *const libc::c_int).cast::<c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// Resolve the actual bound address of `fd` (e.g. an ephemeral `:0` TCP port).
pub(crate) fn local_addr(
    fd: RawFd,
    kind: &ServerAddr,
) -> crate::Result<ServerAddr> {
    // SAFETY: sockaddr_storage is plain data; all-zero is valid.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: getsockname writes at most `len` bytes into `storage`.
    Errno::result(unsafe {
        libc::getsockname(
            fd,
            (&mut storage as *mut libc::sockaddr_storage)
                .cast::<libc::sockaddr>(),
            &mut len,
        )
    })?;
    Ok(match (kind, parse_inet(&storage)) {
        (ServerAddr::Tcp(_), Some(SocketAddr::V4(v4))) => ServerAddr::Tcp(v4),
        (ServerAddr::Tcp6(_), Some(SocketAddr::V6(v6))) => ServerAddr::Tcp6(v6),
        (ServerAddr::Unix(p), _) => ServerAddr::Unix(p.clone()),
        // getsockname on a socket created for this family cannot disagree
        // with it.
        _ => return Err(Error::from(Errno::EINVAL)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_v4() {
        let a = ServerAddr::Tcp("127.0.0.1:8080".parse().unwrap());
        let sa = build_sockaddr(&a).unwrap();
        assert_eq!(sa.len, 16);
        // SAFETY: storage holds a sockaddr_in.
        let sin = unsafe {
            &*(&sa.storage as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in>()
        };
        assert_eq!(sin.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(u16::from_be(sin.sin_port), 8080);
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [127, 0, 0, 1]);
        // round-trip
        match parse_peer(&sa.storage, &a).unwrap() {
            ClientAddr::Inet(SocketAddr::V4(v4)) => {
                assert_eq!(*v4.ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(v4.port(), 8080);
            }
            other => panic!("expected V4, got {other:?}"),
        }
    }

    #[test]
    fn build_v6() {
        let a = ServerAddr::Tcp6("[::1]:9000".parse().unwrap());
        let sa = build_sockaddr(&a).unwrap();
        assert_eq!(sa.len, 28);
        // SAFETY: storage holds a sockaddr_in6.
        let sin6 = unsafe {
            &*(&sa.storage as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in6>()
        };
        assert_eq!(sin6.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(u16::from_be(sin6.sin6_port), 9000);
        assert_eq!(sin6.sin6_addr.s6_addr, Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn build_unix() {
        let a = ServerAddr::Unix(PathBuf::from("/tmp/truenas_ros.sock"));
        let sa = build_sockaddr(&a).unwrap();
        let path = b"/tmp/truenas_ros.sock";
        assert_eq!(sa.len as usize, sun_path_offset() + path.len() + 1);
        // SAFETY: storage holds a sockaddr_un.
        let su = unsafe {
            &*(&sa.storage as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_un>()
        };
        assert_eq!(su.sun_family, libc::AF_UNIX as libc::sa_family_t);
        let stored: Vec<u8> = su
            .sun_path
            .iter()
            .take(path.len())
            .map(|&c| c as u8)
            .collect();
        assert_eq!(stored, path);
    }

    #[test]
    fn unix_path_too_long() {
        let a = ServerAddr::Unix(PathBuf::from("x".repeat(108)));
        assert!(matches!(build_sockaddr(&a), Err(Error::Validation(_))));
    }

    #[test]
    fn parse_inet_dispatches_on_family() {
        // The shared decoder reads ss_family itself: v4 and v6 storages
        // decode to their own variants, anything else is None.
        let v4 =
            build_sockaddr(&ServerAddr::Tcp("10.1.2.3:4567".parse().unwrap()))
                .unwrap();
        assert_eq!(
            parse_inet(&v4.storage),
            Some("10.1.2.3:4567".parse().unwrap())
        );
        let v6 = build_sockaddr(&ServerAddr::Tcp6(
            "[fe80::1%3]:9000".parse().unwrap(),
        ))
        .unwrap();
        match parse_inet(&v6.storage) {
            Some(SocketAddr::V6(a)) => {
                assert_eq!(*a.ip(), "fe80::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(a.port(), 9000);
                assert_eq!(a.scope_id(), 3);
            }
            other => panic!("expected V6, got {other:?}"),
        }
    }

    #[test]
    fn flowinfo_passes_through_unswapped() {
        // std stores `sin6_flowinfo` verbatim in both its to-C and from-C
        // conversions, so this module must too — a byte swap on either side
        // makes the kernel see a different flow label than the same
        // SocketAddrV6 bound via std::net, and makes peers surfaced in
        // ClientAddr compare unequal to std's `peer_addr()` for the very
        // same connection.
        let flow: u32 = 0x0001_2345;
        let addr: SocketAddrV6 =
            SocketAddrV6::new("fe80::1".parse().unwrap(), 9000, flow, 3);
        let sa = build_sockaddr(&ServerAddr::Tcp6(addr)).unwrap();
        // SAFETY: storage holds the sockaddr_in6 just built.
        let sin6 = unsafe {
            &*(&sa.storage as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr_in6>()
        };
        assert_eq!(sin6.sin6_flowinfo, flow, "raw field must be verbatim");
        match parse_inet(&sa.storage) {
            Some(SocketAddr::V6(a)) => assert_eq!(a.flowinfo(), flow),
            other => panic!("expected V6, got {other:?}"),
        }
    }
}
