//! `listen_socket`: create, bind, and listen a stream socket for a bound
//! listener. This is the server-side socket setup (reuse/nodelay/keepalive/
//! user-timeout options, unix-path unlink) driven by the server config; the
//! address builders and the per-option setter it calls are the role-neutral
//! helpers in `net::core::sock`.

use crate::errno::Errno;
use crate::fd::owned_from_raw;
use crate::net::core::protocol::ServerAddr;
use crate::net::core::sock::{build_sockaddr, set_opt};
use crate::net::server::config::ServerConfig;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

/// Create, bind, and `listen` a stream socket. Returns the listener as an
/// ordinary owned fd (only accepted connections become pool descriptors).
pub(crate) fn listen_socket(
    addr: &ServerAddr,
    cfg: &ServerConfig,
) -> crate::Result<OwnedFd> {
    let domain = match addr {
        ServerAddr::Tcp(_) => libc::AF_INET,
        ServerAddr::Tcp6(_) => libc::AF_INET6,
        ServerAddr::Unix(_) => libc::AF_UNIX,
    };
    // SAFETY: standard socket() call; result checked against the -1 sentinel.
    let raw = Errno::result(unsafe {
        libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: socket() returned a fresh owned fd.
    let fd = unsafe { owned_from_raw(raw) };

    // TCP-only options. Everything set on the listener here is inherited by
    // accepted sockets on Linux, which is what makes per-connection behavior
    // (NODELAY, keepalive, user timeout) configurable at all for direct
    // descriptors — the server never holds an accepted connection as a normal
    // fd it could setsockopt.
    // Force single-stack on every IPv6 listener (as Samba does): otherwise the
    // platform default (`net.ipv6.bindv6only`) may accept v4-mapped peers on a
    // `::` bind — which would parse as spurious IPv6 addresses — and collide
    // with a separate IPv4 listener on the same port.
    if matches!(addr, ServerAddr::Tcp6(_)) {
        set_opt(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    }
    if matches!(addr, ServerAddr::Tcp(_) | ServerAddr::Tcp6(_)) {
        set_opt(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        if cfg.reuse_port {
            set_opt(&fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
        }
        if cfg.nodelay {
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
        }
        if let Some(idle) = cfg.keepalive {
            set_opt(&fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
            // TCP_KEEPIDLE is whole seconds and must be >= 1; the config doc
            // promises fractional durations round UP (2.5s → 3), so probing
            // never starts before the configured idle window.
            let secs =
                idle.as_secs()
                    .saturating_add(u64::from(idle.subsec_nanos() != 0))
                    .clamp(1, i32::MAX as u64) as libc::c_int;
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, secs)?;
        }
        if let Some(t) = cfg.tcp_user_timeout {
            // TCP_USER_TIMEOUT is milliseconds.
            let ms = t.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, ms)?;
        }
    }

    if let ServerAddr::Unix(path) = addr {
        if cfg.unlink_unix {
            if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
                // SAFETY: best-effort unlink of a valid NUL-terminated path;
                // failure (e.g. ENOENT) is intentionally ignored.
                unsafe { libc::unlink(c.as_ptr()) };
            }
        }
    }

    let sa = build_sockaddr(addr)?;
    // SAFETY: `sa.storage`/`sa.len` describe a valid sockaddr for this family.
    Errno::result(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&sa.storage as *const libc::sockaddr_storage)
                .cast::<libc::sockaddr>(),
            sa.len,
        )
    })?;
    // SAFETY: fd is a bound stream socket.
    Errno::result(unsafe { libc::listen(fd.as_raw_fd(), cfg.backlog) })?;

    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::core::sock::parse_inet;
    use std::mem::size_of;
    use std::path::PathBuf;

    #[test]
    fn keepalive_rounds_up_to_whole_seconds() {
        // The config doc promises TCP_KEEPIDLE is the duration "rounded up to
        // a whole second": 2.5s must program 3, not truncate to 2 (probing
        // half a second early breaks timing consumers derive from the doc).
        let cfg = ServerConfig {
            keepalive: Some(std::time::Duration::from_millis(2500)),
            ..ServerConfig::default()
        };
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse().unwrap());
        let fd = listen_socket(&addr, &cfg).expect("listen_socket");
        let mut idle: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes a c_int into `idle`.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                (&mut idle as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(TCP_KEEPIDLE)");
        assert_eq!(idle, 3, "2500ms must round UP to 3s");
        // A unix sockaddr (or zeroed storage) is not an inet address.
        let un =
            build_sockaddr(&ServerAddr::Unix(PathBuf::from("/tmp/x.sock")))
                .unwrap();
        assert_eq!(parse_inet(&un.storage), None);
    }
}
