//! Detaching a connection to a worker for a blocking op on the socket fd.
//!
//! `Response::Detach` hands the connection's socket fd to your own worker for a blocking operation on the socket, such
//! as ZFS send and receive, where `lzc_send` and `lzc_receive` block in a `/dev/zfs` ioctl while the kernel streams
//! records over the fd. The library ships no worker pool and no ZFS bindings, so you bring both. The pattern runs in
//! three steps.
//!
//!  1. The body handler stashes what to do in the per-connection state and returns
//!     `Response::Detach(responder.detach())`.
//!  2. The server makes a real fd aliasing the pool socket and calls the `set_detach_handler` closure with the context
//!     and a `Detached` handle that owns that fd.
//!  3. The closure moves the `Detached` to a worker, which does the blocking op on `detached.raw_fd()`, then calls
//!     `detached.resume()` to keep serving or `detached.close()`. A dropped handle closes the connection.
//!
//! This stand-in worker echoes bytes off the fd instead of running ZFS. Run:
//!
//!   cargo run --example tcp_detach --features net-server
//!
//! then send `[4-byte BE len]["stream"]` to detach; the connection then echoes raw bytes until you half-close, and
//! resumes framed serving afterwards.

use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::thread;
use truenas_ros::net::server::{
    Endian, Incoming, PrefixWidth, Protocol, Request, Response, Server, ServerAddr, length_prefix_header,
};

/// Frame a payload with a 4-byte BE length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// Stand-in for the blocking transfer a real consumer runs on the furnished fd. It echoes raw bytes until the peer
/// half-closes, and returns whether it finished cleanly.
fn run_transfer(fd: RawFd) -> bool {
    // Borrow the fd without owning it, since the `Detached` closes it. It shares the pool socket's file description and
    // so its `O_NONBLOCK`, which a blocking op must clear. `Detached::resume` restores `O_NONBLOCK`, but any other
    // file-status flag a worker sets sticks and is its own to restore.
    // SAFETY: `fd` aliases a live socket; wrapped non-owningly via ManuallyDrop.
    let mut s = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    if s.set_nonblocking(false).is_err() {
        return false;
    }
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true, // peer half-closed: transfer done
            Ok(n) => {
                if s.write_all(&buf[..n]).is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}

fn main() -> truenas_ros::Result<()> {
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"stream" {
                // Hand the socket to a worker for the bulk transfer.
                Response::Detach(responder.detach())
            } else {
                // Ordinary framed request: echo it uppercased, inline.
                Response::Reply(frame(&body.to_ascii_uppercase()))
            }
        },
    };

    let addr = ServerAddr::Tcp("127.0.0.1:9000".parse().unwrap());
    let mut server = Server::bind([addr], proto)?;
    server.set_detach_handler(|_ctx, detached| {
        // Move the handle to a worker (never block the ring thread). A real service reads the job from `_ctx.state`.
        thread::spawn(move || {
            if run_transfer(detached.raw_fd()) {
                detached.resume(); // keep the connection for more requests
            } else {
                detached.close();
            }
        });
    });
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}
