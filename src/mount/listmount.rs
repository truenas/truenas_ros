//! `listmount(2)` — enumerate mount ids beneath a mount.

use super::{MntIdReq, MNT_ID_REQ_SIZE_VER1, SYS_LISTMOUNT};
use crate::errno::{self, retry_on_eintr};

/// Sentinel `mnt_id` selecting the root of the mount namespace.
pub const LSMT_ROOT: u64 = u64::MAX;

const LISTMOUNT_REVERSE: libc::c_uint = 1;
const BATCH: usize = 1024;

/// List the mount ids beneath `mnt_id` (use [`LSMT_ROOT`] for the whole
/// namespace).
///
/// With `reverse`, later mounts are listed first — the order wanted for
/// recursive unmount (children before parents).
///
/// See [`listmount(2)`](https://man7.org/linux/man-pages/man2/listmount.2.html).
pub fn listmount(mnt_id: u64, reverse: bool) -> errno::Result<Vec<u64>> {
    let flags = if reverse { LISTMOUNT_REVERSE } else { 0 };
    let mut out = Vec::new();
    let mut last: u64 = 0;
    loop {
        let mut ids = [0u64; BATCH];
        let mut req = MntIdReq {
            size: MNT_ID_REQ_SIZE_VER1,
            mnt_ns_fd: 0,
            mnt_id,
            param: last,
            mnt_ns_id: 0,
        };
        let n = retry_on_eintr(|| unsafe {
            libc::syscall(
                SYS_LISTMOUNT,
                &mut req as *mut MntIdReq,
                ids.as_mut_ptr(),
                BATCH,
                flags,
            )
        })? as usize;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&ids[..n]);
        if n < BATCH {
            break;
        }
        // Continue after the last id. The reverse direction stays in `flags`;
        // `param` carries only the mount id to resume from.
        last = ids[n - 1];
    }
    Ok(out)
}
