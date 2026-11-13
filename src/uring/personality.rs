//! [`Personality`]: a registered io_uring credential snapshot, named per-SQE.

/// A registered io_uring personality: a kernel-held snapshot of one identity's credentials (fsuid/fsgid, supplementary
/// groups, capabilities, LSM label), stamped into an SQE's `personality` field. The kernel - not the library - performs
/// that operation's permission checks under it.
///
/// Mint one for the calling process with [`UringFs::register_self`](crate::uring_fs::UringFs::register_self), or for
/// another identity through the credential broker ([`CredHandle::register`](crate::uring_fs::CredHandle::register)).
/// Ids are never 0 (the kernel's allocator starts at 1), so a `Personality` always names a real registration on the
/// ring it came from. An id this ring never registered fails the operation with `EINVAL` at submission.
///
/// # An id is only meaningful on the ring that issued it
///
/// **A `Personality` carries no ring tag, and using one on the wrong ring does not fail - it runs the operation as a
/// different identity.** Each ring's id space starts at 1 (`XA_FLAGS_ALLOC1`, `io_uring.c:367`), and submission
/// resolves the id against that ring's table alone (`io_uring.c:2269-2273`), so two rings that have each registered
/// one identity both hold id 1.
///
/// A process driving more than one reactor must keep each `Personality` with the ring that minted it. Pairing a broker
/// handle to its ring where both are created, rather than by position in two lists, keeps them from drifting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Personality(pub(crate) u16);

impl Personality {
    /// The raw kernel id.
    pub fn id(self) -> u16 {
        self.0
    }

    /// Name an id registered elsewhere on **this** ring - the form a credential broker's reply takes once it has
    /// registered an identity on the reactor's behalf. Returns `None` for `0`, which is not a valid personality:
    /// **`sqe.personality == 0` means "no credential override", so an op stamped with it runs under the reactor
    /// thread's ambient credentials (the root daemon), bypassing the kernel's per-op identity check entirely.**
    ///
    /// A nonzero id this ring never registered is refused by the kernel with `EINVAL`. An id from a *different* ring
    /// is likely to name a **live registration here** and run the op under it (see [`Personality`]).
    pub fn from_raw(id: u16) -> Option<Personality> {
        (id != 0).then_some(Personality(id))
    }
}
