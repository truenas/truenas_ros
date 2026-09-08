//! [`Personality`]: a registered io_uring credential snapshot, named per-SQE.
//!
//! The type lives in the engine because registration is an engine-level
//! affair (`sys::register_personality` takes a bare ring fd) and more than
//! one domain stamps it: the fs reactor marks every operation
//! it submits, and the net client marks an outbound `CONNECT` so the peer's
//! `SO_PEERCRED` sees the personality rather than the daemon.

/// A registered io_uring personality: a kernel-held snapshot of one
/// identity's credentials (fsuid/fsgid, supplementary groups, capabilities,
/// LSM label), stamped into an SQE's `personality` field. The kernel - not
/// the library - performs that operation's permission checks under it.
///
/// Mint one for the calling process with
/// [`UringFs::register_self`](crate::uring_fs::UringFs::register_self), or
/// for another identity through the credential broker
/// ([`CredHandle::register`](crate::uring_fs::CredHandle::register)). Ids are
/// never 0 (the kernel's allocator starts at 1), so a `Personality` always
/// names a real registration on the ring it came from. An id this ring never
/// registered fails the operation with `EINVAL` at submission.
///
/// # An id is only meaningful on the ring that issued it
///
/// **A `Personality` carries no ring tag, and using one on the wrong ring
/// does not fail - it runs the operation as a different identity.** The
/// kernel's id space is per-ring and starts at 1 for each
/// (`xa_init_flags(&ctx->personalities, XA_FLAGS_ALLOC1)`, `io_uring.c:367`),
/// and submission resolves the id against *this* ring's table only:
/// `req->creds = xa_load(&ctx->personalities, personality)` refuses with
/// `EINVAL` when the lookup misses and otherwise overrides credentials with
/// whatever it found (`io_uring.c:2269-2273`). Two rings that have each
/// registered one identity therefore both hold id 1, and crossing them hits
/// rather than misses - silently, under the other identity's credentials.
///
/// Ring-locality is what makes this a hazard rather than what protects
/// against it. A process driving more than one reactor (the multi-ring
/// recipe in `README.md`) must keep each `Personality` with the ring that
/// minted it; nothing in the type system does that for it. Pairing a broker
/// handle to its ring at the point both are created - rather than by
/// position in two parallel lists - is what keeps the two from drifting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Personality(pub(crate) u16);

impl Personality {
    /// The raw kernel id.
    pub fn id(self) -> u16 {
        self.0
    }

    /// Name an id registered elsewhere on **this** ring - the form a
    /// credential broker's reply takes once it has registered an identity
    /// on the reactor's behalf. Returns `None` for `0`, which is not a valid
    /// personality: **`sqe.personality == 0` means "no credential override",
    /// so an op stamped with it runs under the reactor thread's ambient
    /// credentials (the root daemon), bypassing the kernel's per-op identity
    /// check entirely.** The kernel never allocates id 0 (`XA_FLAGS_ALLOC1`),
    /// so a broker reply of 0 is malformed; refusing it keeps the
    /// "personality-0 is unreachable from this API" invariant true by
    /// construction.
    ///
    /// Forging a *nonzero* id this ring never registered is not a privilege
    /// hole: the kernel resolves the id and refuses with `EINVAL` rather than
    /// falling back to ambient credentials.
    ///
    /// An id from a *different* ring is a different matter, and not a safe
    /// one: id spaces are per-ring and both start at 1, so an id registered
    /// on another ring is very likely to name a **live registration here**
    /// and run the op under it. See the [`Personality`] type docs.
    pub fn from_raw(id: u16) -> Option<Personality> {
        (id != 0).then_some(Personality(id))
    }
}
