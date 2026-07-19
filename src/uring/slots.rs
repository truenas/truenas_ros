//! The generation-guarded slot entry shared by every domain table (the stream
//! stack's connection table; the fs domain's op table next).

/// A slot's state plus the generation guarding its reuse. The generation is
/// `u64` so a long-retained cross-thread handle (which travels by channel —
/// not `user_data`) can never alias a future incarnation of the same slot
/// after 2^32 recycles. The kernel routing token packs only its low 32 bits,
/// which is ample there: a completion never outlives its op's incarnation
/// (a slot frees only once its ops drain), so the low bits match exactly.
/// Domains therefore keep two matchers — full-`u64` for channel handles,
/// low-32 for CQEs — and bump the generation whenever a slot empties.
pub(crate) struct SlotEntry<S> {
    pub(crate) generation: u64,
    pub(crate) state: S,
}
