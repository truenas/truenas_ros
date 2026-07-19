//! The `user_data` completion-routing codec every domain on a ring shares.
//!
//! Layout: low 8 bits = the op tag, bits 8..32 = the slot (24 bits), bits
//! 32..64 = the low 32 bits of the slot's generation. The codec is one
//! mechanism with domain-owned tag vocabularies on top: the stream stack
//! (`net`) assigns its `Op` tags inside `0x00..=0x7F`, and the fs domain owns
//! `0x80..=0xFF` ([`TAG_FS_DOMAIN`]) — so a loop hosting both routes a
//! completion to its domain with a single bit test, before either domain
//! decodes the tag any further. Each domain hand-writes its own dispatch
//! `match` over its tags; nothing here interprets them.

/// The slot field's width: 24 bits, matching the largest supported pool.
pub(crate) const SLOT_MASK: u64 = 0x00ff_ffff;

/// The tag-byte bit that marks a completion as belonging to the fs domain.
/// Stream tags stay below it; a host loop tests `user_data as u8 &
/// TAG_FS_DOMAIN` before its stream `match` (whose unknown-tag arm silently
/// ignores — it must never swallow another domain's completions).
pub(crate) const TAG_FS_DOMAIN: u8 = 0x80;

/// Encode `(tag, slot, generation-low)` into an SQE `user_data` token.
pub(crate) fn pack_raw(tag: u8, slot: u32, generation: u32) -> u64 {
    u64::from(tag)
        | ((u64::from(slot) & SLOT_MASK) << 8)
        | (u64::from(generation) << 32)
}

/// Decode a CQE `user_data` token into `(tag, slot, generation-low)`.
pub(crate) fn unpack_raw(user_data: u64) -> (u8, u32, u32) {
    let tag = (user_data & 0xff) as u8;
    let slot = ((user_data >> 8) & SLOT_MASK) as u32;
    let generation = (user_data >> 32) as u32;
    (tag, slot, generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_codec_round_trip() {
        for &(tag, slot, generation) in &[
            (0u8, 0u32, 0u32),
            (0x7f, SLOT_MASK as u32, u32::MAX),
            (TAG_FS_DOMAIN, 1, 2),
            (0xff, 0x00ab_cdef, 0xdead_beef),
        ] {
            let ud = pack_raw(tag, slot, generation);
            assert_eq!(unpack_raw(ud), (tag, slot, generation));
        }
    }

    #[test]
    fn fs_domain_bit_partitions_the_tag_space() {
        // The stream domain's tags all clear the bit; every fs tag sets it.
        for tag in 0u8..=0x7f {
            assert_eq!(tag & TAG_FS_DOMAIN, 0);
        }
        for tag in 0x80u8..=0xff {
            assert_ne!(tag & TAG_FS_DOMAIN, 0);
        }
    }
}
