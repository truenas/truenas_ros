use super::{FsOpEntry, SlotEntry};

/// The op table's per-slot cost, which [`FsConfig`]'s rustdoc quotes (584 bytes, 616 under `net-server`) to work out
/// the default's resident cost. Pinned loosely, so the figure is re-derived when the entry grows.
///
/// [`FsConfig`]: crate::uring_fs::FsConfig
#[test]
fn the_op_slot_is_the_size_the_config_docs_quote() {
    let n = size_of::<SlotEntry<FsOpEntry>>();
    assert!(
        (576..=624).contains(&n),
        "an op slot is {n} bytes; `FsConfig`'s rustdoc quotes 584 (616 \
             with `net-server`) - re-derive the default's resident cost there"
    );
}
