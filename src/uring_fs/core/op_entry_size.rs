use super::{FsOpEntry, SlotEntry};

/// The op table's per-slot cost, which [`FsConfig`]'s rustdoc quotes to work out the default's resident cost
/// against the ring's locked-memory one.
///
/// It measures 584 bytes, 616 under `net-server`: the default 32768-slot table is 18.25 MiB, 19.25 MiB with the
/// server. The bytes of a name and the `open_how` the kernel reads at prep are most of it, kept in the slot so an
/// op allocates nothing for them. Pinned loosely, because the point is that the figure is re-derived when the entry
/// grows, not that it never may.
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
