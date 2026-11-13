use super::copy_range;
use crate::uring_fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::sync::Arc;

fn handle(f: std::fs::File) -> File {
    File::new(Arc::new(OwnedFd::from(f)))
}

/// The whole range in one call, and the count is the kernel's.
///
/// **A request past the end must answer what moved, not what was asked for.** The caller sizes its destination from
/// a `statx` it took earlier, so a source that has since shrunk is exactly the case where a copy that reported
/// success on trust would publish a short object nothing re-checks.
#[test]
fn a_copy_reports_what_moved_not_what_was_asked_for() {
    let dir = crate::tempdir().expect("tempdir");
    let body: Vec<u8> = (0..40_000u32).flat_map(|i| i.to_le_bytes()).collect();

    let src_path = dir.path().join("src.bin");
    let mut src = std::fs::File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&src_path)
        .expect("source");
    src.write_all(&body).expect("fill the source");
    src.sync_all().expect("sync");

    let dst_path = dir.path().join("dst.bin");
    let dst = std::fs::File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&dst_path)
        .expect("destination");

    // Offer far more than the source holds: one call, whole range.
    let src_h = handle(src);
    let dst_h = handle(dst);
    let moved = copy_range(&src_h, &dst_h, 0, 0, body.len() as u64 * 4).expect("copy");
    assert_eq!(
        moved,
        body.len() as u64,
        "the count is what the source had, not what was requested"
    );

    let mut back = Vec::new();
    let mut f = std::fs::File::open(&dst_path).expect("reopen");
    f.seek(SeekFrom::Start(0)).expect("rewind");
    f.read_to_end(&mut back).expect("read back");
    assert_eq!(back, body, "byte for byte");
}

/// An offset pair the caller chose, so the range really is ranged.
#[test]
fn a_copy_honours_both_offsets() {
    let dir = crate::tempdir().expect("tempdir");
    let src_path = dir.path().join("src.bin");
    let mut src = std::fs::File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&src_path)
        .expect("source");
    src.write_all(b"0123456789").expect("fill");
    src.sync_all().expect("sync");

    let dst_path = dir.path().join("dst.bin");
    let mut dst = std::fs::File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&dst_path)
        .expect("destination");
    dst.write_all(b"..........").expect("prefill");
    dst.sync_all().expect("sync");

    let moved = copy_range(&handle(src), &handle(dst), 2, 5, 3).expect("copy");
    assert_eq!(moved, 3);

    let back = std::fs::read(&dst_path).expect("read back");
    assert_eq!(&back, b".....234..", "the window landed where it was aimed");
}
