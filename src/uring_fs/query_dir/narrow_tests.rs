use super::{narrow, right_size};

/// `narrow`'s property on the buffer shape it is kept for - a refetch buffer sized to the value, so nearly full: it
/// comes back in the allocation that went to the kernel. Pointer identity is the assertion, because length and
/// contents look the same either way.
#[test]
fn narrowing_reuses_the_buffer_instead_of_copying_it() {
    let buf = vec![7u8; 4096];
    let before = buf.as_ptr();
    let got = narrow(buf, 4000).expect("4000 fits in 4096");
    assert_eq!(got.as_ptr(), before, "the value was copied elsewhere");
    assert_eq!(got.len(), 4000);
    assert_eq!(got.capacity(), 4096, "capacity shrank, so it reallocated");
    assert!(got.iter().all(|&b| b == 7));
}

/// `right_size`'s two regimes. A small value gives the probe buffer's surplus back, which `truncate` alone would not,
/// and a value past half the buffer keeps the allocation, pointer-identical.
#[test]
fn right_sizing_returns_a_probe_buffers_surplus() {
    let got = right_size(vec![7u8; 65536], 13).expect("13 fits");
    assert_eq!(got.len(), 13);
    assert_eq!(got.capacity(), 13, "the probe buffer was retained");
    assert!(got.iter().all(|&b| b == 7));

    let buf = vec![9u8; 4096];
    let before = buf.as_ptr();
    let got = right_size(buf, 3000).expect("3000 fits");
    assert_eq!(got.as_ptr(), before, "a near-full buffer was copied");
    assert_eq!(got.capacity(), 4096);
    assert_eq!(got.len(), 3000);
}

/// A count past the end must be refused, not ignored: `truncate` does nothing there and would hand back the whole
/// buffer as if the kernel had filled it. Both narrowers hold the same line.
#[test]
fn a_count_past_the_end_is_refused_rather_than_ignored() {
    assert!(narrow(vec![0u8; 16], 17).is_none());
    assert!(narrow(vec![0u8; 16], usize::MAX).is_none());
    assert_eq!(narrow(vec![0u8; 16], 16).map(|v| v.len()), Some(16));
    assert_eq!(narrow(Vec::new(), 0).map(|v| v.len()), Some(0));
    assert!(right_size(vec![0u8; 16], 17).is_none());
    assert!(right_size(vec![0u8; 16], usize::MAX).is_none());
    assert_eq!(right_size(Vec::new(), 0).map(|v| v.len()), Some(0));
}
