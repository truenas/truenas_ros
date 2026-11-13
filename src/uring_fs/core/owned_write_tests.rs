use super::owned_write_fits;

/// The screen alone, since a buffer of `u32::MAX` bytes is more than a test may allocate.
#[test]
fn an_owned_write_fits_its_buffer_a_u32_and_a_real_offset() {
    assert!(owned_write_fits(8, &(0..8), 0));
    assert!(owned_write_fits(8, &(3..5), u64::MAX - 1));
    assert!(owned_write_fits(8, &(8..8), 0), "an empty range at the end");
    assert!(!owned_write_fits(8, &(4..9), 0), "past the buffer");
    assert!(!owned_write_fits(8, &(9..9), 0), "starts past the buffer");
    #[allow(clippy::reversed_empty_ranges)]
    let inverted = 5..3;
    assert!(!owned_write_fits(8, &inverted, 0), "inverted");
    let most = u32::MAX as usize;
    assert!(owned_write_fits(usize::MAX, &(1..most + 1), 0));
    assert!(!owned_write_fits(usize::MAX, &(0..most + 1), 0), "a u32");
    assert!(!owned_write_fits(8, &(0..8), u64::MAX), "the file's position");
}
