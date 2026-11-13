use super::spare_read_fits;

/// The screen alone, since a buffer with room for `u32::MAX` bytes is more than a test may allocate.
#[test]
fn a_spare_read_fits_its_room_a_u32_and_a_real_offset() {
    assert!(spare_read_fits(8, 8, 0));
    assert!(spare_read_fits(8, 0, u64::MAX - 1));
    assert!(!spare_read_fits(8, 9, 0), "past the room");
    let most = u32::MAX as usize;
    assert!(spare_read_fits(usize::MAX, most, 0));
    assert!(!spare_read_fits(usize::MAX, most + 1, 0), "past a u32");
    assert!(!spare_read_fits(8, 8, u64::MAX), "the file's position");
}
