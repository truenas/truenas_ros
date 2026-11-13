use super::{Errno, FsDone};

/// An xattr op's value comes back alone through `into_value`, the very storage it was given, and as the one buffer
/// through `into_bufs`. A refusal, which hands the value back among its buffers, gives it through `into_value` too.
#[test]
fn into_value_gives_an_xattr_value_back_alone() {
    let value = vec![1, 2, 3];
    let storage = value.as_ptr();
    let done = FsDone {
        value: Some(value),
        ..FsDone::failed(Errno::EIO)
    };
    let back = done.into_value();
    assert_eq!(back.as_ptr(), storage, "the same storage");
    let done = FsDone {
        value: Some(back),
        ..FsDone::failed(Errno::EIO)
    };
    assert_eq!(done.into_bufs(), vec![vec![1, 2, 3]]);
    let refused = FsDone::refused_with(Errno::EBUSY, vec![vec![4]]);
    assert_eq!(refused.into_value(), vec![4]);
}
