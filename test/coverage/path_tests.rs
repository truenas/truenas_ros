use std::ffi::{CString, OsStr};
use std::path::{Path, PathBuf};
use truenas_ros::errno::Errno;
use truenas_ros::path::TnPath;

#[test]
fn len_and_is_empty_across_impls() {
    assert_eq!(TnPath::len("abc"), 3);
    assert_eq!(TnPath::len(OsStr::new("abcd")), 4);
    assert_eq!(TnPath::len(Path::new("abcde")), 5);
    assert_eq!(TnPath::len(&PathBuf::from("ab")), 2);
    assert_eq!(TnPath::len(b"abcdef" as &[u8]), 6);
    let cs = CString::new("xy").unwrap();
    assert_eq!(TnPath::len(cs.as_c_str()), 2);

    assert!(!TnPath::is_empty("x"));
    assert!(TnPath::is_empty(""));
    assert!(TnPath::is_empty(OsStr::new("")));
    assert!(TnPath::is_empty(Path::new("")));
    assert!(TnPath::is_empty(&PathBuf::from("")));
    assert!(TnPath::is_empty(b"" as &[u8]));
    assert!(TnPath::is_empty(CString::new("").unwrap().as_c_str()));
}

#[test]
fn interior_nul_is_einval() {
    assert_eq!("a\0b".with_tn_path(|_| ()).unwrap_err(), Errno::EINVAL);
}

#[test]
fn heap_fallback_for_long_paths() {
    // Longer than the 1024-byte stack buffer -> heap CString path.
    let long = "a".repeat(2000);
    let n = long.as_str().with_tn_path(|c| c.to_bytes().len()).unwrap();
    assert_eq!(n, 2000);
}

/// The `[u8]` conversion writes into a `MaybeUninit<[u8; 1024]>` with a manual NUL and falls back to the heap when
/// the name does not fit, so the interesting lengths are the ones either side of that boundary -- where an
/// off-by-one writes past the array. Every length must yield a `CStr` carrying exactly the input bytes, whichever
/// arm ran.
///
/// The `tn_path` fuzz target sweeps this under AddressSanitizer, where an overrun is a crash rather than a wrong
/// length; pinned here too because a short fuzz run starts from small inputs and does not reach 1 KiB.
#[test]
fn stack_to_heap_boundary_carries_the_bytes_exactly() {
    for len in [0, 1, 1022, 1023, 1024, 1025, 1026, 4096] {
        let name = vec![b'a'; len];
        let got = name
            .as_slice()
            .with_tn_path(|c| c.to_bytes().to_vec())
            .unwrap_or_else(|e| panic!("len {len} refused: {e}"));
        assert_eq!(got, name, "len {len} did not round-trip");
    }
}

#[test]
fn every_impl_materialises_a_cstr() {
    let want = b"pth".to_vec();
    let get = |c: &std::ffi::CStr| c.to_bytes().to_vec();
    assert_eq!("pth".with_tn_path(get).unwrap(), want);
    assert_eq!(OsStr::new("pth").with_tn_path(get).unwrap(), want);
    assert_eq!(Path::new("pth").with_tn_path(get).unwrap(), want);
    assert_eq!(PathBuf::from("pth").with_tn_path(get).unwrap(), want);
    assert_eq!((b"pth" as &[u8]).with_tn_path(get).unwrap(), want);
    let cs = CString::new("pth").unwrap();
    assert_eq!(cs.as_c_str().with_tn_path(get).unwrap(), want);
}
