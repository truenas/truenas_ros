#![no_main]

//! Fuzz the decoder of the bytes a read of a fanotify group returns.
//!
//! `parse` walks events by their `event_len`, the info records of each by
//! their `len`, and a FID record by the `handle_bytes` of its file handle and
//! the NUL that ends its name. Every one of those lengths comes from the
//! buffer, so the properties are that each slice handed back lies inside the
//! input, that an error ends its iteration, and that every step consumes
//! bytes, so the walk always ends.
//!
//! Only the pure decoder is driven. `Fanotify::read` would adopt the
//! descriptors the bytes name, which is sound only for bytes the kernel
//! wrote.

use libfuzzer_sys::fuzz_target;
use std::os::unix::ffi::OsStrExt;
use truenas_ros::sync_fs::fanotify::{EVENT_METADATA_LEN, Info, parse};

fn inside(data: &[u8], part: &[u8]) -> bool {
    let start = data.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= start + data.len()
}

fuzz_target!(|data: &[u8]| {
    let mut events = parse(data);
    let mut seen = 0usize;
    while let Some(event) = events.next() {
        let Ok(event) = event else {
            assert!(events.next().is_none(), "an error must end the events");
            break;
        };
        seen += 1;
        assert!(seen * EVENT_METADATA_LEN <= data.len());
        let _ = (event.mask(), event.raw_fd(), event.pid());

        let mut infos = event.infos();
        let mut records = 0usize;
        while let Some(info) = infos.next() {
            records += 1;
            assert!(records * 4 <= data.len());
            match info {
                Err(_) => {
                    assert!(
                        infos.next().is_none(),
                        "an error must end the records"
                    );
                    break;
                }
                Ok(Info::Fid(fid)) => {
                    assert!(inside(data, fid.handle));
                    assert!(fid.handle.len() >= 8);
                    if let Some(name) = fid.name {
                        assert!(inside(data, name.as_bytes()));
                        assert!(!name.as_bytes().contains(&0));
                    }
                }
                Ok(Info::Other { body, .. }) => assert!(inside(data, body)),
                Ok(_) => {}
            }
        }
    }
});
