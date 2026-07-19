//! The io_uring filesystem reactor — reserved landing zone.
//!
//! This module will host the asynchronous counterpart of [`crate::sync_fs`]:
//! filesystem I/O (`OPENAT2`, `READ`/`WRITE`, `STATX`, `FSYNC`, splice)
//! submitted on the same shared engine (`uring`) the `net` roles drive, with
//! per-op credential override via registered io_uring personalities — a
//! privileged daemon performing filesystem operations *as* the authenticated
//! peer, enforced by the kernel's own permission checks, with no
//! thread-per-identity and no setuid on any hot path. Files open directly
//! into a fixed-descriptor pool (no process fds), completions fire
//! registered callbacks in the owning loop, and a `Send + Sync` handle
//! serves off-loop callers.
//!
//! Nothing is implemented yet: the feature exists so the engine seam and the
//! feature graph are exercised (`async-fs` builds the `uring` engine without
//! any of the net stack) while the design settles into code.
