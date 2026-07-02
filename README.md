# truenas_ros

Idiomatic Rust bindings for modern Linux filesystem and mount syscalls that
glibc does not wrap, plus NFS4/POSIX1E ACLs, a filesystem iterator,
idmapped-mount user namespaces, symlink-safe / atomic file I/O, and a
`configparser`-compatible config-file parser.

This is the Rust equivalent of the Python `truenas_pyos` library. It is
targeted only for TrueNAS kernel versions and depends only on `libc` and
`bitflags`. It calls the kernel directly — glibc does not wrap most of these
syscalls — exposing `bitflags`-typed flag sets, an `Errno`-based `Result`, and
`OwnedFd` / `BorrowedFd` descriptor ownership.

## Features

Every feature is on by default. To pick a subset, set `default-features =
false` and re-enable what you need (or use `full`):

```toml
[dependencies]
truenas_ros = { version = "0.1", default-features = false, features = ["fs", "configfile"] }
```

| Feature | Contents |
|---|---|
| `fs` | `statx`, `openat2`, `renameat2`; `safe_open`, `atomic_write` / `atomic_replace` |
| `xattr` | `fgetxattr` / `fsetxattr` / `flistxattr` / `fremovexattr` |
| `mount` | `statmount`, `listmount`, `iter_mount`, `open_tree`, `move_mount`, `mount_setattr`, `fsopen` / `fsconfig` / `fsmount`, `umount2`; higher-level `statmount_path`, `iter_mountinfo`, `umount` |
| `acl` | NFS4 (`system.nfs4_acl_xdr`) and POSIX1E ACLs — decode / encode / validate + `fgetacl` / `fsetacl` |
| `fhandle` | `name_to_handle_at` / `open_by_handle_at` (`FileHandle`) |
| `fsiter` | single-filesystem depth-first `Iterator` yielding owned entries |
| `namespace` | idmapped-mount user namespaces via `clone3` (`create_idmap_userns`, cached `idmap_userns`) |
| `shutil` | metadata-preserving recursive `copytree` + copy / clone primitives |
| `configfile` | INI config files byte-for-byte compatible with Python's `configparser`, read symlink-safely and written atomically |

## Examples

Open a file without following any symlink in the path, then stat the fd:

```rust
use truenas_ros::fs::{openat2, statx, AtFlags, OFlag, OpenHow, ResolveFlag, StatxMask};
use truenas_ros::AT_FDCWD;

let how = OpenHow::new()
    .flags(OFlag::O_RDONLY)
    .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
let fd = openat2(AT_FDCWD, "/etc/hostname", how)?;
let st = statx(fd, "", AtFlags::AT_EMPTY_PATH, StatxMask::BASIC_STATS)?;
println!("{} bytes", st.size());
```

Read and write an INI config file. Parsing matches Python's `configparser`
exactly (verified by a differential test against the real `configparser`), but
files are read symlink-safely and written atomically with an explicit mode —
durability and safety that `configparser` itself leaves to the caller:

```rust
use truenas_ros::configfile::ConfigFile;
use truenas_ros::fs::AtomicWriteOptions;

let mut cfg = ConfigFile::new();
cfg.read_str("[server]\nHost = localhost\nPort = 8080\n")?;
assert_eq!(cfg.get("server", "host")?.as_deref(), Some("localhost"));
assert_eq!(cfg.get_int("server", "port")?, Some(8080));

// Write it back atomically (temp file + fsync + rename), resolving no
// symlinks, with an explicit mode — none of which configparser does itself:
cfg.set_int("server", "port", 9090)?;
let opts = AtomicWriteOptions { mode: 0o600, ..Default::default() };
cfg.write_path("/etc/app.conf".as_ref(), opts)?;
```

## Requirements

- A TrueNAS kernel version
- Rust 1.75 or newer

## Testing

`cargo test --all-features` runs the suite. Some tests adapt to their
environment:

- **ZFS / privileged tests** (`test/zfs.rs`) skip unless an ACL-typed ZFS
  dataset is present; CI provisions one in a QEMU VM job.
- **`configparser` differential tests** (`test/configparser_compat.rs`) spawn
  the real Python `configparser` and assert byte-for-byte and behavioral
  parity. They skip if `python3` is unavailable; set
  `TRUENAS_ROS_REQUIRE_PYTHON=1` (as CI does) to make a missing interpreter a
  hard failure instead.

## License

MIT — see [`LICENSE`](LICENSE).
