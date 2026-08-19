# truenas_ros

Idiomatic Rust bindings for modern Linux filesystem and mount syscalls that
glibc does not wrap, plus NFS4/POSIX1E ACLs, a filesystem iterator,
idmapped-mount user namespaces, symlink-safe / atomic file I/O, kernel audit
records, and a `configparser`-compatible config-file parser. Alongside them,
an opt-in io_uring stack: stream networking, an HTTP/1.1 codec, and a
filesystem reactor that stamps every operation with a kernel-enforced
identity.

This is the Rust equivalent of the Python `truenas_pyos` library. It is
targeted only for TrueNAS kernel versions and depends on `libc` and
`bitflags`, with `httparse` the single exception, optional and reached only by
the `http` feature's request-head tokenizer. It calls the kernel directly --
glibc does not wrap most of these syscalls - exposing `bitflags`-typed flag
sets, an `Errno`-based `Result`, and `OwnedFd` / `BorrowedFd` descriptor
ownership.

## Features

The features in the table below are on by default. To pick a subset, set
`default-features = false` and re-enable what you need:

```toml
[dependencies]
truenas_ros = { version = "0.1", default-features = false, features = ["sync-fs", "configfile"] }
```

| Feature | Contents |
|---|---|
| `sync-fs` | `statx`, `openat2`, `renameat2`; `safe_open`, `atomic_write` / `atomic_replace` (the `sync_fs` umbrella root; the features below through `shutil` are its submodules) |
| `xattr` | `fgetxattr` / `fsetxattr` / `flistxattr` / `fremovexattr` |
| `mount` | `statmount`, `listmount`, `iter_mount`, `open_tree`, `move_mount`, `mount_setattr`, `fsopen` / `fsconfig` / `fsmount`, `umount2`; higher-level `statmount_path`, `iter_mountinfo`, `umount` |
| `acl` | NFS4 (`system.nfs4_acl_xdr`) and POSIX1E ACLs - decode / encode / validate + `fgetacl` / `fsetacl` |
| `fhandle` | `name_to_handle_at` / `open_by_handle_at` (`FileHandle`) |
| `fsiter` | single-filesystem depth-first `Iterator` yielding owned entries |
| `idmap` | idmapped-mount user namespaces via `clone3` (`create_idmap_userns`, cached `idmap_userns`) - lives at `mount::idmap` |
| `shutil` | metadata-preserving recursive `copytree` + copy / clone primitives |
| `configfile` | INI config files byte-for-byte compatible with Python's `configparser`, read symlink-safely and written atomically; an opt-in scrub-on-release mode for secret-bearing files (with `secrets`, the file image stages in `memfd_secret` memory) |
| `audit` | Kernel audit records over `NETLINK_AUDIT` - PAM-shaped `key=value` events sent straight to `auditd`, replacing libaudit |

Three more are opt-in. An io_uring stack lives alongside the blocking
bindings: `net-server` / `net-client` (stream roles over a shared reactor
core, with kernel-TLS, splice, and peer-credential support), `http` (an
HTTP/1.1 codec over the server's protocol seam - a framer and a vocabulary,
not a server), and `uring-fs` (a filesystem reactor whose every operation runs
under a kernel-enforced identity). All sit on the internal `uring` engine
feature; see the crate docs. `secrets` is separate: `memfd_secret(2)`-backed
protected memory for long-lived in-process secrets, off swap and absent from
core dumps, wanted only by a daemon that holds any.

`full` is the default set plus the net roles, `http`, and `secrets`. It never
includes `uring-fs`, which needs a credential broker forked before the daemon
starts threads and so has to be chosen deliberately.

`uring-fs` covers opens, vectored positional I/O (`preadv2` / `pwritev2`),
`splice` from a pipe into a file, sync, the metadata and extended-attribute
ops, cache advice (`fadvise`), the directory-entry family, and directory
listing and subtree walks - off-loop through a blocking handle, or on the
reactor thread through completion callbacks. Beyond plain syscall wrappers it
provides what a storage
service needs and cannot easily build itself: path resolution the caller cannot
weaken (`open_confined`), confined `mkdir -p` (`mkdir_path`), `O_TMPFILE`
publication (`linkat_file`), and an allowlist that lets a server keep its own
metadata in the `trusted.` namespace, where local users cannot read or alter
it - and a blocking-offload seam that runs a request's opcode-less metadata
tail as one pool job, delivered back on the reactor thread.

### Identity

Every `uring-fs` operation carries a `Personality` - a kernel-registered
credential snapshot stamped into the SQE, under which the kernel itself
performs the permission check. There is no ambient-identity variant: the
daemon's own identity is minted explicitly with `UringFs::register_self`, and
acting as an authenticated peer goes through `CredBroker`, a forked process
that impersonates a user just long enough to snapshot their credentials, so
the reactor process never changes identity itself. Wrap it in an
`IdentityCache` to register once per identity rather than once per connection.

```rust
use truenas_ros::uring_fs::{AsUser, CredBroker, FsConfig, UringFs};

// Every ring first, then the broker (it inherits the ring fds), then threads.
let afs = UringFs::new(FsConfig::default())?;
let broker = CredBroker::spawn(&[&afs])?;   // main loses CAP_SETUID here
let creds = broker.handle(0)?;
let who = creds.register(&AsUser::new(1000, 1000).groups(vec![4, 27]))?;
```

A brokered personality carries the user's authority and no elevated
capability. Where a service must resolve a path on behalf of a user entitled
to the object but not to traverse every directory above it, opt in with a
capability mask - bounded by a ceiling fixed at spawn, before the privilege
drop, so it cannot be widened later:

```rust
use truenas_ros::uring_fs::Caps;

let broker = CredBroker::spawn_with_caps(&[&afs], Caps::DAC_READ_SEARCH)?;
let who = creds.register(&AsUser::new(1000, 1000).caps(Caps::DAC_READ_SEARCH))?;
```

`Caps::DAC_READ_SEARCH` is the only capability the allowlist will mint, and it
is broad: it grants traverse and read over the whole filesystem, and on ZFS it
overrides an explicit NFSv4 ACL deny. It does not grant any write, execute, or
delete. Read its docs before reaching for it.

### Listing and walking

`query_directory` lists one directory, optionally enriching each entry with
`statx` and extended attributes scatter-gathered on the ring. `query_tree`
walks a subtree depth-first, descending only through descriptors it already
holds. Both can order entries by the bytes their *full paths* compare by
(`Order::ByPathBytes`), which is the ordering under which per-directory
sorting composes into a correctly ordered walk; a walk yields a `TreeCursor`
that resumes a later walk exactly where this one stopped, with nothing
repeated and nothing skipped.

## Examples

Open a file without following any symlink in the path, then stat the fd:

```rust
use truenas_ros::sync_fs::{openat2, statx, AtFlags, OFlag, OpenHow, ResolveFlag, StatxMask};
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
files are read symlink-safely and written atomically with an explicit mode --
durability and safety that `configparser` itself leaves to the caller:

```rust
use truenas_ros::configfile::ConfigFile;
use truenas_ros::sync_fs::AtomicWriteOptions;

let mut cfg = ConfigFile::new();
cfg.read_str("[server]\nHost = localhost\nPort = 8080\n")?;
assert_eq!(cfg.get("server", "host")?.as_deref(), Some("localhost"));
assert_eq!(cfg.get_int("server", "port")?, Some(8080));

// Write it back atomically (temp file + fsync + rename), resolving no
// symlinks, with an explicit mode - none of which configparser does itself:
cfg.set_int("server", "port", 9090)?;
let opts = AtomicWriteOptions { mode: 0o600, ..Default::default() };
cfg.write_path("/etc/app.conf".as_ref(), opts)?;
```

## Requirements

- A TrueNAS kernel, 6.18 or newer. The floor itself is assumed rather than
  probed - every io_uring operation this crate issues predates it - but
  behaviour that needs a later point release is probed and fails loudly rather
  than degrading: a server configured for `unix_peercred` refuses to start
  below 6.18.16 (the `AF_UNIX` cmd fix), `UringFs::new` probes `OPENAT2`, and
  `SecretMem::available` reports whether `memfd_secret` is compiled in.
- Rust 1.97 or newer

## Testing

`cargo test --all-features` runs the suite. Tests whose fixture may be absent
skip rather than fail, which would let a mis-provisioned runner pass green
having tested nothing - so every skip is gated on a `TRUENAS_ROS_REQUIRE_*`
variable that CI arms, turning the skip back into a hard failure:

| Set to `1` | Forces |
|---|---|
| `TRUENAS_ROS_REQUIRE_PYTHON` | the `configparser` differential tests (`test/configparser_compat.rs`), which spawn the real Python `configparser` and assert byte-for-byte and behavioural parity |
| `TRUENAS_ROS_REQUIRE_IO_URING` | the io_uring suites (`test/net_*.rs`, `test/uring_fs.rs`, `test/http_live.rs`), which otherwise skip when a ring cannot be created |
| `TRUENAS_ROS_REQUIRE_KTLS` | the kernel-TLS data path, which needs the `tls` ULP *and* an OpenSSL built with `enable-ktls` |
| `TRUENAS_ROS_REQUIRE_PEERCRED` | `unix_peercred`, which needs Linux >= 6.18.16 |
| `TRUENAS_ROS_REQUIRE_ZFS` | the ACL suites needing a provisioned ACL-typed ZFS dataset (`test/zfs.rs`) |
| `TRUENAS_ROS_REQUIRE_SECRETMEM` | the `secrets` tests (`test/secrets.rs`), which need `CONFIG_SECRETMEM` |
| `TRUENAS_ROS_REQUIRE_AUDIT` | the audit tests (`test/audit.rs`), which need a `NETLINK_AUDIT` socket |

Anything privileged or ZFS-backed is proven in a QEMU job booting a real
TrueNAS kernel against real datasets, not on a dev box: a local pass on tmpfs
says nothing about `aclmode`, mount propagation, or `open_by_handle_at`.

### Fuzzing

Everything in the library that decodes bytes it did not write has a fuzz target
under [`fuzz/`](fuzz): the ACL wire formats, the INI parser, the `statmount`
reply, the file-handle and resume-cursor codecs, the audit record encoder and
its netlink ack decoder, the path checks, the credential-broker request
header, and the net/http framing.
It is a separate, self-rooted crate, so it never touches the library's
`libc`+`bitflags` charter or its MSRV.

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz build                          # compile every target
cargo +nightly fuzz run statmount_parse -- -max_total_time=300
cargo +nightly fuzz run tree_cursor -- -dict=dicts/tree_cursor.dict
```

Targets assert **properties**, not just the absence of a panic - decode/encode
idempotence, total ordering, injection safety, or a privilege check holding --
so read a target's `//!` header for what it actually claims.

**The corpus is a generated artifact, not source**, which is cargo-fuzz's own
default (`fuzz/corpus/` is in its scaffolded `.gitignore`) and worth keeping
for three reasons. Seed files are opaque in review, so nobody can tell a good
seed from a corrupt one. They encode host byte order, because several of these
formats use native-endian magics. And they drift silently: change a format and
the seeds still load, they just stop covering the path they were written for.

The `http_*` corpora are the exception - tracked, and owned with the codec.

What seeds were doing here, measured over equal 45s runs, was 0-5%:

| target | from seeds | from empty |
| --- | --- | --- |
| `statmount_parse` | 457 | 448 |
| `configfile_ini` | 1050 | 998 |
| `acl_nfs4` | 224 | 224 |
| `tree_cursor` | 78 | 78 |

libFuzzer recovers a magic like `TnCk` from comparison interception in seconds,
so the usual argument for checking seeds in - that a fuzzer will never guess
one - does not hold. Where a token hint is genuinely wanted, it goes in
[`fuzz/dicts/`](fuzz/dicts) as plain reviewable text.

**Regressions belong in `cargo test`, not in a corpus.** When a target finds
something, fix it and pin the input as a unit test beside the code, where the
assertion names the invariant instead of leaving a hex blob to be re-derived --
`a_declared_string_count_cannot_size_an_allocation` in `mount/statmount.rs` and
`entry_ids_decode_the_way_the_kernel_writes_them` in `sync_fs/acl/posix.rs` are
both fuzz findings that now run in every `cargo test`. CI builds every target
and gives each ten seconds, from its seeds where it has them. That catches a
harness which builds but aborts on any input; it is not a regression suite.
Finding new bugs is a job for a real campaign.

### Model checking

Cross-thread protocols that cannot be settled by timing-based tests are
verified with [loom](https://docs.rs/loom), which enumerates the interleavings
the memory model permits. Models live in `loom_tests` modules beside the code
they check, and are compiled only under `--cfg loom`:

```sh
RUSTFLAGS="--cfg loom" cargo test --lib --features uring    loom_
RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
```

Covered: the SQ/CQ ring's acquire/release discipline, the wake eventfd's poke
accumulation, the graceful-drain flag publication, the inject path's refusal
after shutdown, the offload pool's lifecycle (growth, idle retirement, drop
quiescence, the self-join guard, lazy-init races), the offload completion
handoff, and the credential cache's single-flight mint. `src/sync.rs` is the
std/loom shim - outside a model build it is a
plain re-export, so none of this costs anything in a shipped binary.

When one of these fails, loom's exploration is deterministic, so re-running the
model alone reproduces the same failure at the same iteration; the models are
small enough that a fresh run reaches it quickly. Narrow to the one model and
set `LOOM_LOG` to print the interleaving that failed:

```sh
RUSTFLAGS="--cfg loom" LOOM_LOG=trace \
  cargo test --lib --features uring-fs loom_the_one
```

Two limits are worth knowing before adding a model. loom caps a model at 5
threads and explores exhaustively, so models must stay small; the heavier ones
here run under a preemption bound, which makes them bounded rather than
exhaustive proofs. And loom only models what it provides - its `mpsc` has no
sender count, so channel disconnect is not expressible, and
`Condvar::wait_timeout` never reports a timeout, so timeout-predicated branches
need an explicit `cfg(loom)` seam. Properties that fall outside those limits
are tested with real threads instead, and say so where they live.

## License

MIT - see [`LICENSE`](LICENSE).
