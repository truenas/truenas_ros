# Working in this repo

Conventions that are settled. Each one is here because it was decided once and
then re-litigated; the reasoning is included so it can be argued with on the
merits rather than rediscovered.

## The crate's charter

`libc` + `bitflags`, MSRV 1.97. A new runtime dependency is a design decision,
not a convenience - the one exception (`httparse`, for the HTTP request-head
tokenizer) is argued for in `Cargo.toml`. Dev-only crates in a separate,
self-rooted workspace (`fuzz/`) do not count against this and do not have to
hold the MSRV.

Every feature must build alone. `cargo build --no-default-features --features
<one>` is part of the gate, because the per-subsystem gates and dependency
edges only stay honest if something checks them.

Internals a fuzz target needs are exposed through a `#[cfg(feature =
"__fuzz")] pub mod fuzz` seam next to the code, never by widening real
visibility. `__fuzz` is outside `default` and `full`. See
`mount/statmount.rs`, `audit/mod.rs`, `uring_fs/mod.rs`.

## Where things are

- `src/sync_fs/` blocking syscalls; `src/uring/` the shared io_uring engine;
  `src/uring_fs/` the async fs reactor and credential broker; `src/net/` the
  reactor and server/client roles; `src/http/` the HTTP/1.1 codec on top.
- Reference trees, cited rather than recalled: **`/CODE/linux`** (the
  `truenas/linux` fork) and **`/CODE/zfs`** (the `truenas/zfs` fork). See
  *Validating against the platform* below for which revision of each is the
  one that counts.
- Two CI workflows, and they prove different things:
  - `ci.yml` - unprivileged `ubuntu-latest`. fmt, clippy, tests, the feature
    matrix, loom, and the fuzz build. The hosted runner's fd limit is orders
    of magnitude below a typical dev box's, so a test that leans on
    descriptors fails here and nowhere else; reproduce with `ulimit -Sn 1024`.
  - `qemu-test.yml` - a real TrueNAS kernel in a VM, over ssh as root, with
    ZFS datasets (`scripts/qemu-*.sh`, staged 1..6). This is the authority for
    anything privileged: ACLs on a real dataset, mount/idmap,
    `open_by_handle_at`, io_uring behaviour. Container sandboxes block file
    handles outright (escape protections), so `fhandle` work is only really
    exercised here.

## Settled decisions

Do not reopen these without a reason that is new.

- **No `fchmod` on the shutil ACL path.** A sticky ACL-bearing directory loses
  `S_ISVTX`, on purpose: on ZFS a `chmod` rewrites the ACL to match the mode,
  and under the default `aclmode=discard` it replaces it outright
  (`zfs_acl_chmod_setattr`, `zfs_acl.c`). The reasoning is at
  `copy_permissions`.
- **`query_tree` skips only what has nothing left to list** - `EACCES`,
  `EPERM`, `ENOENT`. Everything else, `ENOTDIR` included, surfaces as
  `Some(Err)`, because a partial listing that reads as complete is data loss
  for the recursive copy/delete built on it. `is_subtree_skip` documents the
  line.
- **`CredBroker::spawn` runs before any threads exist**, and the forked child's
  request loop allocates nothing. A raw `clone3` skips glibc's atfork malloc
  mitigation, so an allocation in the child can deadlock on an arena lock held
  at fork time. `drop_setid_caps` runs in the parent only.
- **Listings are ordered by `Order::ByPathBytes` and nothing else.**
  `cmp_path_bytes` must stay a total order - `sort_by` panics on an
  inconsistent comparator, and the names come from whoever owns the directory.

### The file-body reply path

- **A body's range is bounded at `begin_file_reply`, never in the submit
  path.** `offset` reaches `sqe.off_addr2` and the kernel reads it as a signed
  `loff_t`, so the bound is `offset + len <= i64::MAX` - the sum, because
  `next_offset` walks to it. Down in `submit_pump_read` `u64::MAX` is the
  *correct* idiom for a stream file with no position, which
  `cancel_owned_by_reaches_a_pump_read` reads a pipe with; a guard there breaks
  it. What the sentinel does on a regular file is
  `io_kiocb_update_pos` (`io_uring/rw.c:484-490`) substituting `f_pos` and
  `rw.c:670-671` writing it back - a read that succeeds from the wrong place.
- **A second `ReplyFile` queues, it does not shed.** One tail at a time is
  structural, but the first response's head and `Content-Length` are already on
  the wire when the second arrives, so closing destroys the request that did
  nothing wrong. It rides the same diversion as every other PDU, in one list
  (`PendingItem`) so ordering survives.
- **The tail advance takes the buffer, not a length.**
  `Connection::advance_file_tail(buf)` derives the count from `buf.len()`, so
  the requested length is not in scope and cannot be used by mistake. A short
  read continues from the offset it reached; short reads are ordinary on ZFS,
  where every ring read is an io-wq punt.
- **A full op table parks the read; it does not close the connection.** A
  missing chunk buffer already waits for a flush, so a missing op slot waits
  too (`Server::parked_tails`, re-driven once per completing fs op).
- **`op_free` is one unpartitioned list, and partitioning it is not the fix.**
  The table is `fs_ops + pool_size`. Handler ops cannot be starved by bodies:
  `FileTail::reading` gates body reads to one per connection and connections
  never exceed `pool_size`, so at least `fs_ops` slots always remain -
  pigeonhole, not arithmetic. The other direction is what parking handles.
- **The `fs_ops + pool_size <= MAX_POOL` bound is about field *width*.** An
  op-slot index is packed into the 24-bit `user_data` slot field
  (`user_data::SLOT_MASK`); `TAG_FS_DOMAIN` keeping the two tag vocabularies
  disjoint is true and irrelevant to it.

### The offload pool

- **`WorkerPool::drop` waits `SHUTDOWN_DETACH_AFTER` and then detaches.**
  Detaching is sound because `Job` is `Box<dyn FnOnce() + Send>` and therefore
  `'static` - no job holds a borrow of what the dropper frees - and each worker
  owns an `Arc<PoolShared>`. The wait buys quiescence, not soundness.
  **Shutdown is not the reason it is bounded**: FUSE (`fs/fuse/dev.c:212`) and
  sunrpc (`net/sunrpc/sched.c:346`) wait `TASK_KILLABLE`, so a supervisor's
  SIGKILL reaps a wedged worker at process exit. The case with no backstop is
  mid-run - `Drop` runs wherever the last handle falls, including on another
  pool's worker or a request thread.
- **`ON_POOL_WORKER` carries the pool's identity, not a bare flag.** A bare
  "am I a worker" leaks the self-join exemption to every pool in the process.

### Where a poisoned lock fails closed

- **`SingleFlight`'s `get_or_try_init` returning `EIO` on a poisoned map is the
  whole story.** All three of its map acquisitions use `?`, so a poisoned
  `live` fails every `acquire` - including cache hits, since the fast path sits
  behind that lock. There is no state where invalidation is skipped *and* a
  stale identity is still served.

## Validating against the platform

**Any change under `src/uring/`, `src/uring_fs/`, `src/sync_fs/` or
`src/mount/` must be checked against the kernel and OpenZFS the product
actually ships, not against upstream, a man page, or recollection.** These
modules are almost entirely syscall behaviour and on-disk semantics; a claim
about either is wrong often enough that an unchecked one is a defect waiting
to be found by someone else.

The floor is **Linux 6.18** (`README.md`, `src/lib.rs`). Behaviour that needs
a later point release is called out where it is relied on (`unix_peercred`
needs 6.18.16 or later) and is probed or gated rather than assumed.
A finding that only reproduces below the floor is not a finding.

Which revisions count is not a constant to memorise here, because it moves.
The authority is **`.github/trains.json` in the ZFS fork**, which pairs each
ZFS branch with the kernel release it is built and tested against; the same
pairing drives what this repo's QEMU job boots (`train-for-ref.sh` ->
`tn-fetch-debs.sh` -> the `<train>-nightly` release). At the time of writing
that resolves to Linux **6.18.42** (`truenas/linux`) and OpenZFS **2.4.3**
(`truenas/zfs-2.4-release`), which is what the trees under `/CODE` are checked
out at.

So, in practice:

- Cite kernel behaviour by function and file from `/CODE/linux` at the paired
  revision - `handle_privileged_root` in `security/commoncap.c`, not "the
  kernel recomputes caps on exec".
- Cite ZFS behaviour the same way from `/CODE/zfs` - `zfs_acl_chmod_setattr`
  in `module/os/linux/zfs/zfs_acl.c`, and check the property default in
  `module/zcommon/zfs_prop.c` rather than assuming the documented one.
- Confirm the tree you are reading is the paired one (`git log -1`) before
  citing it. A fix present upstream and absent in the fork is not shipped, and
  the reverse also happens.
- Anything privileged or ZFS-backed is proven in the QEMU job, not on a dev
  box. A local pass on tmpfs says nothing about `aclmode`, mount propagation,
  or `open_by_handle_at`.

## Concurrency and loom

Cross-thread protocols get a loom model rather than a timing-based test. Models
live in `loom_tests` modules beside the code, are named `loom_*` so one filter
catches them, and compile only under `--cfg loom` - production builds are
byte-identical, since `src/sync.rs` is a plain re-export of `std` otherwise.

Three limits shape every model, and they are documented at `src/sync.rs`:

- **No `OnceLock`.** Use the `OnceCell` shim's closure-taking `with`.
- **`wait_timeout` never times out.** Loom delegates it to `wait` and hardcodes
  `timed_out() == false`, so a branch predicated on a timeout is unreachable
  and needs an explicit `cfg(loom)` seam.
- **No clocks.** `Instant` is not modelled; run those paths with the interval
  at zero and say so.

`loom::MAX_THREADS` is 5 including main, so models are deliberately tiny, and
`preemption_bound` keeps them to seconds rather than minutes. Every
`#[cfg(test)]` module under `src/uring*/` must be `#[cfg(all(test,
not(loom)))]`, or ordinary tests break the loom build on `thread::sleep` and
friends.

## Fuzzing

**Do not check a corpus into the repo.** `fuzz/corpus/` is in cargo-fuzz's own
scaffolded `.gitignore` and belongs there. If you are about to add seed files,
read this first.

`fuzz/corpus/http_*` is the standing exception: tracked, and owned with the
HTTP codec rather than by this rule. Leave it alone - do not delete those
seeds, and do not extend the pattern to a new target without agreement.

- Seed files are opaque in review. Git cannot diff them, so the choice becomes
  a `.gitattributes` `binary` marking that hides them entirely, or leaving them
  as text and having `core.autocrlf` corrupt any seed containing CRLF - an
  HTTP chunked terminator, for instance.
- They encode host byte order. Several of these formats use native-endian
  magics, so a seed written on x86 is silently rejected on a big-endian host
  and covers nothing.
- They drift. Change a wire format and the seeds still load; they just stop
  reaching the code they were written for, and nothing fails.
- They do not buy much. Measured over equal 45-second runs, seeds moved
  coverage 0-5% (`statmount_parse` 457 vs 448, `configfile_ini` 1050 vs 998,
  `acl_nfs4` and `tree_cursor` dead level). libFuzzer recovers a 4-byte magic
  from comparison interception in seconds, so "a fuzzer will never guess
  `TnCk`" is not a real argument.

Instead:

- **Regressions go in `cargo test`.** When a target finds a bug, fix it and pin
  the input as a unit test beside the code, where the assertion names the
  invariant. See `a_declared_string_count_cannot_size_an_allocation`
  (`mount/statmount.rs`) and `entry_ids_decode_the_way_the_kernel_writes_them`
  (`sync_fs/acl/posix.rs`) - both fuzz findings, both now running in every
  `cargo test` instead of sitting in a blob.
- **Token hints go in `fuzz/dicts/*.dict`** - plain text, reviewable. Note
  that libFuzzer's dictionary parser understands only `\\`, `\"` and `\xAB`.
  `\r` and `\n` are a parse error, and the dictionary is then silently ignored.
- **CI builds every target and smoke-runs each for ten seconds from empty.**
  That catches a harness that builds but aborts on any input. It is not a
  regression suite and is not expected to reproduce anything specific.

Targets assert properties - round-trip idempotence, total ordering, injection
safety, a privilege bound - not merely the absence of a panic. A target that
cannot fail is worth nothing: prove a new one bites by breaking the code it
guards, then revert.

## Tests

Nothing may exhaust a **process-wide** resource. `cargo test` runs a binary's
tests as threads in one process, so a test that fills the fd table starves
whatever else is running and fails an unrelated test - a different one each
run, depending on the limit. This happened; provoke failures locally instead
(swap a directory for a file to get `ENOTDIR`, and so on).

A test that silently skips is worse than no test. Where a fixture may be
absent, gate the skip behind a `TRUENAS_ROS_REQUIRE_*` variable and **arm that
variable in CI**, so a mis-provisioned runner turns red rather than passing
green having tested nothing.

Prove a test bites before trusting it. Break the thing it guards, watch it
fail, restore. This applies to loom models too - the negative control is the
evidence that the model is checking anything.

Know what your environment hides. Running as **root** means DAC never denies
anything, so an `EACCES` path cannot be provoked directly - go through a
brokered unprivileged personality, or pin the predicate as a unit test. A
generous **fd limit** hides descriptor leaks that fail at the runner's 1024. A
**container** blocks `open_by_handle_at` outright. A test that returns early on
any of these is invisible, so make the skip loud or gate it on a
`TRUENAS_ROS_REQUIRE_*` variable.

## Reviews

External reviews land in `/CODE/truenas_ros-review-<date>/` and are re-run
after merge, so every finding above LOW needs a disposition that survives the
next pass: fixed, or engaged in the code with the reasoning written down.
A finding that is merely true-but-declined comes back.

Check findings against the source before acting. Reviews are often right about
the defect and wrong about the fix - one patch here would have made
`CredBroker::spawn` fatal for the unprivileged callers its own contract
allows, because the reasoning assumed an unprivileged process has an empty
capability bounding set, and it does not. Verify the claim, verify the patch,
and say which parts you changed.

Point a re-review at the current branch. A review run against an older base
re-reports things already fixed, which costs more time than it saves.

## Commits

Terse subject, body wrapped at **72 columns**, no line longer. No attribution
trailers of any kind: no `Co-Authored-By`, no "generated with", no tool or
model names. Nothing in the history carries them and nothing should start.

Say what changed and why it was wrong before, in the imperative. Do not write
commentary about the review process, the agent, or how the problem was found
unless it changes what a reader should do.

One commit per logical change. Unrelated fixes to different subsystems are
separate commits even when they ship together.

## Comments

Write for the next person changing the code, not to defend the last change.

- No back-compatibility apparatus for consumers that do not exist. This library
  has no external consumers yet; a format does not need two accepted versions,
  and a doc comment should not claim that tokens "written by an older build"
  still decode.
- Do not narrate past mistakes. "This is deliberate, not an oversight" and
  "the previous behaviour was X" are noise; state the constraint and the
  consequence, and let that stand on its own.
- Do keep a warning that stops a plausible wrong "simplification" - those read
  as forward-looking and earn their space. `is_subtree_skip` in
  `uring_fs/query_tree.rs` is the shape to copy.

Cite sources rather than asserting behaviour. Kernel and ZFS claims are checked
against the trees in `/CODE/linux` and `/CODE/zfs` and cited by function or
`file:line`, because "the kernel does X" is exactly the kind of claim that is
wrong often enough to matter.

## The gate

Before reporting anything done:

```sh
cargo fmt --all --check
cargo fmt --all --check --manifest-path fuzz/Cargo.toml   # its own workspace
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features --no-fail-fast
RUSTFLAGS="--cfg loom" cargo test --lib --features uring    loom_
RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
RUSTFLAGS="--cfg loom" cargo test --lib --features http     loom_
(cd fuzz && cargo +nightly fuzz build)
```

Report failures with their output. A skipped step is a skipped step; say so.
