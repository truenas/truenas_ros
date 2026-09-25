# Working in this repo

Settled conventions. Each carries its reason, so it can be argued with on
the merits rather than rediscovered; the full reasoning lives at the code
each entry names.

## The crate's charter

`libc` + `bitflags`, MSRV 1.98.1. A new runtime dependency is a design
decision, not a convenience. There are two optional exceptions, each argued
for in `Cargo.toml` and pulled only by the feature that needs it:
`httparse` (the HTTP head tokenizer, for the `http` codec and the `ws` `101`
head) and `openssl` (SHA-1 + base64 for the `ws` handshake's RFC 6455 §1.3
accept digest, off unless `ws` is on). The self-rooted workspaces
(`fuzz/`, and the shipping `truenas_api_client/`) do not count against this
and do not have to hold the MSRV.

Every feature must build alone, and the gate checks it with **clippy over
`--all-targets`**: dead code behind a feature only becomes dead once the
tests are compiled, so `--all-features` and a per-feature `build` both pass
over it.

Internals a fuzz target needs are exposed through a `#[cfg(feature =
"__fuzz")] pub mod fuzz` seam next to the code, never by widening real
visibility. `__fuzz` is outside `default` and `full`. See
`mount/statmount.rs`, `audit/mod.rs`, `uring_fs/mod.rs`.

**The generic layers are protocol-neutral.** `net`, `uring` and `uring_fs`
serve more than one protocol - object storage over HTTP, and NFS. A size that
follows from one protocol's framing (a window, a lease depth, a buffer
size) is a `ServerConfig` field with a neutral default, and the codec states
its own figure for it (`HttpConfig::recv_buffer_bytes`,
`HttpConfig::receipt_window_bytes`). Do not hard-code a consumer's shape
below its codec.

## Where things are

- `src/sync_fs/` blocking syscalls; `src/uring/` the shared io_uring engine;
  `src/uring_fs/` the async fs reactor and credential broker; `src/net/` the
  reactor and server/client roles; `src/http/` the HTTP/1.1 codec on top;
  `src/ws/` the RFC 6455 client WebSocket codec (checked against
  `/CODE/libwebsockets`).
- Reference trees, cited rather than recalled: **`/CODE/linux`** (the
  `truenas/linux` fork) and **`/CODE/zfs`** (the `truenas/zfs` fork). See
  *Validating against the platform* for which revision counts.
- Two CI workflows, proving different things:
  - `ci.yml` - unprivileged `ubuntu-latest`: fmt, clippy, tests (debug and
    release), the feature matrix, loom, the fuzz build. Its fd limit is far
    below a dev box's, so a test that leans on descriptors fails only
    there; reproduce with `ulimit -Sn 1024`.
  - `qemu-test.yml` - a real TrueNAS kernel in a VM, as root, with ZFS
    datasets (`scripts/qemu-*.sh`). The authority for anything privileged:
    ACLs on a real dataset, mount/idmap, `open_by_handle_at`, io_uring
    behaviour. Containers block file handles outright, so `fhandle` work is
    only exercised here.

## Settled decisions

Do not reopen these without a reason that is new.

- **No `fchmod` on the shutil ACL path.** A sticky ACL-bearing directory
  loses `S_ISVTX`, on purpose: on ZFS a `chmod` rewrites the ACL to match
  the mode, and under the default `aclmode=discard` replaces it outright
  (`zfs_acl_chmod_setattr`). The reasoning is at `copy_permissions`.
- **Metadata calls are fd-based, and `O_PATH` is an error, not a case to
  work around.** `fchmod`, `fchown`, `futimens` and the `f*xattr` family
  take a real descriptor, so no name is resolved twice. An `O_PATH` handle
  gets `EBADF` from `fchmod(2)`, `fsetxattr(2)` and `setxattrat(2)`'s
  empty-path form. **Two workarounds are forbidden** (both tried and
  reverted): `fchmodat2(2)` with `AT_EMPTY_PATH` on an `O_PATH` pin, and
  `setxattr("/proc/self/fd/N", ...)`. They carry only the *mode*; the ACL
  and xattrs cannot travel, so the copy reports `Ok` having dropped the
  access control. `fchmod_fd` screens for `O_PATH` and says why.
  - `fchownat` and `utimensat` with `AT_EMPTY_PATH` *are* fine on an
    `O_PATH` handle, and are the only way to touch a symlink, which has no
    mode or xattrs to lose; `make_symlink_meta` is correct. The rule is
    about getting around a call that *refused* the handle - only chmod and
    the xattr family.
  - `copytree` opens a FIFO `O_RDONLY|O_NONBLOCK` and carries its full
    metadata, and **refuses the mode of a socket or device node** (a socket
    answers `ENXIO` to every open; a device open runs its driver). Owner
    and timestamps still ride the `AT_EMPTY_PATH` pair. The refusal goes
    through `guard`: under `raise_error: false` the copy continues and the
    node keeps its creation hold. Pinned by
    `a_socket_is_refused_rather_than_moded_through_a_path`,
    `a_socket_carries_everything_but_its_mode` and
    `a_refused_special_type_is_swallowed_when_errors_are_not_raised`.
- **`query_tree` skips only what has nothing left to list** - `EACCES`,
  `EPERM`, `ENOENT`. Everything else, `ENOTDIR` included, surfaces as
  `Some(Err)`: a partial listing that reads as complete is data loss for the
  recursive copy/delete built on it. `is_subtree_skip` documents the line.
- **`CredBroker::spawn` runs before any threads exist**, and the forked
  child's request loop allocates nothing: a raw `clone3` skips glibc's
  atfork malloc mitigation, so a child allocation can deadlock on an arena
  lock held at fork time. `drop_setid_caps` runs in the parent only.
- **Listings are ordered by `Order::ByPathBytes` and nothing else.**
  `cmp_path_bytes` must stay a total order - `sort_by` panics on an
  inconsistent comparator, and the names come from whoever owns the
  directory.

### The file-body reply path

- **A body's range is bounded at `begin_file_reply`, never in the submit
  path.** The kernel reads `offset` as a signed `loff_t`, so the bound is
  `offset + len <= i64::MAX`. In `submit_pump_read`, `u64::MAX` is the
  correct idiom for a stream file with no position
  (`cancel_owned_by_reaches_a_pump_read`); on a regular file the sentinel
  reads from `f_pos` (`io_kiocb_update_pos`, `io_uring/rw.c`) - a read
  that succeeds from the wrong place.
- **A second `ReplyFile` queues; it does not shed.** The first response's
  head is already on the wire, so closing destroys a request that did
  nothing wrong. It rides the same diversion as every other PDU, in one
  list (`PendingItem`), so ordering survives.
- **The tail advance takes the buffer, not a length.**
  `Connection::advance_file_tail(buf)` derives the count from `buf.len()`.
  A short read continues from where it stopped; short reads are ordinary on
  ZFS, where every ring read is an io-wq punt.
- **A full op table parks a file-body read and refuses every handler op.**
  A body read belongs to a response whose head is on the wire, so it waits
  (`Server::parked_tails`, re-driven at each fs completion). A handler op,
  leased writes included, is refused with a marked `EBUSY`. Do not park
  leased writes alone: waiting writes take each slot as it frees, so the
  table stays full and the handler's other ops - the open before a body,
  the fsync and rename after it - are refused in their place, after the
  body was written.
- **`op_free` is one unpartitioned list.** The table is `fs_ops +
  pool_size`, and bodies cannot starve handler ops: `FileTail::reading`
  allows one body read per connection and connections never exceed
  `pool_size` - pigeonhole. The other direction is what parking handles.
  - Wall-clock holds - timers, and an `Allow` open's two slots charged as
    one count - are capped per owner at `max_in_flight_requests`
    (`FsCore::set_timer_cap`); a smaller constant would couple this crate
    to a consumer's pipelining. A retraction returns the headroom at once
    and the slot at its CQE, the retiring slots are counted (`WallClock`),
    and an arm is refused once armed + retiring reaches twice the cap.
  - **Both classes that park on `retiring` must be counted**: a retracted
    timer, and an `Allow` pair whose open answered while its guard slot was
    parked. A screen that counts one reads as correct and is not.
  - The table is not resized for holds: they spend the handler budget their
    owner already has.
- **A host refusal is delivered, not dropped.** Every submit screen's
  refusal - full table, two-slot charge, wall-clock cap, swept owner,
  staging failure - goes through one queue (`FsCore::refuse`), drained
  where finished offloads deliver: it is an offload that resolved at submit
  time. Capacity refusals arrive marked with the payload handed back; a
  swept owner's arrive as an unmarked `ECANCELED`. One pass delivers only
  what was queued when it began, so a re-arming callback cannot spin the
  ring. **The drain is unconditional in both hosts** - it is the queue's
  only consumer - so `Server::on_wake` gates the re-arm and injection
  drains, never `drain_fs_offloads`.
- **The `fs_ops + pool_size <= MAX_POOL` bound is about field width**: an
  op-slot index is packed into the 24-bit `user_data` slot field
  (`user_data::SLOT_MASK`).
- **Dropping a stranded body drops everything queued behind it.** A
  response's association with its request is its position, so releasing
  the followers answers the wrong requests. `drop_queued_file_reply`
  returns the discarded items' `outstanding` charges by hand; the
  read-ahead gate, the idle timeout and the drain all read that counter.
- **A close-carrying reply stops the recv gate when the handler returns
  it**, not when its body reaches the wire. A deferred `ReplyFile{close}`
  cannot arm `close_on_flush` (the dry checks would belong to the body
  ahead of it), so `Connection::deferred_close` carries the verdict until
  install.
- **`FileTail::parked` is the parked list's dedup key: set on push, cleared
  on pop, nowhere else.** `reading` tracks the read in flight. Clearing
  `parked` on submit lets one connection be queued twice, unbounding the
  list. `redrive_parked_tail` checks for a free slot *before* popping,
  because a cancel completion and a stale-generation miss free nothing.
- **Chunk buffers belong to the ring, not to a connection.** They are
  provided buffers on their own group (`BGID_FILE_BODY`), picked at
  completion and returned when the chunk reaches the peer; a connection
  holds a count (`chunk_out`, capped at `FILE_TAIL_BUFS`) and no storage,
  so memory tracks bodies in flight
  (`serving_file_bodies_does_not_allocate_per_connection`).
- **A provided buffer serves a file read.** `IORING_OP_READV` supports
  `buffer_select` with a single iovec (`io_iov_buffer_select_prep`), and
  the destination arrives with `IORING_CQE_F_BUFFER` before the chunk is
  queued for send.
- **The buffer id rides out on `SendProgress`**, because only the reactor
  holds the pool. Teardown drains what is still queued
  (`drain_pooled_send_bids` in `free_slot`): a buffer never handed back can
  be neither reissued nor freed.
- **The send-backlog check covers `FILE_TAIL_BUFS` chunks** - every chunk
  buffer a connection has - and bounds one body's chunks only. Heads,
  released diversions and earlier pipelined bodies scale with
  `max_in_flight_requests`.

### The recv buffer pool

- **A provided buffer cannot be reserved at submit time.** The kernel picks
  one when the op *completes* (`io_ring_buffer_select`), so gating a submit
  on `lent < entries` sheds the fifth of five concurrent connections.
  Shortage is `-ENOBUFS` on the completion and is handled only there:
  `recv_buffer_shortage` grows the pool and re-pumps, and on the file-body
  ring `on_pump_read` does the same - a dry ring is pressure, not a failed
  transfer (`a_burst_of_file_bodies_grows_the_ring_instead_of_shedding`).
  Growth doubles.
  - When growth cannot succeed - the ring at its registered bound, every
    buffer lent - the recv side follows `recv_shortage_retry`: park and
    retry on a standalone `TIMEOUT` (the default; TCP slows the peer), or
    `None` to fall back to an owned buffer. One live timer per connection
    (`recv_retry_armed`), and the retry re-pumps, so a still-dry pool parks
    again. The pump path always falls back to owned buffers: its shortage
    is the send side's to relieve.
- **Supply runs ahead of demand.** A pool starts with
  `buf_pool_initial_bytes` of buffers and grows a step on the loan that
  leaves a quarter free, so a burst does not pay a failed read per step. A
  step doubles the pool but adds at most `buf_pool_max_step_bytes`, so past
  its starting budget a pool holds at most 4/3 of its peak loans plus one
  step. Growth on a free count is fine; *gating* on one is not (above).
  Tests of the `-ENOBUFS` path lend through the ring (`kernel_picks`),
  because a pool's own loan grows ahead of the shortage they need.
- **`post` writes a descriptor field by field and never `resv`.** Entry
  zero's `resv` is the ring's published tail, and the kernel's only
  emptiness test is `tail == head`; a whole-struct write zeroes the tail
  and the kernel takes stale descriptors as recv destinations. Pinned by
  `a_post_never_touches_the_published_tail`, with a loom model of the
  tail's release/acquire pairing
  (`loom_a_descriptor_is_published_before_the_tail_that_names_it`).
- **Every completion carrying `IORING_CQE_F_BUFFER` owes its id back on
  every exit path**, EOF included: an EOF read completes `res = 0` with the
  flag set, so `on_pump_read`'s early returns call
  `Reactor::requeue_body_bid` (`a_truncated_body_close_returns_its_buffer`).
  A cancelled *socket* read carries no buffer, because a socket is
  pollable; a regular-file `READV` never is (`io_file_can_poll`), so its
  buffer is committed at selection and a cancelled pump read *does* carry
  one. Do not cite the socket case to skip a requeue.
- **A short leased write surfaces as `Err(EIO)`, never `Ok(n)`.** ZFS
  returns partial writes as successes (`zfs_write`), and by then the source
  buffer is back in the pool, so a retry would write another connection's
  bytes. The copy path stays retryable (`into_bufs` hands the source back);
  the asymmetry is documented on `pwritev2_from`.
- **Rings are registered at their demand bound.** A ring cannot be
  resized after registration, so `ring_entries` sizes it to the most
  buffers demand can hold at once - `pool_size x (recv_lease_depth + 1)`
  for recv, `pool_size x FILE_TAIL_BUFS` for file bodies - clamped to the
  kernel's 32768, and the pool grows to that and no further
  (`BufPool::limit`); `buf_pool_max_bytes` lowers the limit. Descriptor
  slots are 16 bytes of locked memory; buffers are allocated on demand.
- **A pool buffer's size is a free parameter** (`recv_buffer_bytes`),
  because a message that outgrows one is promoted (`RecvBuf::promote_for`:
  one copy bounded by the buffer) rather than refused. Size it so a
  codec's streamed window fits with its framing and a pipelined remainder;
  otherwise every window goes to placement and the pool carries only
  heads.
- **The ring is a conveyor of descriptors, not a slab.** Each descriptor
  carries its own address, so buffers are allocated and posted on demand
  (SPDK's `uring_sock_group_populate_buf_ring`). A buffer is freed only in
  `BufRing::release`, after the kernel has handed it back - a per-buffer
  question, where a slab would need a whole-pool proof that nothing is lent.
  Buffers are allocated uninitialized: every reader stops at the bytes the
  kernel wrote (`post`).
- **Shrinking lowers the target; buffers follow as they cycle.** A posted
  descriptor cannot be retracted, so surplus is given up in `release`, one
  buffer per cycle. A pool that goes silent keeps its residue, bounded by
  the ring.
- **Gathering a message out of several buffers does not transfer here**
  (SPDK's `recv_stream`): a head scan needs contiguous bytes, and the join
  is the copy the ring exists to avoid. SPDK's dry-ring fallback does
  transfer - `set_recv_owned`.
- **A pooled connection does not place a body the pool can serve** - one
  its held claim covers, or, with no claim, one that fits a pool buffer.
  Against a claim the second buffer is churn; without one it forfeits the
  buffer the read gets free for one `pwritev2_from` must copy. The
  no-claim case is every window after the first in a codec frame longer
  than a window. `frame_step` is state-free, so `enact_frame_step`
  downgrades `place`. Pinned by
  `a_streamed_upload_does_not_allocate_per_window` and
  `a_streamed_put_at_oversized_http_chunks_still_does_not_copy`.
- **A placed body must not also take a pool buffer.** The kernel clamps a
  selecting read to the buffer it picked, so an exact read longer than one
  completes short and the connection dies `TruncatedMessage`. Reachable
  from a `header_len: 0` frame - every message after the first in a
  streaming codec (`a_placed_body_never_takes_a_pool_buffer`).
- **Teardown forfeits the claim; it does not wait for the buffer to
  empty.** `ConnTable::forfeit_recv_claim` runs in `free_slot`, before
  `table.free`; `release_recv_buf`'s refusal while bytes are buffered is
  for the serving path only.
- **A failed drain leaks the pool along with the connection buffers.** An
  op still in flight names a registered buffer by index, so freeing it
  hands the kernel freed pages. `drain_or_leak` forgets the `BufPool`.

### Leased writes

A streamed window is written to a file straight out of its recv buffer.

- **A deferred stream open must release the withheld `100 Continue` on
  resume**, by `resume()` and by a redrive that returns `Continue`: an
  expecting client sends nothing until it arrives
  (`StreamPark::expect_interim`,
  `a_deferred_stream_open_still_sends_the_interim`).
- **The write borrows the recv buffer; the claim goes to its writes, not
  the connection.** `deliver_one` consumes the message when the handler
  returns, so every range a delivery submits shares one `Arc<LeaseHold>`
  and `Arc::into_inner` at reap surfaces the id from the last completion.
  `RecvBuf::drain_front` takes the claim without releasing it; the id rides
  `FsDone::take_recv_lease` to the pool. Release and forfeit refuse while
  leased: two owners releasing one id re-posts a buffer a write's DMA may
  still read.
- **`defer_stream` exists because `defer` copies the body into the park.**
  A streamed window resumed by `HttpStreamDeferred::resume` never re-runs
  the handler, so the park keeps the head only
  (`a_streamed_put_writes_windows_without_copying_them`).
- **Pipelined ingest is a handler pattern, not a reactor mode.** A
  streaming handler floats each window's write with `Continue` and brakes
  with `defer_stream` at its own depth; stopping the reads is the whole
  backpressure mechanism (SPDK's shape: `module/sock/uring/uring.c`
  re-arms on `-ENOBUFS`, `lib/nvmf/tcp.c` caps with `resource_count`). The
  cap exists for the tail - a txg stall would otherwise eat the op table
  and run the ring to its wall. At `Stage::End` the park is a plain
  `defer`, answered from the last completion.
- **`recv_lease_depth` is why the recv ring registers past one slot per
  connection.** A claim outlives its message - a leased write until its
  CQE, a leased job until its completion is taken, a `LeasedWindow` until
  spent or dropped - so a connection holds its claims plus the one
  arriving. Past the pool's bound the next read parks until a buffer comes
  home, or with `recv_shortage_retry: None` falls back to owned buffers
  permanently (`a_pipelined_put_overlaps_writes_with_arrivals` runs with
  `None` so the fallback shows as allocations;
  `a_held_window_is_digested_from_the_previous_jobs_completion`). A
  handler that holds windows until more of the stream arrives has to stay
  inside its share, or its parked read waits on a buffer it holds. The
  default is a few writes deep; a consumer that holds more - gathering
  windows into record-sized writes (`pwritev2_leased`) - sets its own.
- **A `Content-Length` body streams only above one window, and its End
  rides the delivery that exhausts the length.** No wire byte remains to
  frame an End from and the reactor refuses a zero-length message, so the
  exhausting window dispatches End inline on `Continue`, or from the resume
  when it parked (restore phase `StreamDone`). Bytes behind the tail are
  the next request's (`pipelined_known_length_streams_do_not_desync`).
- **A known-length window is a full `STREAM_WINDOW`, however little is
  buffered.** `known_step` answers `More` on an empty buffer, which draws
  the rest from the pool zero-copy; bounding windows to the buffered bytes
  multiplies deliveries, wakes and writes. `remaining` keeps the next
  request out of the last window (`a_known_length_put_streams_without_copying`,
  `a_known_length_body_streams_above_one_window`).

### The two receive clocks

- **Two clocks, because neither can do the other's job.** `request_timeout`
  is re-armed by every recv: it asks whether the peer is still there, and
  is not a rate floor. Alone it leaves `pool_size` unauthenticated peers
  holding every slot at a byte per period. `validate` refuses
  `max_receipt_time <= request_timeout`.
- **The budget bounds one message, not one connection.** A streamed body
  makes each window a message, so any size is admitted at a floor of one
  window per `max_receipt_time`; a spliced body earns a budget per
  `receipt_window_bytes` moved.
- **Armed in `submit_recv` on the first non-idle read, retired in
  `deliver_one`, never cancelled in between.** A `More` scan re-enters
  `submit_recv` per chunk, so cancel-then-arm would restart the budget on
  every trickle (`a_chunk_scan_budget_is_not_restarted_by_progress`).
- **`close_conn` cancels every standalone timer, and there are three**:
  `RecvRetry`, `SpliceDeadline`, `ReceiptDeadline`. Nothing else reaps
  them, and one left armed holds `inflight` up until it expires. A fourth
  of that shape has to be added to `close_conn` by hand.
- **A spliced body arms and retires its budget in `submit_splice_recv` /
  `on_splice_recv_complete`**, since that path has neither `submit_recv`
  nor `deliver_one`. A budget left armed reaps a connection for finishing
  on time and suppresses later budgets
  (`the_receipt_budget_bounds_a_spliced_body_and_ends_with_it`).
- **Only a wire delivery retires it** (`Delivery::FromWire`). A
  redelivery's budget was retired at its first delivery; the one armed now
  belongs to a later message
  (`a_redelivery_does_not_retire_the_next_message_budget`).
- **Retiring at delivery keeps it a bound on receipt**: a
  `Response::Defer` may run arbitrarily long.
- **"Idle" is the framer's verdict, not `buffered() == 0`.** Between a
  streaming codec's windows the buffer is empty mid-request; read off
  `buffered()`, such a connection gets `idle_timeout` and no receipt
  budget. `Framing::MoreInMessage` says a message is under way;
  `Phase::Head` and `Phase::Parked` do not answer it, because handling is
  not clocked (`a_stalled_streamed_upload_is_reaped_mid_body`).

### Delivering a message

- **A redelivery owns neither the frame nor the budget.**
  `Deferred::redeliver` re-enters `deliver_one` with an *empty* frame; the
  pump may already have framed the next pipelined request, and delivering
  against that frame slices out of range and lets `consume` eat the next
  header. The `Delivery` split keeps them apart. The in-tree http codec
  never reaches it, so the control is a framer that frames what is buffered
  (`a_redelivery_does_not_take_the_read_ahead_frame`).

### The offload pool

- **`WorkerPool::drop` waits `SHUTDOWN_DETACH_AFTER` in total, then
  detaches.** The bound is one deadline (`ShutdownClock`); re-passing the
  timeout to each `wait_timeout` would make it `workers x` the timeout, and
  a spurious wake would remove it. Detaching is sound because a `Job` is
  `'static` and each worker owns an `Arc<PoolShared>`. It is bounded for
  the mid-run case - `Drop` runs wherever the last handle falls - not for
  shutdown, where a supervisor's SIGKILL reaps a worker waiting
  `TASK_KILLABLE` (FUSE, sunrpc).
- **`ON_POOL_WORKER` carries the pool's identity, not a bare flag**, or the
  self-join exemption leaks to every pool in the process.

### Where a poisoned lock fails closed

- **`SingleFlight::get_or_try_init` fails closed on a poisoned map because
  of where its first map acquisition sits.** That lock
  (`map_err(|_| Errno::EIO)?`) precedes the cache-hit fast path, so a
  poisoned map fails every `acquire` before a stale identity is served.
  Poison handling is not uniform - the failed mint's eviction,
  `invalidate`, `clear` and `len` swallow it. **Hoisting the fast path
  above that lock removes the guarantee.**

## Validating against the platform

**Any change under `src/uring/`, `src/uring_fs/`, `src/sync_fs/` or
`src/mount/` must be checked against the kernel and OpenZFS the product
ships** - not upstream, a man page, or recollection.

The floor is **Linux 6.18** (`README.md`, `src/lib.rs`). Behaviour that
needs a later point release is probed or gated where it is relied on
(`unix_peercred` needs 6.18.16). A finding that only reproduces below the
floor is not a finding.

The revisions that count are set by **`.github/trains.json` in the ZFS
fork**, which pairs each ZFS branch with its kernel; the same pairing picks
what the QEMU job boots (`train-for-ref.sh` -> `tn-fetch-debs.sh`). The
trees under `/CODE` track it.

- Cite kernel behaviour by function and file from `/CODE/linux` -
  `handle_privileged_root` in `security/commoncap.c`, not "the kernel
  recomputes caps on exec".
- Cite ZFS the same way from `/CODE/zfs`, and read property defaults from
  `module/zcommon/zfs_prop.c` rather than the documentation.
- Confirm the tree is at the paired revision (`git log -1`) before citing
  it. A fix upstream and absent in the fork is not shipped.
- Anything privileged or ZFS-backed is proven in the QEMU job. A tmpfs pass
  says nothing about `aclmode`, mount propagation or `open_by_handle_at`.

## Concurrency and loom

Cross-thread protocols get a loom model, not a timing-based test. Models
live in `loom_tests` modules beside the code, are named `loom_*`, and
compile only under `--cfg loom`; `src/sync.rs` is a plain re-export of
`std` otherwise.

**A model drives the code that ships, not a copy of its ordering.** Where
production and model differ only in which cell is touched (`ring.rs`'s
index words: mmap pointers in production, owned atomics in a model), the
`cfg` picks the cell and the ordering has one spelling
(`load_acquire`/`store_release`). Where the writer lives in another module,
the pairing moves to where both reach it
(`LoopShared::request_graceful`/`graceful_requested`, `finish_offload`). A
model with its own copy stays green when the shipping half is weakened -
the control for any model is to weaken the production ordering and watch it
fail.

Three limits, documented at `src/sync.rs`:

- **No `OnceLock`.** Use the `OnceCell` shim's closure-taking `with`.
- **`wait_timeout` never times out**, so a timeout branch needs an explicit
  `cfg(loom)` seam.
- **No clocks.** Run those paths with the interval at zero and say so.

`loom::MAX_THREADS` is 5 including main, so models are tiny and
`preemption_bound` keeps them to seconds. A `#[cfg(test)]` module that
builds a ring or drives real threads must be `#[cfg(all(test,
not(loom)))]` - `src/net/` as much as `src/uring*/`.

Types shared with the engine come from `crate::sync`, never `std::sync`: a
`std::sync::Arc` holding a `crate::sync::Arc` value is a distinct type under
`--cfg loom`. The loom lane is one `--all-features` invocation that asserts
the model **count**, because a filter that matches nothing exits 0.

## Fuzzing

**Do not check a corpus into the repo.** `fuzz/corpus/` is in cargo-fuzz's
scaffolded `.gitignore`. The standing exception is `fuzz/corpus/http_*`,
owned with the HTTP codec: leave those seeds alone and do not extend the
pattern without agreement. Seeds are opaque in review (and `core.autocrlf`
corrupts CRLF), encode host byte order, drift silently when a format
changes, and move coverage only a few percent - libFuzzer recovers a
4-byte magic from comparison interception in seconds.

Instead:

- **Regressions go in `cargo test`**, pinned beside the code where the
  assertion names the invariant
  (`a_declared_string_count_cannot_size_an_allocation`,
  `entry_ids_decode_the_way_the_kernel_writes_them`).
- **Token hints go in `fuzz/dicts/*.dict`.** The parser understands only
  `\\`, `\"` and `\xAB`; `\r` or `\n` is a parse error, and the dictionary
  is then silently ignored.
- **CI builds every target and smoke-runs each for ten seconds from
  empty**, which catches a harness that aborts on any input. It is not a
  regression suite.

Targets assert properties - round-trip idempotence, total ordering,
injection safety, a privilege bound - not merely no panic. Prove a new one
bites by breaking the code it guards, then revert.

## Tests

Nothing may exhaust a **process-wide** resource: a binary's tests share one
process, so filling the fd table fails an unrelated test. Provoke failures
locally instead (swap a directory for a file to get `ENOTDIR`, and so on).

A test that silently skips is worse than none. Gate a skip behind a
`TRUENAS_ROS_REQUIRE_*` variable and **arm it in CI**, so a mis-provisioned
runner goes red.

Prove a test bites before trusting it: break the thing it guards, watch it
fail, restore. Loom models too.

**A guard written as `debug_assert` plus an `if` needs a test per half, and
the gate runs both builds.** `should_panic` is vacuous in release, so those
tests carry `#[cfg(debug_assertions)]` and a `#[cfg(not(debug_assertions))]`
sibling asserts the `if`'s effect on state
(`releasing_one_id_twice_is_refused{,_without_asserts}`,
`promote_under_a_lease_fails_closed{,_without_asserts}`). Release turns an
arithmetic guard's panic into a wrap, so the sibling asserts the wrapped
value.

Know what your environment hides: as **root**, DAC never denies, so reach
`EACCES` through a brokered unprivileged personality or a unit test of the
predicate; a generous **fd limit** hides leaks that fail at 1024; a
**container** blocks `open_by_handle_at`. Make such skips loud or gated.

## Reviews

External reviews land in `/CODE/truenas_ros-review-<date>/` and are re-run
after merge, so every finding above LOW needs a disposition that survives
the next pass: fixed, or engaged in the code with the reasoning written
down. A finding that is merely true-but-declined comes back.

Check findings against the source. Reviews are often right about the defect
and wrong about the fix (an unprivileged process's capability bounding set
is not empty, which one proposed patch to `CredBroker::spawn` assumed).
Verify the claim and the patch, and say which parts you changed. Point a
re-review at the current branch.

## Commits

Terse subject, body wrapped at **72 columns**, no line longer. No
attribution trailers of any kind: no `Co-Authored-By`, no "generated with",
no tool or model names.

Say what changed and why it was wrong before, in the imperative. No
commentary about the review process, the agent, or how the problem was
found unless it changes what a reader should do.

One commit per logical change. Unrelated fixes to different subsystems are
separate commits even when they ship together.

## Comments

Write for the next person changing the code, not to defend the last change.

- No back-compatibility apparatus for consumers that do not exist.
- Do not narrate past mistakes ("the previous behaviour was X"); state the
  constraint and the consequence.
- Do keep a warning that stops a plausible wrong simplification.
  `is_subtree_skip` in `uring_fs/query_tree.rs` is the shape to copy.
- Do not name a consumer of the crate; say what a consumer relies on, as
  the `READONLY` pins in `test/zfs.rs` do.

Cite sources rather than asserting behaviour: kernel and ZFS claims are
checked against `/CODE/linux` and `/CODE/zfs` and cited by function or
`file:line`.

## The gate

Before reporting anything done:

```sh
cargo fmt --all --check
cargo fmt --all --check --manifest-path fuzz/Cargo.toml   # its own workspace
cargo fmt --all --check --manifest-path truenas_api_client/Cargo.toml  # ditto
cargo clippy --all-features --all-targets -- -D warnings
# Release too: the `cfg(not(debug_assertions))` half of every
# `debug_assert` guard is compiled and linted only here.
cargo clippy --release --all-features --all-targets -- -D warnings
# The only step that resolves intra-doc links.
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

# What `ci.yml` arms on an unprivileged runner; the other gates need root,
# ZFS, audit or a real kernel, and `qemu-4-test.sh` arms them. An isolated
# ring-setup `ENOMEM` under `REQUIRE_IO_URING` is the box, not the code:
# re-run before believing it.
export TRUENAS_ROS_REQUIRE_IO_URING=1 TRUENAS_ROS_REQUIRE_PYTHON=1 \
       TRUENAS_ROS_REQUIRE_BTIME=1
cargo test --all-features --no-fail-fast
cargo test --release --all-features --no-fail-fast   # the guards that ship

# Loom in CI's spelling: one invocation, the model count read out of
# ci.yml and asserted.
MODELS=$(sed -n 's/^ *MODELS: "\([0-9]*\)"$/\1/p' .github/workflows/ci.yml)
.github/workflows/scripts/counted-cargo-test.sh "$MODELS" loom -- \
  env RUSTFLAGS="--cfg loom" cargo test --lib --all-features loom_
# Lint that configuration too: no clippy step above compiles `--cfg loom`.
RUSTFLAGS="--cfg loom" cargo clippy --all-targets --all-features -- -D warnings

(cd fuzz && cargo +nightly fuzz build)

# The MSRV `Cargo.toml` declares.
cargo "+$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)" \
  check --all-features --all-targets

# No feature at all, then every feature alone. Keep the list in step with
# `ci.yml`'s feature-matrix job. `|| exit 1`, because `break` and a bare
# loop both report success past a failure in the middle of the list.
cargo clippy --no-default-features --all-targets -- -D warnings
for f in sync-fs xattr mount acl fhandle fsiter idmap shutil \
         configfile audit secrets signal uring net-core net-server \
         net-client uring-fs http ws __fuzz; do
  cargo clippy --no-default-features --features "$f" \
    --all-targets -- -D warnings || exit 1
done

# The api-client satellite ships, so it gets the full discipline against
# its own manifest (`ci.yml`'s `api-client` job is the authority).
(cd truenas_api_client \
  && cargo clippy --all-targets -- -D warnings \
  && cargo clippy --release --all-targets -- -D warnings \
  && cargo test --no-fail-fast \
  && cargo test --release --no-fail-fast \
  && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps \
  && cargo "+$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)" \
       check --all-targets)
```

CI also runs `miri.yml` on every PR, which the local gate does not: it
interprets everything Miri can reach, under both aliasing models, and is
the one instrument that checks the task executor's wake protocol without
trusting our own loom model. Adding a Miri-eligible test means bumping
`MIRI_TESTS`, as a new loom model means bumping `MODELS`.

Report failures with their output. A skipped step is a skipped step; say so.
