# Working in this repo

Conventions that are settled. Each one is here because it was decided once and
then re-litigated; the reasoning is included so it can be argued with on the
merits rather than rediscovered.

## The crate's charter

`libc` + `bitflags`, MSRV 1.97.1. A new runtime dependency is a design
decision, not a convenience - the one exception (`httparse`, for the HTTP
request-head tokenizer) is argued for in `Cargo.toml`. Dev-only crates in a
separate, self-rooted workspace (`fuzz/`) do not count against this and do
not have to hold the MSRV.

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
  - `ci.yml` - unprivileged `ubuntu-latest`. fmt, clippy, tests (debug and
    release), the feature matrix, loom, and the fuzz build. The hosted
    runner's fd limit is orders of magnitude below a typical dev box's, so
    a test that leans on descriptors fails here and nowhere else; reproduce
    with `ulimit -Sn 1024`.
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
- **Dropping a stranded body drops everything queued behind it.** A response's
  association with its request is its position, so releasing the followers into
  the send queue puts the next response where the dropped one belonged and the
  peer answers the wrong request - the same "response out of order" the
  diversion exists to prevent, arriving by the close path.
  `drop_queued_file_reply` also returns the discarded items' `outstanding`
  charges by hand, because nothing will flush to credit them and the read-ahead
  gate, the idle timeout's owes-work test and the drain's quiesced predicate
  all read that counter.
- **A close-carrying reply stops the recv gate when the handler returns it,
  not when its body reaches the wire.** A deferred `ReplyFile{close}` cannot
  arm `close_on_flush` - the flush-close dry checks would then belong to the
  body still streaming in front of it - so `Connection::deferred_close` carries
  the verdict until install hands it over. Without it the gate stays open and
  the connection keeps answering requests behind a reply already declared
  final.
- **`FileTail::parked` is the parked list's dedup key: set on push, cleared on
  pop, nowhere else.** It does not track whether a read is in flight
  (`reading` does). Clearing it on a successful submit leaves the queue entry
  behind, which lets one connection be recorded twice - unbounding a list whose
  length is supposed to be capped by the connection count and destroying its
  longest-waiting-first order. `redrive_parked_tail` also checks for a free
  slot *before* popping, because `on_cqe` returns early for a cancel
  completion and for a stale-generation miss and neither frees anything.
- **Chunk buffers belong to the ring, not to a connection.** They are
  provided buffers on their own group (`BGID_FILE_BODY`), selected by the
  kernel when the read completes and handed back when the chunk reaches the
  peer, so the memory tracks *bodies in flight* rather than the connection
  table. A connection holds a *count* (`Connection::chunk_out`, capped at
  `FILE_TAIL_BUFS`) and no storage. What a connection owned before -
  `chunk_spare`, minted on its first file reply and held until it closed -
  made the worst case `pool_size x 2 x fs_body_chunk`: 256 MiB at the
  defaults and a gigabyte at ts3's megabyte chunk, resident whether or not
  anything was streaming.
  `serving_file_bodies_does_not_allocate_per_connection` measures it with
  a counting allocator: 16 large allocations for 4 connections and 128
  for 32 before, zero for both after.
- **A provided buffer serves a file read.** `IORING_OP_READV` carries
  `buffer_select` (`io_uring/opdef.c`) and the one extra rule is a single
  iovec - `io_iov_buffer_select_prep` answers `-EINVAL` above one
  (`io_uring/rw.c`) - which `submit_pump_read` already satisfied. The
  destination does not have to be known at submit: it arrives with
  `IORING_CQE_F_BUFFER` on the completion, which is before the chunk is
  queued for send, and that is the only moment it is needed.
- **The id rides out on `SendProgress`, because only the reactor holds the
  pool.** `advance_sent` runs on `Connection`, which cannot reach it, so a
  flushed chunk reports its buffer id and the reactor releases it. Teardown
  drains whatever is still queued (`drain_pooled_send_bids` in `free_slot`)
  for the same reason the recv claim is forfeited there: a buffer never
  handed back can be neither reissued nor freed.
- **The send-backlog check covers `FILE_TAIL_BUFS` chunks.** That is every
  chunk buffer the connection has, so a body can queue all of them and no
  more. It bounds one body's chunks and nothing else; a reply head, a
  retired tail's released diversion and an earlier pipelined body's unflushed
  chunks scale with `max_in_flight_requests` instead.

### The recv buffer pool

- **A provided buffer cannot be reserved at submit time.** The kernel picks
  one when the op *completes*, not when it is armed
  (`io_ring_buffer_select`, `io_uring/kbuf.c`), so any number of
  `IOSQE_BUFFER_SELECT` recvs can be outstanding against a pool of any size
  and `BufPool::lent` - which counts at completion - cannot see them coming.
  Gating the submit on `lent < entries` therefore looks right, passes a
  single-connection test, and sheds the fifth of five concurrent
  connections. Shortage is reported by the kernel as `-ENOBUFS` on the
  completion, and that is the only place it can be handled:
  `recv_buffer_shortage` grows the pool and re-pumps; on the file-body
  ring, `on_pump_read` does the same - a dry ring there is pressure, not a
  failed transfer, and treating it as a read error closes the connection
  mid-body (`a_burst_of_file_bodies_grows_the_ring_instead_of_shedding`
  pins the distinction). Growth doubles rather than steps, because the
  shortage says the pool is under its working set. When growth CANNOT
  succeed - the ring at its registered bound with every buffer lent, which
  only leases held past their message can reach - the recv side's answer is
  `recv_shortage_retry`: park the read and retry it on a standalone
  `TIMEOUT` (the default; the unread socket fills and TCP slows the peer
  while pool memory holds at its bound, `recv_shortage_parks` counts it),
  or `None` to drop the connection back to owning its buffer and keep it
  moving through the spike. One live timer per connection
  (`recv_retry_armed`), and the retry re-pumps rather than re-arming
  blindly, so a still-dry pool parks again and a torn-down slot is inert.
  The pump path (file bodies) keeps the owned fallback unconditionally -
  its shortage is the send side's to relieve, not the peer's.
- **`post` writes a descriptor field by field and never `resv`.** Entry
  zero's `resv` is not reserved - it is the ring's published tail, and the
  kernel's only emptiness test is `tail == head`
  (`io_ring_buffer_select`, `io_uring/kbuf.c:202-216`) - so a whole-struct
  descriptor write zeroes the tail every `entries`-th post and the kernel
  then reads a nearly full ring of unpublished descriptors, taking their
  stale addresses verbatim as recv destinations. Found by external review
  with the consequence demonstrated on this kernel (buffers re-selected
  while lent); `a_post_never_touches_the_published_tail` pins it, and the
  tail's release/acquire pairing has a loom model
  (`loom_a_descriptor_is_published_before_the_tail_that_names_it`) because
  the misordering is invisible to every functional test.
- **Every completion carrying `IORING_CQE_F_BUFFER` owes its id back on
  every exit path.** The kernel puts the kbuf with no guard on the result
  (`io_req_rw_complete`, `io_uring/rw.c:591`), and an EOF read completes
  `res = 0` with the flag set - measured - so the pump's abandon paths
  (`Reactor::requeue_body_bid` at each early return in `on_pump_read`)
  return the id or the ring drains one abandoned body at a time while
  `recv_bufs_lent` stays flat. A *socket* read cancelled while blocked
  carries no buffer (measured: io_uring recycles the selection at the
  `-EAGAIN` punt) - but only because a socket is pollable. A `READV` on a
  regular file never is (`io_file_can_poll`, `io_uring/io_uring.h`), so
  its kbuf is committed at selection (`io_should_commit`,
  `io_uring/kbuf.c:183-189`) and a cancelled pump read *does* carry its
  buffer - do not cite this entry to skip a requeue there. Cancellation
  on the recv path cannot reproduce the leak, which is why the regression
  drives the EOF arm instead
  (`a_truncated_body_close_returns_its_buffer`).
- **A short leased write surfaces as `Err(EIO)`, never `Ok(n)`.** ZFS
  returns partial writes as successes by design (`zfs_write`,
  `module/zfs/zfs_vnops.c:1085-1094`), and by the time a leased caller saw
  the count its source buffer is already back in the pool - a retry would
  write another connection's bytes and a shrug stores a truncated object.
  The copy path stays retryable (`into_bufs` hands the source back); that
  asymmetry is documented on `pwritev2_from` rather than papered over.
- **Rings are registered at the physical bound; there is no sizing knob.**
  A ring cannot be resized after registration (re-registering a live `bgid`
  is `-EEXIST`), so `ring_entries` sizes it to the most buffers real demand
  could ever hold at once - one per connection for recv, `FILE_TAIL_BUFS`
  per connection for file bodies - clamped to the kernel's 32768-entry cap
  (`io_uring/kbuf.c:633-637`). A descriptor slot is 16 bytes, so that
  headroom is not memory; the backing buffers are, and they track demand
  between `POOL_INITIAL` and the bound. An earlier ceiling knob defaulted
  far below the bound, which turned an ordinary burst into the per-read
  malloc fallback the ring exists to remove. `recv_pool` and `fs_body_pool`
  are booleans, and everything else is derived.
- **A pool buffer's size is a free parameter, because a message that
  outgrows one promotes instead of being refused.** `RecvBuf::promote_for`
  copies what is accumulated into owned storage and hands the buffer back,
  so the cost of an oversized message is one copy bounded by the *buffer*,
  not by the message. Without it `recv_pool_buf_len` had to be
  `max_request_bytes + RECV_CHUNK` and the pool had to default off - the
  size was chasing a cap that has nothing to do with how much a typical
  message needs. `RECV_POOL_BUF` is 256 KiB so a streamed window
  (`STREAM_WINDOW`, 128 KiB) fits with its framing and a pipelined
  remainder - a buffer that could not hold one would push every window
  into placement and the pool would carry heads and nothing that moves
  data.
- **The ring is a conveyor of descriptors, not a slab.** Each
  `io_uring_buf` carries its own `addr` and `len`, so the ring is registered
  once at its ceiling and buffers are allocated and posted behind it on
  demand - SPDK's model
  (`uring_sock_group_populate_buf_ring`, `module/sock/uring/uring.c`, which
  refills entries every poll from an application callback). The payoff is
  not elasticity but locality: **a buffer is freed only in
  `BufRing::release`, which runs when the kernel has already handed it
  back.** The slab-per-group alternative has to prove nothing anywhere in
  the group is still lent before freeing the slab under it - a whole-pool
  invariant guarding a use-after-free, where this asks a per-buffer
  question.
- **Shrinking lowers the target; the buffers follow as they cycle.** A
  posted descriptor cannot be retracted - the kernel owns that entry until
  it picks it - so surplus storage is given up in `release`, one buffer per
  cycle. A pool going from busy to *quieter* returns its surplus promptly; a
  pool going from busy to *silent* keeps it, because nothing is cycling.
  That residue is bounded by the ring's ceiling and is no worse than the
  per-connection buffer it replaces, which also never shrank.
- **SPDK's own answer to an oversized message does not transfer.** It
  queues several buffers on `sock->recv_stream` and lets the consumer gather
  out of them, which works because that consumer reads into its own iovecs.
  A head scan cannot: `httparse` needs the bytes contiguous, so a chain has
  to be joined before framing and the join is the copy the ring exists to
  avoid - hence promoting. What does transfer is SPDK's dry-ring fallback, a
  plain `sock_readv` into the caller's buffer, which is the shape
  `set_recv_owned` already had.
- **A pooled connection does not place a body the pool can serve** - one
  its held claim already covers, or, with no claim, one that fits a pool
  buffer (`RECV_POOL_BUF` is sized so a window does). Placement buys a move
  on delivery by allocating a buffer per body; against a held claim the
  second buffer is churn, and against no claim it forfeits the buffer the
  read gets free (the kernel picks at completion) to allocate one
  `pwritev2_from` must then copy. The no-claim case arises whenever a peer's
  HTTP chunks are larger than a window: every window after the first in a
  chunk carries no chunk header, so the claim is already leased to the
  previous window's write. Measured at 1 MiB HTTP chunks before this
  suppression: 14 large allocations and 896 KiB copied per MiB, 87.5% of
  payload. **This is not the default client.** botocore's HTTP chunks are
  128 KiB - exactly one window - so a default upload carries a chunk header
  on every window and never reaches the no-claim arm; its 1 MiB
  `_DEFAULT_CHUNK_SIZE` frames an inner aws-chunked payload that this layer
  decodes as body bytes rather than frames (see `STREAM_WINDOW`).
  `a_streamed_upload_does_not_allocate_per_window` and
  `a_streamed_put_at_oversized_http_chunks_still_does_not_copy` pin the two
  cases. `frame_step` cannot make this call - it is deliberately
  state-free - so `enact_frame_step` downgrades `place`. The trade is a
  copy for a handler that takes ownership of a body in that size range,
  which is why placement still governs anything a pool buffer cannot hold
  and every unpooled connection.
- **A placed body must not also be handed a pool buffer.** It reads into
  its own allocation, and the kernel clamps a selecting read down to the
  buffer it picked (`io_ring_buffer_select`, `io_uring/kbuf.c`), so an exact
  read longer than a pool buffer completes short of the declared frame and
  the connection dies `TruncatedMessage`. Only reachable from a
  `header_len: 0` frame - with a header buffered the connection already
  holds a claim and asks for nothing - which is every message after the
  first in a streaming codec. `a_placed_body_never_takes_a_pool_buffer`
  carries its own framer for exactly that reason.
- **Teardown forfeits the claim; it does not wait for the buffer to empty.**
  `Connection::release_recv_buf` refuses while bytes are buffered, which is
  right on the serving path and wrong on the closing one: a buffer never
  handed back is one the pool can never reissue and never free, since
  `release` is the only place either happens.
  `ConnTable::forfeit_recv_claim` is the teardown form, and `free_slot` is
  where it runs - before `table.free` drops the connection.
- **A failed drain leaks the pool along with the connection buffers.**
  Registered buffers are kernel-visible on the same ring; an op still in
  flight names one by index, so unregistering the ring and freeing its
  buffers hands the kernel freed pages to write into. `drain_or_leak`
  forgets the `BufPool` for the same reason it leaks the table.

### Leased writes (PUT windows straight to a file)

- **A deferred stream open must release the withheld `100 Continue` on
  resume** - both the `resume()` path and a redrive that returns
  `Continue`. The interim is withheld pending the open decision and an
  expecting client sends nothing until it arrives, so a park that swallows
  it stalls every expecting PUT for the client's own timeout; deciding an
  upload off-thread (authorization) is exactly what `defer_stream` at
  `Open` is for. `StreamPark::expect_interim` carries it;
  `a_deferred_stream_open_still_sends_the_interim` pins both routes.

- **The write borrows the recv buffer; the claim is surrendered to its
  writes, not pinned on the connection.** `deliver_one` consumes the
  message the moment the handler returns - `Defer` included - so anything
  that must outlive the handler cannot live on the connection. Every
  in-bounds range a delivery submits shares one `Arc<LeaseHold>`; each
  op parks a share, and `Arc::into_inner` at reap surfaces the id from
  exactly the completion that dropped the last one, so N ranges of one
  window all write zero-copy and the buffer cannot come back while a
  sibling's DMA still reads it. The facade keeps only a `Weak`, so it
  never delays the release. `RecvBuf::drain_front` sees the lease at
  consume and takes the claim *without* releasing it (keeping only the
  pipelined remainder, which is empty on the streaming hot path); the
  surfaced id rides `FsDone::take_recv_lease` and the server dispatch
  hands it to the pool. Release and forfeit refuse while
  leased for the same reason: two owners releasing one bid re-posts a
  buffer the kernel may hand to a recv while the write's DMA still reads
  it. The ring's own state machine catches the double-release
  (`releasing a buffer nobody took`), which is how the negative control
  bites.
- **`defer_stream` exists because `defer` copies the body into the park.**
  A deferral that resolves by re-running the handler has to retain the
  window; a streamed window resolved by `HttpStreamDeferred::resume` never
  re-runs the handler - the stream just moves to its next read - so the
  park retains the head only and the body copy is gone. Without it the
  leased write saves nothing: the park's copy replaces the write's copy,
  one 128 KiB allocation per window either way.
  `a_streamed_put_writes_windows_without_copying_them` measures the whole
  chain - 32/128 large allocations per 4/16 MiB with either fallback forced,
  zero with both in place, file bytes verified against the upload.

- **Pipelined ingest is a handler pattern, not a reactor mode.** The lease
  outlives the delivery's verdict, so a streaming handler floats each
  window's write with `Continue` and brakes with `defer_stream` only at its
  own depth cap - stopping the reads is the entire backpressure mechanism
  (the socket buffer fills and TCP slows the sender), which is SPDK's shape:
  its sock layer treats a dry provided-buffer ring as flow control, not
  error (`module/sock/uring/uring.c`, the `-ENOBUFS` re-arm), and nvmf/tcp
  caps in-flight work with a per-connection resource pool
  (`lib/nvmf/tcp.c` `resource_count`). The cap exists for the tail, not the
  steady state: write latency is a distribution, and during a txg stall an
  uncapped connection eats the op table - whose write-path exhaustion sheds
  connections - and runs the ring to its wall. At `Stage::End` the park is
  a plain `defer` (an End park retains no resume state, so `resume()` there
  closes by design) answered from the last completion.
- **`RECV_LEASE_DEPTH` (4) is why the recv ring registers past one slot per
  connection.** A leased write holds its buffer beyond its message's
  consume, so a pipelined connection holds up to its depth plus the one
  arriving. The registration is the wall growth stops at, and past it a
  connection degrades to owned buffers *permanently* - measured at ~2 large
  allocations per window (the owned growth plus the write's copy fallback)
  against zero inside the wall, which is
  `a_pipelined_put_overlaps_writes_with_arrivals`'s negative control.
  Descriptor slots are 16 bytes, so the headroom is free.
- **A `Content-Length` body streams only above one window, and its End
  stage rides the delivery that exhausts the length.** At or under
  `STREAM_WINDOW` a whole delivery is one pool-buffered read already, so
  streaming it would add Open/End dispatches and save nothing. Above it,
  no wire byte remains to frame an End from and the reactor refuses a
  zero-length message (`frame_step`, fuzz-pinned), so the exhausting
  window's step dispatches End inline on `Continue` - or from the resume
  when that window parked, with a restore phase of `StreamDone` as the
  marker (chunked never parks with it). Bytes buffered behind the tail
  are the next pipelined request's;
  `pipelined_known_length_streams_do_not_desync` pins the handoff.
- **A known-length window is a full `STREAM_WINDOW`, however little is
  buffered.** The exact read that completes it draws from the recv pool:
  `known_step` answers `More` on an empty buffer, which re-acquires a
  claim, and the reactor refuses to place a frame one pool buffer can
  serve - so the remainder arrives zero-copy and the feared owned-handoff
  fires only on an unpooled connection, where a per-window `Vec` is the
  degraded mode's ordinary cost. This replaces an earlier bound to the
  buffered bytes, whose windows were `RECV_CHUNK`-sized in practice:
  ~33x the deliveries, eventfd wakes and leased writes per payload,
  measured at 31x the pokes and 21x the `io_uring_enter` calls, while the
  owned-allocation cost it guarded against measured zero on a pooled
  connection. The `remaining` bound is what keeps a pipelined next
  request out of the exhausting window's tail.
  `a_known_length_put_streams_without_copying` still measures allocation
  flatness (from `MED`, the tighter of the counting allocator's two
  thresholds), and `a_known_length_body_streams_above_one_window` pins
  the full-window law.

### The two receive clocks

- **Two clocks, because neither can do the other's job.** `request_timeout` is
  re-armed by every recv, so it answers "is this peer still there" and is
  explicitly not a rate floor. Making it absolute instead would close a peer
  transferring perfectly well, merely slowly; keeping only it leaves
  `pool_size` **unauthenticated** peers holding every slot at one byte per
  period, because a slot is taken at accept and accept is gated on a free one.
  `validate` refuses `max_receipt_time <= request_timeout`, which would
  pre-empt the inactivity bound and leave it configured but dead.
- **The budget bounds one *message*, not one connection.** That is what makes
  it compose with a streamed body - each window is its own message, so an
  upload of any size is admitted while the floor stays `STREAM_WINDOW /
  max_receipt_time`. A per-connection budget would cap upload size by wall
  clock, the ceiling the streaming path exists to remove.
- **Armed in `submit_recv` on the first non-idle read, retired in
  `deliver_one`, never cancelled in between.** A `More` scan re-enters
  `submit_recv` on every chunk, so a cancel-then-arm there rides the trickle
  and reproduces `request_timeout` under a second name. An exact read cannot
  show this - a length-prefixed body is one `submit_recv` whatever happens
  afterwards - so the control for it has to be a chunk scan
  (`a_chunk_scan_budget_is_not_restarted_by_progress`).
- **A spliced body arms and retires it in `submit_splice_recv` /
  `on_splice_recv_complete`.** That path never enters `submit_recv`, so the
  arm site the buffered framings share cannot reach it, and the two clocks
  that do reach it - `request_timeout` on the readiness poll, the kTLS
  watchdog - are both inactivity bounds any arriving byte re-arms. There is
  also no `deliver_one` there, so the whole-body tail is the only place the
  message ends: a budget left armed reaps a connection for having finished
  on time, and suppresses every later message's budget until it does
  (`arm_receipt_deadline` is idempotent on the flag).
  `the_receipt_budget_bounds_a_spliced_body_and_ends_with_it` drives both
  halves with `idle_timeout` unset, so neither can be masked.
- **Only a *wire* delivery retires it** (`Delivery::FromWire`). A
  redelivery's message was consumed and its budget retired at its first
  delivery, so the budget armed when a worker's `redeliver` lands belongs to
  a later message the read-ahead has begun - and retiring that one restarts
  the bound. Where the next read is already in flight (an exact body read)
  nothing re-arms it and the trickling peer is never reclaimed at all:
  `a_redelivery_does_not_retire_the_next_message_budget`.
- **Retiring at *delivery* is what keeps it a bound on receipt.** A
  `Response::Defer` may run arbitrarily long, and a budget still armed would
  clock the handler, then the next idle period, on a connection that has done
  nothing wrong.
- **"Idle" is the framer's verdict, not `buffered() == 0`.** A streaming
  codec consumes each window as its own message, so between windows - and
  after the 100-continue dance has consumed the head - the buffer is empty
  while the request is very much in progress, which is indistinguishable at
  the reactor from a connection parked for its next request. Read off
  `buffered()` alone, such a connection takes `idle_timeout` instead of
  `request_timeout` and arms **no** receipt budget: with `idle_timeout`
  unset it is never reaped at all, which is the exact denial both knobs
  exist to close. `Framing::MoreInMessage` is the framer saying "a message
  is under way"; `known_step`, `stream_step` and `scan_step` answer it, and
  `Phase::Head` and `Phase::Parked` deliberately do not - a parked request
  is being *handled*, and handling is not clocked.
  `a_stalled_streamed_upload_is_reaped_mid_body` runs with `idle_timeout`
  unset so the misclassification has nothing to fall back on.

### Delivering a message

- **A redelivery owns neither the frame nor the budget.**
  `Deferred::redeliver` re-enters `deliver_one` for a request the glue
  retained, and its documented contract is an *empty* frame - the bytes went
  at the first delivery. Above the default read-ahead cap the pump may have
  framed the next pipelined request already, and delivering against that
  frame slices a body out of a buffer holding only its header
  (`Body::inline(&rest[..body_len])`, an out-of-range slice that panics the
  reactor thread) and then lets `consume` eat that request's header. The
  `Delivery` split is what keeps the two apart; the in-tree http codec never
  reaches it, because `Phase::Parked` holds pipelined bytes unframed, so the
  control has to be a framer that frames what is buffered
  (`a_redelivery_does_not_take_the_read_ahead_frame`).

### The offload pool

- **`WorkerPool::drop` waits `SHUTDOWN_DETACH_AFTER` *in total* and then
  detaches.** The bound is a deadline computed once (`ShutdownClock`), not the
  duration passed to each `wait_timeout`: every worker exit notifies, so
  re-passing the full timeout would make the real bound `workers x
  SHUTDOWN_DETACH_AFTER` - 128 s at the default ceiling, 2048 s at the
  validated maximum - and a spurious wake would remove the bound entirely.
  Detaching is sound because `Job` is `Box<dyn FnOnce() + Send>` and therefore
  `'static` - no job holds a borrow of what the dropper frees - and each worker
  owns an `Arc<PoolShared>`. The wait buys quiescence, not soundness, which is
  why a still-draining pool may be detached rather than waited out.
  **Shutdown is not the reason it is bounded**: FUSE (`fs/fuse/dev.c:212`) and
  sunrpc (`net/sunrpc/sched.c:346`) wait `TASK_KILLABLE`, so a supervisor's
  SIGKILL reaps a wedged worker at process exit. The case with no backstop is
  mid-run - `Drop` runs wherever the last handle falls, including on another
  pool's worker or a request thread.
- **`ON_POOL_WORKER` carries the pool's identity, not a bare flag.** A bare
  "am I a worker" leaks the self-join exemption to every pool in the process.

### Where a poisoned lock fails closed

- **`SingleFlight`'s `get_or_try_init` fails closed on a poisoned map because
  of *where* the first acquisition sits, not because its poison handling is
  uniform.** It is not uniform: of the four map acquisitions in that function,
  `:67` and `:90` use `map_err(|_| Errno::EIO)?` while `:101` and `:115` use
  `if let Ok(mut live)`, which swallows poison - and `invalidate`, `clear` and
  `len` swallow it too. What makes the whole thing safe is that `:67` is the
  **first** acquisition and precedes the cache-hit fast path at `:73`, so a
  poisoned `live` fails every `acquire` before a stale identity can be served.
  That is an ordering property. **Hoisting the fast path above the `:67` lock
  is the obvious optimisation and it removes the guarantee**, so if that lock
  moves, the fail-closed reasoning has to be re-established rather than
  assumed.

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

**A guard written as `debug_assert` plus an `if` needs a test per half, and
the gate runs both builds.** `should_panic` on the assert covers the build
that panics and is vacuous in the one that ships - it fails outright there,
having nothing to catch - so those tests carry `#[cfg(debug_assertions)]` and
a `#[cfg(not(debug_assertions))]` sibling asserts the `if`'s behaviour on
*state* instead. That is not a formality where the `if` is what stands between
a double release and two descriptors naming one buffer: see
`releasing_one_id_twice_is_refused{,_without_asserts}` and
`promote_under_a_lease_fails_closed{,_without_asserts}`. Note that release
turns an arithmetic guard's failure from a panic into a wrap, so the state a
sibling test asserts on is the wrapped value, not an abort.

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

- No back-compatibility apparatus for consumers that do not exist. A format
  does not need two accepted versions, and a doc comment should not claim that
  tokens "written by an older build" still decode.
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
cargo test --release --all-features --no-fail-fast   # the guards that ship
RUSTFLAGS="--cfg loom" cargo test --lib --features uring    loom_
RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
RUSTFLAGS="--cfg loom" cargo test --lib --features http     loom_
(cd fuzz && cargo +nightly fuzz build)
```

Report failures with their output. A skipped step is a skipped step; say so.
