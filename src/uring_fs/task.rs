//! Awaitable operations and on-loop tasks over the callback facade.
//!
//! The callback facade stays the primitive. Everything here consumes
//! [`FsConn`]'s existing submit methods: an op future is one submission
//! whose delivery fills a slot instead of running a chain, and the two
//! styles compose - a request may hold callbacks at one step and `await`
//! the next. Nothing routes a ring op through the offload pool: the
//! wrapper re-shapes delivery only, and submission stays the eager,
//! on-ring path the callback form uses.
//!
//! "Poll" in this module is always [`Future::poll`] - the state-machine
//! step, `std`'s own vocabulary - never `poll(2)` or a readiness op. A
//! task poll issues no syscall; the ops a poll submits do their kernel
//! work through the ring like every other submission.
//!
//! - [`FsConn::fut`] wraps one submission. It hands the closure a boxed
//!   callback ([`OnDone`]) to pass as any submit method's `on_done` and
//!   returns the [`FsFuture`] that callback resolves.
//! - [`FsConn::offload_fut`] is the same shape over
//!   [`FsConn::offload_result`], for a blocking metadata tail.
//! - [`FsConn::spawn`] starts a **task**: a `'static` future polled
//!   inline on the loop thread, owner-scoped exactly like a chained
//!   continuation. The task body receives a [`TaskFs`], which is how
//!   code inside the task submits: a task cannot hold the facade across
//!   an `await`, so each poll runs with the delivering facade parked
//!   where [`TaskFs`] can reach it, and nowhere else. Spawning returns
//!   a [`JoinHandle`] resolving with the task's output, or a
//!   [`JoinError`]; dropping the handle detaches rather than kills.
//! - **A panicking task is contained.** Its poll unwinds no further
//!   than the executor: the payload reaches its [`JoinHandle`] as
//!   [`JoinError::Panic`], the slot retires, and the reactor thread
//!   keeps serving every other connection. This is the one place in
//!   the crate that catches an unwind on the loop - a callback that
//!   panics still takes the thread down - because a task is a
//!   request's own work and a request's bug should cost the request.
//!
//! # Contract
//!
//! - **Submission is eager.** The op is in flight when [`FsConn::fut`]
//!   returns, polled or not. Dropping an [`FsFuture`] abandons the
//!   outcome - the completion fires into a slot nobody reads - and does
//!   not cancel the op; its registry entry owns everything the kernel
//!   still touches.
//! - **A callback dropped unfired resolves the future** with
//!   `ECANCELED` rather than pending forever. That is the future form
//!   of "dropping the continuation closes the connection": a refused
//!   submission, or teardown, reaches the awaiting task as an error it
//!   can act on, **and it says which**. The callback form still drops
//!   `on_done` for all of them, which is its own contract; the futures
//!   layer stages a reason sink beside the callback, and a sink runs no
//!   consumer code, so nothing is delivered inline from a submit path.
//!   Three things make the distinction usable:
//!   - [`FsDone::was_refused`] says the errno is **this crate's**, not
//!     the kernel's. Read it first: `EBUSY` from a full op table is
//!     worth retrying and `EBUSY` from the kernel is permanent for that
//!     path, and nothing about the errno alone separates them.
//!   - The refusal **hands the payload back** ([`FsDone::into_bufs`]),
//!     so the retry it advises is possible without keeping a second
//!     copy of every write.
//!   - The sink is **shared across a multi-step call's steps**
//!     ([`FsConn::open_chain`], [`FsConn::mkdir_path`]), which submit
//!     from a fresh facade after the first, so a mid-chain refusal
//!     keeps its errno instead of arriving as teardown.
//!
//!   `ECANCELED` with `was_refused()` false is left meaning teardown
//!   alone.
//! - **A task's facade is a continuation facade.** Each poll gets a
//!   fresh owner-scoped [`FsConn`], the same one a completion callback
//!   is handed, and everything a continuation must tolerate - an owner
//!   gone mid-chain - a task must tolerate too. A task ends by
//!   returning; there is no external kill, so a task must terminate
//!   when its ops start failing or the source feeding it closes.
//! - **A task's facade carries no recv-buffer claim**, so
//!   [`pwritev2_from`](FsConn::pwritev2_from) from inside a task
//!   copies instead of writing the delivered buffer in place. The
//!   claim belongs to the delivery that is holding the body, and a
//!   task outlives it. Submitting the write from the delivery's own
//!   callback and handing the [`FsFuture`] to the task keeps the
//!   zero-copy path; a task that wants the bytes must own them,
//!   which its `'static` future requires in any case.
//! - **Tasks are polled from the delivery points that fire callbacks**
//!   (completion and offload delivery), plus [`FsConn::run_woken`] for
//!   a callback that wakes a task by hand and wants it run before the
//!   next completion. Each pass is bounded to what was queued when it
//!   began - a wake landing mid-pass runs next pass, behind a poke of
//!   the loop's wake eventfd - so a self-waking task cannot starve the
//!   ring. A waker used off-loop pushes under the run-queue lock and
//!   then pokes the same eventfd - the offload pool's push-then-poke
//!   protocol (`finish_offload`).
//! - **The task table and run queue are uncapped**, like the offload
//!   registry: bound in-flight work upstream, at the request cap.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use super::core::{FsConn, FsCore, FsDone, Owner};
use crate::errno::Errno;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::sync::{Arc, Mutex};
use crate::uring::engine::Engine;
use crate::uring::wake::LoopShared;

// ---- completion slots -----------------------------------------------------

/// One completion slot: filled at most once by a [`Fire`], read at most
/// once by its future.
enum SlotState<V> {
    /// Unfired; the waker parked by the most recent poll, if any.
    Pending(Option<Waker>),
    /// Fired; the next poll takes it.
    Ready(V),
    /// The callback was dropped unfired (a refused submission, or
    /// teardown): resolve rather than pend forever.
    Gone,
    /// Read; nothing left. A poll after readiness resolves as [`Gone`]
    /// rather than parking a waker nothing will ever wake.
    Spent,
}

struct Slot<V>(RefCell<SlotState<V>>);

impl<V> Slot<V> {
    fn new() -> Rc<Slot<V>> {
        Rc::new(Slot(RefCell::new(SlotState::Pending(None))))
    }

    /// A slot born resolved-as-gone, for a submission that never
    /// happened ([`TaskFs`] reached outside a poll).
    fn gone() -> Rc<Slot<V>> {
        Rc::new(Slot(RefCell::new(SlotState::Gone)))
    }

    /// Fill with the outcome (`None` = the callback dropped unfired)
    /// and wake whoever parked.
    fn fill(&self, landed: Option<V>) {
        {
            // A real answer is final; `Gone` is not. The two arrive in
            // either order - a refused submission drops its callback
            // (which lands as `Gone`) and reports its errno through
            // the waiter's sink - and the errno is the better answer
            // whichever came first.
            let cur = self.0.borrow();
            let settled =
                matches!(*cur, SlotState::Ready(_) | SlotState::Spent);
            if settled || (matches!(*cur, SlotState::Gone) && landed.is_none())
            {
                return;
            }
        }
        let next = match landed {
            Some(v) => SlotState::Ready(v),
            None => SlotState::Gone,
        };
        // The borrow ends before the wake: the waker re-enters the
        // executor's queue, never this slot, but keeping the borrow
        // narrow costs nothing and removes the question.
        let prev = std::mem::replace(&mut *self.0.borrow_mut(), next);
        if let SlotState::Pending(Some(w)) = prev {
            w.wake();
        }
    }

    fn poll_take(&self, cx: &mut Context<'_>) -> Poll<Option<V>> {
        let mut s = self.0.borrow_mut();
        match std::mem::replace(&mut *s, SlotState::Spent) {
            SlotState::Ready(v) => Poll::Ready(Some(v)),
            SlotState::Gone | SlotState::Spent => Poll::Ready(None),
            SlotState::Pending(_) => {
                *s = SlotState::Pending(Some(cx.waker().clone()));
                Poll::Pending
            }
        }
    }
}

/// The filling half of a slot: firing consumes it; dropping it unfired
/// fills [`SlotState::Gone`], so the future resolves either way.
struct Fire<V>(Option<Rc<Slot<V>>>);

impl<V> Fire<V> {
    fn fire(mut self, v: V) {
        if let Some(s) = self.0.take() {
            s.fill(Some(v));
        }
    }
}

impl<V> Drop for Fire<V> {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.fill(None);
        }
    }
}

/// The boxed callback [`FsConn::fut`] hands its closure - pass it as
/// any submit method's `on_done`. Dropping it unfired resolves the
/// future as `ECANCELED`, which is what a submit method's silent
/// argument refusal turns into on this path.
pub type OnDone = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// The boxed callback [`FsConn::result_fut`] hands its closure - pass it
/// as the `on_done` of any facade method whose outcome is a
/// [`crate::Result`] rather than an [`FsDone`] (the offload-backed
/// metadata tails, and the two directory-walk steps). Dropping it
/// unfired resolves the future as `ECANCELED`, exactly as [`OnDone`]
/// does.
pub type OnResult<T> = Box<dyn FnOnce(crate::Result<T>, &mut FsConn<'_>)>;

/// One submitted op's completion, as a future. Resolves to the same
/// [`FsDone`] the callback form receives; a callback dropped unfired
/// resolves as a failed `ECANCELED` outcome instead of pending forever.
pub struct FsFuture(Rc<Slot<FsDone>>);

impl std::fmt::Debug for FsFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsFuture").finish_non_exhaustive()
    }
}

impl Future for FsFuture {
    type Output = FsDone;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FsDone> {
        self.0
            .poll_take(cx)
            .map(|v| v.unwrap_or_else(|| FsDone::failed(Errno::ECANCELED)))
    }
}

/// One offloaded blocking job's outcome, as a future. Resolves to what
/// the job returned; a delivery dropped unfired resolves `ECANCELED`.
pub struct OffloadFuture<T>(Rc<Slot<crate::Result<T>>>);

impl<T> std::fmt::Debug for OffloadFuture<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffloadFuture").finish_non_exhaustive()
    }
}

impl<T> Future for OffloadFuture<T> {
    type Output = crate::Result<T>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<crate::Result<T>> {
        self.0
            .poll_take(cx)
            .map(|v| v.unwrap_or_else(|| Err(Errno::ECANCELED.into())))
    }
}

/// Why a task produced no output.
#[derive(Debug)]
pub enum JoinError {
    /// The task panicked. The payload is what the poll unwound with,
    /// as [`catch_unwind`](std::panic::catch_unwind) yields it.
    ///
    /// A panicking task is contained: its slot retires, the reactor
    /// thread lives, and every other connection on that ring keeps
    /// being served. Nothing else in this crate contains a panic - a
    /// callback that unwinds still takes the loop down - so this is
    /// deliberately the narrower promise: a task's own bug is a
    /// request's problem, not the ring's.
    Panic(Box<dyn std::any::Any + Send>),
    /// The task never finished and never will: dropped at teardown
    /// before completing, or a release-build [`TaskFs::spawn`] reached
    /// outside a poll, whose body therefore never ran at all.
    Dropped,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Panic(_) => f.write_str("the task panicked"),
            JoinError::Dropped => {
                f.write_str("the task was dropped before it finished")
            }
        }
    }
}

impl std::error::Error for JoinError {}

/// A spawned task's output, as a future.
///
/// Resolves `Ok` with what the task returned, or [`JoinError`] when it
/// produced nothing. Polling again after it has resolved answers
/// [`JoinError::Dropped`]: the output is taken by the poll that got
/// it, and a handle is not a broadcast.
///
/// Dropping the handle detaches - the task runs to completion either
/// way and its output is dropped unread. There is no kill through it.
pub struct JoinHandle<T>(Rc<Slot<Result<T, JoinError>>>);

impl<T> std::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<T, JoinError>> {
        self.0
            .poll_take(cx)
            .map(|v| v.unwrap_or(Err(JoinError::Dropped)))
    }
}

// ---- the awaitable surface on the facade ----------------------------------

impl FsConn<'_> {
    /// Submit one op through `submit` and return its completion as a
    /// future. `submit` receives this facade and the boxed callback to
    /// pass as the op's `on_done`:
    ///
    /// ```ignore
    /// let done = conn
    ///     .fut(|c, done| c.fsync(who, file.clone(), done))
    ///     .await;
    /// done.result()?;
    /// ```
    ///
    /// Submission happens inside this call - the op is in flight when
    /// it returns, whether or not the future is ever polled - so two
    /// futures created back to back overlap on the ring. A `submit`
    /// that drops `on_done` without passing it anywhere resolves the
    /// future as `ECANCELED`.
    pub fn fut(
        &mut self,
        submit: impl FnOnce(&mut FsConn<'_>, OnDone),
    ) -> FsFuture {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        // Why an op never reached the ring, for the future to read:
        // `EBUSY` from a full op table is worth retrying with the
        // payload the sink hands back, `EINVAL` from a refused argument
        // is a caller bug, and teardown is neither. The callback form
        // cannot tell them apart - it drops `on_done` for all three -
        // so the sink is what carries the distinction, and
        // `FsDone::was_refused` is what separates it from the kernel's
        // own `EBUSY`.
        let reason = Rc::clone(&slot);
        // Saved and put back, because `submit` may itself contain a
        // `fut`: assigning over the outer sink would leave the outer op
        // reporting teardown for its own refusal.
        let outer = self.stage_fail_sink(Rc::new(move |errno, bufs| {
            reason.fill(Some(FsDone::refused_with(errno, bufs)));
        }));
        submit(self, Box::new(move |done, _conn| fire.fire(done)));
        // No submission armed the sink: `submit` returned without
        // handing the op to the core at all, which is what the facade's
        // own argument checks do (an absolute path, an empty link
        // target) - the same class of defect the core reports as
        // `EINVAL`.
        if !self.restore_fail_sink(outer) {
            slot.fill(Some(FsDone::refused_with(Errno::EINVAL, Vec::new())));
        }
        FsFuture(slot)
    }

    /// [`offload_result`](Self::offload_result) as a future: run `job`
    /// on the blocking pool and resolve with its result on-loop. The
    /// job contract is [`offload`](Self::offload)'s, unchanged - this
    /// is for the opcode-less blocking tail, never for an op the ring
    /// serves.
    pub fn offload_fut<T, J>(&mut self, job: J) -> OffloadFuture<T>
    where
        J: FnOnce() -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        self.offload_result(job, move |r, _conn| fire.fire(r));
        OffloadFuture(slot)
    }

    /// Submit one op through `submit` and return its outcome as a
    /// future - [`fut`](Self::fut) for the nine facade methods whose
    /// callback carries a [`crate::Result`] instead of an [`FsDone`]:
    /// both `fstatfs` forms, `flistxattr`, `fremovexattr`, the ZFS
    /// attribute pair, `copy_file_range`, and the `open_dir`/`next_batch`
    /// walk. Without it a handler cannot be written wholly as a task, and
    /// the three that are hand-rollable through
    /// [`offload_fut`](Self::offload_fut) lose real guarantees on the
    /// way: `fremovexattr`'s allowlist and `open_dir`'s per-request
    /// `open` are reactor state a pool job cannot see.
    ///
    /// ```ignore
    /// let st = conn.result_fut(|c, cb| c.fstatfs(file.clone(), cb)).await?;
    /// ```
    ///
    /// Submission is eager on the same terms as [`fut`](Self::fut). **No
    /// reason sink is staged**, so a refusal on this shape resolves
    /// `ECANCELED` rather than naming itself. Eight of the nine deliver
    /// through the offload pool, where a refusal has no errno to carry
    /// and `ECANCELED` is already
    /// [`offload_fut`](Self::offload_fut)'s answer; `open_dir` is the
    /// exception - its first step is a ring `open`, so a full op table
    /// reaches this future as teardown would. Await the `open` yourself
    /// with [`fut`](Self::fut) if that distinction matters.
    pub fn result_fut<T, S>(&mut self, submit: S) -> OffloadFuture<T>
    where
        S: FnOnce(&mut FsConn<'_>, OnResult<T>),
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        submit(self, Box::new(move |r, _conn| fire.fire(r)));
        OffloadFuture(slot)
    }

    /// Start a task: `body` builds the future from the [`TaskFs`] it
    /// will submit through, and the task is polled once inline before
    /// this returns - so its first ops are on the ring when the caller
    /// resumes, exactly as an eager callback chain's would be.
    ///
    /// `body` itself runs inside that first poll, so it may submit
    /// through its [`TaskFs`] while assembling the future - the eager
    /// pair this module's contract describes - and not only from
    /// inside the returned future.
    ///
    /// The task is owner-scoped like a continuation: polls after this
    /// one run from completion delivery, each with a fresh facade for
    /// the same owner. A task ends by returning. There is no external
    /// kill; a task whose connection died sees its ops fail and must
    /// wind down on that signal. Whatever outlives the loop is dropped
    /// with the reactor's tables at teardown.
    ///
    /// The returned [`JoinHandle`] resolves with the task's output.
    /// Dropping it detaches: the task runs to completion regardless
    /// and its output is dropped unread - the shape a spawn used for
    /// its effects wants, so the handle is not `#[must_use]`.
    pub fn spawn<F, Fut, T>(&mut self, body: F) -> JoinHandle<T>
    where
        F: FnOnce(TaskFs) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        // Type-erased so the entry, which cannot name `T`, can still
        // answer this handle when its poll unwinds.
        let panicked = {
            let slot = Rc::clone(&slot);
            Box::new(move |payload| {
                slot.fill(Some(Err(JoinError::Panic(payload))));
            })
        };
        // `body` runs *inside* the first poll, not here: it is handed
        // a `TaskFs`, and a facade is parked only for the extent of a
        // poll. Building the future out here would leave every op the
        // caller submits while assembling it - the eager pair this
        // contract advertises - with no facade to submit through.
        let task = Box::pin(async move {
            let fut = body(TaskFs::new());
            fire.fire(Ok(fut.await));
        });
        let (fs, eng, owner) = self.split();
        let id = fs.tasks.insert(eng, owner, task, panicked);
        poll_one(fs, eng, id);
        JoinHandle(slot)
    }

    /// Poll every task woken since the last delivery. The delivery
    /// points call this themselves; it exists for a callback that woke
    /// a task by hand - fed a queue the task awaits, say - and wants it
    /// run now rather than at the next completion.
    pub fn run_woken(&mut self) {
        let (fs, eng, _) = self.split();
        drain(fs, eng);
    }
}

// ---- the facade a task submits through ------------------------------------

std::thread_local! {
    /// The facade of the poll in progress, parked by [`with_current`]
    /// for [`TaskFs`] to reach. `None` outside a poll.
    static CURRENT: Cell<Option<NonNull<FsConn<'static>>>> =
        const { Cell::new(None) };
}

/// The cell a scoped pointer parks in.
type ParkCell<T> = std::thread::LocalKey<Cell<Option<NonNull<T>>>>;

/// Restore a park cell on scope exit, a panic included: a panicking
/// task unwinds through the host loop, and the cell must not keep
/// naming a facade that died with this frame.
struct Restore<T: 'static>(&'static ParkCell<T>, Option<NonNull<T>>);

impl<T: 'static> Drop for Restore<T> {
    fn drop(&mut self) {
        self.0.with(|c| c.set(self.1));
    }
}

/// Park `ptr` in `cell` for the dynamic extent of `f`.
///
/// Generic over the parked type so the protocol can be exercised
/// without an io_uring ring: every test that reaches it through
/// [`FsConn`] builds a real one, and Miri aborts on `io_uring_setup`
/// rather than taking the skip path, which would leave the only
/// `unsafe` in this module unvalidated by it.
fn park_in<T: 'static, R>(
    cell: &'static ParkCell<T>,
    ptr: NonNull<T>,
    f: impl FnOnce() -> R,
) -> R {
    let _restore = Restore(cell, cell.with(|c| c.replace(Some(ptr))));
    f()
}

/// Reach whatever `cell` holds, for the extent of `f`. `None` when
/// nothing is parked.
///
/// **The pointer is taken for the call**, so a nested reach finds an
/// empty cell rather than deriving a second live `&mut` to the same
/// value, and the guard puts it back however `f` ends.
fn reach_in<T: 'static, R>(
    cell: &'static ParkCell<T>,
    f: impl FnOnce(&mut T) -> R,
) -> Option<R> {
    cell.with(|c| {
        let ptr = c.take()?;
        let _restore = Restore(cell, Some(ptr));
        // SAFETY: `ptr` was parked by `park_in` around a call that is
        // still on this thread's stack, so the value it names outlives
        // this borrow; the `take` above makes this the only live
        // reference derived from it, and `f` is generic over the
        // borrow's lifetime so the reference cannot escape.
        let val = unsafe { &mut *ptr.as_ptr() };
        Some(f(val))
    })
}

/// Park `conn` in [`CURRENT`] for the duration of `f` (a task poll).
fn with_current<R>(conn: &mut FsConn<'_>, f: impl FnOnce() -> R) -> R {
    // The lifetime is erased for storage only: the pointer is taken
    // back out strictly inside `f`'s dynamic extent, where `conn` is
    // still exclusively this frame's.
    let ptr = NonNull::from(conn).cast::<FsConn<'static>>();
    park_in(&CURRENT, ptr, f)
}

/// Reach the poll's parked facade. `None` outside a poll. The pointer
/// is *taken* for the call - a nested reach sees an empty cell rather
/// than a second `&mut` to the same facade.
fn with_conn<R>(f: impl FnOnce(&mut FsConn<'_>) -> R) -> Option<R> {
    // The `'static` in the cell is storage-only: `f` is generic over
    // the facade's lifetime, so the reference cannot escape it.
    reach_in(&CURRENT, f)
}

/// A task's handle to the facade of whichever poll is running it.
///
/// Handed to the task body by [`FsConn::spawn`]; methods work only
/// while the task is being polled (which is the only time the task's
/// code runs). It is not `Send`: a task and its ops belong to the loop
/// thread. Smuggling it elsewhere and calling it there debug-asserts,
/// and in release resolves the op as `ECANCELED` / drops the spawn,
/// the facade's shape for a submission that cannot happen.
///
/// **Deliberately not `Clone`.** It carries no task identity, so a
/// copy kept past its poll - parked in connection state, say - and
/// used during a *different* task's poll would find `CURRENT`
/// populated, submit against that task's facade, and be stamped its
/// owner: the wrong connection's teardown sweep would then cancel the
/// op, and the right one would leave its descriptor parked. No assert
/// can catch that, because from inside the cell it is indistinguishable
/// from a legitimate submission. Without `Clone` the handle cannot
/// outlive the body it was handed to.
pub struct TaskFs {
    _on_loop: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for TaskFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskFs").finish_non_exhaustive()
    }
}

impl TaskFs {
    fn new() -> TaskFs {
        TaskFs {
            _on_loop: PhantomData,
        }
    }

    /// [`FsConn::fut`] against the running poll's facade.
    pub fn fut(
        &self,
        submit: impl FnOnce(&mut FsConn<'_>, OnDone),
    ) -> FsFuture {
        match with_conn(|conn| conn.fut(submit)) {
            Some(f) => f,
            None => {
                debug_assert!(false, "TaskFs::fut outside a task poll");
                FsFuture(Slot::gone())
            }
        }
    }

    /// [`FsConn::offload_fut`] against the running poll's facade.
    pub fn offload_fut<T, J>(&self, job: J) -> OffloadFuture<T>
    where
        J: FnOnce() -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        match with_conn(|conn| conn.offload_fut(job)) {
            Some(f) => f,
            None => {
                debug_assert!(false, "TaskFs::offload_fut outside a task poll");
                OffloadFuture(Slot::gone())
            }
        }
    }

    /// [`FsConn::result_fut`] against the running poll's facade.
    pub fn result_fut<T, S>(&self, submit: S) -> OffloadFuture<T>
    where
        S: FnOnce(&mut FsConn<'_>, OnResult<T>),
        T: 'static,
    {
        match with_conn(|conn| conn.result_fut(submit)) {
            Some(f) => f,
            None => {
                debug_assert!(false, "TaskFs::result_fut outside a task poll");
                OffloadFuture(Slot::gone())
            }
        }
    }

    /// [`FsConn::spawn`] against the running poll's facade: the child
    /// task shares this task's owner and is polled once inline. The
    /// handle lets the spawning task await the child's output - two
    /// children spawned back to back run their ops concurrently, and
    /// awaiting both is a join.
    pub fn spawn<F, Fut, T>(&self, body: F) -> JoinHandle<T>
    where
        F: FnOnce(TaskFs) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        match with_conn(|conn| conn.spawn(body)) {
            Some(handle) => handle,
            None => {
                debug_assert!(false, "TaskFs::spawn outside a task poll");
                JoinHandle(Slot::gone())
            }
        }
    }
}

// ---- the task table and its run queue -------------------------------------

/// A task's slot and the incarnation of it this handle names.
///
/// Not packed into a `u64`: no task id ever reaches `user_data`, so
/// nothing here is bounded by the 24-bit slot field the ring routing
/// tokens use, and a full-width generation is what
/// [`SlotEntry`](crate::uring::slots::SlotEntry) documents the reason
/// for - a `Waker` is exactly the long-retained handle that must not
/// alias a future incarnation after the counter wraps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TaskId {
    idx: u32,
    generation: u64,
}

/// What a waker reaches: the run queue, its emptiness hint, and the
/// loop's wake eventfd for an off-loop wake.
pub(crate) struct RunShared {
    /// Woken task ids, in wake order.
    queue: Mutex<VecDeque<TaskId>>,
    /// Queue-length hint, so the per-completion drain check is one
    /// relaxed load instead of a lock acquisition.
    ready: AtomicUsize,
    /// Set for the extent of a [`drain`] pass. A wake landing inside a
    /// pass is taken by that pass or by its trailing poke; a wake
    /// landing outside one has nothing scheduled to collect it, so it
    /// must poke for itself. Nested passes clear it early, which can
    /// only cause a redundant poke - never a missed one - so the flag
    /// needs no depth count.
    draining: AtomicBool,
    /// The loop's shared flags and wake eventfd.
    wake: Arc<LoopShared>,
    /// The loop thread, recorded at first spawn.
    #[cfg(not(loom))]
    loop_thread: std::thread::ThreadId,
    /// The model's stand-in for the thread check. A `cfg` hard-coding
    /// this to `true` is what made the on-loop branch - where the
    /// wake-outside-a-pass bug lived - unreachable from any model
    /// while the module claimed its models carried the liveness
    /// argument; keep it settable so both branches stay expressible.
    #[cfg(loom)]
    model_off_loop: bool,
}

impl RunShared {
    /// Whether the caller is off the loop thread. Under loom there is
    /// no thread identity to read, so a model states which side it is
    /// exercising; both are modelled.
    fn off_loop(&self) -> bool {
        #[cfg(loom)]
        {
            self.model_off_loop
        }
        #[cfg(not(loom))]
        {
            std::thread::current().id() != self.loop_thread
        }
    }

    /// Pop the next woken task id, if any.
    pub(crate) fn take_ready(&self) -> Option<TaskId> {
        let id = self
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()?;
        self.ready.fetch_sub(1, Ordering::AcqRel);
        Some(id)
    }
}

/// One task's waker target. [`std::task::Wake`] wants `std::sync::Arc`
/// specifically, so that is what holds it; the fields go through
/// `crate::sync` like every cross-thread protocol here, so the loom
/// models can drive [`wake_task`] itself.
pub(crate) struct TaskWake {
    id: TaskId,
    /// Wake-dedup edge: set by the wake that enqueues, cleared by
    /// [`poll_window`] just before the task runs.
    queued: AtomicBool,
    run: Arc<RunShared>,
}

impl std::task::Wake for TaskWake {
    fn wake(self: std::sync::Arc<Self>) {
        wake_task(&self);
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        wake_task(self);
    }
}

/// Wake one task: enqueue its id exactly once per wake edge, and poke
/// the loop unless a drain pass is already running to collect it.
/// Returns whether this call enqueued (a dedup-skipped wake returns
/// `false`).
///
/// **The discriminant is whether a pass is running, not which thread
/// the wake came from.** An on-loop wake outside a pass (the inline
/// poll in [`FsConn::spawn`], or a callback waking a task by hand) is
/// otherwise scheduled by nothing: the id sits in the queue while the
/// loop parks on a ring that has no reason to complete, and the
/// `queued` edge then latches, so every later wake - an off-loop one
/// included - is deduped away and the task is unreachable for the
/// life of the reactor.
///
/// Push under the lock, then poke - `finish_offload`'s protocol, and
/// the same one-direction ordering argument: poke first and the loop
/// can wake, find nothing, and park again with the id enqueued behind
/// it.
///
/// A skipped wake is covered by a poll that has not started yet: the
/// flag is set either while the id still sits in the queue, or in the
/// window between its pop and [`poll_window`] - and in both a poll of
/// this task starts after this call returns, which is all the waker
/// contract asks.
pub(crate) fn wake_task(w: &TaskWake) -> bool {
    if w.queued.swap(true, Ordering::AcqRel) {
        return false;
    }
    w.run
        .queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back(w.id);
    w.run.ready.fetch_add(1, Ordering::Release);
    if w.run.off_loop() || !w.run.draining.load(Ordering::Acquire) {
        w.run.wake.wake.poke();
    }
    true
}

/// Run one poll inside the task's window: the dedup edge clears
/// strictly *before* `poll`, so a wake landing mid-poll enqueues a
/// fresh pass instead of vanishing into a poll already past the state
/// it was announcing. Clearing after the poll is the lost-wakeup bug
/// the loom model bites on; the pairing lives here, once, so the model
/// drives the shipping order rather than a copy of it.
pub(crate) fn poll_window<R>(w: &TaskWake, poll: impl FnOnce() -> R) -> R {
    w.queued.store(false, Ordering::Release);
    poll()
}

/// Answers a task's [`JoinHandle`] when its poll unwinds; type-erased
/// because the table cannot name a task's output type.
type PanicSink = Box<dyn FnOnce(Box<dyn std::any::Any + Send>)>;

struct TaskEntry {
    fut: Pin<Box<dyn Future<Output = ()>>>,
    on_panic: Option<PanicSink>,
    owner: Owner,
    wake: std::sync::Arc<TaskWake>,
    waker: Waker,
}

struct TaskSlot {
    /// Bumped at retire, so a stale waker's id misses and its wake is
    /// inert - the run queue may hold ids for tasks already gone.
    generation: u64,
    /// `None` while free *or* while the entry is out being polled; the
    /// free list is what distinguishes the two.
    entry: Option<TaskEntry>,
}

/// The reactor's tasks. A field of `FsCore`, so every host that fires
/// callbacks can drain the woken ones with the same borrows.
pub(crate) struct Tasks {
    slots: Vec<TaskSlot>,
    free: Vec<u32>,
    /// Live tasks - inserted, not yet retired. Shared with an
    /// embedding host so its drain can see work a connection table
    /// cannot: a task can be pending with no connection and no op in
    /// flight, which is invisible to a check that counts connections.
    live: Rc<Cell<usize>>,
    /// Lazily built at the first spawn: the queue needs the engine's
    /// wake eventfd, which `FsCore::new` does not see.
    run: Option<Arc<RunShared>>,
}

impl Tasks {
    pub(crate) fn new() -> Tasks {
        Tasks {
            slots: Vec::new(),
            free: Vec::new(),
            live: Rc::new(Cell::new(0)),
            run: None,
        }
    }

    fn insert(
        &mut self,
        eng: &Engine,
        owner: Owner,
        fut: Pin<Box<dyn Future<Output = ()>>>,
        on_panic: PanicSink,
    ) -> TaskId {
        let run = self.run.get_or_insert_with(|| {
            Arc::new(RunShared {
                queue: Mutex::new(VecDeque::new()),
                ready: AtomicUsize::new(0),
                draining: AtomicBool::new(false),
                wake: Arc::clone(&eng.shared),
                // The first spawn happens on the loop thread (spawns
                // come through a facade, and facades exist only
                // there), so this records the loop.
                #[cfg(not(loom))]
                loop_thread: std::thread::current().id(),
                #[cfg(loom)]
                model_off_loop: false,
            })
        });
        let idx = self.free.pop().unwrap_or_else(|| {
            self.slots.push(TaskSlot {
                generation: 0,
                entry: None,
            });
            (self.slots.len() - 1) as u32
        });
        let id = TaskId {
            idx,
            generation: self.slots[idx as usize].generation,
        };
        let wake = std::sync::Arc::new(TaskWake {
            id,
            queued: AtomicBool::new(false),
            run: Arc::clone(run),
        });
        let waker = Waker::from(std::sync::Arc::clone(&wake));
        self.live.set(self.live.get() + 1);
        self.slots[idx as usize].entry = Some(TaskEntry {
            fut,
            on_panic: Some(on_panic),
            owner,
            wake,
            waker,
        });
        id
    }

    /// A handle on the live-task count, for a host whose drain must
    /// wait for tasks as well as connections.
    pub(crate) fn gauge(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.live)
    }

    /// Take the entry out for a poll; `None` for a stale id (the task
    /// retired and its slot moved on) or one already out.
    fn take_if(&mut self, id: TaskId) -> Option<TaskEntry> {
        let s = self.slots.get_mut(id.idx as usize)?;
        if s.generation != id.generation {
            return None;
        }
        s.entry.take()
    }

    /// Re-enqueue `id` when its slot is the live tenant but currently
    /// out for a poll. A retired slot fails the generation test
    /// (`retire` bumps it) and a free slot cannot match a minted id,
    /// so this fires only for the mid-poll case.
    fn requeue_if_busy(&self, id: TaskId) {
        let busy = self.slots.get(id.idx as usize).is_some_and(|s| {
            s.generation == id.generation && s.entry.is_none()
        });
        if !busy {
            return;
        }
        let Some(run) = self.run.as_ref() else {
            return;
        };
        run.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(id);
        run.ready.fetch_add(1, Ordering::Release);
    }

    fn put_back(&mut self, idx: u32, entry: TaskEntry) {
        self.slots[idx as usize].entry = Some(entry);
    }

    fn retire(&mut self, idx: u32) {
        self.live.set(self.live.get().saturating_sub(1));
        let s = &mut self.slots[idx as usize];
        debug_assert!(s.entry.is_none(), "retiring a task still in its slot");
        s.generation = s.generation.wrapping_add(1);
        self.free.push(idx);
    }
}

/// Marks a drain pass live for [`wake_task`], and clears it however
/// the pass ends.
struct PassGuard(Arc<RunShared>);

impl Drop for PassGuard {
    fn drop(&mut self) {
        self.0.draining.store(false, Ordering::Release);
    }
}

/// Poll woken tasks, each with a fresh owner-scoped facade, bounded to
/// what was queued when the pass began. Called by the delivery points
/// after they fire callbacks, so a completion that woke a task runs it
/// in the same dispatch, at callback latency.
///
/// The entry bound is what keeps the ring serviced: a task that
/// re-wakes itself - or a cascade every pass extends - lands behind it
/// and waits for the next pass, so control returns to the host between
/// passes and CQEs are reaped instead of starved. Work left behind the
/// bound pokes the loop's wake eventfd; without that, a wake with
/// nothing left in flight - a parent woken by its child's final poll -
/// would wait on a completion that is never coming.
pub(crate) fn drain(fs: &mut FsCore, eng: &mut Engine) {
    let Some(run) = fs.tasks.run.as_ref().map(Arc::clone) else {
        return;
    };
    let mut budget = run.ready.load(Ordering::Acquire);
    if budget == 0 {
        return;
    }
    run.draining.store(true, Ordering::Release);
    // Cleared however the pass ends, an unwinding poll included: a
    // flag left set would silence every later wake's poke.
    let _pass = PassGuard(run);
    while budget > 0 {
        let Some(id) = fs.tasks.run.as_ref().and_then(|r| r.take_ready())
        else {
            return;
        };
        budget -= 1;
        poll_one(fs, eng, id);
    }
    if let Some(run) = fs.tasks.run.as_ref()
        && run.ready.load(Ordering::Acquire) != 0
    {
        // An on-loop poke: the pushes are this thread's and already
        // made, the eventfd counts, and the hosts keep its READ armed
        // - so the next wait completes at once and the leftover runs.
        run.wake.wake.poke();
    }
}

/// Poll one task. The entry is held out of the table for the poll, so
/// the facade the task submits through can borrow the tables freely;
/// a task that completes retires its slot, one that pends goes back.
fn poll_one(fs: &mut FsCore, eng: &mut Engine, id: TaskId) {
    let idx = id.idx;
    let Some(mut entry) = fs.tasks.take_if(id) else {
        // A live generation with no entry is the slot's tenant out
        // being polled - a re-entrant drain, which `run_woken` and the
        // facade a submit closure receives both make reachable. That
        // poll already cleared the dedup edge, so this id is the only
        // record of the wake: put it back rather than consume it, or
        // the task is never scheduled again.
        fs.tasks.requeue_if_busy(id);
        return;
    };
    let mut conn = FsConn::new(fs, eng, entry.owner);
    // Disjoint field borrows: the context reads the cached waker and
    // the window reads the wake edge while the poll borrows the
    // future - no waker clone (and no refcount traffic) per poll.
    let mut cx = Context::from_waker(&entry.waker);
    // The entry is out of the table for the poll, so an unwinding
    // future would otherwise leave the slot neither occupied nor free
    // - never reused, its generation never bumped, and `retire`'s own
    // guard unable to see it.
    let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_window(&entry.wake, || {
            with_current(&mut conn, || entry.fut.as_mut().poll(&mut cx))
        })
    }));
    match poll {
        Ok(Poll::Ready(())) => fs.tasks.retire(idx),
        Ok(Poll::Pending) => fs.tasks.put_back(idx, entry),
        Err(payload) => {
            // Contained: the handle learns what happened, the slot
            // retires, and the ring keeps serving every other
            // connection. The payload reaches the awaiter rather than
            // the loop, so a task's own bug cannot take down requests
            // that have nothing to do with it.
            if let Some(sink) = entry.on_panic.take() {
                sink(payload);
            }
            drop(entry);
            fs.tasks.retire(idx);
        }
    }
}

// ---- loom: the wake protocol ----------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// Two claims carry the executor's liveness, and both are cross-thread:
// a wake from off the loop is never lost between the queue and the
// poke (`wake_task`, the push-then-poke order), and a wake landing
// around a poll window is either absorbed by the poll that follows or
// re-enqueued - never swallowed (`poll_window` clearing the dedup edge
// *before* the poll). The models drive the shipping functions; a copy
// of their ordering would stay green with the shipping half weakened.
#[cfg(loom)]
mod loom_tests {
    use super::*;
    use crate::sync::atomic::{AtomicU64, AtomicUsize};
    use crate::uring::wake::WakeHandle;

    fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(f);
    }

    fn run_shared(off_loop: bool) -> Arc<RunShared> {
        Arc::new(RunShared {
            queue: Mutex::new(VecDeque::new()),
            ready: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
            model_off_loop: off_loop,
            wake: Arc::new(LoopShared {
                stop: AtomicBool::new(false),
                graceful: AtomicBool::new(false),
                grace_ms: AtomicU64::new(0),
                wake: WakeHandle::new().expect("the model's wake"),
            }),
        })
    }

    /// A wake racing the drain is delivered exactly once: either this
    /// pass pops it, or the poke leaves the next armed READ completing
    /// immediately and that pass pops it. Zero is the lost wakeup
    /// `wake_task`'s push-then-poke order exists to prevent; two would
    /// be a dedup failure.
    #[test]
    fn loom_a_task_wake_is_never_lost() {
        bounded_model(|| {
            // The **on-loop** branch: no pass is running, so the wake
            // must poke for itself. Gate the poke on `off_loop()`
            // alone and this model reports a deadlock - the loop
            // parks on an eventfd nothing wrote.
            let run = run_shared(false);
            let w = Arc::new(TaskWake {
                id: TaskId {
                    idx: 0,
                    generation: 0,
                },
                queued: AtomicBool::new(false),
                run: Arc::clone(&run),
            });

            let t = {
                let w = Arc::clone(&w);
                loom::thread::spawn(move || {
                    wake_task(&w);
                })
            };

            // The loop as the hosts run it: wake (park on the eventfd
            // stand-in), then drain the queue. Push-then-poke is what
            // makes this terminate - poke first and a schedule exists
            // where the poke is consumed before the push is visible,
            // the pop finds nothing, and the next wait parks forever
            // (loom reports the deadlock).
            let mut delivered = 0usize;
            while delivered == 0 {
                run.wake.wake.drain();
                while let Some(_id) = run.take_ready() {
                    poll_window(&w, || ());
                    delivered += 1;
                }
            }
            t.join().expect("waker thread");
            assert_eq!(delivered, 1, "one wake, {delivered} deliveries");
        });
    }

    /// An **off-loop** wake landing while a pass is running still
    /// pokes: `wake_task`'s condition is `off_loop() || !draining`,
    /// and the left arm is what covers a foreign thread whose wake
    /// the running pass may already have passed by. Narrow the
    /// condition to `!draining` alone and this model deadlocks - the
    /// loop parks while the id sits in the queue.
    ///
    /// (The on-loop-inside-a-pass case is deliberately not modelled
    /// here: on the loop thread the only wake source inside a pass is
    /// a poll, which runs before the pass's leftover check, so it is
    /// sequential and `a_self_waking_task_cannot_monopolise_a_drain_pass`
    /// covers it. Modelling it as a second thread would assert an
    /// interleaving the reactor cannot produce.)
    #[test]
    fn loom_an_off_loop_wake_during_a_pass_still_pokes() {
        bounded_model(|| {
            let run = run_shared(true);
            let w = Arc::new(TaskWake {
                id: TaskId {
                    idx: 0,
                    generation: 0,
                },
                queued: AtomicBool::new(false),
                run: Arc::clone(&run),
            });

            // A pass is live for the whole race.
            run.draining.store(true, Ordering::Release);
            let t = {
                let w = Arc::clone(&w);
                loom::thread::spawn(move || wake_task(&w))
            };

            // The loop: park on the eventfd, then drain the queue.
            let mut delivered = 0usize;
            while delivered == 0 {
                run.wake.wake.drain();
                while let Some(_id) = run.take_ready() {
                    poll_window(&w, || ());
                    delivered += 1;
                }
            }
            t.join().expect("waker thread");
            assert_eq!(delivered, 1, "one wake, {delivered} deliveries");
        });
    }

    /// Two threads racing one task's dedup edge: exactly one may
    /// claim it, and the queue carries exactly one id for the edge
    /// they raced over. The models above drive a single waker, so
    /// `queued.swap`'s losing side is only ever taken by the loop's
    /// own re-wake; two foreign wakers - a completion and an off-loop
    /// hand-wake arriving together - is the shape that exercises it.
    #[test]
    fn loom_two_wakers_race_one_edge() {
        bounded_model(|| {
            let run = run_shared(true);
            let w = Arc::new(TaskWake {
                id: TaskId {
                    idx: 0,
                    generation: 0,
                },
                queued: AtomicBool::new(false),
                run: Arc::clone(&run),
            });

            let hands: Vec<_> = (0..2)
                .map(|_| {
                    let w = Arc::clone(&w);
                    loom::thread::spawn(move || wake_task(&w))
                })
                .collect();
            let enqueued: usize = hands
                .into_iter()
                .map(|h| usize::from(h.join().expect("waker")))
                .sum();
            assert_eq!(enqueued, 1, "{enqueued} of 2 wakers claimed the edge");

            run.wake.wake.drain();
            let mut ids = 0usize;
            while let Some(_id) = run.take_ready() {
                poll_window(&w, || ());
                ids += 1;
            }
            assert_eq!(ids, 1, "the queue held {ids} ids for one edge");
        });
    }

    /// A pass that samples a budget of zero still leaves the id
    /// reachable. `drain` reads `ready` once at entry and polls no
    /// more than that, while `wake_task` pushes the id *before*
    /// incrementing - so a pass can genuinely see zero with an id
    /// already queued. That window is harmless because the increment
    /// precedes the poke, so the loop the poke wakes reads a budget
    /// that covers the id; the property worth holding is liveness,
    /// not any instantaneous relation between counter and queue.
    #[test]
    fn loom_a_zero_budget_pass_still_delivers() {
        bounded_model(|| {
            let run = run_shared(true);
            let w = Arc::new(TaskWake {
                id: TaskId {
                    idx: 0,
                    generation: 0,
                },
                queued: AtomicBool::new(false),
                run: Arc::clone(&run),
            });

            let t = {
                let w = Arc::clone(&w);
                loom::thread::spawn(move || wake_task(&w))
            };

            // `drain`'s shape: sample once, poll no more than that.
            let mut polled = 0usize;
            for _ in 0..run.ready.load(Ordering::Acquire) {
                if run.take_ready().is_some() {
                    poll_window(&w, || ());
                    polled += 1;
                }
            }
            if polled == 0 {
                // Deliberately *before* the join: joining first would
                // serialize the waker's whole epilogue and the
                // ordering this guards would be unobservable. The loop
                // parks on the poke, so what must hold is that the
                // count is published before the poke that wakes a
                // reader of it.
                run.wake.wake.drain();
                let budget = run.ready.load(Ordering::Acquire);
                assert!(budget > 0, "a poke woke a pass with no budget");
                let mut later = 0usize;
                for _ in 0..budget {
                    if run.take_ready().is_some() {
                        poll_window(&w, || ());
                        later += 1;
                    }
                }
                assert_eq!(later, 1, "the id was not reachable after");
            }
            t.join().expect("waker thread");
        });
    }

    /// A wake landing around a poll window is never swallowed: if the
    /// waker's call was dedup-skipped, a poll of that task *starts*
    /// after it - which is all the waker contract asks. [`poll_window`]
    /// clearing the edge before the poll is what makes it true; clear
    /// after the poll instead and a wake mid-poll skips against a stale
    /// edge with no later poll coming, which this model reports.
    #[test]
    fn loom_a_wake_around_a_poll_window_is_covered() {
        bounded_model(|| {
            let run = run_shared(true);
            let w = Arc::new(TaskWake {
                id: TaskId {
                    idx: 0,
                    generation: 0,
                },
                queued: AtomicBool::new(false),
                run: Arc::clone(&run),
            });
            // First wake, on the loop side: the task is queued as a
            // completion would leave it.
            wake_task(&w);

            let polls = Arc::new(AtomicUsize::new(0));
            let t = {
                let (w, polls) = (Arc::clone(&w), Arc::clone(&polls));
                loom::thread::spawn(move || {
                    let before = polls.load(Ordering::Acquire);
                    let enqueued = wake_task(&w);
                    (before, enqueued)
                })
            };

            // The loop: pop, then poll inside the window.
            let mut drained = 0usize;
            while let Some(_id) = run.take_ready() {
                poll_window(&w, || {
                    polls.fetch_add(1, Ordering::Release);
                });
                drained += 1;
            }
            let (before, enqueued) = t.join().expect("waker thread");
            run.wake.wake.drain();
            while let Some(_id) = run.take_ready() {
                poll_window(&w, || {
                    polls.fetch_add(1, Ordering::Release);
                });
                drained += 1;
            }
            assert!(drained >= 1, "the first wake was lost");
            if !enqueued {
                // A skipped wake must be covered by a poll that had
                // not started when the wake returned.
                assert!(
                    polls.load(Ordering::Acquire) > before,
                    "a dedup-skipped wake was never followed by a poll"
                );
            }
        });
    }
}

// ---- tests ----------------------------------------------------------------

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::sync_fs::{AtFlags, Mode, OFlag, OpenHow, StatxMask};
    use crate::uring::sys::{IORING_CQE_F_MORE, register_personality};
    use crate::uring::user_data::{TAG_FS_DOMAIN, pack_raw, unpack_raw};
    use crate::uring_fs::core::{
        TAG_CANCEL, TAG_WAKE, deliver_embedded, deliver_pool_completions,
    };
    use crate::uring_fs::{
        Anchor, Leaf, OffloadBounds, OpenStep, Personality, RwFlags, StepPath,
        ZfsAttr,
    };
    use std::cell::Cell as StdCell;
    use std::cell::RefCell as StdRefCell;
    use std::time::{Duration, Instant};

    const RING_ENTRIES: u32 = 64;
    const POOL: u32 = 8;

    /// Build a real `Engine` or signal an environment skip (mirrors the
    /// integration suites' io_uring guard, gate included).
    fn engine_or_skip() -> Option<Engine> {
        match Engine::new(RING_ENTRIES, POOL) {
            Ok(e) => Some(e),
            Err(crate::Error::Errno(e))
                if crate::uring::setup_unavailable(e) =>
            {
                None
            }
            Err(e) => panic!("Engine::new: {e}"),
        }
    }

    /// A ring, its fs tables, and a personality for the tests' own
    /// credentials - or a skip where rings cannot be created.
    fn rig() -> Option<(Engine, FsCore, Personality)> {
        let eng = engine_or_skip()?;
        let who = Personality(
            register_personality(eng.ring.raw_fd())
                .expect("register_personality"),
        );
        Some((eng, FsCore::new(8, OffloadBounds::default()), who))
    }

    /// One pass of the host loop: flush staged SQEs, then route every
    /// reaped CQE exactly as `UringFs::dispatch` does. Never blocks -
    /// [`drive`] bounds a stall with a deadline instead, so a broken
    /// chain names itself rather than hanging the suite.
    fn turn(fs: &mut FsCore, eng: &mut Engine) -> usize {
        eng.ring.submit().expect("submit");
        let mut reaped_n = 0;
        while let Some(cqe) = eng.ring.reap() {
            reaped_n += 1;
            if cqe.flags & IORING_CQE_F_MORE == 0 {
                eng.inflight = eng.inflight.saturating_sub(1);
            }
            let (tag, slot, gen32) = unpack_raw(cqe.user_data);
            if tag & TAG_FS_DOMAIN == 0 {
                continue;
            }
            match tag {
                TAG_WAKE => {
                    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0))
                        .expect("re-arm wake");
                    deliver_pool_completions(fs, eng);
                }
                TAG_CANCEL => {}
                _ => {
                    let reaped = fs.on_cqe(eng, tag, slot, gen32, cqe.res);
                    deliver_embedded(fs, eng, reaped);
                }
            }
        }
        reaped_n
    }

    /// Drive turns until `done` reads true; panic past the deadline so
    /// a stalled chain names itself instead of hanging the suite.
    fn drive(
        fs: &mut FsCore,
        eng: &mut Engine,
        done: &Rc<StdCell<bool>>,
        what: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done.get() {
            assert!(Instant::now() < deadline, "{what}: never finished");
            if turn(fs, eng) == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Pending pokes on the wake eventfd, read without blocking. The
    /// counter is consumed by the read, as the loop's armed READ does.
    fn pending_pokes(run: &RunShared) -> u64 {
        let mut buf: u64 = 0;
        // SAFETY: an 8-byte read from the live eventfd into a `u64`;
        // the fd is non-blocking, so an empty counter answers EAGAIN
        // rather than parking the test.
        let n = unsafe {
            libc::read(
                run.wake.wake.as_raw_fd(),
                std::ptr::addr_of_mut!(buf).cast::<libc::c_void>(),
                8,
            )
        };
        if n == 8 { buf } else { 0 }
    }

    fn spec_dir() -> OpenHow {
        OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY)
    }

    fn creating() -> OpenHow {
        OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600))
    }

    /// A timer completes on its own ring: relative, one-shot, expiry
    /// delivered as success - and not before its duration has passed.
    #[test]
    fn a_timer_fires_after_its_duration() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        let done = Rc::new(StdCell::new(false));
        let started = Instant::now();
        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.timeout(Duration::from_millis(50), move |d, _conn| {
                assert!(
                    d.result().is_ok(),
                    "expiry is success, not ETIME: {:?}",
                    d.result().err()
                );
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "timer");
        assert!(
            started.elapsed() >= Duration::from_millis(45),
            "fired early: {:?}",
            started.elapsed()
        );
    }

    /// The timer composes with the future layer like any submission: a
    /// task awaits its tick and resumes on the loop that armed it.
    #[test]
    fn a_task_awaits_a_timer() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        let done = Rc::new(StdCell::new(false));
        let started = Instant::now();
        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let fired = t
                    .fut(|c, cb| c.timeout(Duration::from_millis(30), cb))
                    .await;
                assert!(fired.result().is_ok(), "{:?}", fired.result().err());
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "task timer");
        assert!(
            started.elapsed() >= Duration::from_millis(25),
            "fired early: {:?}",
            started.elapsed()
        );
    }

    /// The core claim: a whole write chain - open, write, fsync, stat,
    /// read back - as one straight-line task, every hop on the ring.
    #[test]
    fn a_task_awaits_a_whole_chain_on_the_ring() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let payload: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let done = Rc::new(StdCell::new(false));

        {
            let (done, payload) = (Rc::clone(&done), payload.clone());
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let opened = t
                    .fut(|c, cb| {
                        c.open(who, &anchor, c"demo.bin", creating(), cb)
                    })
                    .await;
                let file = opened.file().expect("open");

                let wrote = t
                    .fut(|c, cb| {
                        c.pwritev2(
                            who,
                            file.clone(),
                            vec![payload.clone()],
                            0,
                            RwFlags::empty(),
                            cb,
                        )
                    })
                    .await;
                assert_eq!(
                    wrote.result().expect("write") as usize,
                    payload.len()
                );

                t.fut(|c, cb| c.fsync(who, file.clone(), cb))
                    .await
                    .result()
                    .expect("fsync");

                let stat = t
                    .fut(|c, cb| {
                        c.fstatx(
                            who,
                            &file,
                            AtFlags::empty(),
                            StatxMask::BASIC_STATS,
                            cb,
                        )
                    })
                    .await;
                assert_eq!(
                    stat.stat().expect("statx").size(),
                    payload.len() as u64
                );

                let read = t
                    .fut(|c, cb| {
                        c.preadv2(
                            who,
                            file.clone(),
                            vec![vec![0u8; payload.len()]],
                            0,
                            RwFlags::empty(),
                            cb,
                        )
                    })
                    .await;
                assert_eq!(
                    read.result().expect("read") as usize,
                    payload.len()
                );
                assert_eq!(read.into_bufs()[0], payload);
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "write chain");
    }

    /// Two futures made back to back are both in flight before either
    /// is awaited - eager submission is what overlaps them.
    #[test]
    fn futures_submit_eagerly_and_overlap() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        std::fs::write(dir.path().join("a"), b"a").expect("seed a");
        std::fs::write(dir.path().join("b"), b"bb").expect("seed b");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let ro = || OpenHow::new().flags(OFlag::O_RDONLY);
                let a = t.fut(|c, cb| c.open(who, &anchor, c"a", ro(), cb));
                let b = t.fut(|c, cb| c.open(who, &anchor, c"b", ro(), cb));
                // Both submitted above; awaiting in either order works.
                let (a, b) = (a.await, b.await);
                assert!(a.file().is_some(), "a: {:?}", a.result());
                assert!(b.file().is_some(), "b: {:?}", b.result());
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "overlapping opens");
    }

    /// A refused submission resolves with the reason, not a blanket
    /// `ECANCELED`: an argument the facade will never accept answers
    /// `EINVAL`, and a full op table answers `EBUSY` - which a task
    /// can retry. Both arrive with no CQE ever produced.
    #[test]
    fn a_refusal_resolves_with_the_errno_it_was_refused_for() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // An absolute path: refused by the facade, never submitted.
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let bad = conn.fut(|c, cb| {
            c.open(who, &anchor, c"/etc/hostname", creating(), cb)
        });
        let mut bad = std::pin::pin!(bad);
        let Poll::Ready(done) = bad.as_mut().poll(&mut cx) else {
            panic!("a refused submission left its future pending");
        };
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))),
            "want EINVAL, got {:?}",
            done.result()
        );

        // Fill the op table (8 slots), then one more: EBUSY.
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(
                conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)),
            );
        }
        let busy = held
            .into_iter()
            .filter_map(|f| {
                let mut f = std::pin::pin!(f);
                match f.as_mut().poll(&mut cx) {
                    Poll::Ready(d) => Some(d.result()),
                    Poll::Pending => None,
                }
            })
            .find(|r| matches!(r, Err(crate::Error::Errno(Errno::EBUSY))));
        assert!(
            busy.is_some(),
            "a full op table must answer EBUSY, not ECANCELED"
        );
    }

    /// ZFS's `f_type` magic - `statfs(2)`, and `Statfs::fs_type`'s own
    /// doc.
    const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

    /// The offload-shaped half of the facade, awaited from one task: the
    /// capacity tail, the xattr list, the ZFS attribute ioctl,
    /// server-side copy, and the `open_dir`/`next_batch` walk whose
    /// first step is itself a ring op.
    ///
    /// This is also the module's only test whose result depends on which
    /// filesystem it runs on, and it needs no fixture to be: it reads
    /// `f_type` through the same `fstatfs` it is exercising, then
    /// requires the attribute ioctl to answer `Ok` on ZFS and `ENOTTY`
    /// anywhere else. Point `TMPDIR` at a dataset and it takes the ZFS
    /// arm; leave it on tmpfs and it takes the other. Both arms are
    /// assertions, so neither silently degrades into a skip.
    ///
    /// Outcomes are collected and asserted after the drive rather than
    /// inside the body: an `assert!` in a task body is contained into
    /// its `JoinHandle`, so it would surface as this test's deadline
    /// expiring with the message lost.
    #[test]
    fn a_task_awaits_the_offload_shaped_ops_and_sees_the_filesystem() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let done = Rc::new(StdCell::new(false));

        type Seen = (
            Option<i64>,                    // fstatfs f_type
            Option<usize>,                  // flistxattr count
            Option<crate::Result<ZfsAttr>>, // the ioctl, either way
            Option<crate::Result<u64>>,     // copy_file_range
            Option<usize>,                  // next_batch names
        );
        let seen: Rc<StdRefCell<Seen>> =
            Rc::new(StdRefCell::new(Default::default()));

        {
            let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
            let anchor2 = anchor.clone();
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let src = t
                    .fut(|c, cb| {
                        c.open(who, &anchor2, c"src.bin", creating(), cb)
                    })
                    .await
                    .file()
                    .expect("open src");
                let wrote = t
                    .fut(|c, cb| {
                        c.pwritev2(
                            who,
                            src.clone(),
                            vec![b"payload".to_vec()],
                            0,
                            RwFlags::empty(),
                            cb,
                        )
                    })
                    .await;
                assert_eq!(wrote.result().expect("write"), 7);

                let st = t
                    .result_fut(|c, cb| c.fstatfs(src.clone(), cb))
                    .await
                    .expect("fstatfs");
                seen.borrow_mut().0 = Some(st.fs_type());

                let names = t
                    .result_fut(|c, cb| c.flistxattr(src.clone(), cb))
                    .await
                    .expect("flistxattr");
                seen.borrow_mut().1 = Some(names.len());

                seen.borrow_mut().2 = Some(
                    t.result_fut(|c, cb| c.fget_zfs_attrs(src.clone(), cb))
                        .await,
                );

                let dst = t
                    .fut(|c, cb| {
                        c.open(who, &anchor2, c"dst.bin", creating(), cb)
                    })
                    .await
                    .file()
                    .expect("open dst");
                seen.borrow_mut().3 = Some(
                    t.result_fut(|c, cb| {
                        c.copy_file_range(src.clone(), dst, 0, 0, 7, cb)
                    })
                    .await,
                );

                let walk = t
                    .result_fut(|c, cb| c.open_dir(who, &anchor2, cb))
                    .await
                    .expect("open_dir");
                let batch = t
                    .result_fut(|c, cb| c.next_batch(&walk, cb))
                    .await
                    .expect("next_batch");
                seen.borrow_mut().4 = Some(batch.names.len());

                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "offload-shaped ops");

        let (f_type, xattrs, zfs, copied, entries) =
            std::mem::take(&mut *seen.borrow_mut());
        let f_type = f_type.expect("fstatfs answered");
        assert_eq!(xattrs, Some(0), "a fresh file carries no xattrs");
        assert_eq!(copied.expect("copy answered").expect("copy"), 7);
        assert_eq!(entries, Some(2), "src.bin and dst.bin");

        let zfs = zfs.expect("the ioctl answered");
        if f_type == ZFS_SUPER_MAGIC {
            zfs.expect("a ZFS dataset must answer the attribute ioctl");
        } else {
            match zfs {
                Err(crate::Error::Errno(Errno::ENOTTY)) => {}
                other => panic!(
                    "f_type {f_type:#x} is not ZFS, so the attribute ioctl \
                     must answer ENOTTY, not {other:?}"
                ),
            }
        }
    }

    /// A refusal hands the payload back, because the retry it advises
    /// is impossible without it: the buffers a write was given are
    /// dropped on the way out of `deliver`, and nothing tells a caller
    /// to keep a second copy.
    #[test]
    fn a_refusal_hands_back_the_payload_it_advises_retrying() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let done = Rc::new(StdCell::new(false));
        /// Whether the refusal was marked as this crate's, and the
        /// payload it handed back.
        type Refused = Option<(bool, Vec<Vec<u8>>)>;
        let seen: Rc<StdRefCell<Refused>> = Rc::new(StdRefCell::new(None));

        {
            let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
            let anchor2 = anchor.clone();
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let file = t
                    .fut(|c, cb| {
                        c.open(who, &anchor2, c"payload.bin", creating(), cb)
                    })
                    .await
                    .file()
                    .expect("open");
                // Fill the op table, then write through it.
                let mut held = Vec::new();
                for _ in 0..POOL {
                    held.push(t.fut(|c, cb| {
                        c.open(who, &anchor2, c".", spec_dir(), cb)
                    }));
                }
                let refused = t
                    .fut(|c, cb| {
                        c.pwritev2(
                            who,
                            file,
                            vec![b"the body a retry needs".to_vec()],
                            0,
                            RwFlags::empty(),
                            cb,
                        )
                    })
                    .await;
                assert!(
                    matches!(
                        refused.result(),
                        Err(crate::Error::Errno(Errno::EBUSY))
                    ),
                    "a full op table must answer EBUSY"
                );
                *seen.borrow_mut() =
                    Some((refused.was_refused(), refused.into_bufs()));
                drop(held);
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "refused payload");

        let (refused, bufs) = std::mem::take(&mut *seen.borrow_mut())
            .expect("the write answered");
        assert!(refused, "a full op table is this crate's refusal");
        assert_eq!(
            bufs,
            vec![b"the body a retry needs".to_vec()],
            "a refusal that keeps the payload cannot be retried"
        );
    }

    /// The errno alone cannot say who answered. `EBUSY` from a full op
    /// table is worth retrying; `EBUSY` from the kernel - a directory
    /// that is a mountpoint, which every nested dataset is - is
    /// permanent, so a task that cannot tell them apart spins forever.
    #[test]
    fn a_refused_errno_is_marked_as_this_crates_own() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let done = Rc::new(StdCell::new(false));
        let seen: Rc<StdRefCell<Vec<(Errno, bool)>>> =
            Rc::new(StdRefCell::new(Vec::new()));

        {
            let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
            let anchor2 = anchor.clone();
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                // The kernel's: nothing of that name.
                let miss = t
                    .fut(|c, cb| {
                        c.statx(
                            who,
                            &anchor2,
                            Leaf::new(b"absent").expect("leaf"),
                            AtFlags::empty(),
                            StatxMask::INO,
                            cb,
                        )
                    })
                    .await;
                let Err(crate::Error::Errno(e)) = miss.result() else {
                    panic!("a missing name must fail");
                };
                seen.borrow_mut().push((e, miss.was_refused()));

                // This crate's: an absolute path the facade will not take.
                let bad = t
                    .fut(|c, cb| {
                        c.open(who, &anchor2, c"/etc/hostname", creating(), cb)
                    })
                    .await;
                let Err(crate::Error::Errno(e)) = bad.result() else {
                    panic!("an absolute path must be refused");
                };
                seen.borrow_mut().push((e, bad.was_refused()));
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "refusal provenance");

        let seen = std::mem::take(&mut *seen.borrow_mut());
        assert_eq!(
            seen,
            vec![(Errno::ENOENT, false), (Errno::EINVAL, true)],
            "the kernel's errno must not read as a refusal, nor the reverse"
        );
    }

    /// A chain submits every step after the first from the fresh facade
    /// its predecessor's completion was handed. A sink that one
    /// submission consumed would leave every later step reporting
    /// teardown for a refusal the caller is told to retry.
    #[test]
    fn a_chain_step_past_the_first_still_names_its_refusal() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir sub");
        std::fs::write(dir.path().join("sub/leaf"), b"x").expect("leaf");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let chained = {
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.fut(|c, cb| {
                c.open_chain(
                    &anchor,
                    vec![
                        OpenStep {
                            path: StepPath::Fixed(c"sub".to_owned()),
                            who,
                            how: spec_dir(),
                        },
                        OpenStep {
                            path: StepPath::Fixed(c"leaf".to_owned()),
                            who,
                            how: OpenHow::new().flags(OFlag::O_RDONLY),
                        },
                    ],
                    cb,
                )
            })
        };
        let mut chained = std::pin::pin!(chained);

        // Take every free slot in the window `on_cqe` opens and
        // `deliver_embedded` closes - which is exactly where the net
        // server's `redrive_parked_tail` takes one - so step two meets a
        // full table.
        let mut stolen = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        let done = loop {
            assert!(Instant::now() < deadline, "the chain never answered");
            if let Poll::Ready(d) = chained.as_mut().poll(&mut cx) {
                break d;
            }
            eng.ring.submit().expect("submit");
            let Some(cqe) = eng.ring.reap() else {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            };
            if cqe.flags & IORING_CQE_F_MORE == 0 {
                eng.inflight = eng.inflight.saturating_sub(1);
            }
            let (tag, slot, gen32) = unpack_raw(cqe.user_data);
            if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL {
                continue;
            }
            let reaped = fs.on_cqe(&mut eng, tag, slot, gen32, cqe.res);
            if !stolen {
                stolen = true;
                let mut thief = FsConn::new(&mut fs, &mut eng, None);
                for _ in 0..POOL {
                    thief.open(who, &anchor, c".", spec_dir(), |_, _| {});
                }
            }
            deliver_embedded(&mut fs, &mut eng, reaped);
        };

        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
            "step two's refusal must keep its errno, got {:?}",
            done.result()
        );
        assert!(done.was_refused(), "and must read as this crate's own");
    }

    /// A `fut` inside another `fut`'s submit closure stages a sink of
    /// its own. Assigning over the outer's would leave the outer op
    /// reporting teardown for its own refusal.
    #[test]
    fn a_nested_fut_does_not_swallow_the_outer_ones_reason() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);

        // Leave exactly one free slot: the nested `fut` takes it, so the
        // outer's own submission is the one refused.
        let mut held = Vec::new();
        for _ in 0..POOL - 1 {
            held.push(
                conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)),
            );
        }
        let mut inner = None;
        let outer = conn.fut(|c, cb| {
            inner =
                Some(c.fut(|c2, cb2| {
                    c2.open(who, &anchor, c".", spec_dir(), cb2)
                }));
            c.open(who, &anchor, c".", spec_dir(), cb);
        });
        let mut outer = std::pin::pin!(outer);
        let Poll::Ready(done) = outer.as_mut().poll(&mut cx) else {
            panic!("the outer submission left its future pending");
        };
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
            "want the outer's own EBUSY, got {:?}",
            done.result()
        );
        assert!(done.was_refused());
        drop((inner, held));
    }

    /// Dropping a pending future abandons the result; the completion
    /// fires into an unread slot and everything after it still works.
    #[test]
    fn a_dropped_future_leaves_its_completion_inert() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            let abandoned = conn.fut(|c, cb| {
                c.open(who, &anchor, c"dropped.bin", creating(), cb)
            });
            drop(abandoned);
            conn.spawn(move |t| async move {
                let opened = t
                    .fut(|c, cb| {
                        c.open(who, &anchor, c"kept.bin", creating(), cb)
                    })
                    .await;
                assert!(opened.file().is_some());
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "abandoned open");
    }

    /// The offload seam as a future: the job runs on the pool, the
    /// result resolves on-loop through the wake path.
    #[test]
    fn an_offload_future_delivers_on_loop() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let n =
                    t.offload_fut(|| Ok(41 + 1)).await.expect("offload job");
                assert_eq!(n, 42);
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "offload future");
    }

    /// A task spawned from inside a task runs, and slots recycle once
    /// tasks retire - the second spawn reuses the first one's slot.
    #[test]
    fn tasks_nest_and_slots_recycle() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let inner_ran = Rc::new(StdCell::new(false));
                {
                    let inner_ran = Rc::clone(&inner_ran);
                    t.spawn(move |t2| async move {
                        // One real suspension, so the child outlives
                        // its parent's poll.
                        t2.offload_fut(|| Ok(())).await.expect("child offload");
                        inner_ran.set(true);
                    });
                }
                while !inner_ran.get() {
                    // Yield to the loop until the child lands.
                    t.offload_fut(|| Ok(())).await.expect("tick");
                }
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "nested tasks");
        assert_eq!(fs.tasks.free.len(), fs.tasks.slots.len());
    }

    /// A stale waker - its task retired, the slot's generation moved
    /// on - is inert: draining it must not poll the slot's next tenant.
    #[test]
    fn a_stale_waker_does_not_poll_the_slots_next_tenant() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        // A future that parks forever, counting its polls and leaking
        // its waker to the test.
        struct Park {
            polls: Rc<StdCell<u32>>,
            waker_out: Rc<RefCell<Option<Waker>>>,
        }
        impl Future for Park {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                self.polls.set(self.polls.get() + 1);
                *self.waker_out.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let first_waker = Rc::new(RefCell::new(None));
        let polls = Rc::new(StdCell::new(0u32));
        {
            let waker_out = Rc::clone(&first_waker);
            let polls = Rc::clone(&polls);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            // An immediately-ready task: retires at its spawn poll.
            conn.spawn(move |_t| async move {});
            // Its slot is free again; this task takes it.
            conn.spawn(move |_t| Park { polls, waker_out });
        }
        // The parked task's waker id names (slot 0, generation 1).
        // Rebuild a *stale* waker for generation 0 and fire it.
        let stale = std::sync::Arc::new(TaskWake {
            id: TaskId {
                idx: 0,
                generation: 0,
            },
            queued: AtomicBool::new(false),
            run: Arc::clone(fs.tasks.run.as_ref().expect("run queue")),
        });
        wake_task(&stale);

        assert!(
            first_waker.borrow().is_some(),
            "the tenant was polled at spawn and parked"
        );
        assert_eq!(polls.get(), 1, "one spawn poll before the stale wake");
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.run_woken();
        // The stale id was consumed without polling the slot's tenant.
        assert_eq!(polls.get(), 1, "tenant disturbed by a stale wake");
        assert!(fs.tasks.slots[0].entry.is_some(), "tenant evicted");
    }

    /// `TaskFs` reached outside a poll refuses. Debug builds assert;
    /// this is the release half - the op resolves `ECANCELED`.
    #[cfg(not(debug_assertions))]
    #[test]
    fn task_fs_outside_a_poll_resolves_ecanceled() {
        let t = TaskFs::new();
        let fut = t.fut(|_c, _cb| unreachable!("no facade to submit on"));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = std::pin::pin!(fut);
        let Poll::Ready(done) = fut.as_mut().poll(&mut cx) else {
            panic!("an unsubmittable op left its future pending");
        };
        assert!(matches!(
            done.result(),
            Err(crate::Error::Errno(Errno::ECANCELED))
        ));
    }

    /// The debug half: reaching `TaskFs` outside a poll asserts.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "outside a task poll")]
    fn task_fs_outside_a_poll_debug_asserts() {
        let t = TaskFs::new();
        drop(t.fut(|_c, _cb| {}));
    }

    /// The live gauge an embedding host's drain reads: a spawned task
    /// counts until it retires, so a drain that consults it cannot
    /// stop the loop with task work outstanding. A task pending with
    /// no op in flight is invisible to a connection count, which is
    /// the case this exists for.
    #[test]
    fn the_task_gauge_tracks_live_tasks() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        let gauge = fs.task_gauge();
        assert_eq!(gauge.get(), 0, "idle");

        struct Park;
        impl Future for Park {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }

        {
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            // Pending forever, with nothing in flight: exactly the
            // shape a connection count cannot see.
            conn.spawn(|_t| Park);
            assert_eq!(gauge.get(), 1, "a parked task is live");
            // And one that finishes immediately does not linger.
            conn.spawn(|_t| async {});
        }
        assert_eq!(gauge.get(), 1, "the finished task retired");
    }

    /// A panicking task is contained: the caller that spawned it keeps
    /// running, the slot retires, and the payload reaches the handle.
    /// An unwind escaping here would take the reactor thread and every
    /// connection on it.
    #[test]
    fn a_panicking_task_is_contained_and_reported() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        struct Boom;
        impl Future for Boom {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                panic!("task panic");
            }
        }

        // The default hook would print this one; it is expected.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let handle = {
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(|_t| Boom)
        };
        std::panic::set_hook(prev);

        assert_eq!(
            fs.tasks.free.len(),
            fs.tasks.slots.len(),
            "the panicking task stranded its slot"
        );

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut handle = std::pin::pin!(handle);
        let Poll::Ready(Err(JoinError::Panic(payload))) =
            handle.as_mut().poll(&mut cx)
        else {
            panic!("the handle did not report the panic");
        };
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"task panic"),
            "the payload did not survive"
        );
    }

    /// The other two misuse guards, release halves: reaching
    /// `offload_fut` or `spawn` outside a poll cannot submit, so each
    /// resolves rather than pends. `CLAUDE.md` wants a test per half
    /// of a `debug_assert` + `if` pair; the debug halves are below.
    #[cfg(not(debug_assertions))]
    #[test]
    fn the_other_task_fs_guards_resolve_outside_a_poll() {
        let t = TaskFs::new();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut off =
            std::pin::pin!(t.offload_fut(|| Ok::<_, crate::Error>(1)));
        assert!(
            matches!(
                off.as_mut().poll(&mut cx),
                Poll::Ready(Err(crate::Error::Errno(Errno::ECANCELED)))
            ),
            "offload_fut outside a poll must resolve, not pend"
        );

        let mut join = std::pin::pin!(t.spawn(|_t| async { 7u8 }));
        assert!(
            matches!(
                join.as_mut().poll(&mut cx),
                Poll::Ready(Err(JoinError::Dropped))
            ),
            "a spawn that never ran must resolve its join"
        );
    }

    /// The debug halves of the same two guards.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "TaskFs::offload_fut outside a task poll")]
    fn task_fs_offload_outside_a_poll_debug_asserts() {
        drop(TaskFs::new().offload_fut(|| Ok::<_, crate::Error>(1)));
    }

    /// And `spawn`'s.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "TaskFs::spawn outside a task poll")]
    fn task_fs_spawn_outside_a_poll_debug_asserts() {
        drop(TaskFs::new().spawn(|_t| async {}));
    }

    /// `run_woken` drains a task woken by hand from a callback-side
    /// context, without waiting for the next completion.
    #[test]
    fn run_woken_polls_a_hand_woken_task() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        // A future that parks once, hands its waker out, and finishes
        // on its second poll.
        struct Once {
            waker_out: Rc<RefCell<Option<Waker>>>,
            polled: bool,
        }
        impl Future for Once {
            type Output = ();
            fn poll(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<()> {
                if self.polled {
                    return Poll::Ready(());
                }
                self.polled = true;
                *self.waker_out.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let waker_slot = Rc::new(RefCell::new(None));
        {
            let waker_out = Rc::clone(&waker_slot);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |_t| Once {
                waker_out,
                polled: false,
            });
        }
        let waker: Waker =
            waker_slot.borrow_mut().take().expect("parked at spawn");
        waker.wake();

        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.run_woken();
        assert_eq!(
            fs.tasks.free.len(),
            fs.tasks.slots.len(),
            "the woken task did not run to completion"
        );
    }

    /// A drain pass covers exactly what was queued when it began: a
    /// task that wakes itself on every poll runs once per pass and its
    /// re-wake waits for the next, instead of the pass spinning on it
    /// forever with the ring starved. The guard inside the future is
    /// what a regression hits - an unbounded pass re-polls it past the
    /// cap and fails by name rather than hanging the suite.
    #[test]
    fn a_self_waking_task_cannot_monopolise_a_drain_pass() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        struct Spin {
            polls: Rc<StdCell<u32>>,
        }
        impl Future for Spin {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                let n = self.polls.get() + 1;
                self.polls.set(n);
                assert!(n < 10, "an unbounded drain pass kept re-polling");
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let polls = Rc::new(StdCell::new(0));
        {
            let polls = Rc::clone(&polls);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |_t| Spin { polls });
        }
        assert_eq!(polls.get(), 1, "the spawn poll");
        drain(&mut fs, &mut eng);
        assert_eq!(polls.get(), 2, "one poll per pass");
        drain(&mut fs, &mut eng);
        assert_eq!(polls.get(), 3, "one poll per pass, again");
    }

    // ---- the scoped-pointer protocol, without a ring ----------------
    //
    // Every test that reaches `with_current`/`with_conn` through an
    // `FsConn` builds a real io_uring, and Miri aborts on
    // `io_uring_setup` rather than taking the skip path - so these
    // drive the same `park_in`/`reach_in` with a plain type, which is
    // what lets Miri validate the module's only `unsafe`.

    std::thread_local! {
        static PROBE: Cell<Option<NonNull<u32>>> = const { Cell::new(None) };
    }

    /// The parked value is reachable inside the extent and nowhere
    /// else, and a reach hands out a usable `&mut`.
    #[test]
    fn a_parked_pointer_is_reachable_only_inside_its_extent() {
        assert!(reach_in(&PROBE, |_: &mut u32| ()).is_none(), "before");
        let mut v = 7u32;
        park_in(&PROBE, NonNull::from(&mut v), || {
            let doubled = reach_in(&PROBE, |p: &mut u32| {
                *p *= 2;
                *p
            });
            assert_eq!(doubled, Some(14));
        });
        assert!(reach_in(&PROBE, |_: &mut u32| ()).is_none(), "after");
        assert_eq!(v, 14, "the reach wrote through to the parked value");
    }

    /// A reach nested inside a reach finds an empty cell: the pointer
    /// is *taken* for the call, so no second live `&mut` to the same
    /// value can be derived. This is the aliasing claim the module's
    /// SAFETY comment rests on.
    #[test]
    fn a_nested_reach_cannot_alias_the_outer_borrow() {
        let mut v = 1u32;
        park_in(&PROBE, NonNull::from(&mut v), || {
            let inner = reach_in(&PROBE, |outer: &mut u32| {
                *outer += 1;
                let nested = reach_in(&PROBE, |_: &mut u32| ());
                // Still holding `outer` here: the nested reach must
                // have found nothing.
                *outer += 1;
                nested
            });
            assert_eq!(inner, Some(None), "a nested reach aliased");
        });
        assert_eq!(v, 3);
    }

    /// Both halves restore the cell when their closure unwinds - a
    /// panicking task unwinds through the host loop, and a cell left
    /// naming a dead frame is a dangling pointer for the next poll.
    #[test]
    fn an_unwind_restores_the_cell() {
        let mut v = 5u32;
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                park_in(&PROBE, NonNull::from(&mut v), || {
                    reach_in(&PROBE, |_: &mut u32| panic!("boom"));
                });
            }));
        assert!(caught.is_err(), "the panic must propagate");
        assert!(
            reach_in(&PROBE, |_: &mut u32| ()).is_none(),
            "the cell still names a frame that is gone"
        );
    }

    /// Parks nest: an inner park shadows the outer and the outer is
    /// restored on the way out, so a task spawned from inside a poll
    /// does not strand its parent's facade.
    #[test]
    fn parks_nest_and_restore_in_order() {
        let (mut outer, mut inner) = (1u32, 2u32);
        park_in(&PROBE, NonNull::from(&mut outer), || {
            park_in(&PROBE, NonNull::from(&mut inner), || {
                assert_eq!(reach_in(&PROBE, |p: &mut u32| *p), Some(2));
            });
            assert_eq!(reach_in(&PROBE, |p: &mut u32| *p), Some(1));
        });
    }

    /// The eager idiom the contract advertises: ops submitted while
    /// the body is being *assembled*, outside the async block, must
    /// reach the ring like any other. They did not before - `body`
    /// ran before any facade was parked, so each one resolved
    /// `ECANCELED` for an op that was never submitted, which reads to
    /// a task as "the connection went away".
    #[test]
    fn a_body_may_submit_while_it_is_being_assembled() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");
        std::fs::write(dir.path().join("eager"), b"x").expect("seed");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| {
                // Submitted here, before the async block exists.
                let opened = t.fut(|c, cb| {
                    c.open(
                        who,
                        &anchor,
                        c"eager",
                        OpenHow::new().flags(OFlag::O_RDONLY),
                        cb,
                    )
                });
                async move {
                    let res = opened.await;
                    assert!(
                        res.file().is_some(),
                        "an op submitted while assembling the body did \
                         not reach the ring: {:?}",
                        res.result()
                    );
                    done.set(true);
                }
            });
        }
        drive(&mut fs, &mut eng, &done, "eager submit from the body");
    }

    /// A wake from an inline `spawn` poll - on the loop thread, with
    /// no drain pass running to collect it - pokes the loop. Without
    /// it the id sits queued while the host parks on a ring that has
    /// no reason to complete, and `queued` then latches so even a
    /// later off-loop wake is deduped away.
    #[test]
    fn an_on_loop_wake_outside_a_pass_pokes_the_loop() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        struct WakeOnce {
            polls: Rc<StdCell<u32>>,
        }
        impl Future for WakeOnce {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                self.polls.set(self.polls.get() + 1);
                if self.polls.get() == 1 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(())
            }
        }

        let polls = Rc::new(StdCell::new(0));
        {
            let polls = Rc::clone(&polls);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |_t| WakeOnce { polls });
        }
        let run = Arc::clone(fs.tasks.run.as_ref().expect("run queue"));
        assert_eq!(run.ready.load(Ordering::Acquire), 1, "queued");
        assert!(
            pending_pokes(&run) > 0,
            "nothing poked: the loop will park and never schedule it"
        );
    }

    /// A re-entrant drain - `run_woken` from inside a poll - must not
    /// consume the running task's own queued wake. The poll cleared
    /// the dedup edge before running, so that id is the only record;
    /// eat it and the task is never scheduled again.
    #[test]
    fn a_reentrant_drain_does_not_eat_the_running_tasks_wake() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        struct WakeThenReenter {
            polls: Rc<StdCell<u32>>,
        }
        impl Future for WakeThenReenter {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                self.polls.set(self.polls.get() + 1);
                if self.polls.get() == 1 {
                    cx.waker().wake_by_ref();
                    // The documented hand-wake shape: re-enter the
                    // executor from inside the poll.
                    with_conn(|c| c.run_woken());
                    return Poll::Pending;
                }
                Poll::Ready(())
            }
        }

        let polls = Rc::new(StdCell::new(0));
        {
            let polls = Rc::clone(&polls);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |_t| WakeThenReenter { polls });
        }
        assert_eq!(polls.get(), 1, "the spawn poll");
        FsConn::new(&mut fs, &mut eng, None).run_woken();
        assert_eq!(
            polls.get(),
            2,
            "the re-entrant drain consumed the task's own wake"
        );
        assert_eq!(
            fs.tasks.free.len(),
            fs.tasks.slots.len(),
            "the task did not run to completion"
        );
    }

    /// A task awaits its child's output through the handle. The
    /// parent's resume rides the leftover poke: the child's completion
    /// wakes the parent after the pass's budget was taken, so without
    /// the poke this join would stall with nothing left in flight.
    #[test]
    fn a_join_handle_resolves_with_the_tasks_output() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(move |t| async move {
                let child = t.spawn(|t2| async move {
                    t2.offload_fut(|| Ok(40 + 2)).await.expect("child offload")
                });
                assert_eq!(child.await.expect("child joined"), 42);
                done.set(true);
            });
        }
        drive(&mut fs, &mut eng, &done, "join of a child task");
    }

    /// Dropping the handle detaches: the task still runs to its end,
    /// and only the output goes unread.
    #[test]
    fn a_dropped_join_handle_detaches() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
        let done = Rc::new(StdCell::new(false));

        {
            let done = Rc::clone(&done);
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            let handle = conn.spawn(move |t| async move {
                t.offload_fut(|| Ok(())).await.expect("offload");
                done.set(true);
                "unread"
            });
            drop(handle);
        }
        drive(&mut fs, &mut eng, &done, "detached task");
    }

    /// A task dropped before finishing - which only teardown does -
    /// resolves its join as `None` rather than leaving it pending.
    #[test]
    fn a_task_dropped_at_teardown_resolves_its_join_as_none() {
        let Some((mut eng, mut fs, _who)) = rig() else {
            return;
        };

        /// Parks forever; only teardown ends it.
        struct Forever;
        impl Future for Forever {
            type Output = u32;
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
                Poll::Pending
            }
        }

        let handle = {
            let mut conn = FsConn::new(&mut fs, &mut eng, None);
            conn.spawn(|_t| Forever)
        };
        drop(fs);

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut handle = std::pin::pin!(handle);
        assert!(
            matches!(
                handle.as_mut().poll(&mut cx),
                Poll::Ready(Err(JoinError::Dropped))
            ),
            "teardown must resolve the join, not strand it"
        );
    }
}
