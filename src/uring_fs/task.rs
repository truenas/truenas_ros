//! Awaitable operations and on-loop tasks over the callback facade.
//!
//! The callback facade stays the primitive. An op future is one submission whose delivery fills a slot instead of
//! running a chain, so the two styles compose, and submission stays the eager, on-ring path the callback form uses.
//! [`FsConn::fut`] wraps one submission, [`FsConn::offload_fut`] one offload, and [`FsConn::spawn`] starts a **task**,
//! a `'static` future polled inline on the loop thread through a [`TaskFs`]. "Poll" here is always [`Future::poll`],
//! never `poll(2)`.
//!
//! # Contract
//!
//! - **Submission is eager.** The op is in flight when [`FsConn::fut`] returns, polled or not. Dropping an [`FsFuture`]
//!   abandons the outcome and does not cancel the op.
//! - **A callback dropped unfired resolves the future** rather than leaving it pending. [`FsDone::was_refused`] says
//!   the errno is **this crate's**, so read it first, since `EBUSY` from a full op table is worth retrying and `EBUSY`
//!   from the kernel is not. A refusal **hands the payload back** ([`FsDone::into_bufs`]), and `ECANCELED` with
//!   `was_refused()` false means teardown alone.
//! - **A task's facade is a continuation facade**, fresh and owner-scoped for each poll. There is no external kill, so
//!   a task must end when its ops start failing or its source closes. A task whose awaits are all offloads sees
//!   neither, so it polls [`TaskFs::owner_is_gone`] and [`TaskFs::draining`] between awaits.
//! - **A task's facade carries no recv-buffer claim**, so [`pwritev2_from`](FsConn::pwritev2_from) from inside a task
//!   copies. Submit the write from the delivery's own callback and hand the [`FsFuture`] to the task to keep it
//!   zero-copy.
//! - **A panicking task is contained**, unwinding no further than the executor, and its [`JoinHandle`] answers
//!   [`JoinError::Panic`]. A callback that panics still takes the thread down.
//! - **A drain pass polls only what was queued when it began**, so a self-waking task cannot starve the ring. The task
//!   table and run queue are uncapped, so bound in-flight work at the request cap.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use super::core::{FsConn, FsCore, FsDone, Owner, SinkInner};
use crate::errno::Errno;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::sync::{Arc, Mutex};
use crate::uring::engine::Engine;
use crate::uring::wake::LoopShared;

// ---- completion slots -----------------------------------------------------

/// One completion slot: filled at most once by a [`Fire`], read at most once by its future.
enum SlotState<V> {
    /// Unfired; the waker parked by the most recent poll, if any.
    Pending(Option<Waker>),
    /// A staged reason sink's refusal, parked until the callback route settles it, since a real completion supersedes
    /// it and the callback dropping unfired adopts it. **Do not settle `Ready` straight from the sink**, or a refusal
    /// from another submission answers for an op still in flight, and its real completion (a fresh `File` included) is
    /// dropped.
    Refused(V, Option<Waker>),
    /// Fired; the next poll takes it.
    Ready(V),
    /// The callback was dropped unfired (a refused submission, or teardown): resolve rather than pend forever.
    Gone,
    /// Read; nothing left. A poll after readiness resolves as [`Gone`] rather than parking a waker nothing will ever
    /// wake.
    Spent,
}

struct Slot<V>(RefCell<SlotState<V>>);

impl<V> Slot<V> {
    fn new() -> Rc<Slot<V>> {
        Rc::new(Slot(RefCell::new(SlotState::Pending(None))))
    }

    /// A slot born resolved-as-gone: teardown took the submission, and there is nothing to say about it beyond that.
    fn gone() -> Rc<Slot<V>> {
        Rc::new(Slot(RefCell::new(SlotState::Gone)))
    }

    /// A slot born already holding `v`, for an answer settled before any op could exist - see [`no_facade`].
    fn ready(v: V) -> Rc<Slot<V>> {
        Rc::new(Slot(RefCell::new(SlotState::Ready(v))))
    }

    /// Fill through the callback route (`None` = the callback dropped unfired) and wake whoever parked.
    fn fill(&self, landed: Option<V>) {
        let woken = {
            let mut s = self.0.borrow_mut();
            let (next, waker) = match (std::mem::replace(&mut *s, SlotState::Spent), landed) {
                // A real answer is final, and a taken slot stays taken.
                (cur @ (SlotState::Ready(_) | SlotState::Spent), _) => {
                    *s = cur;
                    return;
                }
                // `Gone` is not final: a refused submission drops its callback (which lands as `Gone`) and reports its
                // errno through the waiter's sink, in either order, and the errno is the better answer.
                (SlotState::Gone, Some(v)) => (SlotState::Ready(v), None),
                (SlotState::Gone, None) => {
                    *s = SlotState::Gone;
                    return;
                }
                // The callback route settles a parked refusal: a real completion supersedes it - the op the caller
                // awaited answers for itself - and the callback dropping unfired adopts it.
                (SlotState::Refused(_, w), Some(v)) => (SlotState::Ready(v), w),
                (SlotState::Refused(r, w), None) => (SlotState::Ready(r), w),
                (SlotState::Pending(w), Some(v)) => (SlotState::Ready(v), w),
                (SlotState::Pending(w), None) => (SlotState::Gone, w),
            };
            *s = next;
            waker
        };
        if let Some(w) = woken {
            w.wake();
        }
    }

    /// Park a staged reason sink's refusal (see [`SlotState::Refused`]). The first refusal wins, and a slot already
    /// `Gone` takes the reason at once, the callback route having ended.
    fn fill_refused(&self, v: V) {
        let mut s = self.0.borrow_mut();
        match &*s {
            SlotState::Pending(_) => {
                let SlotState::Pending(w) = std::mem::replace(&mut *s, SlotState::Spent) else {
                    unreachable!("matched Pending above");
                };
                *s = SlotState::Refused(v, w);
            }
            SlotState::Gone => *s = SlotState::Ready(v),
            SlotState::Refused(..) | SlotState::Ready(_) | SlotState::Spent => {}
        }
    }

    fn poll_take(&self, cx: &mut Context<'_>) -> Poll<Took<V>> {
        let mut s = self.0.borrow_mut();
        match std::mem::replace(&mut *s, SlotState::Spent) {
            SlotState::Ready(v) => Poll::Ready(Took::Value(v)),
            SlotState::Gone => Poll::Ready(Took::Gone),
            SlotState::Spent => Poll::Ready(Took::Spent),
            SlotState::Pending(_) => {
                *s = SlotState::Pending(Some(cx.waker().clone()));
                Poll::Pending
            }
            SlotState::Refused(v, _) => {
                *s = SlotState::Refused(v, Some(cx.waker().clone()));
                Poll::Pending
            }
        }
    }
}

/// What a poll took out of a slot. Three outcomes, because the two empty ones need different answers: nothing ever
/// landed, against an earlier poll having taken what did.
enum Took<V> {
    Value(V),
    /// The filler was dropped unfired - a refused submission with no reason to report, or teardown.
    Gone,
    /// A previous poll took the outcome. A slot is not a broadcast.
    Spent,
}

/// The filling half of a slot: firing consumes it; dropping it unfired fills [`SlotState::Gone`], so the future
/// resolves either way.
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

/// The boxed callback [`FsConn::fut`] hands its closure - pass it as any submit method's `on_done`. Dropping it unfired
/// resolves the future as `ECANCELED`, which is what a submit method's silent argument refusal turns into on this path.
pub type OnDone = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// The boxed callback [`FsConn::result_fut`] hands its closure - pass it as the `on_done` of any facade method whose
/// outcome is a [`crate::Result`] rather than an [`FsDone`] (the offload-backed metadata tails, and the two
/// directory-walk steps). Dropping it unfired resolves the future as `ECANCELED`, exactly as [`OnDone`] does.
pub type OnResult<T> = Box<dyn FnOnce(crate::Result<T>, &mut FsConn<'_>)>;

/// One submitted op's completion, as a future. Resolves to the same [`FsDone`] the callback form receives; a callback
/// dropped unfired resolves as a failed `ECANCELED` outcome instead of pending forever.
pub struct FsFuture(Rc<Slot<FsDone>>);

impl std::fmt::Debug for FsFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsFuture").finish_non_exhaustive()
    }
}

impl Future for FsFuture {
    type Output = FsDone;

    /// A second poll answers `ECANCELED` too, with [`FsDone::was_refused`] false, since polling a resolved future again
    /// is a caller bug.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FsDone> {
        self.0.poll_take(cx).map(|took| match took {
            Took::Value(done) => done,
            Took::Gone | Took::Spent => FsDone::failed(Errno::ECANCELED),
        })
    }
}

/// One offloaded blocking job's outcome, as a future. Resolves to what the job returned; a delivery dropped unfired
/// resolves `ECANCELED`.
pub struct OffloadFuture<T>(Rc<Slot<crate::Result<T>>>);

impl<T> std::fmt::Debug for OffloadFuture<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffloadFuture").finish_non_exhaustive()
    }
}

impl<T> Future for OffloadFuture<T> {
    type Output = crate::Result<T>;

    /// A second poll answers `ECANCELED` too; see [`FsFuture::poll`].
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<T>> {
        self.0.poll_take(cx).map(|took| match took {
            Took::Value(r) => r,
            Took::Gone | Took::Spent => Err(Errno::ECANCELED.into()),
        })
    }
}

/// Why a task produced no output.
#[derive(Debug)]
pub enum JoinError {
    /// The task panicked. The payload is what the poll unwound with, as [`catch_unwind`](std::panic::catch_unwind)
    /// yields it.
    ///
    /// **Keep panic-on-drop guards out of task state.** The poll's unwind drops the future's state, and a `Drop` that
    /// panics during an unwind aborts the process before any guard in this crate can run.
    Panic(Box<dyn std::any::Any + Send>),
    /// The task produced no output and never will, since it was dropped at teardown, or a release-build
    /// [`TaskFs::spawn`] called out of turn never ran its body.
    Dropped,
    /// This handle already yielded the task's output, so the caller polled a resolved handle.
    Consumed,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Panic(_) => f.write_str("the task panicked"),
            JoinError::Dropped => f.write_str("the task produced no output and never will"),
            JoinError::Consumed => f.write_str("this join handle was already consumed"),
        }
    }
}

impl std::error::Error for JoinError {}

/// A spawned task's output, as a future.
///
/// Resolves `Ok` with what the task returned, [`JoinError`] when it produced nothing, and [`JoinError::Consumed`] when
/// polled again. Dropping the handle detaches, and the task runs to completion with its output dropped unread. **A
/// detached task's panic has no programmatic recipient** beyond the default panic hook, so keep the handle for work
/// whose failure has to be acted on.
pub struct JoinHandle<T>(Rc<Slot<Result<T, JoinError>>>);

impl<T> std::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<T, JoinError>> {
        self.0.poll_take(cx).map(|took| match took {
            Took::Value(out) => out,
            Took::Gone => Err(JoinError::Dropped),
            Took::Spent => Err(JoinError::Consumed),
        })
    }
}

// ---- the awaitable surface on the facade ----------------------------------

impl FsConn<'_> {
    /// Submit one op through `submit` and return its completion as a future. `submit` receives this facade and the
    /// boxed callback to pass as the op's `on_done`:
    ///
    /// ```no_run
    /// # use truenas_ros::uring_fs::{File, Personality, TaskFs};
    /// # async fn body(t: TaskFs, who: Personality, file: File) {
    /// let done = t.fut(|c, done| c.fsync(who, file.clone(), done)).await;
    /// let _ = done.result();
    /// # }
    /// ```
    ///
    /// Submission happens inside this call - the op is in flight when it returns, whether or not the future is ever
    /// polled - so two futures created back to back overlap on the ring. A `submit` that drops `on_done` without
    /// passing it anywhere resolves the future as `ECANCELED`.
    ///
    /// **`submit` submits exactly one op.** The reason sink staged here answers for the *first* submission the closure
    /// makes, and the future resolves with the outcome of the submission carrying `on_done`. Submit an extra op before
    /// or after the call, not inside it.
    pub fn fut(&mut self, submit: impl FnOnce(&mut FsConn<'_>, OnDone)) -> FsFuture {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        // The sink carries why an op never reached the ring, which the callback form cannot say, since it drops
        // `on_done` for a full table, a refused argument and teardown alike.
        let reason = Rc::clone(&slot);
        // Saved and put back, because `submit` may itself contain a `fut`: assigning over the outer sink would leave
        // the outer op reporting teardown for its own refusal.
        let outer = self.stage_fail_sink(Rc::new(SinkInner::new(move |errno, bufs| {
            reason.fill_refused(FsDone::refused_with(errno, bufs));
        })));
        submit(self, Box::new(move |done, _conn| fire.fire(done)));
        // No submission armed the sink, so `submit` handed nothing to the core, as the facade's own argument checks do.
        // That is the defect the core reports as `EINVAL`.
        if !self.restore_fail_sink(outer) {
            slot.fill(Some(FsDone::refused_with(Errno::EINVAL, Vec::new())));
        }
        FsFuture(slot)
    }

    /// [`offload_result`](Self::offload_result) as a future: run `job` on the blocking pool and resolve with its result
    /// on-loop. The job contract is [`offload`](Self::offload)'s, unchanged - this is for the opcode-less blocking
    /// tail, never for an op the ring serves.
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

    /// Submit one op through `submit` and return its outcome as a future, as [`fut`](Self::fut) does for the facade
    /// methods whose callback carries a [`crate::Result`] instead of an [`FsDone`] (both `fstatfs` forms, `flistxattr`,
    /// `fremovexattr`, the ZFS attribute pair, `copy_file_range`, and the `open_dir`/`next_batch` walk).
    ///
    /// ```no_run
    /// # use truenas_ros::uring_fs::{File, TaskFs};
    /// # async fn body(t: TaskFs, file: File) -> truenas_ros::Result<()> {
    /// let st = t.result_fut(|c, cb| c.fstatfs(file.clone(), cb)).await?;
    /// # let _ = st;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Submission is eager and one op per call, as for [`fut`](Self::fut). A refusal of `open_dir`'s ring `open`
    /// resolves with its errno, and a method delivered through the offload pool resolves `ECANCELED` on a refusal, as
    /// [`offload_fut`](Self::offload_fut) does.
    pub fn result_fut<T, S>(&mut self, submit: S) -> OffloadFuture<T>
    where
        S: FnOnce(&mut FsConn<'_>, OnResult<T>),
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        let reason = Rc::clone(&slot);
        // A frame of its own, or a submission inside another future's `submit` would fill that future's slot with its
        // own refusal. An unarmed sink is ordinary here, since most of these methods never reach the op table.
        let outer = self.stage_fail_sink(Rc::new(SinkInner::new(move |errno, _bufs| {
            reason.fill_refused(Err(errno.into()));
        })));
        submit(self, Box::new(move |r, _conn| fire.fire(r)));
        self.restore_fail_sink(outer);
        OffloadFuture(slot)
    }

    /// Start a task: `body` builds the future from the [`TaskFs`] it will submit through, and the task is polled once
    /// inline before this returns, so its first ops are on the ring when the caller resumes. `body` itself runs inside
    /// that first poll, so it may submit while assembling the future.
    ///
    /// A task ends by returning, with no external kill (see the module's contract). The returned [`JoinHandle`]
    /// resolves with the task's output, and dropping it detaches, so it is not `#[must_use]`.
    pub fn spawn<F, Fut, T>(&mut self, body: F) -> JoinHandle<T>
    where
        F: FnOnce(TaskFs) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        // Type-erased so the entry, which cannot name `T`, can still answer this handle when its poll unwinds.
        let panicked = {
            let slot = Rc::clone(&slot);
            Box::new(move |payload| {
                slot.fill(Some(Err(JoinError::Panic(payload))));
            })
        };
        // `body` runs inside the first poll, since a facade is parked only for the extent of a poll, and ops submitted
        // while assembling the future need one.
        let task = Box::pin(async move {
            let fut = body(TaskFs::new());
            fire.fire(Ok(fut.await));
        });
        let (fs, eng, owner) = self.split();
        let id = fs.tasks.insert(eng, owner, task, panicked);
        poll_one(fs, eng, id);
        JoinHandle(slot)
    }

    /// Poll every task woken since the last delivery. The delivery points call this themselves; it exists for a
    /// callback that woke a task by hand - fed a queue the task awaits, say - and wants it run now rather than at the
    /// next completion.
    pub fn run_woken(&mut self) {
        let (fs, eng, _) = self.split();
        drain(fs, eng);
    }
}

// ---- the facade a task submits through ------------------------------------

std::thread_local! {
    /// The facade of the poll in progress, parked by [`with_current`] for [`TaskFs`] to reach. `None` outside a poll.
    static CURRENT: Cell<Option<NonNull<FsConn<'static>>>> =
        const { Cell::new(None) };

    /// Which task that poll is running. Set and cleared with [`CURRENT`], by [`with_current`] alone.
    ///
    /// A [`TaskFs`] is refused during any other task's poll. Without that, an op written in one task's terms is stamped
    /// another's owner, so the wrong connection's teardown sweep cancels it and the right one leaves its descriptor
    /// parked.
    static CURRENT_TASK: Cell<Option<TaskId>> = const { Cell::new(None) };

    /// Set while a [`Tasks`] table is dropping the futures still parked in it, so a destructor that reaches [`TaskFs`]
    /// is answered rather than asserted at. See [`Tasks::drop`].
    static TEARDOWN: Cell<bool> = const { Cell::new(false) };
}

/// Restore [`CURRENT_TASK`] on scope exit, a panic included - the pair of [`Restore`] for the id that travels with the
/// parked facade.
struct RestoreTask(Option<TaskId>);

impl Drop for RestoreTask {
    fn drop(&mut self) {
        CURRENT_TASK.with(|c| c.set(self.0));
    }
}

/// The same, for [`TEARDOWN`].
struct RestoreTeardown(bool);

impl Drop for RestoreTeardown {
    fn drop(&mut self) {
        TEARDOWN.with(|c| c.set(self.0));
    }
}

/// Whether a [`Tasks`] table is dropping its pending futures right now.
fn tearing_down() -> bool {
    TEARDOWN.with(|c| c.get())
}

/// The cell a scoped pointer parks in.
type ParkCell<T> = std::thread::LocalKey<Cell<Option<NonNull<T>>>>;

/// Restore a park cell on scope exit, a panic included: a panicking task unwinds through the host loop, and the cell
/// must not keep naming a facade that died with this frame.
struct Restore<T: 'static>(&'static ParkCell<T>, Option<NonNull<T>>);

impl<T: 'static> Drop for Restore<T> {
    fn drop(&mut self) {
        self.0.with(|c| c.set(self.1));
    }
}

/// Park `ptr` in `cell` for the dynamic extent of `f`.
///
/// Generic over the parked type so the protocol can be exercised without an io_uring ring: every test that reaches it
/// through [`FsConn`] builds a real one, and Miri aborts on `io_uring_setup` rather than taking the skip path, which
/// would leave the only `unsafe` in this module unvalidated by it.
fn park_in<T: 'static, R>(cell: &'static ParkCell<T>, ptr: NonNull<T>, f: impl FnOnce() -> R) -> R {
    let _restore = Restore(cell, cell.with(|c| c.replace(Some(ptr))));
    f()
}

/// Reach whatever `cell` holds, for the extent of `f`. `None` when nothing is parked.
///
/// **The pointer is taken for the call**, so a nested reach finds an empty cell rather than deriving a second live
/// `&mut` to the same value, and the guard puts it back however `f` ends.
///
/// **`T` must not carry a lifetime, and this does not check it.** The bound is `T: 'static`, which `FsConn<'static>`
/// satisfies, so `f` here may be instantiated at a single concrete lifetime and can return a borrow that outlives the
/// value. [`with_conn`] is what makes the facade safe, by taking `impl FnOnce(&mut FsConn<'_>) -> R` - which desugars
/// higher-ranked - and every reach of [`CURRENT`] goes through it. Reaching the cell directly is a use-after-free from
/// safe code.
fn reach_in<T: 'static, R>(cell: &'static ParkCell<T>, f: impl FnOnce(&mut T) -> R) -> Option<R> {
    cell.with(|c| {
        let ptr = c.take()?;
        let _restore = Restore(cell, Some(ptr));
        // SAFETY: `ptr` was parked by `park_in` around a call that is still on this thread's stack, so the value it
        // names outlives this borrow; the `take` above makes this the only live reference derived from it, and `f` is
        // generic over the borrow's lifetime so the reference cannot escape.
        let val = unsafe { &mut *ptr.as_ptr() };
        Some(f(val))
    })
}

/// Park `conn`, and the id of the task it is being polled for, for the duration of `f`.
fn with_current<R>(conn: &mut FsConn<'_>, task: TaskId, f: impl FnOnce() -> R) -> R {
    // The lifetime is erased for storage only: the pointer is taken back out strictly inside `f`'s dynamic extent,
    // where `conn` is still exclusively this frame's.
    let ptr = NonNull::from(conn).cast::<FsConn<'static>>();
    let _task = RestoreTask(CURRENT_TASK.with(|c| c.replace(Some(task))));
    park_in(&CURRENT, ptr, f)
}

/// Reach the poll's parked facade **on behalf of `who`**. `None` outside a poll, and `None` when the running poll is
/// some other task's - a handle that left its body. The pointer is *taken* for the call, so a nested reach sees an
/// empty cell rather than a second `&mut` to the same facade.
fn with_conn<R>(who: Option<TaskId>, f: impl FnOnce(&mut FsConn<'_>) -> R) -> Option<R> {
    if who.is_none() || CURRENT_TASK.with(|c| c.get()) != who {
        return None;
    }
    // The `'static` in the cell is storage-only: `f` is generic over the facade's lifetime, so the reference cannot
    // escape it.
    reach_in(&CURRENT, f)
}

/// A task's handle to the facade of whichever poll is running it.
///
/// Handed to the task body by [`FsConn::spawn`], and its methods work only while that task is being polled. Calling one
/// out of turn, or from a handle moved into `'static` state and picked up during another task's poll, debug-asserts,
/// and in release it is refused as a submission that cannot happen. At teardown a destructor of the "submit on drop"
/// shape reaches it legitimately, and there the call is refused quietly.
pub struct TaskFs {
    /// `None` is unreachable - a body is built inside its own first poll - and fails every method closed if it ever is
    /// not.
    task: Option<TaskId>,
    _on_loop: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for TaskFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskFs").finish_non_exhaustive()
    }
}

/// The slot a [`TaskFs`] call answers with when it cannot reach a facade. Teardown is [`Slot::gone`], `ECANCELED` with
/// `was_refused` false, the signal a consumer winds down on. Use out of turn is a caller's bug, and reporting it as
/// teardown would shut a healthy server down, so `refused` names the caller instead.
fn no_facade<V>(refused: impl FnOnce() -> V) -> Rc<Slot<V>> {
    if tearing_down() {
        Slot::gone()
    } else {
        Slot::ready(refused())
    }
}

impl TaskFs {
    fn new() -> TaskFs {
        TaskFs {
            task: CURRENT_TASK.with(|c| c.get()),
            _on_loop: PhantomData,
        }
    }

    /// [`FsConn::fut`] against the running poll's facade.
    ///
    /// Using this handle outside its own task's poll submits nothing and resolves `EINVAL` with [`FsDone::was_refused`]
    /// true; the same misuse at teardown resolves `ECANCELED` instead, which is this module's one meaning for "the
    /// reactor is going away".
    pub fn fut(&self, submit: impl FnOnce(&mut FsConn<'_>, OnDone)) -> FsFuture {
        match with_conn(self.task, |conn| conn.fut(submit)) {
            Some(f) => f,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::fut with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                FsFuture(no_facade(|| FsDone::refused_with(Errno::EINVAL, Vec::new())))
            }
        }
    }

    /// [`FsConn::offload_fut`] against the running poll's facade.
    ///
    /// Misuse resolves `EINVAL` and teardown `ECANCELED`, as [`fut`](Self::fut) does - the errno is the whole
    /// distinction here, since a [`crate::Result`] carries no provenance bit.
    pub fn offload_fut<T, J>(&self, job: J) -> OffloadFuture<T>
    where
        J: FnOnce() -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        match with_conn(self.task, |conn| conn.offload_fut(job)) {
            Some(f) => f,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::offload_fut with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                OffloadFuture(no_facade(|| Err(Errno::EINVAL.into())))
            }
        }
    }

    /// [`FsConn::result_fut`] against the running poll's facade.
    ///
    /// Misuse resolves `EINVAL` and teardown `ECANCELED`; see [`offload_fut`](Self::offload_fut).
    pub fn result_fut<T, S>(&self, submit: S) -> OffloadFuture<T>
    where
        S: FnOnce(&mut FsConn<'_>, OnResult<T>),
        T: 'static,
    {
        match with_conn(self.task, |conn| conn.result_fut(submit)) {
            Some(f) => f,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::result_fut with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                OffloadFuture(no_facade(|| Err(Errno::EINVAL.into())))
            }
        }
    }

    /// [`FsConn::owner_is_gone`] against the running poll's facade - the wind-down signal for a task whose awaits never
    /// fail.
    ///
    /// A task awaiting only offloads never sees an op fail, so it would keep running for a dead connection and hold a
    /// graceful drain open. Poll this between awaits and return. With no facade (outside this task's poll, or nested
    /// inside a call already holding it) it answers the teardown state and **never guesses "gone"**, since a wrong
    /// `true` abandons work for a live connection.
    pub fn owner_is_gone(&self) -> bool {
        match with_conn(self.task, |conn| conn.owner_is_gone()) {
            Some(gone) => gone,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::owner_is_gone with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                tearing_down()
            }
        }
    }

    /// [`FsConn::draining`] against the running poll's facade, the server-side half of the wind-down pair, which ends a
    /// task holding a graceful drain open from a connection that is fine. Never `true` on a standalone host. With no
    /// facade it answers the teardown state, as [`owner_is_gone`](Self::owner_is_gone) does.
    pub fn draining(&self) -> bool {
        match with_conn(self.task, |conn| conn.draining()) {
            Some(draining) => draining,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::draining with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                tearing_down()
            }
        }
    }

    /// [`FsConn::spawn`] against the running poll's facade: the child task shares this task's owner and is polled once
    /// inline. The handle lets the spawning task await the child's output - two children spawned back to back run their
    /// ops concurrently, and awaiting both is a join.
    pub fn spawn<F, Fut, T>(&self, body: F) -> JoinHandle<T>
    where
        F: FnOnce(TaskFs) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        match with_conn(self.task, |conn| conn.spawn(body)) {
            Some(handle) => handle,
            None => {
                debug_assert!(
                    tearing_down(),
                    "TaskFs::spawn with no facade: outside its task's poll, or nested inside a call already holding it"
                );
                JoinHandle(Slot::gone())
            }
        }
    }
}

// ---- the task table and its run queue -------------------------------------

/// A task's slot and the incarnation of it this handle names.
///
/// Not packed into a `u64`, since no task id reaches `user_data`, and a `Waker` is exactly the long-retained handle a
/// full-width generation keeps from aliasing a later task (see [`SlotEntry`](crate::uring::slots::SlotEntry)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TaskId {
    idx: u32,
    generation: u64,
}

/// What a waker reaches: the run queue, its emptiness hint, and the loop's wake eventfd for an off-loop wake.
pub(crate) struct RunShared {
    /// Woken task ids, in wake order.
    queue: Mutex<VecDeque<TaskId>>,
    /// Queue-length hint, so the per-completion drain check is one relaxed load instead of a lock acquisition.
    ready: AtomicUsize,
    /// Set for the extent of a [`drain`] pass, so a wake inside a pass leaves the poke to it. Written only through
    /// [`RunShared::begin_pass`] and [`PassGuard`].
    ///
    /// **Every access is the loop thread's, so all three are `Relaxed` and no ordering is claimed.** The one read
    /// ([`wake_task`]) sits behind `off_loop() ||`, which keeps an off-loop waker from reaching it. A change that lets
    /// another thread read this flag must bring the ordering *and* a loom model with it.
    draining: AtomicBool,
    /// The loop's shared flags and wake eventfd.
    wake: Arc<LoopShared>,
    /// The loop thread, recorded at first spawn.
    #[cfg(not(loom))]
    loop_thread: std::thread::ThreadId,
    /// The model's stand-in for the thread check. Keep it settable, since a value fixed at `true` would leave the
    /// on-loop branch of [`wake_task`] unreachable from every model.
    #[cfg(loom)]
    model_off_loop: bool,
}

impl RunShared {
    /// Mark a drain pass live, answering what was there before so [`PassGuard`] can put it back.
    ///
    /// A nested pass must not un-mark the outer one, or the outer pass's remaining deliveries poke the loop for work it
    /// is about to do.
    fn begin_pass(&self) -> bool {
        self.draining.swap(true, Ordering::Relaxed)
    }

    /// Whether the caller is off the loop thread. Under loom there is no thread identity to read, so a model states
    /// which side it is exercising; both are modelled.
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
    ///
    /// The count is **published from under the lock**, never adjusted by a delta. A delta drifts whenever a push and
    /// its count land apart, and a nested pass can spend count an outer pass's budget was sampled from, so the
    /// subtraction that finds nothing left wraps to `usize::MAX`, which [`drain`] samples as the entry bound that
    /// returns this thread to the ring. Storing the length the lock holder can see cannot wrap and cannot contradict a
    /// push it already observed.
    pub(crate) fn take_ready(&self) -> Option<TaskId> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let id = q.pop_front()?;
        self.ready.store(q.len(), Ordering::Release);
        Some(id)
    }
}

/// One task's waker target. [`std::task::Wake`] wants `std::sync::Arc` specifically, so that is what holds it; the
/// fields go through `crate::sync` like every cross-thread protocol here, so the loom models can drive [`wake_task`]
/// itself.
pub(crate) struct TaskWake {
    id: TaskId,
    /// Wake-dedup edge: set by the wake that enqueues, cleared by [`poll_window`] just before the task runs.
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

/// Wake one task: enqueue its id exactly once per wake edge, and poke the loop unless a drain pass is already running
/// to collect it. Returns whether this call enqueued (a dedup-skipped wake returns `false`).
///
/// **The discriminant is whether a pass is running, not which thread the wake came from.** An on-loop wake outside a
/// pass is otherwise scheduled by nothing, and the `queued` edge then latches, so the task is unreachable for good.
/// Push under the lock, then poke, as `finish_offload` does, or the loop can wake, find nothing and park again. A
/// skipped wake is covered by a poll of this task that starts after this call returns.
pub(crate) fn wake_task(w: &TaskWake) -> bool {
    if w.queued.swap(true, Ordering::AcqRel) {
        return false;
    }
    {
        let mut q = w.run.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(w.id);
        // Published from under the lock, so the count can never disagree with a push the lock holder has already made -
        // see `take_ready`.
        w.run.ready.store(q.len(), Ordering::Release);
    }
    if w.run.off_loop() || !w.run.draining.load(Ordering::Relaxed) {
        w.run.wake.wake.poke();
    }
    true
}

/// Run one poll inside the task's window. The dedup edge clears strictly *before* `poll`, so a wake landing mid-poll
/// enqueues a fresh pass instead of vanishing into a poll already past the state it announced.
///
/// **A swap, not a store, because this is the acquire half of the dedup edge.** A deduped wake takes no lock, so the
/// swap is all that orders what the waker published before waking. No in-tree waker leaves the loop thread, but the
/// public [`Waker`] surface allows an off-loop one. **The Miri lane owns this edge**
/// (`miri_a_deduped_wake_publishes_what_it_wrote`), since x86's TSO hides a weakened spelling from native runs, so do
/// not retire that lane.
pub(crate) fn poll_window<R>(w: &TaskWake, poll: impl FnOnce() -> R) -> R {
    w.queued.swap(false, Ordering::AcqRel);
    poll()
}

/// Answers a task's [`JoinHandle`] when its poll unwinds; type-erased because the table cannot name a task's output
/// type.
type PanicSink = Box<dyn FnOnce(Box<dyn std::any::Any + Send>)>;

struct TaskEntry {
    fut: Pin<Box<dyn Future<Output = ()>>>,
    on_panic: Option<PanicSink>,
    owner: Owner,
    wake: std::sync::Arc<TaskWake>,
    waker: Waker,
}

struct TaskSlot {
    /// Bumped at retire, so a stale waker's id misses and its wake is inert - the run queue may hold ids for tasks
    /// already gone.
    generation: u64,
    /// `None` while free *or* while the entry is out being polled; the free list is what distinguishes the two.
    entry: Option<TaskEntry>,
}

/// The reactor's tasks. A field of `FsCore`, so every host that fires callbacks can drain the woken ones with the same
/// borrows.
pub(crate) struct Tasks {
    slots: Vec<TaskSlot>,
    free: Vec<u32>,
    /// Live tasks - inserted, not yet retired. Shared with an embedding host so its drain can see work a connection
    /// table cannot: a task can be pending with no connection and no op in flight, which is invisible to a check that
    /// counts connections.
    live: Rc<Cell<usize>>,
    /// Lazily built at the first spawn: the queue needs the engine's wake eventfd, which `FsCore::new` does not see.
    run: Option<Arc<RunShared>>,
}

impl Drop for Tasks {
    /// Drop the still-pending futures inside a [`TEARDOWN`] mark.
    ///
    /// A destructor here runs with no poll on the stack, so a submit-on-drop guard reaches [`TaskFs`] with nothing
    /// parked. That is the documented teardown, not misuse, and an assert there would be a second panic that aborts a
    /// teardown which is itself an unwind. Parking a facade is not possible, since `ops` and `offload_reg` drop before
    /// `tasks`, the last field of `FsCore`. Each task drops under its own guard, and a payload goes to its join handle
    /// as [`poll_one`] does.
    fn drop(&mut self) {
        let _restore = RestoreTeardown(TEARDOWN.with(|c| c.replace(true)));
        // Explicit, because the field's own drop glue runs *after* this returns - by then the mark is cleared.
        for slot in &mut self.slots {
            let Some(mut entry) = slot.entry.take() else {
                continue;
            };
            // Held back so the sink survives its own entry's unwind, and dropped unfired otherwise - the future's
            // `Fire` has already answered the handle by then.
            let sink = entry.on_panic.take();
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(entry)));
            if let (Err(payload), Some(sink)) = (unwound, sink) {
                // Guarded on the same rule as `poll_one`'s: filling a detached handle's slot releases the last share of
                // it, so the payload's own disposal must not unwind either.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink(payload)));
            }
        }
    }
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
                // The first spawn happens on the loop thread (spawns come through a facade, and facades exist only
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

    /// A handle on the live-task count, for a host whose drain must wait for tasks as well as connections.
    pub(crate) fn gauge(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.live)
    }

    /// Take the entry out for a poll; `None` for a stale id (the task retired and its slot moved on) or one already
    /// out.
    fn take_if(&mut self, id: TaskId) -> Option<TaskEntry> {
        let s = self.slots.get_mut(id.idx as usize)?;
        if s.generation != id.generation {
            return None;
        }
        s.entry.take()
    }

    /// Re-enqueue `id` when its slot is the live tenant but currently out for a poll. A retired slot fails the
    /// generation test (`retire` bumps it) and a free slot cannot match a minted id, so this fires only for the
    /// mid-poll case.
    fn requeue_if_busy(&self, id: TaskId) {
        let busy = self
            .slots
            .get(id.idx as usize)
            .is_some_and(|s| s.generation == id.generation && s.entry.is_none());
        if !busy {
            return;
        }
        let Some(run) = self.run.as_ref() else {
            return;
        };
        let mut q = run.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(id);
        run.ready.store(q.len(), Ordering::Release);
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

/// Puts the drain-pass mark back however the pass ends, an unwinding poll included: a flag left set would silence every
/// later wake's poke, and a flag cleared by a *nested* pass would put the outer pass's remaining deliveries back to
/// poking. See [`RunShared::begin_pass`].
struct PassGuard(Arc<RunShared>, bool);

impl Drop for PassGuard {
    fn drop(&mut self) {
        self.0.draining.store(self.1, Ordering::Relaxed);
    }
}

/// Run one delivery point's callbacks inside a drain pass, then poll the tasks they woke.
///
/// **The mark and the drain are one call because they are one invariant**, since a delivery point that marked a pass
/// and did not drain would swallow the wake. Marking *before* the callbacks lets a completion that wakes its task skip
/// the eventfd write, CQE and re-arm the callback form never pays.
pub(crate) fn in_pass(fs: &mut FsCore, eng: &mut Engine, deliver: impl FnOnce(&mut FsCore, &mut Engine)) {
    // `None` where the reactor has never spawned a task, and there no task wake can arrive. One clone, not a clone per
    // guard: this runs once per CQE in both hosts, and the `Arc` is genuinely cross-thread, so a redundant refcount
    // pair here is two locked RMWs on the delivery hot path - the same cost the poll loop avoids by caching its waker.
    let _pass = fs.tasks.run.clone().map(|run| {
        let prev = run.begin_pass();
        PassGuard(run, prev)
    });
    deliver(fs, eng);
    drain(fs, eng);
}

/// Poll woken tasks, each with a fresh owner-scoped facade, bounded to what was queued when the pass began, so a task
/// that re-wakes itself waits for the next pass and the ring is not starved. Work left behind the bound pokes the
/// loop's wake eventfd, since a wake with nothing left in flight would otherwise wait on a completion that never comes.
pub(crate) fn drain(fs: &mut FsCore, eng: &mut Engine) {
    let Some(run) = fs.tasks.run.clone() else {
        return;
    };
    let mut budget = run.ready.load(Ordering::Acquire);
    if budget == 0 {
        return;
    }
    let prev = run.begin_pass();
    let _pass = PassGuard(run, prev);
    while budget > 0 {
        let Some(id) = fs.tasks.run.as_ref().and_then(|r| r.take_ready()) else {
            return;
        };
        budget -= 1;
        poll_one(fs, eng, id);
    }
    if let Some(run) = fs.tasks.run.as_ref()
        && run.ready.load(Ordering::Acquire) != 0
    {
        // An on-loop poke. The pushes are this thread's and already made, the eventfd counts, and the hosts keep its
        // READ armed, so the next wait completes at once and the leftover runs.
        run.wake.wake.poke();
    }
}

/// Poll one task. The entry is held out of the table for the poll, so
/// the facade the task submits through can borrow the tables freely;
/// a task that completes retires its slot, one that pends goes back.
fn poll_one(fs: &mut FsCore, eng: &mut Engine, id: TaskId) {
    let idx = id.idx;
    let Some(mut entry) = fs.tasks.take_if(id) else {
        // The slot's tenant is out being polled by a re-entrant drain. That poll already cleared the dedup edge, so
        // this id is the only record of the wake, and it goes back rather than being consumed.
        fs.tasks.requeue_if_busy(id);
        return;
    };
    let mut conn = FsConn::new(fs, eng, entry.owner);
    // Disjoint field borrows: the context reads the cached waker and the window reads the wake edge while the poll
    // borrows the future - no waker clone (and no refcount traffic) per poll.
    let mut cx = Context::from_waker(&entry.waker);
    // The entry is out of the table for the poll, so an unwinding future would otherwise leave the slot neither
    // occupied nor free, never reused, its generation never bumped, and `retire`'s own guard unable to see it.
    let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let done = poll_window(&entry.wake, || {
            with_current(&mut conn, id, || entry.fut.as_mut().poll(&mut cx))
        });
        // With the handle detached, the panic sink holds the last share of the output's slot, so releasing it runs the
        // output's destructor. Release it here under the guard, or a panicking `Drop` takes the reactor thread down.
        if done.is_ready() {
            drop(entry.on_panic.take());
        }
        done
    }));
    match poll {
        Ok(Poll::Ready(())) => fs.tasks.retire(idx),
        Ok(Poll::Pending) => fs.tasks.put_back(idx, entry),
        Err(payload) => {
            // Two guards, delivery first, as `Tasks::drop` does. Filling a detached handle's slot releases its last
            // share, so the payload's disposal must not unwind, and a guard shared with the future's destructors could
            // swallow `sink(payload)` and resolve the handle `Dropped` for work that panicked.
            let sink = entry.on_panic.take();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(sink) = sink {
                    sink(payload);
                }
            }));
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(entry);
            }));
            fs.tasks.retire(idx);
        }
    }
}

// loom models of the wake protocol, driving the shipping functions. Liveness models assert delivery counts, which stay
// green under `Relaxed`, so `loom_a_deduped_wake_publishes_what_it_wrote` carries a payload across the edge. A new
// ordering site needs a model of that second kind.
#[cfg(all(test, loom))]
mod loom_tests;

// ---- tests ----------------------------------------------------------------

#[cfg(all(test, not(loom)))]
mod tests;
