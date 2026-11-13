//! Awaitable operations and on-loop tasks over the callback facade.
//!
//! The callback facade stays the primitive. Everything here consumes [`FsConn`]'s existing submit methods: an op future
//! is one submission whose delivery fills a slot instead of running a chain, and the two styles compose - a request may
//! hold callbacks at one step and `await` the next. Nothing routes a ring op through the offload pool: the wrapper
//! re-shapes delivery only, and submission stays the eager, on-ring path the callback form uses.
//!
//! "Poll" in this module is always [`Future::poll`] - the state-machine step, `std`'s own vocabulary - never `poll(2)`
//! or a readiness op. A task poll issues no syscall; the ops a poll submits do their kernel work through the ring like
//! every other submission.
//!
//! - [`FsConn::fut`] wraps one submission. It hands the closure a boxed callback ([`OnDone`]) to pass as any submit
//!   method's `on_done` and returns the [`FsFuture`] that callback resolves.
//! - [`FsConn::offload_fut`] is the same shape over [`FsConn::offload_result`], for a blocking metadata tail.
//! - [`FsConn::spawn`] starts a **task**: a `'static` future polled inline on the loop thread, owner-scoped exactly
//!   like a chained continuation. The task body receives a [`TaskFs`], which is how code inside the task submits: a
//!   task cannot hold the facade across an `await`, so each poll runs with the delivering facade parked where
//!   [`TaskFs`] can reach it, and nowhere else. Spawning returns a [`JoinHandle`] resolving with the task's output, or
//!   a [`JoinError`]; dropping the handle detaches rather than kills.
//! - **A panicking task is contained.** Its poll unwinds no further than the executor: the payload reaches its
//!   [`JoinHandle`] as [`JoinError::Panic`], the slot retires, and the reactor thread keeps serving every other
//!   connection. This is the one place in the crate that catches an unwind on the loop - a callback that panics still
//!   takes the thread down - because a task is a request's own work and a request's bug should cost the request.
//!
//!   Containment covers **the disposal of what the poll produced**, not
//!   only the poll. A detached task's output is dropped by the
//!   executor, because the handle is gone and nothing else holds the
//!   slot, and that drop runs inside the same guard; outside it an
//!   output whose `Drop` unwinds would take the delivery path, which is
//!   the reactor thread. An output handed to a live [`JoinHandle`] is
//!   disposed of by whoever polls or drops that handle, in their frame,
//!   like any other value.
//!
//! # Contract
//!
//! - **Submission is eager.** The op is in flight when [`FsConn::fut`] returns, polled or not. Dropping an [`FsFuture`]
//!   abandons the outcome - the completion fires into a slot nobody reads - and does not cancel the op; its registry
//!   entry owns everything the kernel still touches.
//! - **A callback dropped unfired resolves the future** with `ECANCELED` rather than pending forever. That is the
//!   future form of "dropping the continuation closes the connection": a refused submission, or teardown, reaches the
//!   awaiting task as an error it can act on, **and it says which**. The callback form still drops `on_done` for all of
//!   them, which is its own contract; the futures layer stages a reason sink beside the callback, and a sink runs no
//!   consumer code, so nothing is delivered inline from a submit path. Three things make the distinction usable:
//!   - [`FsDone::was_refused`] says the errno is **this crate's**, not the kernel's. Read it first: `EBUSY` from a full
//!     op table is worth retrying and `EBUSY` from the kernel is permanent for that path, and nothing about the errno
//!     alone separates them.
//!   - The refusal **hands the payload back** ([`FsDone::into_bufs`]), so the retry it advises is possible without
//!     keeping a second copy of every write.
//!   - The sink is **shared across a multi-step call's steps** ([`FsConn::open_chain`], [`FsConn::mkdir_path`]), which
//!     submit from a fresh facade after the first, so a mid-chain refusal keeps its errno instead of arriving as
//!     teardown.
//!
//!   `ECANCELED` with `was_refused()` false is left meaning teardown
//!   alone.
//! - **A task's facade is a continuation facade.** Each poll gets a fresh owner-scoped [`FsConn`], the same one a
//!   completion callback is handed, and everything a continuation must tolerate - an owner gone mid-chain - a task must
//!   tolerate too. A task ends by returning; there is no external kill, so a task must terminate when its ops start
//!   failing or the source feeding it closes. **Neither of those reaches a task whose awaits are all offloads**,
//!   because an offload is never cancelled and always delivers, so that shape has to ask - [`TaskFs::owner_is_gone`]
//!   for "your connection closed", [`TaskFs::draining`] for "the server is going away", polled between awaits. A task
//!   that never winds down holds a graceful drain open to its grace deadline.
//! - **A task's facade carries no recv-buffer claim**, so [`pwritev2_from`](FsConn::pwritev2_from) from inside a task
//!   copies instead of writing the delivered buffer in place. The claim belongs to the delivery that is holding the
//!   body, and a task outlives it. Submitting the write from the delivery's own callback and handing the [`FsFuture`]
//!   to the task keeps the zero-copy path; a task that wants the bytes must own them, which its `'static` future
//!   requires in any case.
//! - **Tasks are polled from the delivery points that fire callbacks** (completion and offload delivery), plus
//!   [`FsConn::run_woken`] for a callback that wakes a task by hand and wants it run before the next completion. Each
//!   pass is bounded to what was queued when it began - a wake landing mid-pass runs next pass, behind a poke of the
//!   loop's wake eventfd - so a self-waking task cannot starve the ring. A waker used off-loop pushes under the
//!   run-queue lock and then pokes the same eventfd - the offload pool's push-then-poke protocol (`finish_offload`).
//! - **The task table and run queue are uncapped**, like the offload registry: bound in-flight work upstream, at the
//!   request cap.

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
    /// A staged reason sink's refusal, parked provisionally. The submission carrying the frame's callback owns the
    /// slot, so a sink's verdict waits for the callback route to settle it: [`Fire::fire`] with a real outcome
    /// supersedes it, and the callback dropping unfired adopts it. Do not settle `Ready` straight from the sink: a
    /// refusal whose arm rode a *different* submission would then answer for an op still in flight, and the real
    /// completion lands in a settled slot and is dropped, `File` and all - closing a fresh descriptor under a caller
    /// told a marked `EBUSY` for a create that ran.
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
        // The borrow ends before the wake: the waker re-enters the executor's queue, never this slot, but keeping the
        // borrow narrow costs nothing and removes the question.
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

    /// Park a staged reason sink's refusal. Provisional on purpose: the submission carrying the frame's callback owns
    /// the slot ([`SlotState::Refused`]), so the reason resolves the future only once that callback drops unfired, and
    /// a real completion still in flight supersedes it. The first refusal wins over later ones; a slot already `Gone`
    /// takes the reason at once, the callback route having already ended.
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

    /// A second poll answers `ECANCELED` too, with [`FsDone::was_refused`] false: the outcome went to the poll that got
    /// it, and there is nothing left to hand over. Distinguishing that from teardown would cost a variant nobody can
    /// act on - polling a resolved future again is a caller bug either way.
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
    /// A panicking task is contained: its slot retires, the reactor thread lives, and every other connection on that
    /// ring keeps being served - **unless the panicking future also holds a destructor that panics.** The poll's unwind
    /// drops the future's state, so a `Drop` that panics there is a panic during an unwind, which aborts by language
    /// rule before any guard in this crate can run; no placement of `catch_unwind` closes it. Keep panic-on-drop guards
    /// out of task state. (Teardown is different: there the entries drop with no unwind in progress, and one
    /// destructor's panic is contained per slot.)
    ///
    /// Elsewhere in this crate a panic is not contained - a callback that unwinds still takes the loop down - so this
    /// is deliberately the narrower promise: a task's own bug is a request's problem, not the ring's.
    Panic(Box<dyn std::any::Any + Send>),
    /// The task produced no output and never will: dropped at teardown before completing, or a release-build
    /// [`TaskFs::spawn`] called out of turn, whose body therefore never ran at all. Both are "this work did not
    /// happen"; neither is worth retrying through this handle, which has no task behind it either way.
    Dropped,
    /// This handle already yielded the task's output. A handle is not a broadcast: the poll that got the output took
    /// it, and the task itself ran to completion - which is why this is not [`JoinError::Dropped`], whose answer is
    /// "look at why the work did not happen" and whose answer here is "fix the caller polling a resolved handle".
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
/// Resolves `Ok` with what the task returned, or [`JoinError`] when it produced nothing. Polling again after it has
/// resolved answers
/// [`JoinError::Consumed`]: the output went to the poll that got it,
/// and a handle is not a broadcast.
///
/// Dropping the handle detaches - the task runs to completion either way and its output is dropped unread. There is no
/// kill through it.
///
/// **A detached task's panic has no programmatic recipient.** It is still contained and the slot still retires, but
/// [`JoinError::Panic`] lands in a slot nobody reads, so the default panic hook printing it is the only report. Keep
/// the handle for work whose failure has to be acted on.
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
    /// **`submit` submits exactly one op.** The reason sink staged here answers for a single submission, and the
    /// *first* one the closure makes takes its share; a later submission in the same frame arms nothing. And whichever
    /// submission a refusal reaches the sink from, the submission carrying this future's own `on_done` owns the slot:
    /// the sink's verdict is parked provisionally (`SlotState::Refused`), a real completion supersedes it, and the
    /// refusal's own delivery - every host refusal fires its callback with its verdict at the wake drain
    /// (`FsCore::refuse`) - settles it with the same marked errno. So a refused arm can never answer for an op still in
    /// flight, and whichever submission carried `on_done`, the future resolves with that submission's own outcome.
    /// Submit the extra op before or after the call, not inside it.
    pub fn fut(&mut self, submit: impl FnOnce(&mut FsConn<'_>, OnDone)) -> FsFuture {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        // Why an op never reached the ring, for the future to read: `EBUSY` from a full op table is worth retrying with
        // the payload the sink hands back, `EINVAL` from a refused argument is a caller bug, and teardown is neither.
        // The callback form cannot tell them apart - it drops `on_done` for all three - so the sink is what carries the
        // distinction, and `FsDone::was_refused` is what separates it from the kernel's own `EBUSY`.
        let reason = Rc::clone(&slot);
        // Saved and put back, because `submit` may itself contain a `fut`: assigning over the outer sink would leave
        // the outer op reporting teardown for its own refusal.
        let outer = self.stage_fail_sink(Rc::new(SinkInner::new(move |errno, bufs| {
            reason.fill_refused(FsDone::refused_with(errno, bufs));
        })));
        submit(self, Box::new(move |done, _conn| fire.fire(done)));
        // No submission armed the sink: `submit` returned without handing the op to the core at all, which is what the
        // facade's own argument checks do (an absolute path, an empty link target) - the same class of defect the core
        // reports as `EINVAL`.
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

    /// Submit one op through `submit` and return its outcome as a future - [`fut`](Self::fut) for the nine facade
    /// methods whose callback carries a [`crate::Result`] instead of an [`FsDone`]: both `fstatfs` forms, `flistxattr`,
    /// `fremovexattr`, the ZFS attribute pair, `copy_file_range`, and the `open_dir`/`next_batch` walk. Without it a
    /// handler cannot be written wholly as a task, and the three that are hand-rollable through
    /// [`offload_fut`](Self::offload_fut) lose real guarantees on the way: `fremovexattr`'s allowlist and `open_dir`'s
    /// per-request `open` are reactor state a pool job cannot see.
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
    /// The one-op rule on [`fut`](Self::fut)'s `submit` applies here too, and for the same reason.
    ///
    /// Submission is eager on the same terms as [`fut`](Self::fut), and it stages a reason sink for the same reason -
    /// `open_dir`'s first step is a ring `open`, so a full op table refuses this shape too and would otherwise reach
    /// the future as `ECANCELED`, which [`FsFuture`] reserves for teardown.
    ///
    /// **Staging is what keeps the sink from being ambient.** The sink lives on the facade, because a multi-step call's
    /// later steps submit from a fresh one; so a submission made inside *another* future's `submit` closure arms
    /// whatever is staged, and without a frame of its own this call would fill the enclosing future's slot with its own
    /// refusal while the enclosing op was still in flight. It does not copy [`fut`](Self::fut)'s "nothing armed, so
    /// nothing will ever answer" rule: eight of the nine methods here never reach the op table at all, so on this shape
    /// an unarmed sink is the ordinary case rather than a refused argument.
    ///
    /// Eight of the nine deliver through the offload pool, where a refusal has no errno to carry and the future
    /// resolves `ECANCELED` as [`offload_fut`](Self::offload_fut) does.
    pub fn result_fut<T, S>(&mut self, submit: S) -> OffloadFuture<T>
    where
        S: FnOnce(&mut FsConn<'_>, OnResult<T>),
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        let reason = Rc::clone(&slot);
        let outer = self.stage_fail_sink(Rc::new(SinkInner::new(move |errno, _bufs| {
            reason.fill_refused(Err(errno.into()));
        })));
        submit(self, Box::new(move |r, _conn| fire.fire(r)));
        self.restore_fail_sink(outer);
        OffloadFuture(slot)
    }

    /// Start a task: `body` builds the future from the [`TaskFs`] it will submit through, and the task is polled once
    /// inline before this returns - so its first ops are on the ring when the caller resumes, exactly as an eager
    /// callback chain's would be.
    ///
    /// `body` itself runs inside that first poll, so it may submit through its [`TaskFs`] while assembling the future -
    /// the eager pair this module's contract describes - and not only from inside the returned future.
    ///
    /// The task is owner-scoped like a continuation: polls after this one run from completion delivery, each with a
    /// fresh facade for the same owner. A task ends by returning. There is no external kill; a task whose connection
    /// died sees its ops fail and must wind down on that signal - or, where its awaits cannot fail, asks
    /// [`TaskFs::owner_is_gone`]. Whatever outlives the loop is dropped with the reactor's tables at teardown.
    ///
    /// The returned [`JoinHandle`] resolves with the task's output. Dropping it detaches: the task runs to completion
    /// regardless and its output is dropped unread - the shape a spawn used for its effects wants, so the handle is not
    /// `#[must_use]`.
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
        // `body` runs *inside* the first poll, not here: it is handed a `TaskFs`, and a facade is parked only for the
        // extent of a poll. Building the future out here would leave every op the caller submits while assembling it -
        // the eager pair this contract advertises - with no facade to submit through.
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
    /// A [`TaskFs`] carries the id it was minted under and is refused against any other, so a handle that left its body
    /// cannot submit during a different task's poll. Without it the facade is reached by whoever is running, and an op
    /// written in one task's terms is stamped another's owner - the wrong connection's teardown sweep cancels it, the
    /// right one leaves its descriptor parked, and nothing anywhere says so.
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
/// Handed to the task body by [`FsConn::spawn`]; methods work only while that task is being polled. It is not `Send`: a
/// task and its ops belong to the loop thread. Calling one out of turn debug-asserts, and in release resolves the op as
/// `ECANCELED` / drops the spawn, the facade's shape for a submission that cannot happen.
///
/// A poll is not the only time a task's code runs: **destructors do too**, including at teardown, where the tables the
/// facade would borrow are already gone. A guard of the "submit on drop" shape therefore reaches this outside a poll by
/// design, and teardown is the one place that is not misuse - the assert is suppressed there and the submission is
/// refused like any other that cannot happen; the reasoning is on the task table's `Drop`, which is internal.
///
/// **It carries the id of the task it was minted for**, and every method is refused unless that is the task being
/// polled. The handle is `'static` and `!Send`, so removing `Clone` does not keep it inside its body: a body can *move*
/// it into any `'static` non-`Send` place on the loop thread - connection state, a `thread_local!` - and something else
/// can pick it up there. Used during a different task's poll it would otherwise find `CURRENT` populated, submit
/// against that task's facade and be stamped its owner, so the wrong connection's teardown sweep would cancel the op
/// and the right one would leave its descriptor parked, with no diagnostic anywhere. The id is what makes that case
/// indistinguishable from reaching outside a poll, which is a refusal this already had a shape for.
///
/// Not `Clone` all the same: nothing needs a second handle, and the narrower surface is one less thing for the id check
/// to be the only guard on.
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

/// The slot a [`TaskFs`] call answers with when it cannot reach a facade, which happens for two unrelated reasons.
///
/// Teardown is [`Slot::gone`]: it polls as `ECANCELED` with [`FsDone::was_refused`] false, which is this module's one
/// meaning for "the reactor is going away" and the signal a consumer winds down on. The other reason is this handle
/// being used out of turn - moved into `'static` state and submitted through from somewhere else - and reporting *that*
/// as teardown tells a release build to shut a healthy server down over a caller's bug. `refused` names the caller
/// instead, on the same rule as every other submission the crate itself refuses.
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
    /// This module's contract says a task "must terminate when its ops start failing or the source feeding it closes",
    /// and for a task awaiting only offloads neither is ever true: an offload is never cancelled and always delivers.
    /// Such a task keeps running for a dead connection, stays counted in the live gauge, and holds a graceful drain
    /// open until the grace period ends it. Poll this between awaits and return.
    ///
    /// Reached with no facade - outside this task's poll, or nested inside a call already holding it - this cannot read
    /// the owner's state and **must not guess "gone"**: the documented reaction to `true` is to wind down, so a wrong
    /// `true` makes a task abandon work for a live connection. The nested reach is the one a helper that both submits
    /// and checks takes - `t.fut(|c, cb| { if t.owner_is_gone() { .. } .. })` - and the facade is parked out of the
    /// cell for exactly the extent of that closure. Both misuses take the siblings' shape: a debug assert, and in
    /// release the teardown state, which is the only thing knowable from here.
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

    /// [`FsConn::draining`] against the running poll's facade - the server-side half of the wind-down pair. Poll it
    /// between awaits with [`owner_is_gone`](Self::owner_is_gone): that one ends a task whose connection died, this one
    /// ends a task holding a graceful drain open from a connection that is fine. Never `true` on a standalone host; see
    /// [`FsConn::draining`].
    ///
    /// With no facade - outside the poll, or nested - the answer is the teardown state, on
    /// [`owner_is_gone`](Self::owner_is_gone)'s reasoning: a wrong `true` makes a task abandon work, so nothing is
    /// guessed.
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
/// Not packed into a `u64`: no task id ever reaches `user_data`, so nothing here is bounded by the 24-bit slot field
/// the ring routing tokens use, and a full-width generation is what [`SlotEntry`](crate::uring::slots::SlotEntry)
/// documents the reason for - a `Waker` is exactly the long-retained handle that must not alias a future incarnation
/// after the counter wraps.
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
    /// Set for the extent of a [`drain`] pass. A wake landing inside a pass is taken by that pass or by its trailing
    /// poke; a wake landing outside one has nothing scheduled to collect it, so it must poke for itself. Written only
    /// through [`RunShared::begin_pass`] and [`PassGuard`].
    ///
    /// **Every access is the loop thread's, so all three are spelled `Relaxed` and no ordering is claimed.** The
    /// census: both writers run only inside the loop's delivery passes, and the single read ([`wake_task`]) sits behind
    /// `off_loop() ||`, whose short-circuit is exactly what keeps an off-loop waker from ever reaching it. The module's
    /// rule stands - an ordering site needs a model that carries a payload across it or it is unchecked - and the way
    /// this site satisfies it is by claiming none; a change that lets another thread read this flag must bring the
    /// ordering *and* the model with it.
    draining: AtomicBool,
    /// The loop's shared flags and wake eventfd.
    wake: Arc<LoopShared>,
    /// The loop thread, recorded at first spawn.
    #[cfg(not(loom))]
    loop_thread: std::thread::ThreadId,
    /// The model's stand-in for the thread check. A `cfg` hard-coding this to `true` is what made the on-loop branch -
    /// where the wake-outside-a-pass bug lived - unreachable from any model while the module claimed its models carried
    /// the liveness argument; keep it settable so both branches stay expressible.
    #[cfg(loom)]
    model_off_loop: bool,
}

impl RunShared {
    /// Mark a drain pass live, answering what was there before so [`PassGuard`] can put it back.
    ///
    /// A nested pass - a callback calling [`run_woken`](FsConn::run_woken) from inside a delivery - must not un-mark
    /// the outer one when it ends: the outer pass's remaining deliveries would then poke the loop for work the outer
    /// pass is already about to do. Restoring rather than clearing is one word here and removes the depth question.
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
    /// The count is **published from under the lock**, never adjusted by a delta. A delta is only as good as the
    /// pairing, and the pairing is broken by design at both ends: [`wake_task`] pushes under this lock and adds after
    /// releasing it, so an off-loop waker leaves the queue longer than the count for a window, and a nested pass can
    /// spend count an outer pass's budget was sampled from. The subtraction that finds nothing left wraps to
    /// `usize::MAX`, which [`drain`] samples as the entry bound that returns this thread to the ring. Storing the
    /// length the lock holder can see cannot wrap and cannot contradict a push it already observed.
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
/// pass (the inline poll in [`FsConn::spawn`], or a callback waking a task by hand) is otherwise scheduled by nothing:
/// the id sits in the queue while the loop parks on a ring that has no reason to complete, and the `queued` edge then
/// latches, so every later wake - an off-loop one included - is deduped away and the task is unreachable for the life
/// of the reactor.
///
/// Push under the lock, then poke - `finish_offload`'s protocol, and the same one-direction ordering argument: poke
/// first and the loop can wake, find nothing, and park again with the id enqueued behind it.
///
/// A skipped wake is covered by a poll that has not started yet: the flag is set either while the id still sits in the
/// queue, or in the window between its pop and [`poll_window`] - and in both a poll of this task starts after this call
/// returns, which is all the waker contract asks.
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

/// Run one poll inside the task's window: the dedup edge clears strictly *before* `poll`, so a wake landing mid-poll
/// enqueues a fresh pass instead of vanishing into a poll already past the state it was announcing. Clearing after the
/// poll is the lost-wakeup bug the loom model bites on; the pairing lives here, once, so the model drives the shipping
/// order rather than a copy of it.
///
/// **A swap, not a store, because this is the acquire half of the dedup edge.** A wake that finds the flag already set
/// ([`wake_task`]'s early return) touches nothing else: it does not take the run-queue lock, so the lock is not there
/// to carry what the waker published before waking, and the covering poll is this one. A plain store cannot read the
/// release that skipping waker performed, so it establishes no happens-before and the poll may run against stale data.
/// tokio writes its state back unchanged on exactly this path for exactly this reason (`runtime/task/state.rs`, "to
/// pair with the Acquire in `transition_to_running`").
///
/// In-tree no waker leaves the loop thread - every [`Slot`] is a `RefCell` behind an `Rc` and the only production
/// `wake()` is inside [`Slot::fill`] - so this pairs nothing today. It is the public [`Waker`] surface that makes it
/// reachable: an off-loop lock-free waker is what a consumer may legitimately build, and its readiness would otherwise
/// be invisible to the poll that is meant to cover it.
///
/// **The Miri lane owns this edge** (`miri_a_deduped_wake_publishes_what_it_wrote`, seeded): the old `store(false,
/// Release)` spelling survived 200k native rounds - x86's TSO hides it - and the loom model's exploration is documented
/// as unable to vouch for it, while Miri kills it within a handful of seeds. The mirror-image edge is the
/// graceful-drain publication (`uring::wake::LoopShared::request_graceful`), which only loom catches; retire either
/// lane and its edge goes unwatched.
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
    /// A task pending when the reactor's tables go has its destructors run with no poll on the stack, so a guard that
    /// submits on drop reaches [`TaskFs`] and finds nothing parked. Asserting is right for a handle used out of turn
    /// and wrong here: this is the documented "whatever outlives the loop is dropped with the reactor's tables", and in
    /// a debug build the assert is a *second* panic - which, when the teardown is itself an unwind, aborts the process
    /// and replaces the diagnosis of the first panic with a bare SIGABRT. Both profiles run in the gate.
    ///
    /// Parking a facade for the drop instead is not available: `tasks` is the last field of `FsCore` and nothing above
    /// it has a `Drop`, so `ops` and `offload_reg` are already destroyed by the time this runs and the facade would
    /// name a dead op table.
    ///
    /// **Dropped one task at a time, each contained.** A destructor here runs with no poll on the stack, so nothing
    /// else would catch it: one task's unwinding guard would escape this `Drop` impl and take every task after it, and
    /// when the teardown is itself an unwind - the case the mark above exists for - a panic escaping a `Drop` aborts
    /// and replaces the first panic's diagnosis with a bare SIGABRT. That is the harm this whole function is about, so
    /// suppressing only the assert it raised would be answering the symptom. The payload goes to that task's own join
    /// handle, the route [`poll_one`] already uses for a panicking poll.
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
/// **The mark and the drain are one call because they are one invariant.** The flag is what tells [`wake_task`] the
/// loop is already about to poll, so a delivery point that marked a pass and then did not drain would swallow the wake
/// outright. A guard the caller has to pair by hand is how that gets broken by the next delivery point somebody adds.
///
/// Marking *before* the callbacks is the whole point: a completion that resolves an op future wakes its task from
/// inside the callback, one statement before the drain that polls it, so the eventfd write, the CQE it produces and the
/// re-arm SQE that follows are all spent announcing work this call is already doing. The callback form pays none of
/// that, and an awaited op should not either.
///
/// A nested [`drain`] - a callback calling [`run_woken`](FsConn::run_woken) - restores the mark rather than clearing
/// it, so the rest of this pass keeps it.
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

/// Poll woken tasks, each with a fresh owner-scoped facade, bounded to what was queued when the pass began. Called by
/// [`in_pass`] once its delivery point has fired its callbacks, so a completion that woke a task runs it in the same
/// dispatch, at callback latency.
///
/// The entry bound is what keeps the ring serviced: a task that re-wakes itself - or a cascade every pass extends -
/// lands behind it and waits for the next pass, so control returns to the host between passes and CQEs are reaped
/// instead of starved. Work left behind the bound pokes the loop's wake eventfd; without that, a wake with nothing left
/// in flight - a parent woken by its child's final poll - would wait on a completion that is never coming.
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
        // An on-loop poke: the pushes are this thread's and already made, the eventfd counts, and the hosts keep its
        // READ armed
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
        // A live generation with no entry is the slot's tenant out being polled - a re-entrant drain, which `run_woken`
        // and the facade a submit closure receives both make reachable. That poll already cleared the dedup edge, so
        // this id is the only record of the wake: put it back rather than consume it, or the task is never scheduled
        // again.
        fs.tasks.requeue_if_busy(id);
        return;
    };
    let mut conn = FsConn::new(fs, eng, entry.owner);
    // Disjoint field borrows: the context reads the cached waker and the window reads the wake edge while the poll
    // borrows the future - no waker clone (and no refcount traffic) per poll.
    let mut cx = Context::from_waker(&entry.waker);
    // The entry is out of the table for the poll, so an unwinding future would otherwise leave the slot neither
    // occupied nor free
    // - never reused, its generation never bumped, and `retire`'s own
    // guard unable to see it.
    let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let done = poll_window(&entry.wake, || {
            with_current(&mut conn, id, || entry.fut.as_mut().poll(&mut cx))
        });
        // A finished task has just put its output in the slot, and the panic sink below is the executor's share of that
        // slot. With the handle detached - which the contract blesses - it is the *last* share, so releasing it runs
        // the output's destructor. Release it here, under the guard: outside, that destructor runs on the delivery path
        // with nothing to catch it, and an output whose `Drop` panics takes the reactor thread and every connection on
        // it down.
        if done.is_ready() {
            drop(entry.on_panic.take());
        }
        done
    }));
    match poll {
        Ok(Poll::Ready(())) => fs.tasks.retire(idx),
        Ok(Poll::Pending) => fs.tasks.put_back(idx, entry),
        Err(payload) => {
            // Contained: the handle learns what happened, the slot retires, and the ring keeps serving every other
            // connection. The payload reaches the awaiter rather than the loop, so a task's own bug cannot take down
            // requests that have nothing to do with it.
            //
            // Guarded for the reason above: filling a detached handle's slot is what releases the last share of it, so
            // the payload's own disposal must not unwind the delivery path either. A sink already taken above is a
            // `Ready` poll whose output panicked on the way out - contained, and with the handle gone there is nobody
            // left to report it to.
            // Two guards, delivery first, which is the order `Tasks::drop` uses. The future's destructors run under
            // their own: a destructor whose panic is its first is contained rather than aborting, so sharing one guard
            // with the delivery would let it swallow `sink(payload)` and resolve the handle `Dropped` for work that ran
            // and panicked.
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

// ---- loom: the wake protocol ----------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// Two claims carry the executor's liveness, and both are cross-thread: a wake from off the loop is never lost between
// the queue and the poke (`wake_task`, the push-then-poke order), and a wake landing around a poll window is either
// absorbed by the poll that follows or re-enqueued - never swallowed (`poll_window` clearing the dedup edge *before*
// the poll). The models drive the shipping functions; a copy of their ordering would stay green with the shipping half
// weakened.
//
// A third claim carries its *visibility*, and needs a different kind of model. Liveness models assert delivery counts,
// and a count is invariant under `Relaxed` - weaken every ordering here and they all stay green, because nothing
// crosses the edge they model. `loom_a_deduped_wake_publishes_what_it_wrote` carries a payload across it and goes red
// on either half, which is the control `CLAUDE.md` asks for. Add an ordering site here and it needs a model of that
// second kind, or it is unchecked however many models pass.
#[cfg(all(test, loom))]
mod loom_tests;

// ---- tests ----------------------------------------------------------------

#[cfg(all(test, not(loom)))]
mod tests;
