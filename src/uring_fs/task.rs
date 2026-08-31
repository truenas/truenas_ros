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
//!   a [`JoinHandle`] resolving with the task's output; dropping the
//!   handle detaches rather than kills.
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
//!   can act on.
//! - **A task's facade is a continuation facade.** Each poll gets a
//!   fresh owner-scoped [`FsConn`], the same one a completion callback
//!   is handed, and everything a continuation must tolerate - an owner
//!   gone mid-chain - a task must tolerate too. A task ends by
//!   returning; there is no external kill, so a task must terminate
//!   when its ops start failing or the source feeding it closes.
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

/// A spawned task's output, as a future. Resolves `Some` with what the
/// task returned; `None` if the task was dropped before finishing,
/// which the reactor does only at teardown.
///
/// Dropping the handle detaches - the task runs to completion either
/// way and its output is dropped unread. There is no kill through it.
pub struct JoinHandle<T>(Rc<Slot<T>>);

impl<T> std::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.poll_take(cx)
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
        submit(self, Box::new(move |done, _conn| fire.fire(done)));
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

    /// Start a task: `body` builds the future from the [`TaskFs`] it
    /// will submit through, and the task is polled once inline before
    /// this returns - so its first ops are on the ring when the caller
    /// resumes, exactly as an eager callback chain's would be.
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
        F: FnOnce(TaskFs) -> Fut,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let slot = Slot::new();
        let fire = Fire(Some(Rc::clone(&slot)));
        let fut = body(TaskFs::new());
        let task = Box::pin(async move { fire.fire(fut.await) });
        let (fs, eng, owner) = self.split();
        let id = fs.tasks.insert(eng, owner, task);
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

/// Restore [`CURRENT`] on scope exit, a panic included: a panicking
/// task unwinds through the host loop, and the cell must not keep
/// naming a facade that died with this frame.
struct Restore(Option<NonNull<FsConn<'static>>>);

impl Drop for Restore {
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.0));
    }
}

/// Park `conn` in [`CURRENT`] for the duration of `f` (a task poll).
fn with_current<R>(conn: &mut FsConn<'_>, f: impl FnOnce() -> R) -> R {
    // The lifetime is erased for storage only: the pointer is taken
    // back out strictly inside `f`'s dynamic extent, where `conn` is
    // still exclusively this frame's.
    let ptr = NonNull::from(conn).cast::<FsConn<'static>>();
    let _restore = Restore(CURRENT.with(|c| c.replace(Some(ptr))));
    f()
}

/// Reach the poll's parked facade. `None` outside a poll. The pointer
/// is *taken* for the call - a nested reach sees an empty cell rather
/// than a second `&mut` to the same facade.
fn with_conn<R>(f: impl FnOnce(&mut FsConn<'_>) -> R) -> Option<R> {
    CURRENT.with(|c| {
        let ptr = c.take()?;
        let _restore = Restore(Some(ptr));
        // SAFETY: `ptr` was parked by `with_current` around the poll
        // running right now on this thread; the facade it names is the
        // executor's for that whole extent, and the `take` above makes
        // this the only live reference derived from it. The `'static`
        // in the cell is storage-only: `f` is generic over the
        // facade's lifetime, so the reference cannot escape it.
        let conn = unsafe { &mut *ptr.as_ptr() };
        Some(f(conn))
    })
}

/// A task's handle to the facade of whichever poll is running it.
///
/// Handed to the task body by [`FsConn::spawn`]; methods work only
/// while the task is being polled (which is the only time the task's
/// code runs). It is not `Send`: a task and its ops belong to the loop
/// thread. Smuggling it elsewhere and calling it there debug-asserts,
/// and in release resolves the op as `ECANCELED` / drops the spawn,
/// the facade's shape for a submission that cannot happen.
#[derive(Clone)]
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

    /// [`FsConn::spawn`] against the running poll's facade: the child
    /// task shares this task's owner and is polled once inline. The
    /// handle lets the spawning task await the child's output - two
    /// children spawned back to back run their ops concurrently, and
    /// awaiting both is a join.
    pub fn spawn<F, Fut, T>(&self, body: F) -> JoinHandle<T>
    where
        F: FnOnce(TaskFs) -> Fut,
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

/// Pack a task's slot index and generation into the id its waker carries.
fn pack_task(idx: u32, generation: u32) -> u64 {
    (u64::from(idx) << 32) | u64::from(generation)
}

fn unpack_task(id: u64) -> (u32, u32) {
    ((id >> 32) as u32, id as u32)
}

/// What a waker reaches: the run queue, its emptiness hint, and the
/// loop's wake eventfd for an off-loop wake.
pub(crate) struct RunShared {
    /// Woken task ids, in wake order.
    queue: Mutex<VecDeque<u64>>,
    /// Queue-length hint, so the per-completion drain check is one
    /// relaxed load instead of a lock acquisition.
    ready: AtomicUsize,
    /// The loop's shared flags and wake eventfd.
    wake: Arc<LoopShared>,
    /// The loop thread, recorded at first spawn: a wake from it needs
    /// no poke (a drain follows in the same dispatch), a wake from
    /// anywhere else does.
    #[cfg(not(loom))]
    loop_thread: std::thread::ThreadId,
}

impl RunShared {
    /// Whether the caller is off the loop thread. Under loom there is
    /// no comparable thread identity, and the models exercise the
    /// off-loop path - the one with an ordering to check.
    fn off_loop(&self) -> bool {
        #[cfg(loom)]
        {
            true
        }
        #[cfg(not(loom))]
        {
            std::thread::current().id() != self.loop_thread
        }
    }

    /// Pop the next woken task id, if any.
    pub(crate) fn take_ready(&self) -> Option<u64> {
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
    id: u64,
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
/// the loop when woken from off it. Returns whether this call enqueued
/// (a dedup-skipped wake returns `false`).
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
    if w.run.off_loop() {
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

struct TaskEntry {
    fut: Pin<Box<dyn Future<Output = ()>>>,
    owner: Owner,
    wake: std::sync::Arc<TaskWake>,
    waker: Waker,
}

struct TaskSlot {
    /// Bumped at retire, so a stale waker's id misses and its wake is
    /// inert - the run queue may hold ids for tasks already gone.
    generation: u32,
    /// `None` while free *or* while the entry is out being polled; the
    /// free list is what distinguishes the two.
    entry: Option<TaskEntry>,
}

/// The reactor's tasks. A field of `FsCore`, so every host that fires
/// callbacks can drain the woken ones with the same borrows.
pub(crate) struct Tasks {
    slots: Vec<TaskSlot>,
    free: Vec<u32>,
    /// Lazily built at the first spawn: the queue needs the engine's
    /// wake eventfd, which `FsCore::new` does not see.
    run: Option<Arc<RunShared>>,
}

impl Tasks {
    pub(crate) fn new() -> Tasks {
        Tasks {
            slots: Vec::new(),
            free: Vec::new(),
            run: None,
        }
    }

    fn insert(
        &mut self,
        eng: &Engine,
        owner: Owner,
        fut: Pin<Box<dyn Future<Output = ()>>>,
    ) -> u64 {
        let run = self.run.get_or_insert_with(|| {
            Arc::new(RunShared {
                queue: Mutex::new(VecDeque::new()),
                ready: AtomicUsize::new(0),
                wake: Arc::clone(&eng.shared),
                // The first spawn happens on the loop thread (spawns
                // come through a facade, and facades exist only
                // there), so this records the loop.
                #[cfg(not(loom))]
                loop_thread: std::thread::current().id(),
            })
        });
        let idx = self.free.pop().unwrap_or_else(|| {
            self.slots.push(TaskSlot {
                generation: 0,
                entry: None,
            });
            (self.slots.len() - 1) as u32
        });
        let id = pack_task(idx, self.slots[idx as usize].generation);
        let wake = std::sync::Arc::new(TaskWake {
            id,
            queued: AtomicBool::new(false),
            run: Arc::clone(run),
        });
        let waker = Waker::from(std::sync::Arc::clone(&wake));
        self.slots[idx as usize].entry = Some(TaskEntry {
            fut,
            owner,
            wake,
            waker,
        });
        id
    }

    /// Take the entry out for a poll; `None` for a stale id (the task
    /// retired and its slot moved on) or one already out.
    fn take_if(&mut self, idx: u32, generation: u32) -> Option<TaskEntry> {
        let s = self.slots.get_mut(idx as usize)?;
        if s.generation != generation {
            return None;
        }
        s.entry.take()
    }

    fn put_back(&mut self, idx: u32, entry: TaskEntry) {
        self.slots[idx as usize].entry = Some(entry);
    }

    fn retire(&mut self, idx: u32) {
        let s = &mut self.slots[idx as usize];
        debug_assert!(s.entry.is_none(), "retiring a task still in its slot");
        s.generation = s.generation.wrapping_add(1);
        self.free.push(idx);
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
    let Some(mut budget) = fs
        .tasks
        .run
        .as_ref()
        .map(|r| r.ready.load(Ordering::Acquire))
    else {
        return;
    };
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
fn poll_one(fs: &mut FsCore, eng: &mut Engine, id: u64) {
    let (idx, generation) = unpack_task(id);
    let Some(mut entry) = fs.tasks.take_if(idx, generation) else {
        return;
    };
    let mut conn = FsConn::new(fs, eng, entry.owner);
    // Disjoint field borrows: the context reads the cached waker and
    // the window reads the wake edge while the poll borrows the
    // future - no waker clone (and no refcount traffic) per poll.
    let mut cx = Context::from_waker(&entry.waker);
    let poll = poll_window(&entry.wake, || {
        with_current(&mut conn, || entry.fut.as_mut().poll(&mut cx))
    });
    match poll {
        Poll::Ready(()) => fs.tasks.retire(idx),
        Poll::Pending => fs.tasks.put_back(idx, entry),
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

    fn run_shared() -> Arc<RunShared> {
        Arc::new(RunShared {
            queue: Mutex::new(VecDeque::new()),
            ready: AtomicUsize::new(0),
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
            let run = run_shared();
            let w = Arc::new(TaskWake {
                id: pack_task(0, 0),
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

    /// A wake landing around a poll window is never swallowed: if the
    /// waker's call was dedup-skipped, a poll of that task *starts*
    /// after it - which is all the waker contract asks. [`poll_window`]
    /// clearing the edge before the poll is what makes it true; clear
    /// after the poll instead and a wake mid-poll skips against a stale
    /// edge with no later poll coming, which this model reports.
    #[test]
    fn loom_a_wake_around_a_poll_window_is_covered() {
        bounded_model(|| {
            let run = run_shared();
            let w = Arc::new(TaskWake {
                id: pack_task(0, 0),
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
    use crate::uring_fs::{Anchor, OffloadBounds, Personality, RwFlags};
    use std::cell::Cell as StdCell;
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

    fn creating() -> OpenHow {
        OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600))
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

    /// A submission the facade refuses (an absolute path) drops the
    /// callback unfired; the future resolves `ECANCELED` with no CQE
    /// ever arriving, instead of pending forever.
    #[test]
    fn a_refused_submission_resolves_ecanceled() {
        let Some((mut eng, mut fs, who)) = rig() else {
            return;
        };
        let dir = crate::tempdir::tempdir().expect("tempdir");
        let anchor = Anchor::open(dir.path()).expect("anchor");

        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let fut = conn.fut(|c, cb| {
            c.open(who, &anchor, c"/etc/hostname", creating(), cb)
        });

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = std::pin::pin!(fut);
        let Poll::Ready(done) = fut.as_mut().poll(&mut cx) else {
            panic!("a refused submission left its future pending");
        };
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
            "{:?}",
            done.result()
        );
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
            id: pack_task(0, 0),
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
                assert_eq!(child.await, Some(42));
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
        assert_eq!(
            handle.as_mut().poll(&mut cx),
            Poll::Ready(None),
            "teardown must resolve the join, not strand it"
        );
    }
}
