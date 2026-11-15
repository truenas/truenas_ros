//! Callbacks kept by value in rooms of one allocation, so an op whose callback fits a room allocates nothing for it.
//!
//! A table has a room for each place and one more to stage in. A submit stages its callback before it knows its op
//! slot, the slot it gets takes the callback into its own room, and the completion takes the callback out to run. The
//! run moves it onto the stack of a function written for its type before it calls it, so the next op the callback
//! submits may take the same slot and room. A callback larger or more aligned than a room is boxed instead, and so is
//! one that has to leave its room before it runs.
//!
//! The rooms are one allocation the table reaches through a raw pointer of its own, so a `&mut` of whatever owns the
//! table, taken while a callback runs, covers none of their bytes.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;

/// The alignment of every room. A callback aligned to more is boxed.
pub(crate) const ROOM_ALIGN: usize = 16;

/// What the callbacks of a table run with, and what one becomes in a box of its own.
pub(crate) trait Sig: Sized + 'static {
    /// The arguments a callback runs with.
    type Args<'a, 'b>
    where
        'b: 'a;
    /// A callback in a box of its own.
    type Boxed;
    /// Put `c` in a box.
    fn boxed<C: Call<Self>>(c: C) -> Self::Boxed;
}

/// A callback a table of `S` can keep.
pub(crate) trait Call<S: Sig>: 'static {
    /// Run the callback.
    fn call<'a, 'b>(self, args: S::Args<'a, 'b>)
    where
        'b: 'a;
}

/// The functions written for one type of callback, which a room's record points at.
trait Shim<S: Sig> {
    /// Move the callback at `at` out and run it.
    ///
    /// # Safety
    /// `at` holds a live callback of this type, which nothing reads or drops again.
    unsafe fn run<'a, 'b>(&self, at: *mut u8, args: S::Args<'a, 'b>)
    where
        'b: 'a;
    /// Drop the callback at `at` uncalled.
    ///
    /// # Safety
    /// As [`Shim::run`]'s.
    unsafe fn discard(&self, at: *mut u8);
    /// Move the callback at `at` into a box.
    ///
    /// # Safety
    /// As [`Shim::run`]'s.
    unsafe fn boxed(&self, at: *mut u8) -> S::Boxed;
    /// The callback's size in bytes.
    fn size(&self) -> usize;
}

/// The shim of callbacks of type `C`, a value of no size whose reference is the record of a room holding one.
struct ShimOf<C>(PhantomData<fn() -> C>);

impl<S: Sig, C: Call<S>> Shim<S> for ShimOf<C> {
    unsafe fn run<'a, 'b>(&self, at: *mut u8, args: S::Args<'a, 'b>)
    where
        'b: 'a,
    {
        // SAFETY: the caller's word that `at` holds a live `C`, aligned as every room is, that this moves out once.
        let c = unsafe { at.cast::<C>().read() };
        c.call(args);
    }

    unsafe fn discard(&self, at: *mut u8) {
        // SAFETY: as in `run`.
        unsafe { at.cast::<C>().drop_in_place() };
    }

    unsafe fn boxed(&self, at: *mut u8) -> S::Boxed {
        // SAFETY: as in `run`.
        S::boxed(unsafe { at.cast::<C>().read() })
    }

    fn size(&self) -> usize {
        size_of::<C>()
    }
}

fn shim<S: Sig, C: Call<S>>() -> &'static dyn Shim<S> {
    const { &ShimOf::<C>(PhantomData) }
}

/// A base for a table with no bytes, aligned as a room is, which only a callback of no size is kept at.
#[repr(align(16))]
struct Aligned;

/// The rooms of a table of callbacks of `S`. See the [module](self).
pub(crate) struct Rooms<S: Sig> {
    /// `held.len()` rooms of `stride` bytes each, the last the staging room, or a dangling pointer when `stride` is 0.
    base: NonNull<u8>,
    stride: usize,
    /// The record of each room, the shim of the callback it holds or `None` when it is empty.
    held: Box<[Option<&'static dyn Shim<S>>]>,
}

impl<S: Sig> Rooms<S> {
    /// A room of at least `bytes` bytes for each of `places` places and one to stage in, allocated now and never again.
    /// With `bytes` 0 nothing is allocated for them, and only a callback of no size is kept.
    ///
    /// # Panics
    /// If the rooms are larger than an allocation may be.
    pub(crate) fn new(places: usize, bytes: usize) -> Rooms<S> {
        let stride = bytes.next_multiple_of(ROOM_ALIGN);
        let count = places.checked_add(1).expect("a place count below usize::MAX");
        let layout = stride
            .checked_mul(count)
            .and_then(|size| Layout::from_size_align(size, ROOM_ALIGN).ok())
            .expect("rooms that fit an allocation");
        let base = if layout.size() == 0 {
            NonNull::<Aligned>::dangling().cast()
        } else {
            // SAFETY: the layout's size is not 0.
            NonNull::new(unsafe { alloc(layout) }).unwrap_or_else(|| handle_alloc_error(layout))
        };
        Rooms {
            base,
            stride,
            held: vec![None; count].into_boxed_slice(),
        }
    }

    /// Whether a callback of type `C` fits a room.
    pub(crate) fn fits<C>(&self) -> bool {
        size_of::<C>() <= self.stride && align_of::<C>() <= ROOM_ALIGN
    }

    fn staging(&self) -> usize {
        self.held.len() - 1
    }

    fn room(&self, i: usize) -> *mut u8 {
        self.base.as_ptr().wrapping_add(i * self.stride)
    }

    /// Keep `c` in the staging room, or hand it back when it does not fit a room or another callback is staged.
    pub(crate) fn stage<C: Call<S>>(&mut self, c: C) -> Result<(), C> {
        let at = self.staging();
        if !self.fits::<C>() || self.held[at].is_some() {
            return Err(c);
        }
        // SAFETY: the staging room is empty, `stride` bytes long and aligned to `ROOM_ALIGN`, and `C` fits both.
        unsafe { self.room(at).cast::<C>().write(c) };
        self.held[at] = Some(shim::<S, C>());
        Ok(())
    }

    /// Move the staged callback into the room of `place`. False, with nothing moved, when nothing is staged, `place` is
    /// not a place, or its room holds a callback.
    pub(crate) fn park(&mut self, place: usize) -> bool {
        let from = self.staging();
        if place >= from || self.held[place].is_some() {
            return false;
        }
        let Some(shim) = self.held[from].take() else {
            return false;
        };
        // SAFETY: two rooms of one allocation that do not overlap, since `place` is not the staging room, and the
        // callback's size fits a room. Its record moves with its bytes, so one room holds it at a time.
        unsafe { std::ptr::copy_nonoverlapping(self.room(from), self.room(place), shim.size()) };
        self.held[place] = Some(shim);
        true
    }

    /// The staged callback, moved into a box.
    pub(crate) fn unstage(&mut self) -> Option<S::Boxed> {
        self.boxed(self.staging())
    }

    /// The callback in the room of `place`, moved into a box, for one that must leave its room before it runs.
    pub(crate) fn unpark(&mut self, place: usize) -> Option<S::Boxed> {
        if place >= self.staging() {
            return None;
        }
        self.boxed(place)
    }

    fn boxed(&mut self, i: usize) -> Option<S::Boxed> {
        let shim = self.held[i].take()?;
        // SAFETY: the room held a live callback of the shim's type, and its record is gone, so this is its one move.
        Some(unsafe { shim.boxed(self.room(i)) })
    }

    /// Drop the callback in the room of `place` uncalled.
    pub(crate) fn discard(&mut self, place: usize) {
        if place >= self.staging() {
            return;
        }
        if let Some(shim) = self.held[place].take() {
            // SAFETY: as in `boxed`.
            unsafe { shim.discard(self.room(place)) };
        }
    }

    /// Take the callback in the room of `place` out to run. The room is empty from here, for the next callback its
    /// place takes.
    pub(crate) fn take(&mut self, place: usize) -> Option<Taken<S>> {
        if place >= self.staging() {
            return None;
        }
        let shim = self.held[place].take()?;
        Some(Taken {
            shim,
            at: self.room(place),
        })
    }
}

impl<S: Sig> Drop for Rooms<S> {
    fn drop(&mut self) {
        for i in 0..self.held.len() {
            if let Some(shim) = self.held[i].take() {
                // SAFETY: as in `boxed`.
                unsafe { shim.discard(self.room(i)) };
            }
        }
        let layout = Layout::from_size_align(self.stride * self.held.len(), ROOM_ALIGN).expect("as `new` made it");
        if layout.size() != 0 {
            // SAFETY: `new` allocated `base` with this layout, and nothing points into it once the table is gone.
            unsafe { dealloc(self.base.as_ptr(), layout) };
        }
    }
}

/// A callback taken out of its room's record and still in the room's bytes, to be run at once. Dropped unrun, it leaks
/// what it holds.
#[must_use = "a taken callback is run, or it leaks what it holds"]
pub(crate) struct Taken<S: Sig> {
    shim: &'static dyn Shim<S>,
    at: *mut u8,
}

impl<S: Sig> Taken<S> {
    /// Move the callback out of its room and run it with `args`, which may stage and park another callback in the same
    /// room as it runs.
    ///
    /// # Safety
    /// The table it was taken from is alive, and nothing has been parked in its room since [`Rooms::take`].
    pub(crate) unsafe fn run<'a, 'b>(self, args: S::Args<'a, 'b>)
    where
        'b: 'a,
    {
        // SAFETY: the caller's word that the room's bytes are still the callback `take` found there, and the record
        // `take` cleared makes this its one move.
        unsafe { self.shim.run(self.at, args) }
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
