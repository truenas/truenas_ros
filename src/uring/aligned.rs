//! A page-aligned, fixed-capacity byte buffer for direct writes.
//!
//! ZFS writes direct only when the buffer base, the length and the file
//! offset are page-aligned, the length is at least the file's block size,
//! and the block size is no longer growing (`zfs_setup_direct`,
//! `module/zfs/zfs_vnops.c`; `o_direct_defer` in `zfs_write`). A
//! page-misaligned write is buffered, or `EINVAL` under
//! `zfs_dio_strict=1`; a short write or a growing block size is buffered
//! whatever the parameter says. This buffer fixes the base and rounds the
//! capacity to pages; length and offset are the caller's. A `Vec<u8>`
//! cannot promise the base.
//!
//! Filled front to back: [`fill`](AlignedBuf::fill) copies what fits,
//! `AsRef<[u8]>` is the filled prefix, [`clear`](AlignedBuf::clear)
//! rewinds without reallocating.

use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;

use super::page_size;

/// A page-aligned byte buffer of fixed capacity, filled front to back.
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    layout: Layout,
    len: usize,
}

impl AlignedBuf {
    /// A buffer of `capacity` bytes on a page boundary, rounded up to
    /// whole pages; `None` if the allocator refuses.
    pub fn new(capacity: usize) -> Option<AlignedBuf> {
        let page = page_size();
        let capacity = capacity.max(1).checked_next_multiple_of(page)?;
        let layout = Layout::from_size_align(capacity, page).ok()?;
        // SAFETY: `layout` has a non-zero size, checked just above.
        let raw = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw)?;
        Some(AlignedBuf {
            ptr,
            layout,
            len: 0,
        })
    }

    /// The page-aligned base, for registering the whole capacity.
    pub(crate) fn base(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Bytes the buffer can hold.
    pub fn capacity(&self) -> usize {
        self.layout.size()
    }

    /// Bytes filled so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been filled.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes still free at the end.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.len
    }

    /// Whether the buffer holds exactly its capacity.
    pub fn is_full(&self) -> bool {
        self.remaining() == 0
    }

    /// Append what fits of `src`; returns how many bytes were taken.
    #[must_use = "the buffer takes what fits; the rest of `src` is still the caller's"]
    pub fn fill(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.remaining());
        // SAFETY: `[len, len + n)` lies within the allocation
        // (`n <= remaining`), and `src` cannot alias it - this buffer is
        // reachable only through `&mut self`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                n,
            );
        }
        self.len += n;
        n
    }

    /// Rewind to empty, keeping the allocation.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl AsRef<[u8]> for AlignedBuf {
    /// The filled prefix.
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `[0, len)` was written by `fill`, which is the only way
        // `len` grows, and the allocation outlives the borrow.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `layout` are the pair `new` allocated with.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

// SAFETY: one heap allocation owned by this struct, no interior
// mutability; `&AlignedBuf` exposes the filled prefix read-only.
unsafe impl Send for AlignedBuf {}
// SAFETY: as above.
unsafe impl Sync for AlignedBuf {}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuf")
            .field("capacity", &self.capacity())
            .field("len", &self.len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_is_page_aligned_and_page_sized() {
        let b = AlignedBuf::new(1000).expect("allocates");
        let page = page_size();
        assert_eq!(b.capacity() % page, 0);
        assert_eq!(b.capacity(), page);
        assert_eq!((b.ptr.as_ptr() as usize) % page, 0);
        assert!(b.is_empty());
    }

    #[test]
    fn fill_takes_what_fits_and_reads_back_the_prefix() {
        let mut b = AlignedBuf::new(1).expect("allocates");
        let cap = b.capacity();
        let first = vec![0xAB; cap - 3];
        assert_eq!(b.fill(&first), cap - 3);
        assert_eq!(b.remaining(), 3);
        assert_eq!(b.fill(&[1, 2, 3, 4, 5]), 3);
        assert!(b.is_full());
        assert_eq!(b.fill(&[9]), 0);
        let got = b.as_ref();
        assert_eq!(got.len(), cap);
        assert!(got[..cap - 3].iter().all(|&x| x == 0xAB));
        assert_eq!(&got[cap - 3..], &[1, 2, 3]);
        b.clear();
        assert!(b.is_empty());
        assert_eq!(b.as_ref(), &[] as &[u8]);
    }
}
