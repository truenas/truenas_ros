//! The [`TnPath`] trait — passing Rust paths to syscalls as C strings.
//!
//! It converts `str`/`OsStr`/`Path`/`[u8]`/
//! `CStr` into a NUL-terminated `CStr` with a stack buffer for short paths and
//! a heap fallback for long ones, then hands it to a closure. An interior NUL
//! byte yields [`Errno::EINVAL`].

use crate::errno::{Errno, Result};
use std::ffi::{CStr, CString, OsStr};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::{ptr, slice};

/// A type that can be passed to a syscall as a C string path.
pub trait TnPath {
    /// Is the path empty?
    fn is_empty(&self) -> bool;

    /// Length of the path in bytes (excluding any NUL terminator).
    fn len(&self) -> usize;

    /// Run `f` with this path materialised as a `CStr`.
    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T;
}

impl TnPath for str {
    fn is_empty(&self) -> bool {
        TnPath::is_empty(OsStr::new(self))
    }

    fn len(&self) -> usize {
        TnPath::len(OsStr::new(self))
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        OsStr::new(self).with_tn_path(f)
    }
}

impl TnPath for OsStr {
    fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    fn len(&self) -> usize {
        self.as_bytes().len()
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        self.as_bytes().with_tn_path(f)
    }
}

impl TnPath for CStr {
    fn is_empty(&self) -> bool {
        self.to_bytes().is_empty()
    }

    fn len(&self) -> usize {
        self.to_bytes().len()
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        Ok(f(self))
    }
}

impl TnPath for [u8] {
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        // Paths shorter than a page are stack-allocated to avoid a heap
        // allocation on the syscall hot path.
        const MAX_STACK_ALLOCATION: usize = 1024;

        if self.len() >= MAX_STACK_ALLOCATION {
            return with_tn_path_allocating(self, f);
        }

        let mut buf = MaybeUninit::<[u8; MAX_STACK_ALLOCATION]>::uninit();
        let buf_ptr = buf.as_mut_ptr().cast();

        // SAFETY: `self.len() < MAX_STACK_ALLOCATION`, so the copy plus the NUL
        // terminator fit within `buf`.
        unsafe {
            ptr::copy_nonoverlapping(self.as_ptr(), buf_ptr, self.len());
            buf_ptr.add(self.len()).write(0);
        }

        // SAFETY: we just initialised `self.len() + 1` bytes ending in NUL.
        match CStr::from_bytes_with_nul(unsafe {
            slice::from_raw_parts(buf_ptr, self.len() + 1)
        }) {
            Ok(s) => Ok(f(s)),
            Err(_) => Err(Errno::EINVAL),
        }
    }
}

#[cold]
#[inline(never)]
fn with_tn_path_allocating<T, F>(from: &[u8], f: F) -> Result<T>
where
    F: FnOnce(&CStr) -> T,
{
    match CString::new(from) {
        Ok(s) => Ok(f(&s)),
        Err(_) => Err(Errno::EINVAL),
    }
}

impl TnPath for Path {
    fn is_empty(&self) -> bool {
        TnPath::is_empty(self.as_os_str())
    }

    fn len(&self) -> usize {
        TnPath::len(self.as_os_str())
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        self.as_os_str().with_tn_path(f)
    }
}

impl TnPath for PathBuf {
    fn is_empty(&self) -> bool {
        TnPath::is_empty(self.as_os_str())
    }

    fn len(&self) -> usize {
        TnPath::len(self.as_os_str())
    }

    fn with_tn_path<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CStr) -> T,
    {
        self.as_os_str().with_tn_path(f)
    }
}

/// Convert a `&str` into a `CString`, mapping an interior NUL to
/// [`Errno::EINVAL`]. Used for non-path C-string arguments (xattr names,
/// filesystem names, config keys).
#[allow(dead_code)] // unused only when no feature module is compiled
pub(crate) fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Errno::EINVAL)
}

/// Like [`TnPath::with_tn_path`], but a `None` path yields a NULL pointer.
#[allow(dead_code)]
pub(crate) fn with_opt_tn_path<P, T, F>(path: Option<&P>, f: F) -> Result<T>
where
    P: ?Sized + TnPath,
    F: FnOnce(*const libc::c_char) -> T,
{
    match path {
        Some(path) => path.with_tn_path(|cstr| f(cstr.as_ptr())),
        None => Ok(f(ptr::null())),
    }
}
