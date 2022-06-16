// SPDX-License-Identifier: GPL-2.0

//! A lock that never waits.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

const LOCKED: u8 = 1;
const CONTENDED: u8 = 2;

/// A lock that only offers a [`try_lock`](NoWaitLock::try_lock) method.
///
/// That is, on contention it doesn't offer a way for the caller to block waiting for the current
/// owner to release the lock. This is useful for best-effort kind of scenarios where waiting is
/// never needed: in such cases, users don't need a full-featured mutex or spinlock.
///
/// When the lock is released via call to [`NoWaitLockGuard::unlock`], it indicates to the caller
/// whether there was contention (i.e., if another thread tried and failed to acquire this lock).
/// If the return value is `false`, there was definitely no contention but if it is `true`, it's
/// possible that the contention was when attempting to acquire the lock.
///
/// # Examples
///
/// ```
/// use kernel::sync::NoWaitLock;
///
/// #[derive(PartialEq)]
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// let x = NoWaitLock::new(Example{ a: 10, b: 20 });
///
/// // Modifying the protected value.
/// {
///     let mut guard = x.try_lock().unwrap();
///     assert_eq!(guard.a, 10);
///     assert_eq!(guard.b, 20);
///     guard.a += 20;
///     guard.b += 20;
///     assert_eq!(guard.a, 30);
///     assert_eq!(guard.b, 40);
/// }
///
/// // Reading the protected value.
/// {
///     let guard = x.try_lock().unwrap();
///     assert_eq!(guard.a, 30);
///     assert_eq!(guard.b, 40);
/// }
///
/// // Second acquire fails, but succeeds after the guard is dropped.
/// {
///     let guard = x.try_lock().unwrap();
///     assert!(x.try_lock().is_none());
///
///     drop(guard);
///     assert!(x.try_lock().is_some());
/// }
/// ```
///
/// The following examples use the [`NoWaitLockGuard::unlock`] to release the lock and check for
/// contention.
///
/// ```
/// use kernel::sync::NoWaitLock;
///
/// #[derive(PartialEq)]
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// let x = NoWaitLock::new(Example{ a: 10, b: 20 });
///
/// // No contention when lock is released.
/// let guard = x.try_lock().unwrap();
/// assert_eq!(guard.unlock(), false);
///
/// // Contention detected.
/// let guard = x.try_lock().unwrap();
/// assert!(x.try_lock().is_none());
/// assert_eq!(guard.unlock(), true);
///
/// // No contention again.
/// let guard = x.try_lock().unwrap();
/// assert_eq!(guard.a, 10);
/// assert_eq!(guard.b, 20);
/// assert_eq!(guard.unlock(), false);
/// ```
pub struct NoWaitLock<T: ?Sized> {
    state: AtomicU8,
    data: UnsafeCell<T>,
}

// SAFETY: `NoWaitLock` can be transferred across thread boundaries iff the data it protects can.
unsafe impl<T: ?Sized + Send> Send for NoWaitLock<T> {}

// SAFETY: `NoWaitLock` only allows a single thread at a time to access the interior mutability it
// provides, so it is `Sync` as long as the data it protects is `Send`.
unsafe impl<T: ?Sized + Send> Sync for NoWaitLock<T> {}

impl<T> NoWaitLock<T> {
    /// Creates a new instance of the no-wait lock.
    pub fn new(data: T) -> Self {
        Self {
            state: AtomicU8::new(0),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> NoWaitLock<T> {
    /// Tries to acquire the lock.
    ///
    /// If no other thread/CPU currently owns the lock, it returns a guard that can be used to
    /// access the protected data. Otherwise (i.e., the lock is already owned), it returns `None`.
    pub fn try_lock(&self) -> Option<NoWaitLockGuard<'_, T>> {
        // Fast path -- just set the LOCKED bit.
        //
        // Acquire ordering matches the release in `NoWaitLockGuard::drop` or
        // `NoWaitLockGuard::unlock`.
        if self.state.fetch_or(LOCKED, Ordering::Acquire) & LOCKED == 0 {
            // INVARIANTS: The thread that manages to set the `LOCKED` bit becomes the owner.
            return Some(NoWaitLockGuard { lock: self });
        }

        // Set the `CONTENDED` bit.
        //
        // If the `LOCKED` bit has since been reset, the lock was released and the caller becomes
        // the owner of the lock. It will see the `CONTENDED` bit when it releases the lock even if
        // there was no additional contention but this is allowed by the interface.
        if self.state.fetch_or(CONTENDED | LOCKED, Ordering::Relaxed) & LOCKED == 0 {
            // INVARIANTS: The thread that manages to set the `LOCKED` bit becomes the owner.
            Some(NoWaitLockGuard { lock: self })
        } else {
            None
        }
    }
}

/// A guard for the holder of the no-wait lock.
///
/// # Invariants
///
/// Only the current owner can have an instance of [`NoWaitLockGuard`].
pub struct NoWaitLockGuard<'a, T: ?Sized> {
    lock: &'a NoWaitLock<T>,
}

impl<T: ?Sized> NoWaitLockGuard<'_, T> {
    /// Unlocks the no-wait lock.
    ///
    /// The return value indicates whether there was contention while the lock was held, that is,
    /// whether another thread tried (and failed) to acquire the lock.
    pub fn unlock(self) -> bool {
        // Matches the acquire in `NoWaitLock::try_lock`.
        let contention = self.lock.state.swap(0, Ordering::Release) & CONTENDED != 0;
        core::mem::forget(self);
        contention
    }
}

impl<T: ?Sized> core::ops::Deref for NoWaitLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The type invariant guarantees that only the owner has an instance of the guard,
        // so the owner is the only one that can call this function.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> core::ops::DerefMut for NoWaitLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The type invariant guarantees that only the owner has an instance of the guard,
        // so the owner is the only one that can call this function.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for NoWaitLockGuard<'_, T> {
    fn drop(&mut self) {
        // Matches the acquire in `NoWaitLock::try_lock`.
        self.lock.state.store(0, Ordering::Release);
    }
}
