//! C ABI of `storage/storage.h`, replacing `storage/storage.c`,
//! `norcow.c`, the PIN log headers and `storage_utils.c` in Trezor Core.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::c_void;
use core::slice;

use crate::storage::{EXTERNAL_SALT_SIZE, Storage};
use crate::sys::{self, SECFALSE, Secbool};

/// `PIN_UI_WAIT_CALLBACK`.
type PinUiWaitCallback = unsafe extern "C" fn(wait: u32, progress: u32, message: u32) -> Secbool;

// --------------------------------------------------------------------------
// Global state
// --------------------------------------------------------------------------

/// The storage, replacing the `static` variables of the C code.
struct Global(Storage);

// SAFETY: the storage is never used by two threads at the same time and
// never from interrupts, exactly like the C implementation and its static
// variables. In the emulator, tasks are threads, but the scheduler runs only
// one of them at a time and switches only at the points where the storage
// hands control to other code (the UI callback). The storage may be called
// again from there, which `Storage` supports with short `Cell`/`RefCell`
// accesses that are never held across such a point.
unsafe impl Sync for Global {}

static STORAGE: Global = Global(Storage::new());

fn with_storage<R>(f: impl FnOnce(&Storage) -> R) -> R {
    f(&STORAGE.0)
}

/// Progress reporting state (`ui_*` variables of the C code). It is kept
/// apart from [`Storage`] because the secure element drivers call
/// [`ui_progress_callback`] in the middle of storage operations.
pub(crate) struct Ui {
    callback: Cell<Option<PinUiWaitCallback>>,
    total: Cell<u32>,
    begin: Cell<u32>,
    next_update: Cell<u32>,
    message: Cell<u32>,
}

// SAFETY: single thread of execution, see `Global`. `Cell` needs no borrow,
// so the re-entrant progress callback is fine.
unsafe impl Sync for Ui {}

pub(crate) static UI: Ui = Ui {
    callback: Cell::new(None),
    total: Cell::new(0),
    begin: Cell::new(0),
    next_update: Cell::new(0),
    message: Cell::new(0),
};

impl Ui {
    pub(crate) fn total(&self) -> u32 {
        self.total.get()
    }

    pub(crate) fn set_total(&self, total: u32) {
        self.total.set(total);
    }

    pub(crate) fn begin(&self) -> u32 {
        self.begin.get()
    }

    pub(crate) fn set_next_update(&self, next_update: u32) {
        self.next_update.set(next_update);
    }

    pub(crate) fn message(&self) -> u32 {
        self.message.get()
    }

    pub(crate) fn set_message(&self, message: u32) {
        self.message.set(message);
    }
}

/// Reports progress to the UI callback at most every 100 ms. Returns
/// `SECTRUE` if the user cancelled the operation.
pub(crate) fn ui_progress() -> Secbool {
    let now = sys::ticks_ms();
    let Some(callback) = UI.callback.get() else {
        return SECFALSE;
    };
    if UI.message.get() == 0 || now < UI.next_update.get() {
        return SECFALSE;
    }

    // The UI dialog is initialized by calling the callback with
    // progress = 0. On the first call, make sure that progress comes out
    // exactly 0.
    if UI.next_update.get() == 0 {
        UI.begin.set(now);
    }
    UI.next_update
        .set(now.wrapping_add(crate::storage::MIN_PROGRESS_UPDATE_MS));
    let elapsed = now.wrapping_sub(UI.begin.get());
    let total = UI.total.get();

    // Prevent overflow when the total time is underestimated.
    let diff = (total as i32).wrapping_sub(elapsed as i32).max(0);
    // Round the remaining time to the nearest second.
    let rem_sec = (diff.wrapping_add(500) / 1000) as u32;

    // A division by zero gives 0 here; the C code relied on the Cortex-M
    // behavior, which is the same unless division-by-zero traps are enabled.
    #[cfg(not(feature = "emulator"))]
    let mut progress = if total < 1_000_000 {
        1000u32
            .wrapping_mul(elapsed)
            .checked_div(total)
            .unwrap_or(0)
    } else {
        // Avoid uint32 overflow. Precise enough.
        elapsed / (total / 1000)
    };
    // In the emulator, progress comes from the remaining seconds to avoid
    // flaky UI tests.
    #[cfg(feature = "emulator")]
    let mut progress = {
        let total_sec = total.wrapping_add(500) / 1000;
        1000u32.wrapping_sub(
            1000u32
                .wrapping_mul(rem_sec)
                .checked_div(total_sec)
                .unwrap_or(0),
        )
    };

    // Calling the callback with progress = 1000 terminates the UI dialog.
    if progress >= 1000 {
        progress = 999;
    }

    // SAFETY: a callback registered by `storage_init()`.
    unsafe { callback(rem_sec, progress, UI.message.get()) }
}

/// Terminates the UI dialog by calling the callback with progress = 1000.
pub(crate) fn ui_progress_finish() {
    if let Some(callback) = UI.callback.get()
        && UI.message.get() != 0
    {
        // SAFETY: a callback registered by `storage_init()`.
        unsafe { callback(0, 1000, UI.message.get()) };
    }
}

/// `ui_progress` as passed to the Optiga and Tropic drivers.
#[cfg_attr(not(any(feature = "optiga", feature = "tropic")), allow(dead_code))]
pub(crate) extern "C" fn ui_progress_callback() -> Secbool {
    ui_progress()
}

// --------------------------------------------------------------------------
// Pointer conversions
// --------------------------------------------------------------------------

/// A buffer passed in from C as a pointer and a length.
///
/// # Safety
///
/// `ptr` must be null, or valid for reads of `len` bytes for the duration of
/// the call. Null with `len > 0` is a fatal error.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len != 0 {
            let (file, line) = crate::here!();
            sys::fatal(None, file, line);
        }
        return None;
    }
    // SAFETY: guaranteed by the caller.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Like [`bytes`], but null with `len == 0` is an empty slice.
///
/// # Safety
///
/// See [`bytes`].
unsafe fn bytes_or_empty<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: guaranteed by the caller.
    unsafe { bytes(ptr, len) }.unwrap_or(&[])
}

/// An optional external salt of `EXTERNAL_SALT_SIZE` bytes.
///
/// # Safety
///
/// `ptr` must be null or valid for reads of `EXTERNAL_SALT_SIZE` bytes.
unsafe fn ext_salt<'a>(ptr: *const u8) -> Option<&'a [u8; EXTERNAL_SALT_SIZE]> {
    // SAFETY: guaranteed by the caller.
    unsafe { ptr.cast::<[u8; EXTERNAL_SALT_SIZE]>().as_ref() }
}

/// Stops on a null out-parameter, like the C code would have crashed.
fn check_out<T>(ptr: *mut T) {
    if ptr.is_null() {
        let (file, line) = crate::here!();
        sys::fatal(None, file, line);
    }
}

// --------------------------------------------------------------------------
// storage/storage.h
// --------------------------------------------------------------------------

/// # Safety
///
/// `salt` must be null with `salt_len == 0`, or valid for reads of
/// `salt_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_init(
    callback: Option<PinUiWaitCallback>,
    salt: *const u8,
    salt_len: u16,
) {
    // SAFETY: guaranteed by the caller.
    let salt = unsafe { bytes_or_empty(salt, usize::from(salt_len)) };
    UI.callback.set(callback);
    with_storage(|s| s.storage_init(salt));
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_wipe() {
    with_storage(|s| s.wipe());
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_is_unlocked() -> Secbool {
    with_storage(|s| s.storage_is_unlocked())
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_lock() {
    with_storage(|s| s.storage_lock());
}

/// # Safety
///
/// `pin` must be null or valid for reads of `pin_len` bytes; `ext_salt` must
/// be null or valid for reads of `EXTERNAL_SALT_SIZE` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_unlock(
    pin: *const u8,
    pin_len: usize,
    ext_salt: *const u8,
) -> u32 {
    // A null PIN is reported as UNLOCK_NO_PIN, not a fatal error.
    // SAFETY: guaranteed by the caller.
    let pin = if pin.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(pin, pin_len) })
    };
    // SAFETY: guaranteed by the caller.
    let ext_salt = unsafe { self::ext_salt(ext_salt) };
    with_storage(|s| s.storage_unlock(pin, ext_salt))
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_has_pin() -> Secbool {
    with_storage(|s| s.storage_has_pin())
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_pin_fails_increase() -> Secbool {
    with_storage(|s| s.storage_pin_fails_increase())
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_get_pin_rem() -> u32 {
    with_storage(|s| s.storage_get_pin_rem())
}

/// # Safety
///
/// `newpin` must be null or valid for reads of `newpin_len` bytes;
/// `new_ext_salt` must be null or valid for reads of `EXTERNAL_SALT_SIZE`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_change_pin(
    newpin: *const u8,
    newpin_len: usize,
    new_ext_salt: *const u8,
) -> u32 {
    let newpin = if newpin.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        Some(unsafe { slice::from_raw_parts(newpin, newpin_len) })
    };
    // SAFETY: guaranteed by the caller.
    let new_ext_salt = unsafe { ext_salt(new_ext_salt) };
    with_storage(|s| s.storage_change_pin(newpin, new_ext_salt))
}

/// # Safety
///
/// `pin` must be valid for reads of `pin_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_ensure_not_wipe_code(pin: *const u8, pin_len: usize) {
    // SAFETY: guaranteed by the caller.
    let pin = unsafe { bytes_or_empty(pin, pin_len) };
    with_storage(|s| s.storage_ensure_not_wipe_code(pin));
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_has_wipe_code() -> Secbool {
    with_storage(|s| s.storage_has_wipe_code())
}

/// # Safety
///
/// `pin` and `wipe_code` must be null or valid for reads of their lengths;
/// `ext_salt` must be null or valid for reads of `EXTERNAL_SALT_SIZE` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_change_wipe_code(
    pin: *const u8,
    pin_len: usize,
    ext_salt: *const u8,
    wipe_code: *const u8,
    wipe_code_len: usize,
) -> Secbool {
    // Null pointers make the function fail, they are not fatal.
    // SAFETY: guaranteed by the caller.
    let pin = (!pin.is_null()).then(|| unsafe { slice::from_raw_parts(pin, pin_len) });
    let wipe_code = (!wipe_code.is_null())
        // SAFETY: guaranteed by the caller.
        .then(|| unsafe { slice::from_raw_parts(wipe_code, wipe_code_len) });
    // SAFETY: guaranteed by the caller.
    let ext_salt = unsafe { self::ext_salt(ext_salt) };
    with_storage(|s| s.storage_change_wipe_code(pin, ext_salt, wipe_code))
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_has(key: u16) -> Secbool {
    with_storage(|s| s.storage_has(key))
}

/// # Safety
///
/// `val` must be null, or valid for writes of `max_len` bytes; `len` must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_get(
    key: u16,
    val: *mut c_void,
    max_len: u16,
    len: *mut u16,
) -> Secbool {
    check_out(len);
    let dest = if val.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        Some(unsafe { slice::from_raw_parts_mut(val.cast::<u8>(), usize::from(max_len)) })
    };
    let mut out_len = None;
    let ret = with_storage(|s| s.storage_get(key, dest, &mut out_len));
    if let Some(out_len) = out_len {
        // SAFETY: valid for writes, guaranteed by the caller.
        unsafe { len.write(out_len) };
    }
    ret
}

/// # Safety
///
/// `val` must be null with `len == 0`, or valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_set(key: u16, val: *const c_void, len: u16) -> Secbool {
    // SAFETY: guaranteed by the caller.
    let data = unsafe { bytes(val.cast(), usize::from(len)) };
    with_storage(|s| s.storage_set(key, data))
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_delete(key: u16) -> Secbool {
    with_storage(|s| s.storage_delete(key))
}

#[unsafe(no_mangle)]
pub extern "C" fn storage_set_counter(key: u16, count: u32) -> Secbool {
    with_storage(|s| s.storage_set_counter(key, count))
}

/// # Safety
///
/// `count` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_next_counter(key: u16, count: *mut u32) -> Secbool {
    check_out(count);
    let mut value = None;
    let ret = with_storage(|s| s.storage_next_counter(key, &mut value));
    if let Some(value) = value {
        // SAFETY: valid for writes, guaranteed by the caller.
        unsafe { count.write(value) };
    }
    ret
}
