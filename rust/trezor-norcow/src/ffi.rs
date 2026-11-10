//! C ABI of `storage/norcow.h`, replacing `storage/norcow.c`.
//!
//! The flash is accessed through the C flash driver (`flash_area.h`), and the
//! build configuration (`norcow_config.h`) comes from `norcow_rs_glue.c`,
//! which is compiled with the same flags as the rest of the storage. The glue
//! defines a symbol named after the flash layout, so linking fails if the
//! layout feature of this crate does not match the C configuration.

#![allow(unsafe_code)]

use core::cell::RefCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use crate::{Data, Flash, KEY_FREE, Norcow, Source};

#[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
use crate::Blockwise as ActiveLayout;
#[cfg(feature = "bitwise")]
use crate::{BitFlash, Bitwise as ActiveLayout};

type Secbool = u32;
const SECTRUE: Secbool = 0xAAAA_AAAA;
const SECFALSE: Secbool = 0x0000_0000;

fn secbool(value: bool) -> Secbool {
    if value { SECTRUE } else { SECFALSE }
}

/// `flash_area_t`, only handled through pointers.
#[repr(C)]
struct FlashArea {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    // flash_area.h / flash_ll.h
    fn flash_area_get_address(area: *const FlashArea, offset: u32, size: u32) -> *const c_void;
    fn flash_area_erase(
        area: *const FlashArea,
        progress: Option<unsafe extern "C" fn(c_int, c_int)>,
    ) -> Secbool;
    fn flash_area_write_block(area: *const FlashArea, offset: u32, block: *const u32) -> Secbool;
    #[cfg(feature = "bitwise")]
    fn flash_area_write_byte(area: *const FlashArea, offset: u32, data: u8) -> Secbool;
    #[cfg(feature = "bitwise")]
    fn flash_area_write_word(area: *const FlashArea, offset: u32, data: u32) -> Secbool;
    fn flash_unlock_write() -> Secbool;
    fn flash_lock_write() -> Secbool;

    // norcow_rs_glue.c
    fn norcow_rs_area(sector: u8) -> *const FlashArea;
    fn norcow_rs_fatal(msg: *const c_char) -> !;
    static norcow_rs_sector_count: u8;
    static norcow_rs_sector_size: u32;
    static norcow_rs_version: u32;
    static norcow_rs_skip_inactive_wipe: u8;
    #[cfg(feature = "bitwise")]
    static norcow_rs_layout_bitwise: u8;
    #[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
    static norcow_rs_layout_blockwise: u8;
}

/// Checks that the C build uses the same flash layout as this crate. The
/// reference to the layout symbol is what turns a mismatch into a link error.
fn check_layout() {
    // SAFETY: the glue defines the symbol as a `const uint8_t`.
    #[cfg(feature = "bitwise")]
    let marker = unsafe { ptr::read_volatile(&raw const norcow_rs_layout_bitwise) };
    // SAFETY: as above.
    #[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
    let marker = unsafe { ptr::read_volatile(&raw const norcow_rs_layout_blockwise) };
    if marker != 1 {
        CFlash.fatal(Some(c"norcow layout mismatch"));
    }
}

/// [`Flash`] backed by the C flash driver and the C storage configuration.
struct CFlash;

impl CFlash {
    fn area(&self, sector: u8) -> *const FlashArea {
        // The C code checked `sector <= NORCOW_SECTOR_COUNT`, one too many.
        if sector >= self.sector_count() {
            self.fatal(Some(c"invalid sector"));
        }
        // SAFETY: plain call; the glue returns `&STORAGE_AREAS[sector]`.
        unsafe { norcow_rs_area(sector) }
    }

    /// Address of `len` bytes at `offset`, or null if not addressable.
    fn address(&self, sector: u8, offset: u32, len: u32) -> *const c_void {
        // SAFETY: `area()` returns a valid `flash_area_t`; the function only
        // computes an address and checks it against the area bounds.
        unsafe { flash_area_get_address(self.area(sector), offset, len) }
    }
}

impl Flash for CFlash {
    fn sector_count(&self) -> u8 {
        // SAFETY: constant defined by the glue.
        unsafe { norcow_rs_sector_count }
    }

    fn sector_size(&self) -> u32 {
        // SAFETY: constant defined by the glue.
        unsafe { norcow_rs_sector_size }
    }

    fn norcow_version(&self) -> u32 {
        // SAFETY: constant defined by the glue.
        unsafe { norcow_rs_version }
    }

    fn skip_inactive_wipe(&self) -> bool {
        // SAFETY: constant defined by the glue.
        unsafe { norcow_rs_skip_inactive_wipe != 0 }
    }

    fn is_valid(&self, sector: u8, offset: u32, len: u32) -> bool {
        !self.address(sector, offset, len).is_null()
    }

    fn read(&self, sector: u8, offset: u32, buf: &mut [u8]) -> bool {
        let Ok(len) = u32::try_from(buf.len()) else {
            return false;
        };
        let src = self.address(sector, offset, len);
        if src.is_null() {
            return false;
        }
        // SAFETY: `flash_area_get_address()` returned non-null, so `len`
        // bytes at `src` are mapped flash. `buf` is a distinct Rust buffer.
        // No flash write runs during the copy: writes need `&mut self`.
        unsafe { ptr::copy_nonoverlapping(src.cast::<u8>(), buf.as_mut_ptr(), buf.len()) };
        true
    }

    fn erase(&mut self, sector: u8) -> bool {
        let area = self.area(sector);
        // SAFETY: valid area, no progress callback.
        unsafe { flash_area_erase(area, None) == SECTRUE }
    }

    fn unlock(&mut self) -> bool {
        // SAFETY: plain call.
        unsafe { flash_unlock_write() == SECTRUE }
    }

    fn lock(&mut self) -> bool {
        // SAFETY: plain call.
        unsafe { flash_lock_write() == SECTRUE }
    }

    fn write_block(&mut self, sector: u8, offset: u32, block: &[u32]) -> bool {
        use crate::LayoutParams;
        if block.len() != ActiveLayout::BLOCK_WORDS {
            self.fatal(None);
        }
        let area = self.area(sector);
        // SAFETY: `block` holds `FLASH_BLOCK_WORDS` words, the size of
        // `flash_block_t`, which the C function reads.
        unsafe { flash_area_write_block(area, offset, block.as_ptr()) == SECTRUE }
    }

    fn fatal(&self, msg: Option<&'static CStr>) -> ! {
        let msg = msg.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: `msg` is null or a static NUL-terminated string.
        unsafe { norcow_rs_fatal(msg) }
    }
}

#[cfg(feature = "bitwise")]
impl BitFlash for CFlash {
    fn write_byte(&mut self, sector: u8, offset: u32, data: u8) -> bool {
        let area = self.area(sector);
        // SAFETY: valid area; the C function checks the bounds.
        unsafe { flash_area_write_byte(area, offset, data) == SECTRUE }
    }

    fn write_word(&mut self, sector: u8, offset: u32, data: u32) -> bool {
        let area = self.area(sector);
        // SAFETY: valid area; the C function checks the bounds.
        unsafe { flash_area_write_word(area, offset, data) == SECTRUE }
    }
}

/// A value passed in from C as a pointer and a length.
struct RawSource {
    ptr: *const u8,
    len: usize,
}

impl RawSource {
    /// # Safety
    ///
    /// `ptr` must be valid for reads of `len` bytes for as long as the
    /// `RawSource` is used. The memory may be flash that norcow itself
    /// writes to, as long as it stays mapped. `ptr` may be null if `len` is 0.
    unsafe fn new(ptr: *const u8, len: u16) -> Self {
        let len = usize::from(len);
        if ptr.is_null() && len != 0 {
            CFlash.fatal(None);
        }
        Self { ptr, len }
    }
}

impl Source for RawSource {
    fn size(&self) -> usize {
        self.len
    }

    fn copy_to(&self, offset: usize, dst: &mut [u8]) {
        match offset.checked_add(dst.len()) {
            Some(end) if end <= self.len => {}
            _ => CFlash.fatal(None),
        }
        if dst.is_empty() {
            return;
        }
        // SAFETY: the range is within the `len` readable bytes promised to
        // `RawSource::new()`. The bytes are read right before they are
        // written, never cached across a flash write.
        unsafe { ptr::copy_nonoverlapping(self.ptr.add(offset), dst.as_mut_ptr(), dst.len()) };
    }
}

type Impl = Norcow<CFlash, ActiveLayout>;

/// The global norcow state, replacing the `static` variables of `norcow.c`.
struct Global(RefCell<Impl>);

// SAFETY: the storage runs in a single thread of execution and is never
// called from interrupts, exactly like the C implementation and its static
// variables. `RefCell` turns accidental re-entrancy into a fatal error.
unsafe impl Sync for Global {}

static NORCOW: Global = Global(RefCell::new(Norcow::new(CFlash, ActiveLayout::new())));

fn with_norcow<R>(f: impl FnOnce(&mut Impl) -> R) -> R {
    match NORCOW.0.try_borrow_mut() {
        Ok(mut norcow) => f(&mut norcow),
        Err(_) => CFlash.fatal(Some(c"norcow re-entered")),
    }
}

/// Dereferences a C out-parameter, stopping on null like `norcow.c` would
/// have crashed.
///
/// # Safety
///
/// `ptr` must be null or valid for writes.
unsafe fn out<'a, T>(ptr: *mut T) -> &'a mut T {
    // SAFETY: guaranteed by the caller.
    match unsafe { ptr.as_mut() } {
        Some(r) => r,
        None => CFlash.fatal(None),
    }
}

/// Stops on a null out-parameter, like `norcow.c` would have crashed.
///
/// Used where a function has several pointer parameters: they are written
/// through raw pointers instead of `&mut`, so the code stays sound even if a
/// caller passes overlapping pointers, which is legal in C.
fn check_out<T>(ptr: *mut T) {
    if ptr.is_null() {
        CFlash.fatal(None);
    }
}

/// Address of a value in the active sector, as returned to C.
fn value_address(norcow: &Impl, val_offset: u32, len: u16) -> *const c_void {
    let address = norcow
        .flash()
        .address(norcow.active_sector(), val_offset, u32::from(len));
    if address.is_null() {
        // `read_item()` validated the range.
        CFlash.fatal(None);
    }
    address
}

// --------------------------------------------------------------------------
// storage/norcow.h
// --------------------------------------------------------------------------

/// # Safety
///
/// `norcow_version` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_init(norcow_version: *mut u32) {
    check_layout();
    // SAFETY: guaranteed by the caller.
    let norcow_version = unsafe { out(norcow_version) };
    *norcow_version = with_norcow(|n| n.init());
}

#[unsafe(no_mangle)]
pub extern "C" fn norcow_wipe() {
    with_norcow(|n| n.wipe());
}

/// # Safety
///
/// `val` and `len` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_get(key: u16, val: *mut *const c_void, len: *mut u16) -> Secbool {
    check_out(val);
    check_out(len);
    let found = with_norcow(|n| {
        n.get(key)
            .map(|value| (value_address(n, value.offset, value.len), value.len))
    });
    let (address, length) = found.unwrap_or((ptr::null(), 0));
    // SAFETY: non-null and valid for writes, guaranteed by the caller.
    unsafe {
        val.write(address);
        len.write(length);
    }
    secbool(found.is_some())
}

/// # Safety
///
/// All pointers must be valid for writes, `offset` also for reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_get_next(
    offset: *mut u32,
    key: *mut u16,
    val: *mut *const c_void,
    len: *mut u16,
) -> Secbool {
    check_out(offset);
    check_out(key);
    check_out(val);
    check_out(len);
    // SAFETY: non-null and valid for reads, guaranteed by the caller.
    let mut next = unsafe { offset.read() };
    let item = with_norcow(|n| {
        n.get_next(&mut next)
            .map(|item| (item, value_address(n, item.val_offset, item.len)))
    });
    // SAFETY: non-null and valid for writes, guaranteed by the caller.
    unsafe {
        offset.write(next);
        // C also wrote the outputs on failure; `storage.c` never reads them
        // then, so they are left alone here.
        if let Some((item, address)) = item {
            key.write(item.key);
            val.write(address);
            len.write(item.len);
        }
    }
    secbool(item.is_some())
}

/// # Safety
///
/// `val` must be null or valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_set(key: u16, val: *const c_void, len: u16) -> Secbool {
    let mut found = SECFALSE;
    // SAFETY: guaranteed by the caller; `found` is a local.
    unsafe { norcow_set_ex(key, val, len, &mut found) }
}

/// # Safety
///
/// `val` must be null or valid for reads of `len` bytes, `found` must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_set_ex(
    key: u16,
    val: *const c_void,
    len: u16,
    found: *mut Secbool,
) -> Secbool {
    check_out(found);
    let source;
    let src: Option<&dyn Source> = if val.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        source = unsafe { RawSource::new(val.cast(), len) };
        Some(&source)
    };

    let mut was_found = false;
    let result = with_norcow(|n| n.set_ex(key, src, len, &mut was_found));
    // Same as C: `found` is left alone for the invalid key.
    if key != KEY_FREE {
        // SAFETY: non-null and valid for writes, guaranteed by the caller.
        unsafe { found.write(secbool(was_found)) };
    }
    secbool(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn norcow_delete(key: u16) -> Secbool {
    secbool(with_norcow(|n| n.delete(key)))
}

#[unsafe(no_mangle)]
pub extern "C" fn norcow_set_counter(key: u16, count: u32) -> Secbool {
    secbool(with_norcow(|n| n.set_counter(key, count)))
}

/// # Safety
///
/// `count` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_next_counter(key: u16, count: *mut u32) -> Secbool {
    // SAFETY: guaranteed by the caller.
    let count = unsafe { out(count) };
    secbool(with_norcow(|n| n.next_counter(key, count)))
}

/// # Safety
///
/// `data` must be valid for reads of `len` bytes; it may be null if `len` is
/// 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn norcow_update_bytes(key: u16, data: *const u8, len: u16) -> Secbool {
    // SAFETY: guaranteed by the caller.
    let source = unsafe { RawSource::new(data, len) };
    secbool(with_norcow(|n| {
        use crate::Layout;
        ActiveLayout::update_bytes(n, key, Data::Source(&source), len)
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn norcow_upgrade_finish() -> Secbool {
    secbool(with_norcow(|n| n.upgrade_finish()))
}
