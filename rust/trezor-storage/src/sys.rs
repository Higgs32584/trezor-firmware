//! Safe wrappers around the C functions the storage relies on: the crypto
//! library, the RNG, timing, the MPU, fatal errors and the secure elements.
//!
//! Functions that are macros or `static inline` on some platforms are reached
//! through real functions in `storage/storage_rs_glue.c`, named
//! `storage_rs_*`.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::size_of_val;
use core::ptr;

use crate::norcow::{Flash, Layout, LayoutParams, Norcow, Value};

#[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
pub use crate::norcow::Blockwise as ActiveLayout;
#[cfg(feature = "bitwise")]
pub use crate::norcow::{BitFlash, Bitwise as ActiveLayout};

/// `secbool` of the C code.
pub type Secbool = u32;
pub const SECTRUE: Secbool = 0xAAAA_AAAA;
pub const SECFALSE: Secbool = 0x0000_0000;

pub const fn secbool(value: bool) -> Secbool {
    if value { SECTRUE } else { SECFALSE }
}

/// Size reserved for `PBKDF2_HMAC_SHA256_CTX`, checked by the glue.
const PBKDF2_CTX_SIZE: usize = 192;
/// Size reserved for `chacha20poly1305_ctx`, checked by the glue.
const CHACHA_CTX_SIZE: usize = 256;

#[repr(C, align(8))]
struct Pbkdf2Ctx([u8; PBKDF2_CTX_SIZE]);

#[repr(C, align(8))]
struct ChachaCtx([u8; CHACHA_CTX_SIZE]);

/// Progress callback passed to the secure element drivers.
pub type UiProgressFn = unsafe extern "C" fn() -> Secbool;

unsafe extern "C" {
    // crypto/
    fn memzero(pnt: *mut c_void, len: usize);
    fn sha256_Raw(data: *const u8, len: usize, digest: *mut u8);
    fn sha256_Transform(state_in: *const u32, data: *const u32, state_out: *mut u32);
    fn hmac_sha256(key: *const u8, keylen: u32, msg: *const u8, msglen: u32, hmac: *mut u8);
    fn hmac_sha256_prepare(key: *const u8, keylen: u32, opad: *mut u32, ipad: *mut u32);
    fn pbkdf2_hmac_sha256_Init(
        ctx: *mut Pbkdf2Ctx,
        pass: *const u8,
        passlen: usize,
        salt: *const u8,
        saltlen: usize,
        blocknr: u32,
    );
    fn pbkdf2_hmac_sha256_Update(ctx: *mut Pbkdf2Ctx, iterations: u32);
    fn pbkdf2_hmac_sha256_Final(ctx: *mut Pbkdf2Ctx, key: *mut u8);
    fn rfc7539_init(ctx: *mut ChachaCtx, key: *const u8, nonce: *const u8);
    fn rfc7539_auth(ctx: *mut ChachaCtx, data: *const u8, n: usize);
    fn rfc7539_finish(ctx: *mut ChachaCtx, alen: i64, plen: i64, mac: *mut u8);
    fn chacha20poly1305_encrypt(ctx: *mut ChachaCtx, input: *const u8, out: *mut u8, n: usize);
    fn chacha20poly1305_decrypt(ctx: *mut ChachaCtx, input: *const u8, out: *mut u8, n: usize);
    fn random_uniform(n: u32) -> u32;

    // Platform, through storage_rs_glue.c where needed.
    fn storage_rs_random32() -> u32;
    fn storage_rs_rng_fill_buffer_strong(buf: *mut c_void, len: usize);
    fn storage_rs_rng_fill_buffer_strong_time(time_ms: *mut u32);
    fn storage_rs_rng_fill_buffer(buf: *mut c_void, len: usize);
    fn wait_random();
    fn storage_rs_ticks_ms() -> u32;
    fn storage_rs_delay(ms: u32);
    fn storage_rs_mpu_reconfig() -> c_int;
    fn storage_rs_mpu_restore(mode: c_int);
    fn storage_rs_fatal(msg: *const c_char, file: *const c_char, line: c_int) -> !;
    fn show_wipe_code_screen();
    fn show_pin_too_many_screen();
    fn time_estimate_pbkdf2_ms(iterations: u32) -> u32;
    fn time_estimate_clock_cycles_ms(cycles: u32) -> u32;
}

// --------------------------------------------------------------------------
// Build configuration (storage_rs_glue.c)
// --------------------------------------------------------------------------

unsafe extern "C" {
    static storage_rs_sector_count: u8;
    static storage_rs_sector_size: u32;
    static storage_rs_norcow_version: u32;
    static storage_rs_norcow_min_version: u32;
    static storage_rs_skip_inactive_wipe: u8;
    static storage_rs_pin_iter_count: u32;
    static storage_rs_pin_max_tries: u32;
    static storage_rs_stretched_pin_count: u32;
    static storage_rs_storage_salt_size: u32;

    // Exactly one of each pair is defined by the glue, matching the C
    // configuration. Referencing the one that matches the Rust features
    // turns a mismatch into a link error.
    #[cfg(feature = "bitwise")]
    static storage_rs_cfg_layout_bitwise: u8;
    #[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
    static storage_rs_cfg_layout_blockwise: u8;
    #[cfg(feature = "optiga")]
    static storage_rs_cfg_optiga_1: u8;
    #[cfg(not(feature = "optiga"))]
    static storage_rs_cfg_optiga_0: u8;
    #[cfg(feature = "tropic")]
    static storage_rs_cfg_tropic_1: u8;
    #[cfg(not(feature = "tropic"))]
    static storage_rs_cfg_tropic_0: u8;
    #[cfg(all(feature = "hwkey", not(feature = "emulator")))]
    static storage_rs_cfg_hwkey_1: u8;
    #[cfg(not(all(feature = "hwkey", not(feature = "emulator"))))]
    static storage_rs_cfg_hwkey_0: u8;
    #[cfg(feature = "emulator")]
    static storage_rs_cfg_emulator_1: u8;
    #[cfg(not(feature = "emulator"))]
    static storage_rs_cfg_emulator_0: u8;
}

/// `NORCOW_VERSION`.
pub fn norcow_version() -> u32 {
    // SAFETY: constant defined by the glue.
    unsafe { storage_rs_norcow_version }
}

/// `NORCOW_MIN_VERSION`: the oldest storage version that this build can
/// upgrade from.
pub fn norcow_min_version() -> u32 {
    // SAFETY: constant defined by the glue.
    unsafe { storage_rs_norcow_min_version }
}

/// `PIN_ITER_COUNT`.
pub fn pin_iter_count() -> u32 {
    // SAFETY: constant defined by the glue.
    unsafe { storage_rs_pin_iter_count }
}

/// Checks that the C build configuration matches this crate. The marker
/// references make a mismatch of the features fail at link time; the
/// constants derived from them are compared here.
pub fn check_config(pin_max_tries: u32, stretched_pin_count: u32, salt_size: u32) {
    // SAFETY: constants defined by the glue.
    let markers = unsafe {
        [
            #[cfg(feature = "bitwise")]
            ptr::read_volatile(&raw const storage_rs_cfg_layout_bitwise),
            #[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
            ptr::read_volatile(&raw const storage_rs_cfg_layout_blockwise),
            #[cfg(feature = "optiga")]
            ptr::read_volatile(&raw const storage_rs_cfg_optiga_1),
            #[cfg(not(feature = "optiga"))]
            ptr::read_volatile(&raw const storage_rs_cfg_optiga_0),
            #[cfg(feature = "tropic")]
            ptr::read_volatile(&raw const storage_rs_cfg_tropic_1),
            #[cfg(not(feature = "tropic"))]
            ptr::read_volatile(&raw const storage_rs_cfg_tropic_0),
            #[cfg(all(feature = "hwkey", not(feature = "emulator")))]
            ptr::read_volatile(&raw const storage_rs_cfg_hwkey_1),
            #[cfg(not(all(feature = "hwkey", not(feature = "emulator"))))]
            ptr::read_volatile(&raw const storage_rs_cfg_hwkey_0),
            #[cfg(feature = "emulator")]
            ptr::read_volatile(&raw const storage_rs_cfg_emulator_1),
            #[cfg(not(feature = "emulator"))]
            ptr::read_volatile(&raw const storage_rs_cfg_emulator_0),
        ]
    };
    // SAFETY: constants defined by the glue.
    let constants_match = unsafe {
        storage_rs_pin_max_tries == pin_max_tries
            && storage_rs_stretched_pin_count == stretched_pin_count
            && storage_rs_storage_salt_size == salt_size
    };
    if markers.iter().any(|&m| m != 1) || !constants_match {
        let (file, line) = crate::here!();
        fatal(Some(c"storage configuration mismatch"), file, line);
    }
}

// --------------------------------------------------------------------------
// Flash
// --------------------------------------------------------------------------

/// `flash_area_t`, only handled through pointers.
#[repr(C)]
struct FlashArea {
    _opaque: [u8; 0],
}

unsafe extern "C" {
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
    fn storage_rs_area(sector: u8) -> *const FlashArea;
}

/// [`Flash`] backed by the C flash driver and the C storage configuration.
pub struct CFlash;

impl CFlash {
    fn area(&self, sector: u8) -> *const FlashArea {
        // The C code checked `sector <= NORCOW_SECTOR_COUNT`, one too many.
        if sector >= self.sector_count() {
            self.fatal(Some(c"invalid sector"));
        }
        // SAFETY: plain call; the glue returns `&STORAGE_AREAS[sector]`.
        unsafe { storage_rs_area(sector) }
    }

    /// Address of `len` bytes at `offset`, or null if not addressable.
    fn address(&self, sector: u8, offset: u32, len: u32) -> *const u8 {
        // SAFETY: `area()` returns a valid `flash_area_t`; the function only
        // computes an address and checks it against the area bounds.
        unsafe { flash_area_get_address(self.area(sector), offset, len).cast() }
    }
}

impl Flash for CFlash {
    fn sector_count(&self) -> u8 {
        // SAFETY: constant defined by the glue.
        unsafe { storage_rs_sector_count }
    }

    fn sector_size(&self) -> u32 {
        // SAFETY: constant defined by the glue.
        unsafe { storage_rs_sector_size }
    }

    fn norcow_version(&self) -> u32 {
        norcow_version()
    }

    fn skip_inactive_wipe(&self) -> bool {
        // SAFETY: constant defined by the glue.
        unsafe { storage_rs_skip_inactive_wipe != 0 }
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
        unsafe { ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len()) };
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
        if block.len() != ActiveLayout::BLOCK_WORDS {
            self.fatal(None);
        }
        let area = self.area(sector);
        // SAFETY: `block` holds `FLASH_BLOCK_WORDS` words, the size of
        // `flash_block_t`, which the C function reads.
        unsafe { flash_area_write_block(area, offset, block.as_ptr()) == SECTRUE }
    }

    fn fatal(&self, msg: Option<&'static CStr>) -> ! {
        let (file, line) = crate::here!();
        fatal(msg, file, line)
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

/// Computes HMAC-SHA256 over `len` bytes at `offset` within a stored value,
/// reading them directly from flash like the C code.
pub fn hmac_sha256_stored<L: Layout<CFlash>>(
    norcow: &Norcow<CFlash, L>,
    key: &[u8],
    value: &Value,
    offset: u32,
    len: u32,
    out: &mut [u8; SHA256_DIGEST_LENGTH],
) {
    if offset + len > u32::from(value.len) {
        CFlash.fatal(None);
    }
    let msg = norcow
        .flash()
        .address(value.sector, value.offset + offset, len);
    if msg.is_null() {
        CFlash.fatal(None);
    }
    // SAFETY: `len` bytes at `msg` are mapped flash (checked above) and are
    // not written during the call; valid key slice and 32-byte output.
    unsafe { hmac_sha256(key.as_ptr(), key.len() as u32, msg, len, out.as_mut_ptr()) };
}

// --------------------------------------------------------------------------
// Memory
// --------------------------------------------------------------------------

/// A local variable that is always accessed through volatile reads and
/// writes, like the `volatile` counters of the C code, so that the compiler
/// cannot fold checks on it (fault-injection countermeasure).
pub struct Volatile<T: Copy>(T);

impl<T: Copy> Volatile<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn get(&self) -> T {
        // SAFETY: reads a field of `self`.
        unsafe { ptr::read_volatile(&self.0) }
    }

    pub fn set(&mut self, value: T) {
        // SAFETY: writes a field of `self`.
        unsafe { ptr::write_volatile(&mut self.0, value) }
    }
}

/// Plain data that may be overwritten with zeros.
pub trait Pod {}
impl Pod for u8 {}
impl Pod for u16 {}
impl Pod for u32 {}
impl<T: Pod, const N: usize> Pod for [T; N] {}
impl<T: Pod> Pod for [T] {}

/// Zeroes memory with `memzero()`, which the compiler cannot elide.
pub fn wipe<T: Pod + ?Sized>(data: &mut T) {
    let len = size_of_val(data);
    // SAFETY: `data` is valid for `len` bytes, and all-zero bytes are a valid
    // value of any `Pod` type.
    unsafe { memzero((data as *mut T).cast(), len) }
}

// --------------------------------------------------------------------------
// Hashes and KDF
// --------------------------------------------------------------------------

pub const SHA256_DIGEST_LENGTH: usize = 32;
pub const SHA256_BLOCK_LENGTH: usize = 64;

pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LENGTH] {
    let mut digest = [0u8; SHA256_DIGEST_LENGTH];
    // SAFETY: valid input slice and 32-byte output.
    unsafe { sha256_Raw(data.as_ptr(), data.len(), digest.as_mut_ptr()) };
    digest
}

pub fn hmac_sha256_into(key: &[u8], msg: &[u8], out: &mut [u8; SHA256_DIGEST_LENGTH]) {
    // SAFETY: valid input slices and 32-byte output. Lengths are tiny.
    unsafe {
        hmac_sha256(
            key.as_ptr(),
            key.len() as u32,
            msg.as_ptr(),
            msg.len() as u32,
            out.as_mut_ptr(),
        )
    };
}

/// Returns the outer and inner digests of HMAC-SHA256 for `key`.
pub fn hmac_sha256_prepare_digests(key: &[u8], odig: &mut [u32; 8], idig: &mut [u32; 8]) {
    // SAFETY: valid key slice and two 8-word outputs.
    unsafe {
        hmac_sha256_prepare(
            key.as_ptr(),
            key.len() as u32,
            odig.as_mut_ptr(),
            idig.as_mut_ptr(),
        )
    };
}

/// `sha256_Transform(state, data, out)`: compresses one block. The new state
/// is written to the first 8 words of `out`. If `data` is `None`, the block
/// is read from `out` itself, as `sha256_Transform(state, h, h)` does in C.
pub fn sha256_transform(state: &[u32; 8], data: Option<&[u32; 16]>, out: &mut [u32; 16]) {
    let out_ptr = out.as_mut_ptr();
    let data_ptr = match data {
        Some(data) => data.as_ptr(),
        None => out_ptr.cast_const(),
    };
    // SAFETY: valid 8-word state, 16-word block and 16-word output. The C
    // function reads the whole block before it writes the output, which is
    // why in-place use is supported (the C storage relies on it too).
    unsafe { sha256_Transform(state.as_ptr(), data_ptr, out_ptr) };
}

pub struct Pbkdf2(Pbkdf2Ctx);

/// The contexts are created empty and initialized in place, so that no
/// copy of the secret state is left behind by a move.
impl Pbkdf2 {
    pub const fn empty() -> Self {
        Self(Pbkdf2Ctx([0; PBKDF2_CTX_SIZE]))
    }

    pub fn init(&mut self, pass: &[u8], salt: &[u8], blocknr: u32) {
        // SAFETY: the buffer is large enough for the context (checked by the
        // glue) and the slices are valid.
        unsafe {
            pbkdf2_hmac_sha256_Init(
                &mut self.0,
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                salt.len(),
                blocknr,
            )
        };
    }

    pub fn update(&mut self, iterations: u32) {
        // SAFETY: initialized context.
        unsafe { pbkdf2_hmac_sha256_Update(&mut self.0, iterations) };
    }

    pub fn finish(&mut self, key: &mut [u8; SHA256_DIGEST_LENGTH]) {
        // SAFETY: initialized context and 32-byte output.
        unsafe { pbkdf2_hmac_sha256_Final(&mut self.0, key.as_mut_ptr()) };
    }
}

impl Drop for Pbkdf2 {
    fn drop(&mut self) {
        wipe(&mut self.0.0);
    }
}

// --------------------------------------------------------------------------
// ChaCha20-Poly1305 (RFC 7539)
// --------------------------------------------------------------------------

pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;
pub const CHACHA20POLY1305_BLOCK_SIZE: usize = 64;
pub const CHACHA20POLY1305_TAG_SIZE: usize = 16;
pub const RFC7539_NONCE_SIZE: usize = 12;

pub struct ChaCha(ChachaCtx);

impl ChaCha {
    pub const fn empty() -> Self {
        Self(ChachaCtx([0; CHACHA_CTX_SIZE]))
    }

    pub fn init(
        &mut self,
        key: &[u8; CHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; RFC7539_NONCE_SIZE],
    ) {
        // SAFETY: the buffer is large enough for the context (checked by the
        // glue); 32-byte key and 12-byte nonce.
        unsafe { rfc7539_init(&mut self.0, key.as_ptr(), nonce.as_ptr()) };
    }

    pub fn auth(&mut self, data: &[u8]) {
        // SAFETY: initialized context, valid slice.
        unsafe { rfc7539_auth(&mut self.0, data.as_ptr(), data.len()) };
    }

    pub fn encrypt(&mut self, input: &[u8], out: &mut [u8]) {
        let n = input.len().min(out.len());
        // SAFETY: initialized context, `n` bytes valid in both buffers.
        unsafe { chacha20poly1305_encrypt(&mut self.0, input.as_ptr(), out.as_mut_ptr(), n) };
    }

    pub fn decrypt(&mut self, input: &[u8], out: &mut [u8]) {
        let n = input.len().min(out.len());
        // SAFETY: initialized context, `n` bytes valid in both buffers.
        unsafe { chacha20poly1305_decrypt(&mut self.0, input.as_ptr(), out.as_mut_ptr(), n) };
    }

    pub fn finish(&mut self, alen: usize, plen: usize, mac: &mut [u8; CHACHA20POLY1305_TAG_SIZE]) {
        // SAFETY: initialized context and 16-byte output.
        unsafe { rfc7539_finish(&mut self.0, alen as i64, plen as i64, mac.as_mut_ptr()) };
    }
}

impl Drop for ChaCha {
    fn drop(&mut self) {
        wipe(&mut self.0.0);
    }
}

// --------------------------------------------------------------------------
// Randomness
// --------------------------------------------------------------------------

pub fn random32() -> u32 {
    // SAFETY: plain call.
    unsafe { storage_rs_random32() }
}

pub fn random_uniform_below(n: u32) -> u32 {
    // SAFETY: plain call.
    unsafe { random_uniform(n) }
}

/// `rng_fill_buffer_strong()`.
pub fn rng_strong(buf: &mut [u8]) {
    // SAFETY: valid buffer.
    unsafe { storage_rs_rng_fill_buffer_strong(buf.as_mut_ptr().cast(), buf.len()) };
}

/// `rng_fill_buffer_strong_time()`.
pub fn rng_strong_time(time_ms: &mut u32) {
    // SAFETY: valid pointer.
    unsafe { storage_rs_rng_fill_buffer_strong_time(time_ms) };
}

/// `rng_fill_buffer()`.
pub fn rng(buf: &mut [u8]) {
    // SAFETY: valid buffer.
    unsafe { storage_rs_rng_fill_buffer(buf.as_mut_ptr().cast(), buf.len()) };
}

/// Waits a random number of CPU cycles (fault-injection countermeasure).
pub fn wait_random_delay() {
    // SAFETY: plain call.
    unsafe { wait_random() };
}

// --------------------------------------------------------------------------
// Time, MPU, UI screens, fatal errors
// --------------------------------------------------------------------------

pub fn ticks_ms() -> u32 {
    // SAFETY: plain call.
    unsafe { storage_rs_ticks_ms() }
}

pub fn delay_ms(ms: u32) {
    // SAFETY: plain call.
    unsafe { storage_rs_delay(ms) };
}

pub fn pbkdf2_time_ms(iterations: u32) -> u32 {
    // SAFETY: plain call.
    unsafe { time_estimate_pbkdf2_ms(iterations) }
}

pub fn clock_cycles_ms(cycles: u32) -> u32 {
    // SAFETY: plain call.
    unsafe { time_estimate_clock_cycles_ms(cycles) }
}

/// Switches the MPU to storage mode (`mpu_reconfig(MPU_MODE_STORAGE)`) until
/// dropped or [`Mpu::restore`]d.
#[must_use]
pub struct Mpu(c_int);

impl Mpu {
    pub fn storage() -> Self {
        // SAFETY: plain call.
        Self(unsafe { storage_rs_mpu_reconfig() })
    }

    /// `mpu_restore()`.
    pub fn restore(self) {
        drop(self);
    }
}

impl Drop for Mpu {
    fn drop(&mut self) {
        // SAFETY: plain call with the mode returned by `mpu_reconfig()`.
        unsafe { storage_rs_mpu_restore(self.0) };
    }
}

/// Shows the wipe code screen. Does not return on the device.
pub fn wipe_code_screen() {
    // SAFETY: plain call.
    unsafe { show_wipe_code_screen() };
}

/// Shows the "too many PIN attempts" screen. Does not return on the device.
pub fn pin_too_many_screen() {
    // SAFETY: plain call.
    unsafe { show_pin_too_many_screen() };
}

/// `__fatal_error()`.
pub fn fatal(msg: Option<&CStr>, file: &CStr, line: u32) -> ! {
    let msg = msg.map_or(core::ptr::null(), CStr::as_ptr);
    // SAFETY: null or NUL-terminated strings.
    unsafe { storage_rs_fatal(msg, file.as_ptr(), line as c_int) }
}

/// The current source location as a C string and line, for [`fatal`].
#[macro_export]
#[doc(hidden)]
macro_rules! here {
    () => {{
        const FILE: &::core::ffi::CStr =
            match ::core::ffi::CStr::from_bytes_with_nul(concat!(file!(), "\0").as_bytes()) {
                Ok(file) => file,
                Err(_) => panic!(),
            };
        (FILE, line!())
    }};
}

/// `ensure()`: stops the device unless `cond`.
#[macro_export]
#[doc(hidden)]
macro_rules! ensure {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            let (file, line) = $crate::here!();
            $crate::sys::fatal(Some($msg), file, line);
        }
    };
}

// --------------------------------------------------------------------------
// Secure elements and the hardware key
// --------------------------------------------------------------------------

#[cfg(feature = "optiga")]
pub mod optiga {
    use super::UiProgressFn;

    pub const SECRET_SIZE: usize = 32;

    /// `optiga_pin_result`.
    pub const PIN_SUCCESS: u32 = 0;
    pub const PIN_INVALID: u32 = 1;
    pub const PIN_COUNTER_EXCEEDED: u32 = 2;

    unsafe extern "C" {
        fn optiga_read_sec(sec: *mut u8) -> bool;
        fn optiga_pin_init(ui: UiProgressFn) -> bool;
        fn optiga_pin_init_time(time_ms: *mut u32);
        fn optiga_pin_stretch_cmac_ecdh(ui: UiProgressFn, stretched_pin: *mut u8) -> bool;
        fn optiga_pin_stretch_cmac_ecdh_time(time_ms: *mut u32, sec: *mut u8, last: *mut u32);
        fn optiga_pin_set(ui: UiProgressFn, stretched_pins: *mut u8, reset_key: *mut u8) -> bool;
        fn optiga_pin_set_time(time_ms: *mut u32, sec: *mut u8, last: *mut u32);
        fn optiga_pin_reset_hmac_counter(ui: UiProgressFn, reset_key: *const u8) -> bool;
        fn optiga_pin_reset_hmac_counter_time(time_ms: *mut u32, sec: *mut u8, last: *mut u32);
        fn optiga_pin_verify(ui: UiProgressFn, index: u8, stretched_pin: *mut u8) -> u32;
        fn optiga_pin_verify_time(index: u8, time_ms: *mut u32, sec: *mut u8, last: *mut u32);
        fn optiga_pin_verify_v4(ui: UiProgressFn, secret: *const u8, out: *mut u8) -> u32;
        fn optiga_pin_get_rem_v4(ctr: *mut u32) -> bool;
        fn optiga_pin_get_rem(ctr: *mut u32) -> bool;
        fn optiga_pin_decrease_rem_v4(count: u32) -> bool;
        fn optiga_pin_decrease_rem(count: u32) -> bool;
    }

    /// Time estimation state shared by the `*_time` functions.
    #[derive(Default)]
    pub struct TimeState {
        pub sec: u8,
        pub last_time_decreased_ms: u32,
    }

    pub fn read_sec(sec: &mut u8) -> bool {
        // SAFETY: valid pointer.
        unsafe { optiga_read_sec(sec) }
    }

    pub fn pin_init(ui: UiProgressFn) -> bool {
        // SAFETY: plain call.
        unsafe { optiga_pin_init(ui) }
    }

    pub fn pin_init_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { optiga_pin_init_time(time_ms) };
    }

    pub fn pin_stretch_cmac_ecdh(ui: UiProgressFn, pin: &mut [u8; SECRET_SIZE]) -> bool {
        // SAFETY: 32-byte buffer.
        unsafe { optiga_pin_stretch_cmac_ecdh(ui, pin.as_mut_ptr()) }
    }

    pub fn pin_stretch_cmac_ecdh_time(time_ms: &mut u32, st: &mut TimeState) {
        // SAFETY: valid pointers.
        unsafe {
            optiga_pin_stretch_cmac_ecdh_time(time_ms, &mut st.sec, &mut st.last_time_decreased_ms)
        };
    }

    /// `stretched_pins` must hold `STRETCHED_PIN_COUNT` rows.
    pub fn pin_set(
        ui: UiProgressFn,
        stretched_pins: &mut [[u8; SECRET_SIZE]],
        reset_key: &mut [u8; SECRET_SIZE],
    ) -> bool {
        // SAFETY: the caller sizes `stretched_pins` to STRETCHED_PIN_COUNT
        // rows, which the C function reads and writes.
        unsafe {
            optiga_pin_set(
                ui,
                stretched_pins.as_mut_ptr().cast(),
                reset_key.as_mut_ptr(),
            )
        }
    }

    pub fn pin_set_time(time_ms: &mut u32, st: &mut TimeState) {
        // SAFETY: valid pointers.
        unsafe { optiga_pin_set_time(time_ms, &mut st.sec, &mut st.last_time_decreased_ms) };
    }

    pub fn pin_reset_hmac_counter(ui: UiProgressFn, reset_key: &[u8; SECRET_SIZE]) -> bool {
        // SAFETY: 32-byte buffer.
        unsafe { optiga_pin_reset_hmac_counter(ui, reset_key.as_ptr()) }
    }

    pub fn pin_reset_hmac_counter_time(time_ms: &mut u32, st: &mut TimeState) {
        // SAFETY: valid pointers.
        unsafe {
            optiga_pin_reset_hmac_counter_time(time_ms, &mut st.sec, &mut st.last_time_decreased_ms)
        };
    }

    pub fn pin_verify(ui: UiProgressFn, index: u8, pin: &mut [u8; SECRET_SIZE]) -> u32 {
        // SAFETY: 32-byte buffer.
        unsafe { optiga_pin_verify(ui, index, pin.as_mut_ptr()) }
    }

    pub fn pin_verify_time(index: u8, time_ms: &mut u32, st: &mut TimeState) {
        // SAFETY: valid pointers.
        unsafe {
            optiga_pin_verify_time(index, time_ms, &mut st.sec, &mut st.last_time_decreased_ms)
        };
    }

    pub fn pin_verify_v4(
        ui: UiProgressFn,
        secret: &[u8; SECRET_SIZE],
        out: &mut [u8; SECRET_SIZE],
    ) -> u32 {
        // SAFETY: 32-byte buffers.
        unsafe { optiga_pin_verify_v4(ui, secret.as_ptr(), out.as_mut_ptr()) }
    }

    pub fn pin_get_rem(v4: bool, ctr: &mut u32) -> bool {
        // SAFETY: valid pointer.
        unsafe {
            if v4 {
                optiga_pin_get_rem_v4(ctr)
            } else {
                optiga_pin_get_rem(ctr)
            }
        }
    }

    pub fn pin_decrease_rem(v4: bool, count: u32) -> bool {
        // SAFETY: plain call.
        unsafe {
            if v4 {
                optiga_pin_decrease_rem_v4(count)
            } else {
                optiga_pin_decrease_rem(count)
            }
        }
    }
}

#[cfg(feature = "tropic")]
pub mod tropic {
    use super::UiProgressFn;

    pub const MAC_AND_DESTROY_SIZE: usize = 32;

    unsafe extern "C" {
        fn tropic_session_start_time(time_ms: *mut u32);
        fn tropic_pin_stretch(ui: UiProgressFn, pin_index: u16, stretched_pin: *mut u8) -> bool;
        fn tropic_pin_stretch_time(time_ms: *mut u32);
        fn tropic_pin_reset_slots(ui: UiProgressFn, pin_index: u16, reset_key: *const u8) -> bool;
        fn tropic_pin_reset_slots_time(time_ms: *mut u32, pin_index: u16);
        fn tropic_pin_set(ui: UiProgressFn, stretched_pins: *mut u8, reset_key: *mut u8) -> bool;
        fn tropic_pin_set_time(time_ms: *mut u32);
        fn tropic_pin_set_kek_masks(
            ui: UiProgressFn,
            kek: *const u8,
            stretched_pins: *const u8,
        ) -> bool;
        fn tropic_pin_set_kek_masks_time(time_ms: *mut u32);
        fn tropic_pin_unmask_kek(
            ui: UiProgressFn,
            pin_index: u16,
            stretched_pin: *const u8,
            kek: *mut u8,
        ) -> bool;
        fn tropic_pin_unmask_kek_time(time_ms: *mut u32);
    }

    pub fn session_start_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { tropic_session_start_time(time_ms) };
    }

    pub fn pin_stretch(ui: UiProgressFn, index: u16, pin: &mut [u8; MAC_AND_DESTROY_SIZE]) -> bool {
        // SAFETY: 32-byte buffer.
        unsafe { tropic_pin_stretch(ui, index, pin.as_mut_ptr()) }
    }

    pub fn pin_stretch_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { tropic_pin_stretch_time(time_ms) };
    }

    pub fn pin_reset_slots(ui: UiProgressFn, index: u16, key: &[u8; MAC_AND_DESTROY_SIZE]) -> bool {
        // SAFETY: 32-byte buffer.
        unsafe { tropic_pin_reset_slots(ui, index, key.as_ptr()) }
    }

    pub fn pin_reset_slots_time(time_ms: &mut u32, index: u16) {
        // SAFETY: valid pointer.
        unsafe { tropic_pin_reset_slots_time(time_ms, index) };
    }

    /// `stretched_pins` must hold `PIN_MAX_TRIES` rows.
    pub fn pin_set(
        ui: UiProgressFn,
        stretched_pins: &mut [[u8; MAC_AND_DESTROY_SIZE]],
        reset_key: &mut [u8; MAC_AND_DESTROY_SIZE],
    ) -> bool {
        // SAFETY: the caller sizes `stretched_pins` to PIN_MAX_TRIES rows.
        unsafe {
            tropic_pin_set(
                ui,
                stretched_pins.as_mut_ptr().cast(),
                reset_key.as_mut_ptr(),
            )
        }
    }

    pub fn pin_set_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { tropic_pin_set_time(time_ms) };
    }

    /// `stretched_pins` must hold `PIN_MAX_TRIES` rows.
    pub fn pin_set_kek_masks(
        ui: UiProgressFn,
        kek: &[u8; MAC_AND_DESTROY_SIZE],
        stretched_pins: &[[u8; MAC_AND_DESTROY_SIZE]],
    ) -> bool {
        // SAFETY: the caller sizes `stretched_pins` to PIN_MAX_TRIES rows.
        unsafe { tropic_pin_set_kek_masks(ui, kek.as_ptr(), stretched_pins.as_ptr().cast()) }
    }

    pub fn pin_set_kek_masks_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { tropic_pin_set_kek_masks_time(time_ms) };
    }

    /// Unmasks the KEK in place: `pin` holds the stretched PIN on input and
    /// the KEK on output, as in the C code.
    pub fn pin_unmask_kek_in_place(
        ui: UiProgressFn,
        index: u16,
        pin: &mut [u8; MAC_AND_DESTROY_SIZE],
    ) -> bool {
        let ptr = pin.as_mut_ptr();
        // SAFETY: 32-byte buffer; the C storage passes the same buffer as
        // input and output, so the driver supports it.
        unsafe { tropic_pin_unmask_kek(ui, index, ptr.cast_const(), ptr) }
    }

    pub fn pin_unmask_kek_time(time_ms: &mut u32) {
        // SAFETY: valid pointer.
        unsafe { tropic_pin_unmask_kek_time(time_ms) };
    }
}

/// The hardware-bound key (`USE_STORAGE_HWKEY`).
#[cfg(all(feature = "hwkey", not(feature = "emulator")))]
pub mod hwkey {
    use super::{SECTRUE, SHA256_DIGEST_LENGTH, Secbool};

    unsafe extern "C" {
        fn storage_rs_secure_aes_encrypt(
            input: *const u8,
            output: *mut u8,
            size: usize,
            privileged: bool,
        ) -> Secbool;
    }

    /// Encrypts a 32-byte value with the privileged or unprivileged XOR key
    /// (`SECURE_AES_KEY_XORK_SP` / `SECURE_AES_KEY_XORK_SN`).
    pub fn encrypt(
        input: &[u8; SHA256_DIGEST_LENGTH],
        output: &mut [u8; SHA256_DIGEST_LENGTH],
        privileged: bool,
    ) -> bool {
        // SAFETY: 32-byte buffers.
        unsafe {
            storage_rs_secure_aes_encrypt(
                input.as_ptr(),
                output.as_mut_ptr(),
                input.len(),
                privileged,
            ) == SECTRUE
        }
    }
}
