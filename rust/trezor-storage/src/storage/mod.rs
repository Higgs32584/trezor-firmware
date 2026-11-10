//! The storage: a Rust port of `storage/storage.c`.
//!
//! Values are kept in [`Norcow`]. Protected values (neither public nor
//! storage-internal) are encrypted with ChaCha20-Poly1305 under the data
//! encryption key (DEK) and covered by a storage authentication tag computed
//! with the storage authentication key (SAK). The DEK and SAK are stored
//! encrypted under a key derived from the PIN (and the secure elements, when
//! present).
//!
//! The port keeps the structure of the C code, with each function named after
//! its C counterpart, and keeps its fault-injection countermeasures: security
//! decisions use multi-bit [`Secbool`] values, loops are checked for
//! completion, sensitive checks are repeated after random delays, and any
//! inconsistency goes through [`Storage::handle_fault`]. Flash format, key
//! derivation, encryption and the sequence of random numbers drawn are the
//! same as in C, which the storage test suite checks byte for byte.
//!
//! Comments marked "Same as C" point out behavior that is kept for
//! compatibility even though it may look odd.

mod pinlogs;
mod upgrade;

use core::cell::{Cell, RefCell, RefMut};
use core::ffi::CStr;
use core::hint::black_box;

use crate::ensure;
use crate::ffi::{UI, ui_progress, ui_progress_finish};
use crate::norcow::{Item, Norcow, Value};
use crate::sys::{
    self, ActiveLayout, CFlash, CHACHA20POLY1305_BLOCK_SIZE, CHACHA20POLY1305_TAG_SIZE, ChaCha,
    Mpu, Pbkdf2, RFC7539_NONCE_SIZE, SECFALSE, SECTRUE, SHA256_DIGEST_LENGTH, Secbool, secbool,
    wipe,
};

/// Stops the device after a detected fault, see [`Storage::handle_fault`].
macro_rules! fault {
    ($storage:expr, $msg:expr) => {{
        let (file, line) = $crate::here!();
        $storage.handle_fault($msg, file, line)
    }};
}
pub(crate) use fault;

// --------------------------------------------------------------------------
// Constants (storage.h, storage.c)
// --------------------------------------------------------------------------

/// The APP namespace reserved for storage related values.
const APP_STORAGE: u8 = 0x00;

/// PIN entry log and PIN success log.
const PIN_LOGS_KEY: u16 = 0x0001;
/// Combined salt, EDEK, ESAK and PIN verification code entry.
const EDEK_PVC_KEY: u16 = 0x0002;
/// PIN set flag.
const PIN_NOT_SET_KEY: u16 = 0x0003;
/// Authenticated storage version.
const VERSION_KEY: u16 = 0x0004;
/// Storage authentication tag.
const STORAGE_TAG_KEY: u16 = 0x0005;
/// Wipe code data. Introduced in storage version 2.
const WIPE_CODE_DATA_KEY: u16 = 0x0006;
/// Storage upgrade flag. Introduced in storage version 2.
const STORAGE_UPGRADED_KEY: u16 = 0x0007;
/// Unauthenticated storage version. Introduced in storage version 3.
const UNAUTH_VERSION_KEY: u16 = 0x0008;
/// Key used to reset the MAC-and-destroy slots in Tropic after an unlock.
#[cfg(feature = "tropic")]
const TROPIC_MAC_AND_DESTROY_RESET_KEY: u16 = 0x0009;
/// Key used to reset the HMAC counter in Optiga after an unlock.
#[cfg(all(feature = "optiga", feature = "tropic"))]
const OPTIGA_HMAC_RESET_KEY: u16 = 0x000A;

/// If the top bit of APP is set, the value is not encrypted.
pub const FLAG_PUBLIC: u8 = 0x80;
/// If the top two bits of APP are set, the value can be written while locked.
pub const FLAGS_WRITE: u8 = 0xC0;

pub const EXTERNAL_SALT_SIZE: usize = 32;

/// Maximum number of failed unlock attempts. Each attempt needs a stretched
/// PIN slot in the secure elements when Tropic is used.
#[cfg(feature = "tropic")]
pub const PIN_MAX_TRIES: u32 = 10;
#[cfg(not(feature = "tropic"))]
pub const PIN_MAX_TRIES: u32 = 16;

/// Number of PIN slots configured as stretched PINs.
#[cfg(feature = "tropic")]
const STRETCHED_PIN_COUNT: usize = PIN_MAX_TRIES as usize;
#[cfg(not(feature = "tropic"))]
const STRETCHED_PIN_COUNT: usize = 1;

/// Length of the random salt.
#[cfg(feature = "optiga")]
const STORAGE_SALT_SIZE: usize = 32;
#[cfg(not(feature = "optiga"))]
const STORAGE_SALT_SIZE: usize = 4;

/// The uint32 representation of an empty PIN, used prior to version 3.
const V0_PIN_EMPTY: u32 = 1;
/// Maximum number of PIN digits allowed prior to storage version 3.
const V0_MAX_PIN_LEN: usize = 9;
/// Maximum length of the wipe code.
const MAX_WIPE_CODE_LEN: usize = 50;
/// The minimum number of milliseconds between progress updates.
pub(crate) const MIN_PROGRESS_UPDATE_MS: u32 = 100;

const HARDWARE_SALT_SIZE: usize = SHA256_DIGEST_LENGTH;
/// Hardware salt, storage salt and external salt.
const KDF_SALT_SIZE: usize = HARDWARE_SALT_SIZE + STORAGE_SALT_SIZE + EXTERNAL_SALT_SIZE;
const DEK_SIZE: usize = 32;
const SAK_SIZE: usize = 16;
const KEYS_SIZE: usize = DEK_SIZE + SAK_SIZE;
const PVC_SIZE: usize = 8;
const STORAGE_TAG_SIZE: usize = 16;
const WIPE_CODE_SALT_SIZE: usize = 8;
const WIPE_CODE_TAG_SIZE: usize = 8;
/// Overhead of an encrypted value: IV and tag.
const ENCRYPTION_OVERHEAD: usize = RFC7539_NONCE_SIZE + CHACHA20POLY1305_TAG_SIZE;

/// The value of an unconfigured wipe code. It differs from the empty PIN on
/// purpose, see the C code.
const WIPE_CODE_EMPTY: [u8; 4] = [0; 4];
/// The uint32 representation of an empty wipe code used in storage version 2.
const V2_WIPE_CODE_EMPTY: u32 = 0;

const TRUE_BYTE: u8 = 0x01;
const FALSE_BYTE: u8 = 0x00;
const TRUE_WORD: u32 = 0xC35A_69A5;
const FALSE_WORD: u32 = 0x3CA5_965A;

/// `storage_ui_message_t`.
pub mod msg {
    pub const NO_MSG: u32 = 0;
    pub const VERIFYING_PIN_MSG: u32 = 1;
    pub const PROCESSING_MSG: u32 = 2;
    pub const STARTING_MSG: u32 = 3;
    pub const WRONG_PIN_MSG: u32 = 4;
}

/// `storage_unlock_result_t`.
pub mod unlock_result {
    pub const UNLOCK_OK: u32 = 0;
    pub const UNLOCK_NOT_INITIALIZED: u32 = 1;
    pub const UNLOCK_NO_PIN: u32 = 2;
    pub const UNLOCK_PIN_GET_FAILS_FAILED: u32 = 3;
    pub const UNLOCK_TOO_MANY_FAILS: u32 = 4;
    pub const UNLOCK_UI_CANCELLED: u32 = 5;
    pub const UNLOCK_INCREASE_FAILS_FAILED: u32 = 6;
    pub const UNLOCK_INCORRECT_PIN: u32 = 7;
    pub const UNLOCK_WRONG_STORAGE_VERSION: u32 = 8;
    pub const UNLOCK_OPTIGA_GET_HMAC_RESET_KEY_FAILED: u32 = 9;
    pub const UNLOCK_OPTIGA_HMAC_COUNTER_RESET_FAILED: u32 = 10;
    pub const UNLOCK_GET_TROPIC_MAC_AND_DESTROY_RESET_KEY_FAILED: u32 = 11;
    pub const UNLOCK_TROPIC_RESET_SLOTS_FAILED: u32 = 12;
    pub const UNLOCK_PIN_RESET_FAILS_FAILED: u32 = 13;
}
use unlock_result::*;

/// `storage_pin_change_result_t`.
pub mod pin_change_result {
    pub const PIN_CHANGE_OK: u32 = 0;
    pub const PIN_CHANGE_WIPE_CODE: u32 = 1;
    pub const PIN_CHANGE_STORAGE_LOCKED: u32 = 2;
    pub const PIN_CHANGE_WRONG_ARGUMENT: u32 = 3;
    pub const PIN_CHANGE_NOT_INITIALIZED: u32 = 4;
    pub const PIN_CHANGE_CANNOT_SET_PIN: u32 = 5;
}
use pin_change_result::*;

/// `storage_pin_op_t`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PinOp {
    Set,
    Verify,
}

/// Time estimation state of Optiga, threaded through the `*_time` functions.
#[cfg(feature = "optiga")]
type OptigaTime = sys::optiga::TimeState;
#[cfg(not(feature = "optiga"))]
#[derive(Default)]
struct OptigaTime;

/// The progress callback passed to the secure element drivers.
#[cfg(any(feature = "optiga", feature = "tropic"))]
const UI_PROGRESS: sys::UiProgressFn = crate::ffi::ui_progress_callback;

/// Plaintext of a value being encrypted: memory, or a value in flash during
/// storage upgrades.
#[derive(Clone, Copy)]
enum Plain<'a> {
    Mem(&'a [u8]),
    Stored(Value),
}

// --------------------------------------------------------------------------
// State
// --------------------------------------------------------------------------

/// The storage state, replacing the static variables of the C code.
///
/// The UI callback and the secure element drivers hand control to other code
/// in the middle of storage operations, and that code may call the storage
/// again (the app reads settings while the kernel waits for a PIN check) or
/// may never return (a task killed during the callback). Like the C code, the
/// storage has to stay usable in both cases. The methods therefore take
/// `&self`, the state is kept in `Cell`s and `RefCell`s, and borrows are
/// short: none is ever held across `ui_progress()`, a secure element call
/// or a fault.
pub struct Storage {
    norcow: RefCell<Norcow<CFlash, ActiveLayout>>,
    initialized: Cell<Secbool>,
    unlocked: Cell<Secbool>,
    /// DEK followed by SAK.
    cached_keys: RefCell<[u8; KEYS_SIZE]>,
    authentication_sum: RefCell<[u8; SHA256_DIGEST_LENGTH]>,
    hardware_salt: RefCell<[u8; HARDWARE_SALT_SIZE]>,
    norcow_active_version: Cell<u32>,
    /// Fault handling is in progress (`in_progress` of `__handle_fault()`).
    fault_in_progress: Cell<Secbool>,
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            norcow: RefCell::new(Norcow::new(CFlash, ActiveLayout::new())),
            initialized: Cell::new(SECFALSE),
            unlocked: Cell::new(SECFALSE),
            cached_keys: RefCell::new([0; KEYS_SIZE]),
            authentication_sum: RefCell::new([0; SHA256_DIGEST_LENGTH]),
            hardware_salt: RefCell::new([0; HARDWARE_SALT_SIZE]),
            norcow_active_version: Cell::new(0),
            fault_in_progress: Cell::new(SECFALSE),
        }
    }

    /// Norcow, borrowed until the end of the statement. Never keep the
    /// borrow across a callback, a secure element call or a fault.
    pub(crate) fn nc(&self) -> RefMut<'_, Norcow<CFlash, ActiveLayout>> {
        match self.norcow.try_borrow_mut() {
            Ok(norcow) => norcow,
            Err(_) => {
                let (file, line) = crate::here!();
                sys::fatal(Some(c"storage busy"), file, line)
            }
        }
    }

    /// `norcow_get()` within one short borrow.
    pub(crate) fn get_value(&self, key: u16) -> Option<Value> {
        self.nc().get(key)
    }

    /// Reads a stored value of exactly `N` bytes within one short borrow.
    pub(crate) fn get_exact<const N: usize>(&self, key: u16) -> Option<[u8; N]> {
        let norcow = self.nc();
        let value = norcow.get(key)?;
        norcow.read_exact::<N>(&value)
    }

    /// Reads `buf.len()` bytes at `offset` within a stored value.
    pub(crate) fn read_at(&self, value: &Value, offset: u32, buf: &mut [u8]) -> bool {
        self.nc().read_at(value, offset, buf)
    }

    /// `norcow_get_next()` within one short borrow; also returns the
    /// location of the value.
    pub(crate) fn next_item(&self, offset: &mut u32) -> Option<(Item, Value)> {
        let norcow = self.nc();
        let item = norcow.get_next(offset)?;
        let value = norcow.item_value(&item);
        Some((item, value))
    }

    /// Initializes `ctx` with the DEK.
    fn chacha_init_dek(&self, ctx: &mut ChaCha, nonce: &[u8; RFC7539_NONCE_SIZE]) {
        let keys = self.cached_keys.borrow();
        let mut dek = [0u8; DEK_SIZE];
        dek.copy_from_slice(&keys[..DEK_SIZE]);
        ctx.init(&dek, nonce);
        wipe(&mut dek);
    }

    /// HMAC-SHA256 keyed with the SAK.
    fn hmac_sak(&self, msg: &[u8], out: &mut [u8; SHA256_DIGEST_LENGTH]) {
        let keys = self.cached_keys.borrow();
        sys::hmac_sha256_into(&keys[DEK_SIZE..], msg, out);
    }

    // ----------------------------------------------------------------------
    // Fault handling and comparisons
    // ----------------------------------------------------------------------

    /// `__handle_fault()`: increments the PIN fail counter, which doubles as
    /// a fault counter, and halts. A fault during fault handling, or a
    /// counter that does not increment, wipes the storage first.
    pub(crate) fn handle_fault(&self, msg: &CStr, file: &CStr, line: u32) -> ! {
        // If fault handling is already in progress, we are probably facing a
        // fault injection attack, so wipe.
        if self.fault_in_progress.get() != SECFALSE {
            self.wipe();
            sys::fatal(Some(msg), file, line);
        }

        self.fault_in_progress.set(SECTRUE);
        let mut ctr = 0;
        if self.pin_get_fails(&mut ctr) != SECTRUE {
            self.wipe();
            sys::fatal(Some(msg), file, line);
        }

        if self.storage_pin_fails_increase() != SECTRUE {
            self.wipe();
            sys::fatal(Some(msg), file, line);
        }

        let mut ctr_new = 0;
        if self.pin_get_fails(&mut ctr_new) != SECTRUE || ctr.wrapping_add(1) != ctr_new {
            self.wipe();
        }
        sys::fatal(Some(msg), file, line);
    }

    /// Constant-time comparison of two equally long buffers.
    fn secequal(&self, a: &[u8], b: &[u8]) -> Secbool {
        let n = a.len();
        if b.len() != n {
            fault!(self, c"length check");
        }
        let mut diff = 0u8;
        let mut i = 0;
        while i < n {
            diff |= a[i] ^ b[i];
            i += 1;
        }

        // Check loop completion in case of a fault injection attack.
        if black_box(i) != n {
            fault!(self, c"loop completion check");
        }

        if diff != 0 { SECFALSE } else { SECTRUE }
    }

    /// Comparison of two buffers of words, masked with random values.
    fn secequal32(&self, a: &[u8; PVC_SIZE], b: &[u8; PVC_SIZE]) -> Secbool {
        let wn = PVC_SIZE / 4;
        let mut diff = 0u32;
        let mut i = 0;
        while i < wn {
            let w1 = u32::from_ne_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]);
            let w2 = u32::from_ne_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
            let mask = sys::random32();
            diff |= w1.wrapping_add(mask).wrapping_sub(w2) ^ mask;
            i += 1;
        }

        // Check loop completion in case of a fault injection attack.
        if black_box(i) != wn {
            fault!(self, c"loop completion check");
        }

        if diff != 0 { SECFALSE } else { SECTRUE }
    }

    // ----------------------------------------------------------------------
    // Storage authentication tag
    // ----------------------------------------------------------------------

    /// Initializes the storage authentication tag for freshly wiped storage.
    fn auth_init(&self) -> Secbool {
        let mut tag = [0u8; SHA256_DIGEST_LENGTH];
        wipe(&mut *self.authentication_sum.borrow_mut());
        let sum = *self.authentication_sum.borrow();
        self.hmac_sak(&sum, &mut tag);
        secbool(self.nc().set(STORAGE_TAG_KEY, &tag[..STORAGE_TAG_SIZE]))
    }

    /// Updates the storage authentication tag with the given key.
    fn auth_update(&self, key: u16) -> Secbool {
        if is_protected(key) != SECTRUE {
            return SECTRUE;
        }

        let mut tag = [0u8; SHA256_DIGEST_LENGTH];
        self.hmac_sak(&key.to_ne_bytes(), &mut tag);
        let mut sum = self.authentication_sum.borrow_mut();
        for (s, t) in sum.iter_mut().zip(tag.iter()) {
            *s ^= t;
        }
        let sum_copy = *sum;
        drop(sum);
        self.hmac_sak(&sum_copy, &mut tag);
        secbool(self.nc().set(STORAGE_TAG_KEY, &tag[..STORAGE_TAG_SIZE]))
    }

    /// `norcow_set()` that updates the storage authentication tag. `None`
    /// reserves space to be filled with `update_bytes()`.
    fn auth_set(&self, key: u16, data: Option<&[u8]>, len: u16) -> Secbool {
        let mut found = false;
        let src: Option<&dyn crate::norcow::Source> = data.as_ref().map(|d| d as _);
        let mut ret = secbool(self.nc().set_ex(key, src, len, &mut found));
        if ret == SECTRUE && !found {
            ret = self.auth_update(key);
            if ret != SECTRUE {
                self.nc().delete(key);
            }
        }
        ret
    }

    /// `norcow_get()` that checks the storage authentication tag. Also
    /// caches the authentication sum.
    fn auth_get(&self, key: u16) -> Option<Value> {
        let mut sum = [0u32; SHA256_DIGEST_LENGTH / 4];

        // Prepare inner and outer digest.
        let mut odig = [0u32; 8];
        let mut idig = [0u32; 8];
        sys::hmac_sha256_prepare_digests(
            &self.cached_keys.borrow()[DEK_SIZE..],
            &mut odig,
            &mut idig,
        );

        // Prepare SHA-256 message padding.
        let mut g = [0u32; sys::SHA256_BLOCK_LENGTH / 4];
        let mut h = [0u32; sys::SHA256_BLOCK_LENGTH / 4];
        g[15] = (sys::SHA256_BLOCK_LENGTH as u32 + 2) * 8;
        h[15] = (sys::SHA256_BLOCK_LENGTH as u32 + SHA256_DIGEST_LENGTH as u32) * 8;
        h[8] = 0x8000_0000;

        let mut offset = 0;
        // Mitigation against fault injection.
        let mut entry_count: u16 = 0;
        let mut other_count: u16 = 0;
        let mut found = None;
        let mut tag = None;
        while let Some((item, value)) = self.next_item(&mut offset) {
            entry_count = entry_count.wrapping_add(1);
            let k = item.key;
            if k == key {
                found = Some(value);
            } else {
                other_count = other_count.wrapping_add(1);
            }
            if is_protected(k) != SECTRUE {
                if k == STORAGE_TAG_KEY {
                    tag = Some(value);
                }
                continue;
            }
            // Add SHA message padding.
            g[0] = ((u32::from(k) & 0xff) << 24) | ((u32::from(k) & 0xff00) << 8) | 0x8000;
            sys::sha256_transform(&idig, Some(&g), &mut h);
            sys::sha256_transform(&odig, None, &mut h);
            for (s, w) in sum.iter_mut().zip(h.iter()) {
                *s ^= w;
            }
        }
        h[..8].copy_from_slice(&sum);

        sys::sha256_transform(&idig, None, &mut h);
        sys::sha256_transform(&odig, None, &mut h);

        wipe(&mut odig);
        wipe(&mut idig);

        // Cache the authentication sum (as SHA-256 output bytes).
        for (i, word) in sum.iter().enumerate() {
            self.authentication_sum.borrow_mut()[4 * i..4 * i + 4]
                .copy_from_slice(&word.to_be_bytes());
        }

        // Check loop completion in case of a fault injection attack.
        if self.nc().get_next(&mut offset).is_some() {
            fault!(self, c"loop completion check");
        }

        // Check the storage authentication tag.
        let mut computed = [0u8; SHA256_DIGEST_LENGTH];
        for (i, word) in h[..8].iter().enumerate() {
            computed[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        let stored = tag.and_then(|t| self.nc().read_exact::<STORAGE_TAG_SIZE>(&t));
        match stored {
            Some(stored) if self.secequal(&computed[..STORAGE_TAG_SIZE], &stored) == SECTRUE => {}
            _ => fault!(self, c"storage tag check"),
        }

        if found.is_none() {
            // Check for fault injection.
            if other_count != entry_count {
                fault!(self, c"sanity check");
            }
            return None;
        }
        found
    }

    // ----------------------------------------------------------------------
    // Wipe code
    // ----------------------------------------------------------------------

    fn set_wipe_code(&self, wipe_code: &[u8]) -> Secbool {
        if wipe_code.len() > MAX_WIPE_CODE_LEN
            || wipe_code.len() > usize::from(u16::MAX) - WIPE_CODE_SALT_SIZE - WIPE_CODE_TAG_SIZE
        {
            return SECFALSE;
        }

        // An empty wipe code is stored as WIPE_CODE_EMPTY, so that it never
        // matches the empty PIN.
        let wipe_code = if wipe_code.is_empty() {
            &WIPE_CODE_EMPTY[..]
        } else {
            wipe_code
        };
        let len = wipe_code.len();

        // Format: wipe code, random salt (8 bytes), tag (8 bytes). There is
        // extra room for the full HMAC output.
        let mut data = [0u8; MAX_WIPE_CODE_LEN + WIPE_CODE_SALT_SIZE + SHA256_DIGEST_LENGTH];
        data[..len].copy_from_slice(wipe_code);
        let (head, tag) = data.split_at_mut(len + WIPE_CODE_SALT_SIZE);
        let salt = &mut head[len..];
        sys::rng_strong(salt);
        let tag: &mut [u8; SHA256_DIGEST_LENGTH] =
            match (&mut tag[..SHA256_DIGEST_LENGTH]).try_into() {
                Ok(tag) => tag,
                Err(_) => fault!(self, c"wipe code buffer"),
            };
        sys::hmac_sha256_into(salt, wipe_code, tag);

        let ret = secbool(self.nc().set(
            WIPE_CODE_DATA_KEY,
            &data[..len + WIPE_CODE_SALT_SIZE + WIPE_CODE_TAG_SIZE],
        ));

        wipe(&mut data);
        ret
    }

    /// Returns `SECTRUE` if `pin` is not the wipe code.
    fn is_not_wipe_code(&self, pin: &[u8]) -> Secbool {
        let mut salt = [0u8; WIPE_CODE_SALT_SIZE];
        let mut stored_tag = [0u8; WIPE_CODE_TAG_SIZE];
        let mut computed_tag1 = [0u8; SHA256_DIGEST_LENGTH];
        let mut computed_tag2 = [0u8; SHA256_DIGEST_LENGTH];

        // Read the wipe code data from the storage.
        let data = match self.get_value(WIPE_CODE_DATA_KEY) {
            Some(v) if usize::from(v.len) > WIPE_CODE_SALT_SIZE + WIPE_CODE_TAG_SIZE => v,
            _ => fault!(self, c"no wipe code"),
        };
        let wipe_code_len = u32::from(data.len) - (WIPE_CODE_SALT_SIZE + WIPE_CODE_TAG_SIZE) as u32;
        let salt_read = self.read_at(&data, wipe_code_len, &mut salt);
        let tag_read = self.read_at(
            &data,
            wipe_code_len + WIPE_CODE_SALT_SIZE as u32,
            &mut stored_tag,
        );
        if !salt_read || !tag_read {
            fault!(self, c"no wipe code");
        }

        // Check integrity in case of flash read manipulation attack.
        sys::hmac_sha256_stored(
            &self.nc(),
            &salt,
            &data,
            0,
            wipe_code_len,
            &mut computed_tag1,
        );
        if self.secequal(&stored_tag, &computed_tag1[..WIPE_CODE_TAG_SIZE]) != SECTRUE {
            fault!(self, c"wipe code tag");
        }

        // Prepare the authentication tag of the entered PIN.
        sys::wait_random_delay();
        sys::hmac_sha256_into(&salt, pin, &mut computed_tag1);

        // Recompute to check for fault injection attack.
        sys::wait_random_delay();
        sys::hmac_sha256_into(&salt, pin, &mut computed_tag2);
        wipe(&mut salt);
        if self.secequal(&computed_tag1, &computed_tag2) != SECTRUE {
            fault!(self, c"wipe code fault");
        }

        // Compare the wipe code with the entered PIN via the tag.
        sys::wait_random_delay();
        if self.secequal(&stored_tag, &computed_tag1[..WIPE_CODE_TAG_SIZE]) != SECFALSE {
            return SECFALSE;
        }
        wipe(&mut stored_tag);
        SECTRUE
    }

    fn ensure_not_wipe_code(&self, pin: &[u8]) {
        if self.is_not_wipe_code(pin) != SECTRUE {
            self.wipe();
            sys::wipe_code_screen();
        }
    }

    // ----------------------------------------------------------------------
    // Progress estimation
    // ----------------------------------------------------------------------

    fn ui_estimate_time_ms(&self, op: PinOp) -> u32 {
        let mut time_ms = 0;

        let mut pin_index = 0;
        if STRETCHED_PIN_COUNT > 1 && self.pin_get_fails(&mut pin_index) != SECTRUE {
            return 0;
        }

        #[allow(unused_mut, clippy::default_constructed_unit_structs)]
        let mut optiga_time = OptigaTime::default();
        #[cfg(feature = "optiga")]
        if !sys::optiga::read_sec(&mut optiga_time.sec) {
            return 0;
        }

        #[cfg(feature = "tropic")]
        sys::tropic::session_start_time(&mut time_ms);

        match op {
            PinOp::Set => self.set_pin_time(&mut time_ms, &mut optiga_time),
            PinOp::Verify => self.unlock_time(pin_index as u16, &mut time_ms, &mut optiga_time),
        }
        time_ms
    }

    fn ui_progress_init(&self, op: PinOp) {
        let total = self.ui_estimate_time_ms(op);
        UI.set_total(total);
        UI.set_next_update(0);
    }

    #[allow(unused_variables)]
    fn set_pin_time(&self, time_ms: &mut u32, optiga_time: &mut OptigaTime) {
        sys::rng_strong_time(time_ms); // rand_salt

        // From derive_kek_set()
        *time_ms = time_ms.wrapping_add(sys::pbkdf2_time_ms(sys::pin_iter_count()));
        #[cfg(feature = "optiga")]
        {
            sys::optiga::pin_init_time(time_ms);
            sys::optiga::pin_stretch_cmac_ecdh_time(time_ms, optiga_time);
        }
        #[cfg(feature = "tropic")]
        sys::tropic::pin_set_time(time_ms);
        #[cfg(feature = "optiga")]
        sys::optiga::pin_set_time(time_ms, optiga_time);
        #[cfg(feature = "tropic")]
        {
            sys::rng_strong_time(time_ms); // kek
            sys::tropic::pin_set_kek_masks_time(time_ms);
        }

        // The difference between the estimated and measured time on T3W1.
        *time_ms = time_ms.wrapping_add(sys::clock_cycles_ms(2_250_000));
    }

    #[allow(unused_variables)]
    fn unlock_time(&self, pin_index: u16, time_ms: &mut u32, optiga_time: &mut OptigaTime) {
        let mut fail_ctr = 0;
        let _ = self.pin_get_fails(&mut fail_ctr);
        *time_ms = time_ms.wrapping_add(get_backoff_time_ms(fail_ctr));

        *time_ms = time_ms.wrapping_add(sys::pbkdf2_time_ms(sys::pin_iter_count()));
        #[cfg(feature = "optiga")]
        sys::optiga::pin_stretch_cmac_ecdh_time(time_ms, optiga_time);
        #[cfg(feature = "tropic")]
        sys::tropic::pin_stretch_time(time_ms);
        #[cfg(feature = "optiga")]
        sys::optiga::pin_verify_time(pin_index as u8, time_ms, optiga_time);
        #[cfg(feature = "tropic")]
        sys::tropic::pin_unmask_kek_time(time_ms);

        // An upgrade from version 5 or earlier calls set_pin() in
        // storage_upgrade_unlocked().
        if sys::norcow_min_version() <= 5 && self.get_lock_version() <= 5 {
            self.set_pin_time(time_ms, optiga_time);
        }

        #[cfg(all(feature = "optiga", feature = "tropic"))]
        if pin_index != 0 {
            sys::optiga::pin_reset_hmac_counter_time(time_ms, optiga_time);
        }

        #[cfg(feature = "tropic")]
        sys::tropic::pin_reset_slots_time(time_ms, pin_index);

        // The difference between the estimated and measured time on T3W1.
        *time_ms = time_ms.wrapping_add(sys::clock_cycles_ms(13_500_000));
    }

    // ----------------------------------------------------------------------
    // Key derivation
    // ----------------------------------------------------------------------

    /// Concatenates the hardware salt, the storage salt and the optional
    /// external salt into `salt`. Returns the length.
    fn kdf_salt(
        &self,
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        salt: &mut [u8; KDF_SALT_SIZE],
    ) -> usize {
        let mut len = 0;
        salt[..HARDWARE_SALT_SIZE].copy_from_slice(&*self.hardware_salt.borrow());
        len += HARDWARE_SALT_SIZE;
        salt[len..len + STORAGE_SALT_SIZE].copy_from_slice(&storage_salt[..STORAGE_SALT_SIZE]);
        len += STORAGE_SALT_SIZE;
        if let Some(ext_salt) = ext_salt {
            salt[len..len + EXTERNAL_SALT_SIZE].copy_from_slice(ext_salt);
            len += EXTERNAL_SALT_SIZE;
        }
        len
    }

    /// Legacy KEK derivation used in storage versions 1 to 4 without Optiga.
    #[cfg(not(feature = "optiga"))]
    fn derive_kek_v4(
        &self,
        pin: &[u8],
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        kek: &mut [u8; SHA256_DIGEST_LENGTH],
        keiv: &mut [u8; SHA256_DIGEST_LENGTH],
    ) {
        let mut salt = [0u8; KDF_SALT_SIZE];
        let salt_len = self.kdf_salt(storage_salt, ext_salt, &mut salt);
        let iterations = sys::pin_iter_count() / 10;

        let mut ctx = Pbkdf2::empty();
        ctx.init(pin, &salt[..salt_len], 1);
        for _ in 1..=5 {
            ctx.update(iterations);
            ui_progress();
        }

        #[cfg(all(feature = "hwkey", not(feature = "emulator")))]
        {
            let mut pre_kek = [0u8; SHA256_DIGEST_LENGTH];
            ctx.finish(&mut pre_kek);
            ensure!(
                sys::hwkey::encrypt(&pre_kek, kek, false),
                c"secure_aes derive kek failed"
            );
            wipe(&mut pre_kek);
        }
        #[cfg(not(all(feature = "hwkey", not(feature = "emulator"))))]
        ctx.finish(kek);
        drop(ctx);

        let mut ctx = Pbkdf2::empty();
        ctx.init(pin, &salt[..salt_len], 2);
        for _ in 6..=10 {
            ctx.update(iterations);
            ui_progress();
        }
        ctx.finish(keiv);

        drop(ctx);
        wipe(&mut salt);
    }

    /// Stretches the PIN with PBKDF2 over the hardware, storage and external
    /// salts, then with the hardware key if there is one.
    #[allow(unused_variables)]
    fn mcu_pin_stretch(
        &self,
        pin: &[u8],
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        stretched_pin: &mut [u8; SHA256_DIGEST_LENGTH],
        privileged_bhk: Secbool,
    ) {
        let mut salt = [0u8; KDF_SALT_SIZE];
        let salt_len = self.kdf_salt(storage_salt, ext_salt, &mut salt);
        let mut ctx = Pbkdf2::empty();
        ctx.init(pin, &salt[..salt_len], 1);
        wipe(&mut salt);

        for _ in 1..=10 {
            ctx.update(sys::pin_iter_count() / 10);
            ui_progress();
        }

        #[cfg(all(feature = "hwkey", not(feature = "emulator")))]
        {
            let mut tmp = [0u8; SHA256_DIGEST_LENGTH];
            ctx.finish(&mut tmp);
            ensure!(
                sys::hwkey::encrypt(&tmp, stretched_pin, privileged_bhk == SECTRUE),
                c"secure_aes pin stretch failed"
            );
            wipe(&mut tmp);
        }
        #[cfg(not(all(feature = "hwkey", not(feature = "emulator"))))]
        ctx.finish(stretched_pin);
    }

    /// Legacy KEK derivation from the Optiga secret, storage versions 3, 4.
    #[cfg(feature = "optiga")]
    fn derive_kek_optiga_v4(
        optiga_secret: &[u8; sys::optiga::SECRET_SIZE],
        kek: &mut [u8; SHA256_DIGEST_LENGTH],
        keiv: &mut [u8; SHA256_DIGEST_LENGTH],
    ) {
        let mut ctx = Pbkdf2::empty();
        ctx.init(optiga_secret, &[], 1);
        ctx.update(1);
        ctx.finish(kek);
        drop(ctx);

        let mut ctx = Pbkdf2::empty();
        ctx.init(optiga_secret, &[], 2);
        ctx.update(1);
        ctx.finish(keiv);
    }

    /// Derives a new KEK for `pin` and configures the secure elements.
    fn derive_kek_set(
        &self,
        pin: &[u8],
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        kek: &mut [u8; SHA256_DIGEST_LENGTH],
    ) -> Secbool {
        let mut ret = SECFALSE;
        let mut stretched_pins = [[0u8; SHA256_DIGEST_LENGTH]; STRETCHED_PIN_COUNT];
        self.mcu_pin_stretch(pin, storage_salt, ext_salt, &mut stretched_pins[0], SECTRUE);
        #[cfg(feature = "tropic")]
        let mut tropic_reset_key = [0u8; sys::tropic::MAC_AND_DESTROY_SIZE];
        #[cfg(feature = "optiga")]
        let mut optiga_reset_key = [0u8; SHA256_DIGEST_LENGTH];

        'cleanup: {
            #[cfg(feature = "optiga")]
            {
                if !sys::optiga::pin_init(UI_PROGRESS) {
                    break 'cleanup;
                }
                if !sys::optiga::pin_stretch_cmac_ecdh(UI_PROGRESS, &mut stretched_pins[0]) {
                    break 'cleanup;
                }
            }
            let (first, rest) = stretched_pins.split_at_mut(1);
            for pin in rest {
                pin.copy_from_slice(&first[0]);
            }
            #[cfg(feature = "tropic")]
            {
                if !sys::tropic::pin_set(UI_PROGRESS, &mut stretched_pins, &mut tropic_reset_key) {
                    break 'cleanup;
                }
                if self.storage_set_encrypted(
                    TROPIC_MAC_AND_DESTROY_RESET_KEY,
                    Plain::Mem(&tropic_reset_key),
                ) != SECTRUE
                {
                    break 'cleanup;
                }
            }
            #[cfg(feature = "optiga")]
            {
                if !sys::optiga::pin_set(UI_PROGRESS, &mut stretched_pins, &mut optiga_reset_key) {
                    break 'cleanup;
                }
                #[cfg(feature = "tropic")]
                if self.storage_set_encrypted(OPTIGA_HMAC_RESET_KEY, Plain::Mem(&optiga_reset_key))
                    != SECTRUE
                {
                    break 'cleanup;
                }
            }
            #[cfg(feature = "tropic")]
            {
                sys::rng_strong(kek);
                if !sys::tropic::pin_set_kek_masks(UI_PROGRESS, kek, &stretched_pins) {
                    break 'cleanup;
                }
            }
            #[cfg(not(feature = "tropic"))]
            kek.copy_from_slice(&stretched_pins[0]);
            ret = SECTRUE;
        }

        #[cfg(feature = "tropic")]
        wipe(&mut tropic_reset_key);
        #[cfg(feature = "optiga")]
        wipe(&mut optiga_reset_key);
        wipe(&mut stretched_pins);
        ret
    }

    /// Legacy KEK derivation used to unlock storage versions 1 to 4.
    fn derive_kek_unlock_v4(
        &self,
        pin: &[u8],
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        kek: &mut [u8; SHA256_DIGEST_LENGTH],
        keiv: &mut [u8; SHA256_DIGEST_LENGTH],
    ) -> Secbool {
        #[cfg(feature = "optiga")]
        {
            use sys::optiga::{PIN_COUNTER_EXCEEDED, PIN_INVALID, PIN_SUCCESS, SECRET_SIZE};
            let mut optiga_secret = [0u8; SECRET_SIZE];
            let mut stretched_pin = [0u8; SECRET_SIZE];
            self.mcu_pin_stretch(pin, storage_salt, ext_salt, &mut stretched_pin, SECFALSE);
            let ret = sys::optiga::pin_verify_v4(UI_PROGRESS, &stretched_pin, &mut optiga_secret);
            wipe(&mut stretched_pin);
            if ret != PIN_SUCCESS {
                wipe(&mut optiga_secret);
                if ret == PIN_COUNTER_EXCEEDED {
                    // Unreachable: unlock() wipes before this happens.
                    self.wipe();
                    sys::pin_too_many_screen();
                }
                ensure!(ret == PIN_INVALID, c"optiga_pin_verify failed");
                return SECFALSE;
            }
            Self::derive_kek_optiga_v4(&optiga_secret, kek, keiv);
            wipe(&mut optiga_secret);
        }
        #[cfg(not(feature = "optiga"))]
        self.derive_kek_v4(pin, storage_salt, ext_salt, kek, keiv);
        SECTRUE
    }

    /// Derives the KEK for `pin` to unlock the storage.
    fn derive_kek_unlock(
        &self,
        pin: &[u8],
        storage_salt: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        stretched_pin: &mut [u8; SHA256_DIGEST_LENGTH],
        privileged_bhk: Secbool,
    ) -> Secbool {
        self.mcu_pin_stretch(pin, storage_salt, ext_salt, stretched_pin, privileged_bhk);
        #[allow(unused_mut, unused_variables)]
        let mut pin_index: u32 = 0;
        if STRETCHED_PIN_COUNT > 1 {
            let mut pin_fails = 0;
            ensure!(
                self.pin_get_fails(&mut pin_fails) == SECTRUE,
                c"pin_get_fails failed"
            );
            // The counter has already been incremented.
            pin_index = pin_fails.wrapping_sub(1);
        }
        #[cfg(feature = "optiga")]
        ensure!(
            sys::optiga::pin_stretch_cmac_ecdh(UI_PROGRESS, stretched_pin),
            c"optiga_pin_stretch_cmac_ecdh failed"
        );
        #[cfg(feature = "tropic")]
        ensure!(
            sys::tropic::pin_stretch(UI_PROGRESS, pin_index as u16, stretched_pin),
            c"tropic_pin_stretch failed"
        );
        #[cfg(feature = "optiga")]
        {
            use sys::optiga::{PIN_COUNTER_EXCEEDED, PIN_INVALID, PIN_SUCCESS};
            let ret = sys::optiga::pin_verify(UI_PROGRESS, pin_index as u8, stretched_pin);
            if ret != PIN_SUCCESS {
                wipe(stretched_pin);
                if ret == PIN_COUNTER_EXCEEDED {
                    // Unreachable: unlock() wipes before this happens.
                    self.wipe();
                    sys::pin_too_many_screen();
                }
                ensure!(ret == PIN_INVALID, c"optiga_pin_verify failed");
                return SECFALSE;
            }
        }
        #[cfg(feature = "tropic")]
        ensure!(
            sys::tropic::pin_unmask_kek_in_place(UI_PROGRESS, pin_index as u16, stretched_pin),
            c"tropic_pin_unmask_kek failed"
        );
        SECTRUE
    }

    /// Encrypts the cached keys with a KEK derived from the new PIN and
    /// stores them with a new PIN verification code.
    fn set_pin(&self, pin: &[u8], ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>) -> Secbool {
        const SS: usize = STORAGE_SALT_SIZE;
        // Random salt, encrypted keys, PIN verification code (the full tag).
        let mut buffer = [0u8; SS + KEYS_SIZE + CHACHA20POLY1305_TAG_SIZE];
        let mut kek = [0u8; SHA256_DIGEST_LENGTH];
        let keiv = [0u8; RFC7539_NONCE_SIZE];

        sys::rng_strong(&mut buffer[..SS]);
        let mut rand_salt = [0u8; SS];
        rand_salt.copy_from_slice(&buffer[..SS]);
        ensure!(
            self.derive_kek_set(pin, &rand_salt, ext_salt, &mut kek) == SECTRUE,
            c"derive_kek_set failed"
        );
        wipe(&mut rand_salt);
        let mut ctx = ChaCha::empty();
        ctx.init(&kek, &keiv);
        wipe(&mut kek);
        ctx.encrypt(&*self.cached_keys.borrow(), &mut buffer[SS..SS + KEYS_SIZE]);
        let mut pvc = [0u8; CHACHA20POLY1305_TAG_SIZE];
        ctx.finish(0, KEYS_SIZE, &mut pvc);
        drop(ctx);
        buffer[SS + KEYS_SIZE..].copy_from_slice(&pvc);
        wipe(&mut pvc);
        let mut ret = secbool(
            self.nc()
                .set(EDEK_PVC_KEY, &buffer[..SS + KEYS_SIZE + PVC_SIZE]),
        );
        wipe(&mut buffer);

        if ret == SECTRUE {
            let flag = if pin.is_empty() {
                TRUE_BYTE
            } else {
                FALSE_BYTE
            };
            ret = secbool(self.nc().set(PIN_NOT_SET_KEY, &[flag]));
        }
        ret
    }

    /// Decrypts the DEK and SAK with a KEK derived from `pin` and checks the
    /// PIN verification code.
    fn decrypt_dek(&self, pin: &[u8], ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>) -> Secbool {
        const SS: usize = STORAGE_SALT_SIZE;
        const LEN: usize = SS + KEYS_SIZE + PVC_SIZE;

        // Read the storage salt, EDEK, ESAK and PIN verification code entry.
        let entry = if self.initialized.get() != SECTRUE {
            None
        } else {
            self.nc().get(EDEK_PVC_KEY)
        };
        let mut buffer = match entry.and_then(|v| self.nc().read_exact::<LEN>(&v)) {
            Some(buffer) => buffer,
            None => fault!(self, c"no EDEK"),
        };
        let mut storage_salt = [0u8; SS];
        storage_salt.copy_from_slice(&buffer[..SS]);
        let mut pvc = [0u8; PVC_SIZE];
        pvc.copy_from_slice(&buffer[SS + KEYS_SIZE..]);

        // Derive the key encryption key and IV.
        let mut kek = [0u8; SHA256_DIGEST_LENGTH];
        let mut keiv = [0u8; SHA256_DIGEST_LENGTH];
        let lock_version = self.get_lock_version();
        let min_version = sys::norcow_min_version();
        if lock_version >= 6 {
            if self.derive_kek_unlock(pin, &storage_salt, ext_salt, &mut kek, SECTRUE) != SECTRUE {
                return SECFALSE;
            }
        } else if min_version <= 5 && lock_version == 5 {
            if self.derive_kek_unlock(pin, &storage_salt, ext_salt, &mut kek, SECFALSE) != SECTRUE {
                return SECFALSE;
            }
        } else if min_version <= 4 && lock_version <= 4 {
            if self.derive_kek_unlock_v4(pin, &storage_salt, ext_salt, &mut kek, &mut keiv)
                != SECTRUE
            {
                return SECFALSE;
            }
        } else {
            fault!(self, c"Unsupported lock version");
        }

        let mut keys = [0u8; KEYS_SIZE];
        let mut tag = [0u8; CHACHA20POLY1305_TAG_SIZE];

        // Decrypt the DEK and SAK and check the PIN verification code.
        let mut nonce = [0u8; RFC7539_NONCE_SIZE];
        nonce.copy_from_slice(&keiv[..RFC7539_NONCE_SIZE]);
        let mut ctx = ChaCha::empty();
        ctx.init(&kek, &nonce);
        wipe(&mut kek);
        wipe(&mut keiv);
        wipe(&mut nonce);
        ctx.decrypt(&buffer[SS..SS + KEYS_SIZE], &mut keys);
        ctx.finish(0, KEYS_SIZE, &mut tag);
        drop(ctx);
        wipe(&mut buffer);
        sys::wait_random_delay();
        let mut tag_pvc = [0u8; PVC_SIZE];
        tag_pvc.copy_from_slice(&tag[..PVC_SIZE]);
        if self.secequal32(&tag_pvc, &pvc) != SECTRUE {
            wipe(&mut keys);
            wipe(&mut tag);
            wipe(&mut tag_pvc);
            return SECFALSE;
        }
        *self.cached_keys.borrow_mut() = keys;
        wipe(&mut keys);
        wipe(&mut tag);
        wipe(&mut tag_pvc);
        SECTRUE
    }

    // ----------------------------------------------------------------------
    // Initialization, version checks
    // ----------------------------------------------------------------------

    /// Initializes VERSION_KEY, EDEK_PVC_KEY, PIN_NOT_SET_KEY and
    /// PIN_LOGS_KEY of freshly wiped storage, with an empty PIN.
    fn init_wiped_storage(&self) {
        if self.initialized.get() != SECTRUE {
            // The storage contents cannot be initialized before the hardware
            // salt is set.
            return;
        }

        sys::rng_strong(&mut *self.cached_keys.borrow_mut());
        self.unlocked.set(SECTRUE);
        let version = sys::norcow_version().to_ne_bytes();
        ensure!(self.auth_init() == SECTRUE, c"set_storage_auth_tag failed");
        ensure!(
            self.storage_set_encrypted(VERSION_KEY, Plain::Mem(&version)) == SECTRUE,
            c"set_storage_version failed"
        );
        ensure!(
            self.nc().set(UNAUTH_VERSION_KEY, &version),
            c"set_unauth_storage_version failed"
        );
        ensure!(
            self.nc()
                .set(STORAGE_UPGRADED_KEY, &FALSE_WORD.to_ne_bytes()),
            c"set_storage_not_upgraded failed"
        );
        ensure!(self.pin_logs_init(0) == SECTRUE, c"init_pin_logs failed");
        ensure!(
            self.set_wipe_code(&WIPE_CODE_EMPTY) == SECTRUE,
            c"set_wipe_code failed"
        );

        self.ui_progress_init(PinOp::Set);
        if UI.message() == msg::NO_MSG {
            UI.set_message(msg::STARTING_MSG);
        } else {
            UI.set_message(msg::PROCESSING_MSG);
        }
        ensure!(self.set_pin(&[], None) == SECTRUE, c"init_pin failed");
        ui_progress_finish();
    }

    /// Returns the storage version that was used to lock the storage.
    fn get_lock_version(&self) -> u32 {
        match self.get_exact::<4>(UNAUTH_VERSION_KEY) {
            Some(bytes) => u32::from_ne_bytes(bytes),
            None => fault!(self, c"no lock version"),
        }
    }

    fn check_storage_version(&self) -> Secbool {
        let mut version = [0u8; 4];
        let mut len = 0;
        if self.storage_get_encrypted(VERSION_KEY, Some(&mut version), &mut len) != SECTRUE
            || usize::from(len) != version.len()
        {
            fault!(self, c"storage version check");
        }
        let version = u32::from_ne_bytes(version);

        if version != self.get_lock_version() {
            fault!(self, c"storage version check");
        }

        let storage_upgraded = match self.get_exact::<4>(STORAGE_UPGRADED_KEY) {
            Some(bytes) => u32::from_ne_bytes(bytes),
            None => fault!(self, c"storage version check"),
        };

        if version > self.norcow_active_version.get() {
            // Attack: the storage was downgraded.
            self.wipe();
            fault!(self, c"storage version check");
        } else if version < self.norcow_active_version.get() {
            // The storage was upgraded.
            if storage_upgraded != TRUE_WORD {
                // Attack: the upgrade process was bypassed.
                self.wipe();
                fault!(self, c"storage version check");
            }
            let active = self.norcow_active_version.get().to_ne_bytes();
            self.nc()
                .set(STORAGE_UPGRADED_KEY, &FALSE_WORD.to_ne_bytes());
            self.storage_set_encrypted(VERSION_KEY, Plain::Mem(&active));
            self.nc().set(UNAUTH_VERSION_KEY, &active);
        } else if storage_upgraded != FALSE_WORD {
            // Standard operation, but the upgrade flag is set.
            // Attack: the upgrade process was launched when it shouldn't
            // have been.
            self.wipe();
            fault!(self, c"storage version check");
        }
        SECTRUE
    }

    // ----------------------------------------------------------------------
    // Unlocking
    // ----------------------------------------------------------------------

    fn unlock(&self, pin: &[u8], ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>) -> u32 {
        // In case of an upgrade from version 1 or 2, the PIN is encoded in
        // the old format.
        let mut legacy_pin = [0u8; 4];
        let legacy = sys::norcow_min_version() <= 2 && self.get_lock_version() <= 2;
        if legacy {
            legacy_pin = upgrade::pin_to_int(pin).to_ne_bytes();
        }
        let unlock_pin: &[u8] = if legacy { &legacy_pin } else { pin };

        // Now we can check for the wipe code.
        self.ensure_not_wipe_code(unlock_pin);

        // Get the PIN failure counter.
        let mut ctr = 0;
        if self.pin_get_fails(&mut ctr) != SECTRUE {
            wipe(&mut legacy_pin);
            return UNLOCK_PIN_GET_FAILS_FAILED;
        }

        // Wipe the storage if there were too many failures.
        sys::wait_random_delay();
        if ctr >= PIN_MAX_TRIES {
            self.wipe();
            sys::pin_too_many_screen();
            return UNLOCK_TOO_MANY_FAILS;
        }

        ui_progress();

        // Sleep before checking the PIN.
        let begin = sys::ticks_ms();
        while sys::ticks_ms().wrapping_sub(begin) < get_backoff_time_ms(ctr) {
            if ui_progress() == SECTRUE {
                wipe(&mut legacy_pin);
                return UNLOCK_UI_CANCELLED;
            }
            sys::delay_ms(100);
        }

        // Increase the PIN fail counter before checking the PIN. It is reset
        // if the PIN is correct.
        if self.storage_pin_fails_increase() != SECTRUE {
            return UNLOCK_INCREASE_FAILS_FAILED;
        }

        // Check that the PIN fail counter was incremented.
        let mut ctr_ck = 0;
        if self.pin_get_fails(&mut ctr_ck) != SECTRUE || ctr.wrapping_add(1) != ctr_ck {
            fault!(self, c"PIN counter increment");
        }

        // Check whether the entered PIN is correct.
        let unlock_pin: &[u8] = if legacy { &legacy_pin } else { pin };
        if self.decrypt_dek(unlock_pin, ext_salt) != SECTRUE {
            wipe(&mut legacy_pin);
            // Wipe the storage if there were too many failures.
            sys::wait_random_delay();
            if ctr.wrapping_add(1) >= PIN_MAX_TRIES {
                self.wipe();
                sys::pin_too_many_screen();
            }

            // Finish the countdown.
            while sys::ticks_ms().wrapping_sub(UI.begin()) < UI.total() {
                UI.set_message(msg::WRONG_PIN_MSG);
                if ui_progress() == SECTRUE {
                    return UNLOCK_UI_CANCELLED;
                }
                sys::delay_ms(100);
            }

            return UNLOCK_INCORRECT_PIN;
        }
        wipe(&mut legacy_pin);

        // Perform the upgrades that need the storage unlocked, and check that
        // the authenticated version matches the unauthenticated version and
        // the norcow version. This also initializes the authentication sum
        // through storage_get_encrypted() and auth_get().
        if self.storage_upgrade_unlocked(pin, ext_salt) != SECTRUE
            || self.check_storage_version() != SECTRUE
        {
            return UNLOCK_WRONG_STORAGE_VERSION;
        }

        self.unlocked.set(SECTRUE);

        #[cfg(all(feature = "optiga", feature = "tropic"))]
        if ctr != 0 {
            let mut reset_key = [0u8; SHA256_DIGEST_LENGTH];
            let mut len = 0;
            if self.storage_get_encrypted(OPTIGA_HMAC_RESET_KEY, Some(&mut reset_key), &mut len)
                != SECTRUE
                || usize::from(len) != SHA256_DIGEST_LENGTH
            {
                return UNLOCK_OPTIGA_GET_HMAC_RESET_KEY_FAILED;
            }
            if !sys::optiga::pin_reset_hmac_counter(UI_PROGRESS, &reset_key) {
                wipe(&mut reset_key);
                return UNLOCK_OPTIGA_HMAC_COUNTER_RESET_FAILED;
            }
            wipe(&mut reset_key);
        }

        #[cfg(feature = "tropic")]
        {
            let mut reset_key = [0u8; sys::tropic::MAC_AND_DESTROY_SIZE];
            let mut len = 0;
            if self.storage_get_encrypted(
                TROPIC_MAC_AND_DESTROY_RESET_KEY,
                Some(&mut reset_key),
                &mut len,
            ) != SECTRUE
                || usize::from(len) != reset_key.len()
            {
                return UNLOCK_GET_TROPIC_MAC_AND_DESTROY_RESET_KEY_FAILED;
            }
            if !sys::tropic::pin_reset_slots(UI_PROGRESS, ctr as u16, &reset_key) {
                wipe(&mut reset_key);
                return UNLOCK_TROPIC_RESET_SLOTS_FAILED;
            }
            wipe(&mut reset_key);
        }

        // Finally set the counter to 0 to indicate success.
        if self.pin_fails_reset() == SECTRUE {
            UNLOCK_OK
        } else {
            UNLOCK_PIN_RESET_FAILS_FAILED
        }
    }

    // ----------------------------------------------------------------------
    // Encrypted values
    // ----------------------------------------------------------------------

    /// Finds the encrypted value of `key` and sets `len` to its plaintext
    /// length. If `dest` is given and long enough, decrypts the value into
    /// it with the DEK.
    fn storage_get_encrypted(&self, key: u16, dest: Option<&mut [u8]>, len: &mut u16) -> Secbool {
        let stored = self.auth_get(key);
        *len = stored.map_or(0, |v| v.len);
        let Some(stored) = stored else {
            return SECFALSE;
        };

        if usize::from(*len) < ENCRYPTION_OVERHEAD {
            fault!(self, c"ciphertext length check");
        }
        *len -= ENCRYPTION_OVERHEAD as u16;

        let Some(dest) = dest else {
            return SECTRUE;
        };

        let max_len = dest.len();
        if usize::from(*len) > max_len {
            return SECFALSE;
        }
        let plen = usize::from(*len);

        let mut iv = [0u8; RFC7539_NONCE_SIZE];
        let mut tag_stored = [0u8; CHACHA20POLY1305_TAG_SIZE];
        let iv_read = self.read_at(&stored, 0, &mut iv);
        let tag_read = self.read_at(&stored, (RFC7539_NONCE_SIZE + plen) as u32, &mut tag_stored);
        if !iv_read || !tag_read {
            fault!(self, c"ciphertext read");
        }

        let mut tag_computed = [0u8; CHACHA20POLY1305_TAG_SIZE];
        let mut ctx = ChaCha::empty();
        self.chacha_init_dek(&mut ctx, &iv);
        ctx.auth(&key.to_ne_bytes());
        // Decrypt in blocks; the keystream continues across whole blocks.
        let mut chunk = [0u8; CHACHA20POLY1305_BLOCK_SIZE];
        let mut done = 0;
        while done < plen {
            let n = (plen - done).min(CHACHA20POLY1305_BLOCK_SIZE);
            if !self
                .nc()
                .read_at(&stored, (RFC7539_NONCE_SIZE + done) as u32, &mut chunk[..n])
            {
                fault!(self, c"ciphertext read");
            }
            ctx.decrypt(&chunk[..n], &mut dest[done..done + n]);
            done += n;
        }
        ctx.finish(2, plen, &mut tag_computed);
        drop(ctx);
        wipe(&mut chunk);

        // Verify the authentication tag.
        if self.secequal(&tag_computed, &tag_stored) != SECTRUE {
            wipe(dest);
            wipe(&mut tag_computed);
            fault!(self, c"authentication tag check");
        }

        wipe(&mut tag_computed);
        SECTRUE
    }

    /// Encrypts `plain` with the DEK and stores it under `key`.
    fn storage_set_encrypted(&self, key: u16, plain: Plain<'_>) -> Secbool {
        let len = match plain {
            Plain::Mem(data) => data.len(),
            Plain::Stored(value) => usize::from(value.len),
        };
        if len > usize::from(u16::MAX) - ENCRYPTION_OVERHEAD {
            return SECFALSE;
        }

        // Preallocate space on the flash storage.
        if self.auth_set(key, None, (ENCRYPTION_OVERHEAD + len) as u16) != SECTRUE {
            return SECFALSE;
        }

        // Write the IV to the flash.
        let mut buffer = [0u8; CHACHA20POLY1305_BLOCK_SIZE];
        sys::rng(&mut buffer[..RFC7539_NONCE_SIZE]);

        if !self.nc().update_bytes(key, &buffer[..RFC7539_NONCE_SIZE]) {
            return SECFALSE;
        }

        let mut nonce = [0u8; RFC7539_NONCE_SIZE];
        nonce.copy_from_slice(&buffer[..RFC7539_NONCE_SIZE]);
        let mut ctx = ChaCha::empty();
        self.chacha_init_dek(&mut ctx, &nonce);
        ctx.auth(&key.to_ne_bytes());

        // Encrypt all blocks except for the last one.
        let mut plain_chunk = [0u8; CHACHA20POLY1305_BLOCK_SIZE];
        let mut i = 0;
        while i + CHACHA20POLY1305_BLOCK_SIZE < len {
            self.read_plain(plain, i, &mut plain_chunk);
            ctx.encrypt(&plain_chunk, &mut buffer);
            if !self.nc().update_bytes(key, &buffer) {
                drop(ctx);
                wipe(&mut buffer);
                wipe(&mut plain_chunk);
                return SECFALSE;
            }
            i += CHACHA20POLY1305_BLOCK_SIZE;
        }

        // Encrypt the final block and compute the authentication tag.
        let rest = len - i;
        self.read_plain(plain, i, &mut plain_chunk[..rest]);
        ctx.encrypt(&plain_chunk[..rest], &mut buffer[..rest]);
        wipe(&mut plain_chunk);
        let mut ret = secbool(self.nc().update_bytes(key, &buffer[..rest]));
        if ret == SECTRUE {
            let mut tag = [0u8; CHACHA20POLY1305_TAG_SIZE];
            ctx.finish(2, len, &mut tag);
            ret = secbool(self.nc().update_bytes(key, &tag));
            wipe(&mut tag);
        }
        drop(ctx);
        wipe(&mut buffer);
        ret
    }

    fn read_plain(&self, plain: Plain<'_>, offset: usize, dst: &mut [u8]) {
        match plain {
            Plain::Mem(data) => dst.copy_from_slice(&data[offset..offset + dst.len()]),
            Plain::Stored(value) => {
                if !self.nc().read_at(&value, offset as u32, dst) {
                    fault!(self, c"plaintext read");
                }
            }
        }
    }

    // ----------------------------------------------------------------------
    // Public interface (storage.h)
    // ----------------------------------------------------------------------

    pub fn storage_init(&self, salt: &[u8]) {
        sys::check_config(
            PIN_MAX_TRIES,
            STRETCHED_PIN_COUNT as u32,
            STORAGE_SALT_SIZE as u32,
        );
        let mpu = Mpu::storage();

        self.initialized.set(SECFALSE);
        self.unlocked.set(SECFALSE);
        wipe(&mut *self.cached_keys.borrow_mut());
        self.norcow_active_version.set(self.nc().init());
        self.initialized.set(SECTRUE);

        *self.hardware_salt.borrow_mut() = sys::sha256(salt);

        if self.norcow_active_version.get() < sys::norcow_version()
            && self.storage_upgrade() != SECTRUE
        {
            self.wipe();
            ensure!(false, c"storage_upgrade failed");
        }

        // If there is no EDEK, generate a random DEK and SAK and store them.
        if self.nc().get(EDEK_PVC_KEY).is_none() {
            self.init_wiped_storage();
        }

        mpu.restore();
    }

    pub fn storage_pin_fails_increase(&self) -> Secbool {
        if self.initialized.get() != SECTRUE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = self.pin_fails_increase();
        mpu.restore();
        ret
    }

    pub fn storage_is_unlocked(&self) -> Secbool {
        if self.initialized.get() != SECTRUE {
            return SECFALSE;
        }
        self.unlocked.get()
    }

    pub fn storage_lock(&self) {
        self.unlocked.set(SECFALSE);
        wipe(&mut *self.cached_keys.borrow_mut());
        wipe(&mut *self.authentication_sum.borrow_mut());
    }

    pub fn storage_unlock(
        &self,
        pin: Option<&[u8]>,
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
    ) -> u32 {
        if self.initialized.get() != SECTRUE {
            return UNLOCK_NOT_INITIALIZED;
        }

        let Some(pin) = pin else {
            return UNLOCK_NO_PIN;
        };

        let mpu = Mpu::storage();

        self.ui_progress_init(PinOp::Verify);
        if pin.is_empty() {
            if UI.message() == msg::NO_MSG {
                UI.set_message(msg::STARTING_MSG);
            } else {
                UI.set_message(msg::PROCESSING_MSG);
            }
        } else {
            UI.set_message(msg::VERIFYING_PIN_MSG);
        }

        let ret = self.unlock(pin, ext_salt);
        mpu.restore();

        ui_progress_finish();
        ret
    }

    pub fn storage_has(&self, key: u16) -> Secbool {
        let mut len = None;
        self.storage_get(key, None, &mut len)
    }

    /// Finds the value of `key` and sets `len` to its length. If `dest` is
    /// given and long enough, copies (decrypts) the value into it. `len` is
    /// left `None` on the paths where C leaves its out-parameter alone.
    pub fn storage_get(&self, key: u16, dest: Option<&mut [u8]>, len: &mut Option<u16>) -> Secbool {
        let app = (key >> 8) as u8;
        // APP == 0 is reserved for PIN related values.
        if self.initialized.get() != SECTRUE || app == APP_STORAGE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret;

        // Public values are not encrypted and can be read while locked.
        if app & FLAG_PUBLIC != 0 {
            let stored = self.nc().get(key);
            *len = Some(stored.map_or(0, |v| v.len));
            ret = match (stored, dest) {
                (None, _) => SECFALSE,
                (Some(_), None) => SECTRUE,
                (Some(stored), Some(dest)) => {
                    if usize::from(stored.len) > dest.len() {
                        SECFALSE
                    } else {
                        let out = &mut dest[..usize::from(stored.len)];
                        secbool(self.nc().read_at(&stored, 0, out))
                    }
                }
            };
        } else if self.unlocked.get() != SECTRUE {
            ret = SECFALSE;
        } else {
            let mut plain_len = 0;
            ret = self.storage_get_encrypted(key, dest, &mut plain_len);
            *len = Some(plain_len);
        }

        mpu.restore();
        ret
    }

    /// `data` is `None` for a null pointer, which C passes on to norcow
    /// for public values: `norcow_set(key, NULL, 0)` reserves an empty item
    /// rather than overwriting the old one in place.
    pub fn storage_set(&self, key: u16, data: Option<&[u8]>) -> Secbool {
        let app = (key >> 8) as u8;

        // APP == 0 is reserved for PIN related values.
        if self.initialized.get() != SECTRUE || app == APP_STORAGE {
            return SECFALSE;
        }

        if self.unlocked.get() != SECTRUE && (app & FLAGS_WRITE) != FLAGS_WRITE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = match data {
            Some(data) if app & FLAG_PUBLIC != 0 => secbool(self.nc().set(key, data)),
            None if app & FLAG_PUBLIC != 0 => secbool(self.nc().allocate(key, 0)),
            // The value is not read when its length is 0.
            data => self.storage_set_encrypted(key, Plain::Mem(data.unwrap_or(&[]))),
        };
        mpu.restore();
        ret
    }

    pub fn storage_delete(&self, key: u16) -> Secbool {
        let app = (key >> 8) as u8;

        // APP == 0 is reserved for storage related values.
        if self.initialized.get() != SECTRUE || app == APP_STORAGE {
            return SECFALSE;
        }

        if self.unlocked.get() != SECTRUE && (app & FLAGS_WRITE) != FLAGS_WRITE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let mut ret = secbool(self.nc().delete(key));
        if ret == SECTRUE {
            ret = self.auth_update(key);
        }
        mpu.restore();
        ret
    }

    pub fn storage_set_counter(&self, key: u16, count: u32) -> Secbool {
        let app = (key >> 8) as u8;
        if app & FLAG_PUBLIC == 0 {
            return SECFALSE;
        }

        // APP == 0 is reserved for PIN related values.
        if self.initialized.get() != SECTRUE || app == APP_STORAGE {
            return SECFALSE;
        }

        if self.unlocked.get() != SECTRUE && (app & FLAGS_WRITE) != FLAGS_WRITE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = secbool(self.nc().set_counter(key, count));
        mpu.restore();
        ret
    }

    /// `count` is left `None` on the paths where C leaves its out-parameter
    /// alone.
    pub fn storage_next_counter(&self, key: u16, count: &mut Option<u32>) -> Secbool {
        let app = (key >> 8) as u8;
        if app & FLAG_PUBLIC == 0 {
            return SECFALSE;
        }

        // APP == 0 is reserved for PIN related values.
        if self.initialized.get() != SECTRUE || app == APP_STORAGE {
            return SECFALSE;
        }

        if self.unlocked.get() != SECTRUE && (app & FLAGS_WRITE) != FLAGS_WRITE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = secbool(self.nc().next_counter_opt(key, count));
        mpu.restore();
        ret
    }

    pub fn storage_has_pin(&self) -> Secbool {
        if self.initialized.get() != SECTRUE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = match self.get_value(PIN_NOT_SET_KEY) {
            None => SECFALSE,
            Some(v) if v.len == 0 => SECTRUE,
            Some(v) => {
                let mut flag = [0u8; 1];
                if self.read_at(&v, 0, &mut flag) && flag[0] == FALSE_BYTE {
                    SECTRUE
                } else {
                    SECFALSE
                }
            }
        };
        mpu.restore();
        ret
    }

    pub fn storage_get_pin_rem(&self) -> u32 {
        if self.initialized.get() != SECTRUE {
            return 0;
        }

        #[allow(unused_mut)]
        let mut rem_mcu = 0;
        let mpu = Mpu::storage();

        let mut ctr_mcu = 0;
        if self.pin_get_fails(&mut ctr_mcu) == SECTRUE {
            rem_mcu = PIN_MAX_TRIES.wrapping_sub(ctr_mcu);

            #[cfg(feature = "optiga")]
            {
                // Synchronize the counters in case they diverged.
                let mut rem_optiga = 0;
                let v4 = self.get_lock_version() < 5;
                ensure!(
                    sys::optiga::pin_get_rem(v4, &mut rem_optiga),
                    c"optiga_pin_get_rem failed"
                );

                while rem_mcu > rem_optiga {
                    self.storage_pin_fails_increase();
                    rem_mcu -= 1;
                }

                if rem_optiga > rem_mcu {
                    let v4 = self.get_lock_version() < 5;
                    ensure!(
                        sys::optiga::pin_decrease_rem(v4, rem_optiga - rem_mcu),
                        c"optiga_pin_decrease_rem failed"
                    );
                }
            }
        }

        mpu.restore();
        rem_mcu
    }

    pub fn storage_change_pin(
        &self,
        newpin: Option<&[u8]>,
        new_ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
    ) -> u32 {
        if self.initialized.get() != SECTRUE {
            return PIN_CHANGE_NOT_INITIALIZED;
        }

        let Some(newpin) = newpin else {
            return PIN_CHANGE_WRONG_ARGUMENT;
        };

        let mpu = Mpu::storage();

        self.ui_progress_init(PinOp::Set);
        UI.set_message(msg::PROCESSING_MSG);

        let ret = if self.storage_is_unlocked() != SECTRUE {
            PIN_CHANGE_STORAGE_LOCKED
        } else if self.is_not_wipe_code(newpin) != SECTRUE {
            // The new PIN must differ from the wipe code.
            PIN_CHANGE_WIPE_CODE
        } else if self.set_pin(newpin, new_ext_salt) == SECTRUE {
            PIN_CHANGE_OK
        } else {
            PIN_CHANGE_CANNOT_SET_PIN
        };

        mpu.restore();
        ui_progress_finish();
        ret
    }

    pub fn storage_ensure_not_wipe_code(&self, pin: &[u8]) {
        let mpu = Mpu::storage();
        // When unlocking during an upgrade from version 2 or lower, the PIN
        // is encoded in the old format.
        let mut legacy_pin = [0u8; 4];
        let legacy = sys::norcow_min_version() <= 2 && self.get_lock_version() <= 2;
        if legacy {
            legacy_pin = upgrade::pin_to_int(pin).to_ne_bytes();
        }
        let pin: &[u8] = if legacy { &legacy_pin } else { pin };

        self.ensure_not_wipe_code(pin);
        wipe(&mut legacy_pin);
        mpu.restore();
    }

    pub fn storage_has_wipe_code(&self) -> Secbool {
        if self.initialized.get() != SECTRUE || self.unlocked.get() != SECTRUE {
            return SECFALSE;
        }

        let mpu = Mpu::storage();
        let ret = self.is_not_wipe_code(&WIPE_CODE_EMPTY);
        mpu.restore();
        ret
    }

    pub fn storage_change_wipe_code(
        &self,
        pin: Option<&[u8]>,
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
        wipe_code: Option<&[u8]>,
    ) -> Secbool {
        let (Some(pin), Some(wipe_code)) = (pin, wipe_code) else {
            return SECFALSE;
        };
        if self.initialized.get() != SECTRUE || (!pin.is_empty() && pin == wipe_code) {
            return SECFALSE;
        }

        let mpu = Mpu::storage();

        self.ui_progress_init(PinOp::Verify);
        UI.set_message(if !pin.is_empty() && wipe_code.is_empty() {
            msg::VERIFYING_PIN_MSG
        } else {
            msg::PROCESSING_MSG
        });

        let ret = if self.unlock(pin, ext_salt) == UNLOCK_OK {
            self.set_wipe_code(wipe_code)
        } else {
            SECFALSE
        };

        mpu.restore();
        ui_progress_finish();
        ret
    }

    /// `storage_wipe()`.
    pub fn wipe(&self) {
        let mpu = Mpu::storage();
        self.nc().wipe();
        self.norcow_active_version.set(sys::norcow_version());
        wipe(&mut *self.authentication_sum.borrow_mut());
        wipe(&mut *self.cached_keys.borrow_mut());
        self.init_wiped_storage();
        mpu.restore();
    }
}

/// Whether `key` holds an encrypted value covered by the authentication tag.
fn is_protected(key: u16) -> Secbool {
    let app = (key >> 8) as u8;
    if (app & FLAG_PUBLIC) == 0 && app != APP_STORAGE {
        SECTRUE
    } else {
        SECFALSE
    }
}

/// `2 ^ fail_ctr - 1` seconds.
fn get_backoff_time_ms(fail_ctr: u32) -> u32 {
    1000u32.wrapping_mul(1u32.wrapping_shl(fail_ctr).wrapping_sub(1))
}
