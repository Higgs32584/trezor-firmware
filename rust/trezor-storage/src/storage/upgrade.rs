//! Upgrades from older storage versions, ported from `storage/storage.c`.
//!
//! - Version 0: plaintext norcow
//! - Version 1: encrypted norcow
//! - Version 2: adds 9 digit wipe code
//! - Version 3: adds variable length PIN and wipe code
//! - Version 4: changes data structure of encrypted data
//! - Version 5: unifies KEK derivation for non-Optiga and Optiga
//! - Version 6: changes BHK key from unprivileged to privileged
//!
//! `NORCOW_MIN_VERSION` is the oldest version a model can upgrade from. The C
//! code leaves out older upgrade paths at compile time; here they are skipped
//! at run time with the same conditions.

use super::{
    APP_STORAGE, CHACHA20POLY1305_TAG_SIZE, EXTERNAL_SALT_SIZE, FALSE_WORD, FLAG_PUBLIC, PinOp,
    Plain, RFC7539_NONCE_SIZE, STORAGE_UPGRADED_KEY, Storage, TRUE_WORD, UNAUTH_VERSION_KEY,
    V0_MAX_PIN_LEN, V0_PIN_EMPTY, V2_WIPE_CODE_EMPTY, VERSION_KEY, WIPE_CODE_DATA_KEY,
    WIPE_CODE_EMPTY, fault, msg,
};
use crate::ffi::{UI, ui_progress_finish};
use crate::norcow::Value;
use crate::sys::{self, SECFALSE, SECTRUE, Secbool, secbool, wipe};

const V0_PIN_KEY: u16 = 0x0000;
const V0_PIN_FAIL_KEY: u16 = 0x0001;

/// Legacy conversion of a PIN to the uint32 scheme used prior to storage
/// version 3.
pub(super) fn pin_to_int(pin: &[u8]) -> u32 {
    if pin.len() > V0_MAX_PIN_LEN {
        return 0;
    }

    let mut val: u32 = 1;
    for &digit in pin {
        if !digit.is_ascii_digit() {
            return 0;
        }
        val = val.wrapping_mul(10).wrapping_add(u32::from(digit - b'0'));
    }
    val
}

/// Legacy conversion of a PIN from the uint32 scheme used prior to storage
/// version 3. Returns the PIN length, 0 if `val` is not a valid PIN.
fn int_to_pin(mut val: u32, pin: &mut [u8; V0_MAX_PIN_LEN]) -> usize {
    let mut i = V0_MAX_PIN_LEN;
    while val > 9 {
        i -= 1;
        pin[i] = (val % 10) as u8 + b'0';
        val /= 10;
    }

    if val != 1 {
        return 0;
    }

    pin.copy_within(i.., 0);
    V0_MAX_PIN_LEN - i
}

/// Legacy conversion of a wipe code from the uint32 scheme used prior to
/// storage version 3. Writes the digits to the end of `buf` and returns where
/// they start, or `None` if `val` is not a valid wipe code.
fn int_to_wipe_code(mut val: u32, buf: &mut [u8; V0_MAX_PIN_LEN]) -> Option<usize> {
    let mut pos = V0_MAX_PIN_LEN;

    // The special representation of an empty wipe code.
    if val == V2_WIPE_CODE_EMPTY {
        return Some(pos);
    }

    if val == V0_PIN_EMPTY {
        return None;
    }

    // Convert a non-empty wipe code.
    while val != 1 {
        if pos == 0 {
            return None;
        }
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    Some(pos)
}

impl Storage {
    /// Reads the first word of a stored value. Same as C, which dereferences
    /// the value as a `uint32_t` without checking its length.
    fn read_word(&self, value: &Value) -> u32 {
        let word = Value { len: 4, ..*value };
        match self.nc().read_exact::<4>(&word) {
            Some(bytes) => u32::from_ne_bytes(bytes),
            None => 0,
        }
    }

    /// Reads the PIN fail counter in the version 0 format: the first
    /// non-zero word of PIN_FAIL_KEY, with one bit cleared per failure.
    fn v0_pin_get_fails(&self, ctr: &mut u32) -> Secbool {
        if let Some(value) = self.get_value(V0_PIN_FAIL_KEY) {
            for i in 0..u32::from(value.len) / 4 {
                let mut bytes = [0u8; 4];
                if !self.nc().read_at(&value, 4 * i, &mut bytes) {
                    break;
                }
                let word = u32::from_ne_bytes(bytes);
                if word != 0 {
                    *ctr = (!word).count_ones();
                    return SECTRUE;
                }
            }
        }

        // No PIN failures.
        *ctr = 0;
        SECTRUE
    }

    /// Upgrades the storage to the current version. Runs at
    /// initialization, before the storage is unlocked.
    pub(super) fn storage_upgrade(&self) -> Secbool {
        let min_version = sys::norcow_min_version();
        let active_version = self.norcow_active_version.get();

        if min_version == 0 && active_version == 0 {
            sys::rng_strong(&mut *self.cached_keys.borrow_mut());

            // Initialize the storage authentication tag.
            self.auth_init();

            // Set the new storage version number.
            let version = sys::norcow_version().to_ne_bytes();
            if self.storage_set_encrypted(VERSION_KEY, Plain::Mem(&version)) != SECTRUE {
                return SECFALSE;
            }

            // Set EDEK_PVC_KEY and PIN_NOT_SET_KEY.
            let mut pin = [0u8; V0_MAX_PIN_LEN];
            let mut pin_len = 0;
            if let Some(value) = self.get_value(V0_PIN_KEY) {
                let stored = self.read_word(&value);
                if stored != V0_PIN_EMPTY {
                    pin_len = int_to_pin(stored, &mut pin);
                }
            }

            self.ui_progress_init(PinOp::Set);
            UI.set_message(msg::PROCESSING_MSG);
            self.set_pin(&pin[..pin_len], None);
            ui_progress_finish();
            wipe(&mut pin);

            // Convert the PIN failure counter.
            let mut fails = 0;
            self.v0_pin_get_fails(&mut fails);
            self.pin_logs_init(fails);

            // Copy the remaining entries, encrypting the protected ones.
            let mut offset = 0;
            while let Some((item, value)) = self.next_item(&mut offset) {
                let key = item.key;
                if key == V0_PIN_KEY || key == V0_PIN_FAIL_KEY {
                    continue;
                }

                let ret = if ((key >> 8) as u8 & FLAG_PUBLIC) != 0 {
                    secbool(self.nc().set_copy(key, &value))
                } else {
                    self.storage_set_encrypted(key, Plain::Stored(value))
                };

                if ret != SECTRUE {
                    return SECFALSE;
                }
            }

            self.unlocked.set(SECFALSE);
            wipe(&mut *self.cached_keys.borrow_mut());
        } else if min_version < 4 && active_version < 4 {
            // Change the data structure of encrypted entries: the tag moves
            // from after the IV to the end.
            let mut offset = 0;
            while let Some((item, value)) = self.next_item(&mut offset) {
                let key = item.key;
                let app = (key >> 8) as u8;
                let ok = if (app & FLAG_PUBLIC) == 0 && (app != APP_STORAGE || key == VERSION_KEY) {
                    let iv_len = RFC7539_NONCE_SIZE as u16;
                    let tag_len = CHACHA20POLY1305_TAG_SIZE as u16;
                    // Same as C: the length wraps if the entry is too short,
                    // and then the update fails.
                    let ciphertext_len = item.len.wrapping_sub(iv_len + tag_len);
                    // One borrow for the whole sequence.
                    let mut norcow = self.nc();
                    norcow.allocate(key, item.len)
                        && norcow.update_bytes_copy(key, &value, 0, iv_len)
                        && norcow.update_bytes_copy(
                            key,
                            &value,
                            u32::from(iv_len + tag_len),
                            ciphertext_len,
                        )
                        && norcow.update_bytes_copy(key, &value, u32::from(iv_len), tag_len)
                } else {
                    self.nc().set_copy(key, &value)
                };
                if !ok {
                    return SECFALSE;
                }
            }
        } else {
            // Copy all entries.
            let mut offset = 0;
            while let Some((item, value)) = self.next_item(&mut offset) {
                if !self.nc().set_copy(item.key, &value) {
                    return SECFALSE;
                }
            }
        }

        // Set the wipe code.
        if min_version <= 1
            && active_version <= 1
            && self.set_wipe_code(&WIPE_CODE_EMPTY) != SECTRUE
        {
            return SECFALSE;
        }

        if min_version <= 2 && active_version <= 2 {
            // Set UNAUTH_VERSION_KEY, so that it matches VERSION_KEY.
            let mut version: u32 = 1;

            // The storage may have gone through an upgrade to version 2
            // without having been unlocked. STORAGE_UPGRADED_KEY tells.
            if self.get_exact::<4>(STORAGE_UPGRADED_KEY) == Some(FALSE_WORD.to_ne_bytes()) {
                version = 2;
            }

            // Version 0 upgrades directly to the latest.
            if active_version == 0 {
                version = sys::norcow_version();
            }

            if !self.nc().set(UNAUTH_VERSION_KEY, &version.to_ne_bytes()) {
                return SECFALSE;
            }
        }

        if min_version == 0 && active_version == 0 {
            // Version 0 upgrades directly to the latest.
            self.nc()
                .set(STORAGE_UPGRADED_KEY, &FALSE_WORD.to_ne_bytes());
        } else {
            self.nc()
                .set(STORAGE_UPGRADED_KEY, &TRUE_WORD.to_ne_bytes());
        }

        self.norcow_active_version.set(sys::norcow_version());
        secbool(self.nc().upgrade_finish())
    }

    /// Upgrades that need the PIN, run when the storage is unlocked.
    pub(super) fn storage_upgrade_unlocked(
        &self,
        pin: &[u8],
        ext_salt: Option<&[u8; EXTERNAL_SALT_SIZE]>,
    ) -> Secbool {
        let mut version = [0u8; 4];
        let mut len = 0;
        if self.storage_get_encrypted(VERSION_KEY, Some(&mut version), &mut len) != SECTRUE
            || usize::from(len) != version.len()
        {
            fault!(self, c"storage version check");
        }
        let version = u32::from_ne_bytes(version);
        let min_version = sys::norcow_min_version();

        let mut ret = SECTRUE;
        if min_version <= 5 && version <= 5 {
            // Upgrade EDEK_PVC_KEY from:
            // - version 1 or 2 (uint32 PIN scheme)
            // - version 3 or 4 (variable-length PIN scheme)
            // - version 5 (unified PIN scheme with unprivileged BHK)
            // to the unified PIN scheme with privileged BHK.
            if self.set_pin(pin, ext_salt) != SECTRUE {
                return SECFALSE;
            }
        }

        if min_version <= 2 && version == 2 {
            // Upgrade WIPE_CODE_DATA_KEY from the old uint32 scheme to the
            // variable-length scheme.
            let stored = match self.get_value(WIPE_CODE_DATA_KEY) {
                Some(value) if value.len >= 4 => self.read_word(&value),
                _ => fault!(self, c"no wipe code"),
            };

            let mut buf = [0u8; V0_MAX_PIN_LEN];
            let Some(start) = int_to_wipe_code(stored, &mut buf) else {
                fault!(self, c"invalid wipe code");
            };

            ret = self.set_wipe_code(&buf[start..]);
            wipe(&mut buf);
        }

        ret
    }
}
