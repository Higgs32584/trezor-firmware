//! PIN failure counter, ported from `storage/pinlogs_bitwise.h` and
//! `storage/pinlogs_blockwise.h`. Both implement `pin_logs_init()`,
//! `pin_fails_reset()`, `pin_fails_increase()` and `pin_get_fails()` on
//! [`Storage`](super::Storage).

/// PIN logs for flash with bit access: a guard key, a success log and an
/// entry log. Each failure clears bits of the entry log, each success copies
/// the entry log to the success log, so the counter never needs an erase.
/// Guard bits interleaved with the data bits detect manipulation.
#[cfg(feature = "bitwise")]
mod bitwise {
    use super::super::{PIN_LOGS_KEY, PIN_MAX_TRIES, Storage, fault};
    use crate::norcow::Value;
    use crate::sys::{self, SECFALSE, SECTRUE, Secbool, Volatile};

    /// Values used in the guard key integrity check.
    const GUARD_KEY_MODULUS: u32 = 6311;
    const GUARD_KEY_REMAINDER: u32 = 15;

    const LOW_MASK: u32 = 0x5555_5555;

    /// The length of the guard key in words.
    const GUARD_KEY_WORDS: usize = 1;
    /// The length of the PIN entry log or the PIN success log in words.
    const PIN_LOG_WORDS: usize = 16;
    const LOG_WORDS: usize = GUARD_KEY_WORDS + 2 * PIN_LOG_WORDS;
    const LOG_BYTES: usize = 4 * LOG_WORDS;

    const SUCCESS_LOG: usize = GUARD_KEY_WORDS;
    const ENTRY_LOG: usize = GUARD_KEY_WORDS + PIN_LOG_WORDS;

    fn check_guard_key(guard_key: u32) -> Secbool {
        if guard_key % GUARD_KEY_MODULUS != GUARD_KEY_REMAINDER {
            return SECFALSE;
        }

        // Check that each byte of (guard_key & 0xAAAAAAAA) has exactly two
        // bits set.
        let mut count = (guard_key & 0x2222_2222).wrapping_add((guard_key >> 2) & 0x2222_2222);
        count = count.wrapping_add(count >> 4);
        if (count & 0x0e0e_0e0e) != 0x0404_0404 {
            return SECFALSE;
        }

        // Check that the guard_key does not contain a run of 5 (or more)
        // zeros or ones.
        let mut zero_runs = !guard_key;
        zero_runs &= zero_runs >> 2;
        zero_runs &= zero_runs >> 1;
        zero_runs &= zero_runs >> 1;

        let mut one_runs = guard_key;
        one_runs &= one_runs >> 2;
        one_runs &= one_runs >> 1;
        one_runs &= one_runs >> 1;

        if one_runs != 0 || zero_runs != 0 {
            return SECFALSE;
        }

        SECTRUE
    }

    fn generate_guard_key() -> u32 {
        loop {
            let guard_key = sys::random_uniform_below((u32::MAX / GUARD_KEY_MODULUS) + 1)
                .wrapping_mul(GUARD_KEY_MODULUS)
                .wrapping_add(GUARD_KEY_REMAINDER);
            if check_guard_key(guard_key) == SECTRUE {
                return guard_key;
            }
        }
    }

    fn to_bytes(logs: &[u32; LOG_WORDS]) -> [u8; LOG_BYTES] {
        let mut bytes = [0u8; LOG_BYTES];
        for (i, word) in logs.iter().enumerate() {
            bytes[4 * i..4 * i + 4].copy_from_slice(&word.to_ne_bytes());
        }
        bytes
    }

    impl Storage {
        /// Returns the guard mask and the guard bits of a guard key.
        fn expand_guard_key(&self, guard_key: u32) -> (u32, u32) {
            if check_guard_key(guard_key) != SECTRUE {
                fault!(self, c"guard key check");
            }
            let guard_mask = ((guard_key & LOW_MASK) << 1) | ((!guard_key) & LOW_MASK);
            let guard = (((guard_key & LOW_MASK) << 1) & guard_key)
                | (((!guard_key) & LOW_MASK) & (guard_key >> 1));
            (guard_mask, guard)
        }

        /// Finds the PIN logs, or `None` if they are missing or malformed.
        fn pin_logs(&self) -> Option<Value> {
            let value = self.nc().get(PIN_LOGS_KEY)?;
            (usize::from(value.len) == LOG_BYTES).then_some(value)
        }

        /// Reads one word of the PIN logs from flash. Like the C code, which
        /// reads the logs through a pointer to flash, every check reads the
        /// word again (fault-injection countermeasure).
        fn log_word(&self, logs: &Value, index: usize) -> u32 {
            let mut bytes = [0u8; 4];
            if !self.nc().read_at(logs, (4 * index) as u32, &mut bytes) {
                fault!(self, c"PIN logs read");
            }
            u32::from_ne_bytes(bytes)
        }

        /// Copies the PIN logs to memory, to be modified and written back.
        fn copy_pin_logs(&self, logs: &Value) -> [u32; LOG_WORDS] {
            let mut copy = [0u32; LOG_WORDS];
            for (i, word) in copy.iter_mut().enumerate() {
                *word = self.log_word(logs, i);
            }
            copy
        }

        pub(in crate::storage) fn pin_logs_init(&self, fails: u32) -> Secbool {
            if fails >= PIN_MAX_TRIES {
                return SECFALSE;
            }

            // Format: guard key (1 word), PIN success log (PIN_LOG_WORDS),
            // PIN entry log (PIN_LOG_WORDS).
            let mut logs = [0u32; LOG_WORDS];

            logs[0] = generate_guard_key();

            sys::wait_random_delay();
            let (guard_mask, guard) = self.expand_guard_key(logs[0]);

            let unused = guard | !guard_mask;
            for word in &mut logs[GUARD_KEY_WORDS..] {
                *word = unused;
            }

            // Set the first word of the PIN entry log to indicate the
            // requested number of fails.
            logs[ENTRY_LOG] = ((u32::MAX >> (2 * fails)) & !guard_mask) | guard;

            sys::secbool(self.nc().set(PIN_LOGS_KEY, &to_bytes(&logs)))
        }

        pub(in crate::storage) fn pin_fails_reset(&self) -> Secbool {
            let Some(logs) = self.pin_logs() else {
                return SECFALSE;
            };

            let mut new_logs = self.copy_pin_logs(&logs);
            let mut edited = SECFALSE;

            sys::wait_random_delay();
            let guard_key = self.log_word(&logs, 0);
            let (guard_mask, guard) = self.expand_guard_key(guard_key);

            let unused = guard | !guard_mask;
            for i in 0..PIN_LOG_WORDS {
                if self.log_word(&logs, ENTRY_LOG + i) == unused {
                    if edited == SECTRUE {
                        return sys::secbool(self.nc().set(PIN_LOGS_KEY, &to_bytes(&new_logs)));
                    }
                    return SECTRUE;
                }
                if self.log_word(&logs, SUCCESS_LOG + i) != guard {
                    let entry = self.log_word(&logs, ENTRY_LOG + i);
                    if new_logs[SUCCESS_LOG + i] != entry {
                        edited = SECTRUE;
                        new_logs[SUCCESS_LOG + i] = self.log_word(&logs, ENTRY_LOG + i);
                    }
                }
            }
            self.pin_logs_init(0)
        }

        pub(in crate::storage) fn pin_fails_increase(&self) -> Secbool {
            sys::wait_random_delay();
            let Some(logs) = self.pin_logs() else {
                fault!(self, c"no PIN logs");
            };

            let mut new_logs = self.copy_pin_logs(&logs);

            sys::wait_random_delay();
            let guard_key = self.log_word(&logs, 0);
            let (guard_mask, guard) = self.expand_guard_key(guard_key);

            for i in 0..PIN_LOG_WORDS {
                sys::wait_random_delay();
                if (self.log_word(&logs, ENTRY_LOG + i) & guard_mask) != guard {
                    fault!(self, c"guard bits check");
                }
                if self.log_word(&logs, ENTRY_LOG + i) != guard {
                    sys::wait_random_delay();
                    let mut word = self.log_word(&logs, ENTRY_LOG + i) & !guard_mask;
                    word = ((word >> 1) | word) & LOW_MASK;
                    word = (word >> 2) | (word >> 1);

                    sys::wait_random_delay();

                    new_logs[ENTRY_LOG + i] = (word & !guard_mask) | guard;
                    if !self.nc().set(PIN_LOGS_KEY, &to_bytes(&new_logs)) {
                        fault!(self, c"PIN logs update");
                    }
                    return SECTRUE;
                }
            }
            fault!(self, c"PIN log exhausted");
        }

        pub(in crate::storage) fn pin_get_fails(&self, ctr: &mut u32) -> Secbool {
            *ctr = PIN_MAX_TRIES;

            sys::wait_random_delay();
            let Some(logs) = self.pin_logs() else {
                fault!(self, c"no PIN logs");
            };

            sys::wait_random_delay();
            let guard_key = self.log_word(&logs, 0);
            let (guard_mask, guard) = self.expand_guard_key(guard_key);
            let unused = guard | !guard_mask;

            // Volatile like in C and read again at every use, so that the
            // checks below are not folded. The words are read from flash at
            // every use too.
            let mut current = Volatile::new(-1i32);
            let mut i = Volatile::new(0usize);
            while i.get() < PIN_LOG_WORDS {
                if (self.log_word(&logs, ENTRY_LOG + i.get()) & guard_mask) != guard
                    || (self.log_word(&logs, SUCCESS_LOG + i.get()) & guard_mask) != guard
                    || (self.log_word(&logs, ENTRY_LOG + i.get())
                        & self.log_word(&logs, SUCCESS_LOG + i.get()))
                        != self.log_word(&logs, ENTRY_LOG + i.get())
                {
                    fault!(self, c"PIN logs format check");
                }

                if current.get() == -1 {
                    if self.log_word(&logs, ENTRY_LOG + i.get()) != guard {
                        current.set(i.get() as i32);
                    }
                } else if self.log_word(&logs, ENTRY_LOG + i.get()) != unused {
                    fault!(self, c"PIN entry log format check");
                }
                i.set(i.get() + 1);
            }

            if current.get() < 0
                || current.get() >= PIN_LOG_WORDS as i32
                || i.get() != PIN_LOG_WORDS
            {
                fault!(self, c"PIN log exhausted");
            }

            // Strip the guard bits from the current entry word and duplicate
            // each data bit.
            sys::wait_random_delay();
            let mut word = self.log_word(&logs, ENTRY_LOG + current.get() as usize) & !guard_mask;
            word = ((word >> 1) | word) & LOW_MASK;
            word |= word << 1;
            // Verify that the entry word has the form 0*1*.
            if (word & word.wrapping_add(1)) != 0 {
                fault!(self, c"PIN entry log format check");
            }

            if current.get() == 0 {
                current.set(current.get() + 1);
            }

            // Count the set bits in the two current words of the success log.
            sys::wait_random_delay();
            let prev = current.get() as usize - 1;
            let fails_prev = (self.log_word(&logs, SUCCESS_LOG + prev)
                ^ self.log_word(&logs, ENTRY_LOG + prev))
            .count_ones();
            let cur = current.get() as usize;
            let fails_cur = (self.log_word(&logs, SUCCESS_LOG + cur)
                ^ self.log_word(&logs, ENTRY_LOG + cur))
            .count_ones();
            *ctr = fails_prev + fails_cur;
            SECTRUE
        }
    }
}

/// PIN logs for flash written in blocks: the counter in a redundant 2-bit
/// encoding, repeated in every half-word of one block.
#[cfg(all(feature = "blockwise", not(feature = "bitwise")))]
mod blockwise {
    use super::super::{PIN_LOGS_KEY, Storage, fault};
    use crate::norcow::{Blockwise, LayoutParams, Value};
    use crate::sys::{self, SECTRUE, Secbool};

    const PIN_LOG_HALFWORDS: usize = ((Blockwise::BLOCK_WORDS - 1) * 4) / 2;
    const LOG_BYTES: usize = 2 * PIN_LOG_HALFWORDS;

    fn expand_counter(c: u16) -> u16 {
        let mut c = ((c << 4) | c) & 0x0f0f;
        c = ((c << 2) | c) & 0x3333;
        c = ((c << 1) | c) & 0x5555;
        ((c << 1) | c) ^ 0xaaaa
    }

    impl Storage {
        /// Reads one half-word of the PIN logs from flash.
        fn log_half(&self, logs: &Value, index: usize) -> u16 {
            let mut bytes = [0u8; 2];
            if !self.nc().read_at(logs, (2 * index) as u32, &mut bytes) {
                fault!(self, c"PIN logs read");
            }
            u16::from_ne_bytes(bytes)
        }

        fn compress_counter(&self, c: u16) -> u16 {
            if ((c ^ (c << 1)) & 0xAAAA) != 0xAAAA {
                fault!(self, c"ill-formed counter");
            }
            let mut c = c & 0x5555;
            c = ((c >> 1) | c) & 0x3333;
            c = ((c >> 2) | c) & 0x0f0f;
            ((c >> 4) | c) & 0x00ff
        }

        pub(in crate::storage) fn pin_get_fails(&self, ctr: &mut u32) -> Secbool {
            sys::wait_random_delay();

            let logs = match self.get_value(PIN_LOGS_KEY) {
                Some(v) if usize::from(v.len) == LOG_BYTES => v,
                _ => fault!(self, c"no PIN logs"),
            };

            let first = self.log_half(&logs, 0);
            let c = self.compress_counter(first);

            let mut correct_bytes_cnt: u16 = 0;

            for i in 0..PIN_LOG_HALFWORDS {
                sys::wait_random_delay();
                // Read from flash at every iteration, like the C code.
                let half = self.log_half(&logs, i);
                correct_bytes_cnt += u16::from(self.compress_counter(half) == c);
                *ctr = u32::from(c);
            }

            if usize::from(correct_bytes_cnt) != PIN_LOG_HALFWORDS {
                fault!(self, c"PIN logs corrupted");
            }

            sys::secbool(usize::from(correct_bytes_cnt) == PIN_LOG_HALFWORDS)
        }

        pub(in crate::storage) fn pin_logs_init(&self, fails: u32) -> Secbool {
            sys::wait_random_delay();

            // Same as C: the count is truncated to 16 bits.
            let ctr = expand_counter(fails as u16);
            let mut logs = [0u8; LOG_BYTES];
            for i in 0..PIN_LOG_HALFWORDS {
                logs[2 * i..2 * i + 2].copy_from_slice(&ctr.to_ne_bytes());
            }

            if fails != u32::from(self.compress_counter(ctr)) {
                fault!(self, c"PIN logs increase failed");
            }

            sys::secbool(self.nc().set(PIN_LOGS_KEY, &logs))
        }

        pub(in crate::storage) fn pin_fails_reset(&self) -> Secbool {
            self.pin_logs_init(0)
        }

        pub(in crate::storage) fn pin_fails_increase(&self) -> Secbool {
            let mut fails = 0;

            if self.pin_get_fails(&mut fails) != SECTRUE {
                return sys::SECFALSE;
            }

            self.pin_logs_init(fails.wrapping_add(1))
        }
    }
}
