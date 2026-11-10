//! Item layouts, ported from `storage/norcow_bitwise.h` and
//! `storage/norcow_blockwise.h`.

use crate::{BitFlash, Data, Flash, Item, KEY_DELETED, KEY_FREE, KEY_LEN, LEN_LEN, Norcow};

/// Largest `FLASH_BLOCK_WORDS` of any layout.
pub(crate) const MAX_BLOCK_WORDS: usize = 4;
/// Largest `COUNTER_TAIL_WORDS` of any layout.
pub(crate) const MAX_COUNTER_TAIL_WORDS: usize = 2;

/// Size of the stack buffer that values are copied through.
const CHUNK: usize = 16;

/// Constants of an item layout.
pub trait LayoutParams {
    /// `FLASH_BLOCK_WORDS`: the smallest unit that flash is written in.
    const BLOCK_WORDS: usize;
    /// `FLASH_BLOCK_SIZE` in bytes.
    const BLOCK_SIZE: u32 = 4 * Self::BLOCK_WORDS as u32;
    /// `NORCOW_MAX_PREFIX_LEN`: largest overhead of an item.
    const MAX_PREFIX_LEN: u32;
    /// `COUNTER_TAIL_WORDS`: tally words that follow a counter.
    const COUNTER_TAIL_WORDS: usize;
}

/// Encoding of items in flash. Implemented by [`Bitwise`] and [`Blockwise`].
///
/// The methods are internal: use the methods of [`Norcow`].
pub trait Layout<F: Flash>: LayoutParams + Sized {
    /// Decodes the item at `offset`, or returns `None` at the end of the item
    /// list.
    #[doc(hidden)]
    fn read_item(n: &Norcow<F, Self>, sector: u8, offset: u32) -> Option<Item>;

    /// Writes an item at `offset` and returns the offset after it, or `None`
    /// if it does not fit.
    #[doc(hidden)]
    fn write_item(
        n: &mut Norcow<F, Self>,
        sector: u8,
        offset: u32,
        key: u16,
        data: Data<'_>,
        len: u16,
    ) -> Option<u32>;

    /// Overwrites an item with zeros.
    #[doc(hidden)]
    fn delete_item(n: &mut Norcow<F, Self>, sector: u8, len: u16, val_offset: u32);

    /// Tries to store a new value in place of the old one. Succeeds only if
    /// that needs no erasure (`flash_area_write_bytes()` in C).
    #[doc(hidden)]
    fn try_overwrite(
        n: &mut Norcow<F, Self>,
        sector: u8,
        val_offset: u32,
        dest_len: u16,
        data: Data<'_>,
        len: u16,
    ) -> bool;

    #[doc(hidden)]
    fn next_counter(n: &mut Norcow<F, Self>, key: u16, count: &mut u32) -> bool;

    #[doc(hidden)]
    fn update_bytes(n: &mut Norcow<F, Self>, key: u16, data: Data<'_>, len: u16) -> bool;
}

// --------------------------------------------------------------------------
// Bitwise layout
// --------------------------------------------------------------------------

/// Layout for flash that can clear single bits (STM32F4, emulator).
///
/// An item is a 32-bit prefix (`len << 16 | key`) followed by the value,
/// padded with zeros to a multiple of 4 bytes. Counters are followed by two
/// words of tally bits, so incrementing a counter only clears a bit.
#[derive(Default)]
pub struct Bitwise {
    /// Bytes of the value already written by `update_bytes()`.
    write_buffer_flashed: u16,
}

impl Bitwise {
    pub const fn new() -> Self {
        Self {
            write_buffer_flashed: 0,
        }
    }
}

impl LayoutParams for Bitwise {
    const BLOCK_WORDS: usize = 1;
    const MAX_PREFIX_LEN: u32 = KEY_LEN + LEN_LEN;
    const COUNTER_TAIL_WORDS: usize = 2;
}

impl<F: BitFlash> Norcow<F, Bitwise> {
    fn write_byte(&mut self, sector: u8, offset: u32, data: u8) {
        let ok = self.flash.write_byte(sector, offset, data);
        self.ensure(ok, None);
    }

    fn write_word(&mut self, sector: u8, offset: u32, data: u32) {
        let ok = self.flash.write_word(sector, offset, data);
        self.ensure(ok, None);
    }

    /// Writes `len` bytes of `data` byte by byte. The flash must be unlocked.
    fn copy_bytes(&mut self, sector: u8, offset: u32, data: Data<'_>, len: u16) {
        let len = u32::from(len);
        let mut done = 0;
        while done < len {
            let mut buf = [0u8; CHUNK];
            let chunk = &mut buf[..(len - done).min(CHUNK as u32) as usize];
            self.fetch(data, done, chunk);
            for &byte in chunk.iter() {
                self.write_byte(sector, offset + done, byte);
                done += 1;
            }
        }
    }

    /// Overwrites the word at `offset` within the value of `key`.
    fn update_word(&mut self, key: u16, offset: u32, value: u32) -> bool {
        let sector = self.write_sector;
        let Some(item) = self.find_item(sector, key) else {
            return false;
        };
        if !Self::is_aligned(offset) || offset >= u32::from(item.len) {
            return false;
        }
        self.unlock();
        self.write_word(sector, item.val_offset + offset, value);
        self.lock();
        true
    }
}

impl<F: BitFlash> Layout<F> for Bitwise {
    fn read_item(n: &Norcow<F, Self>, sector: u8, offset: u32) -> Option<Item> {
        let mut pos = offset;
        let key = n.read_u16(sector, pos)?;
        pos += KEY_LEN;
        if key == KEY_FREE {
            return None;
        }

        let len = n.read_u16(sector, pos)?;
        pos += LEN_LEN;

        if !n.flash.is_valid(sector, pos, u32::from(len)) {
            return None;
        }
        Some(Item {
            key,
            val_offset: pos,
            len,
            next: Norcow::<F, Self>::align(pos + u32::from(len)),
        })
    }

    fn write_item(
        n: &mut Norcow<F, Self>,
        sector: u8,
        offset: u32,
        key: u16,
        data: Data<'_>,
        len: u16,
    ) -> Option<u32> {
        if sector >= n.flash.sector_count() {
            return None;
        }
        if offset + Self::MAX_PREFIX_LEN + u32::from(len) > n.flash.sector_size() {
            return None;
        }

        let prefix = (u32::from(len) << 16) | u32::from(key);
        let mut offset = offset;

        n.unlock();

        n.write_word(sector, offset, prefix);
        offset += 4;

        if !matches!(data, Data::Alloc) {
            n.copy_bytes(sector, offset, data, len);
        }
        offset += u32::from(len);

        // Pad with zeros.
        while !Norcow::<F, Self>::is_aligned(offset) {
            n.write_byte(sector, offset, 0x00);
            offset += 1;
        }

        n.lock();
        Some(offset)
    }

    fn delete_item(n: &mut Norcow<F, Self>, sector: u8, len: u16, val_offset: u32) {
        let end = val_offset + u32::from(len);

        // Clear the key in the prefix to mark the item as deleted.
        n.unlock();
        n.write_word(sector, val_offset - 4, u32::from(len) << 16);
        n.lock();

        // Delete the value.
        n.unlock();
        let mut offset = val_offset;
        while offset < end {
            n.write_block(sector, offset, &[0]);
            offset += Self::BLOCK_SIZE;
        }
        n.lock();
    }

    fn try_overwrite(
        n: &mut Norcow<F, Self>,
        sector: u8,
        val_offset: u32,
        dest_len: u16,
        data: Data<'_>,
        len: u16,
    ) -> bool {
        if matches!(data, Data::Alloc) || dest_len != len {
            return false;
        }

        // Programming fails as soon as a bit would have to go from 0 to 1.
        // Same as C: the bytes written before the failure stay written.
        let len = u32::from(len);
        let mut updated = true;
        n.unlock();
        let mut done = 0;
        'write: while done < len {
            let mut buf = [0u8; CHUNK];
            let chunk = &mut buf[..(len - done).min(CHUNK as u32) as usize];
            n.fetch(data, done, chunk);
            for &byte in chunk.iter() {
                if !n.flash.write_byte(sector, val_offset + done, byte) {
                    updated = false;
                    break 'write;
                }
                done += 1;
            }
        }
        n.lock();
        updated
    }

    fn next_counter(n: &mut Norcow<F, Self>, key: u16, count: &mut u32) -> bool {
        let sector = n.active_sector;
        let Some(item) = n.find_item(sector, key) else {
            *count = 0;
            return n.set_counter(key, 0);
        };

        let len = u32::from(item.len);
        if len < 4 || len % 4 != 0 {
            return false;
        }
        let len_words = len / 4;
        let word = |i: u32| n.read_item_word(sector, item.val_offset + 4 * i);

        // The counter value is the first word plus the number of cleared bits
        // in the tally words that follow.
        let base = word(0);
        let mut i = 1;
        while i < len_words && word(i) == 0 {
            i += 1;
        }

        *count = base.wrapping_add(1).wrapping_add(32 * (i - 1));
        if *count < base {
            // Value overflow.
            return false;
        }

        if i < len_words {
            let tally = word(i);
            *count = count.wrapping_add((!tally).count_ones());
            if *count < base {
                // Value overflow.
                return false;
            }
            n.update_word(key, 4 * i, tally >> 1)
        } else {
            n.set_counter(key, *count)
        }
    }

    fn update_bytes(n: &mut Norcow<F, Self>, key: u16, data: Data<'_>, len: u16) -> bool {
        let sector = n.write_sector;
        let Some(item) = n.find_item(sector, key) else {
            return false;
        };

        let flashed = n.layout.write_buffer_flashed;
        if u32::from(flashed) + u32::from(len) > u32::from(item.len) {
            return false;
        }

        n.unlock();
        n.copy_bytes(sector, item.val_offset + u32::from(flashed), data, len);
        // Cannot overflow, the sum is at most `item.len`.
        let flashed = flashed + len;
        n.layout.write_buffer_flashed = if flashed >= item.len { 0 } else { flashed };
        n.lock();
        true
    }
}

// --------------------------------------------------------------------------
// Blockwise layout
// --------------------------------------------------------------------------

/// Bytes in a block of the blockwise layout.
const BLOCK: usize = 16;
/// Values up to this length share one block with their key and length.
const SMALL_ITEM_SIZE: u32 = BLOCK as u32 - LEN_LEN - KEY_LEN;
/// Marks a large item as valid. Deleting the item clears it.
const VALID_FLAG: u8 = 0xFF;
const VALID_FLAG_LEN: u32 = 1;

/// Layout for flash that is written in 16-byte blocks, each block only once
/// between erasures, except for overwriting it with zeros (STM32U5).
///
/// A small item (value of at most 12 bytes) is one block: key, length and
/// value, padded with zeros. A large item is a block with the key and length
/// (padded with zeros), followed by the value and a valid flag `0xFF`, padded
/// with `0xFF` to whole blocks. Counters have no tally words.
pub struct Blockwise {
    /// Data passed to `update_bytes()` that does not fill a block yet.
    buffer: [u8; BLOCK],
    /// Bytes used in `buffer`.
    filled: u16,
    /// Key of the item being written by `update_bytes()`.
    key: Option<u16>,
    /// Bytes of the value already written by `update_bytes()`.
    flashed: u16,
}

impl Blockwise {
    pub const fn new() -> Self {
        Self {
            buffer: [0; BLOCK],
            filled: 0,
            key: None,
            flashed: 0,
        }
    }
}

impl Default for Blockwise {
    fn default() -> Self {
        Self::new()
    }
}

impl LayoutParams for Blockwise {
    const BLOCK_WORDS: usize = 4;
    const MAX_PREFIX_LEN: u32 = BLOCK as u32 + VALID_FLAG_LEN;
    const COUNTER_TAIL_WORDS: usize = 0;
}

/// Reinterprets block bytes as words, as `memcpy()` into a `flash_block_t`.
fn to_words(bytes: &[u8; BLOCK]) -> [u32; 4] {
    let word = |i: usize| u32::from_ne_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    [word(0), word(4), word(8), word(12)]
}

impl<F: Flash> Layout<F> for Blockwise {
    fn read_item(n: &Norcow<F, Self>, sector: u8, offset: u32) -> Option<Item> {
        let mut pos = offset;
        let stored_key = n.read_u16(sector, pos)?;
        pos += KEY_LEN;

        let len = n.read_u16(sector, pos)?;
        let small = u32::from(len) <= SMALL_ITEM_SIZE;

        let key = if small {
            if stored_key == KEY_FREE {
                return None;
            }
            pos += LEN_LEN;
            stored_key
        } else {
            pos = offset + Self::BLOCK_SIZE;
            let [flag] = n.read_bytes::<1>(sector, pos + u32::from(len))?;
            if flag != VALID_FLAG {
                KEY_DELETED
            } else if stored_key == KEY_FREE {
                return None;
            } else {
                stored_key
            }
        };

        if !n.flash.is_valid(sector, pos, u32::from(len)) {
            return None;
        }
        let end = if small {
            pos + u32::from(len)
        } else {
            pos + u32::from(len) + VALID_FLAG_LEN
        };
        Some(Item {
            key,
            val_offset: pos,
            len,
            next: Norcow::<F, Self>::align(end),
        })
    }

    fn write_item(
        n: &mut Norcow<F, Self>,
        sector: u8,
        offset: u32,
        key: u16,
        data: Data<'_>,
        len: u16,
    ) -> Option<u32> {
        if sector >= n.flash.sector_count() {
            return None;
        }

        let header = (u32::from(len) << 16) | u32::from(key);
        let len32 = u32::from(len);

        if len32 <= SMALL_ITEM_SIZE {
            // The whole item fits into one block.
            if offset + Self::BLOCK_SIZE > n.flash.sector_size() {
                return None;
            }

            let mut bytes = [0u8; BLOCK];
            bytes[..4].copy_from_slice(&header.to_ne_bytes());
            // Same as C, except that C copies from NULL (undefined behavior)
            // when a small item is allocated without data. The value is left
            // zero here. `storage.c` never does that.
            if len > 0 && !matches!(data, Data::Alloc) {
                n.fetch(data, 0, &mut bytes[4..4 + usize::from(len)]);
            }

            n.unlock();
            n.write_block(sector, offset, &to_words(&bytes));
            n.lock();
            Some(offset + Self::BLOCK_SIZE)
        } else {
            if offset + Norcow::<F, Self>::align(Self::MAX_PREFIX_LEN + len32)
                > n.flash.sector_size()
            {
                return None;
            }

            n.unlock();

            // Header block: key and length, the rest zero.
            n.write_block(sector, offset, &[header, 0, 0, 0]);
            let mut offset = offset + Self::BLOCK_SIZE;
            let pos = Norcow::<F, Self>::align(offset + VALID_FLAG_LEN + len32);

            if !matches!(data, Data::Alloc) {
                // All blocks but the last one.
                let mut done = 0;
                let mut remaining = len32;
                while remaining + VALID_FLAG_LEN > Self::BLOCK_SIZE {
                    let mut bytes = [0u8; BLOCK];
                    n.fetch(data, done, &mut bytes);
                    n.write_block(sector, offset, &to_words(&bytes));
                    offset += Self::BLOCK_SIZE;
                    done += Self::BLOCK_SIZE;
                    remaining -= Self::BLOCK_SIZE;
                }
                // The last block, with the valid flag.
                let mut bytes = [0xFFu8; BLOCK];
                let remaining = remaining as usize;
                n.fetch(data, done, &mut bytes[..remaining]);
                bytes[remaining] = VALID_FLAG;
                n.write_block(sector, offset, &to_words(&bytes));
            }

            n.lock();
            Some(pos)
        }
    }

    fn delete_item(n: &mut Norcow<F, Self>, sector: u8, len: u16, val_offset: u32) {
        let len = u32::from(len);
        let (mut offset, end) = if len <= SMALL_ITEM_SIZE {
            // Delete the whole block, including key and length.
            (
                val_offset - (KEY_LEN + LEN_LEN),
                val_offset + SMALL_ITEM_SIZE,
            )
        } else {
            // Delete the value and the valid flag. The header block stays.
            (val_offset, val_offset + len + VALID_FLAG_LEN)
        };

        n.unlock();
        while offset < end {
            n.write_block(sector, offset, &[0; 4]);
            offset += Self::BLOCK_SIZE;
        }
        n.lock();
    }

    fn try_overwrite(
        n: &mut Norcow<F, Self>,
        sector: u8,
        val_offset: u32,
        dest_len: u16,
        data: Data<'_>,
        len: u16,
    ) -> bool {
        // Blocks cannot be reprogrammed, so this succeeds only if the stored
        // value is already equal.
        if matches!(data, Data::Alloc)
            || !n.flash.is_valid(sector, val_offset, u32::from(dest_len))
            || dest_len != len
        {
            return false;
        }

        let len = u32::from(len);
        let mut done = 0;
        while done < len {
            let size = (len - done).min(CHUNK as u32) as usize;
            let mut stored = [0u8; CHUNK];
            let mut new = [0u8; CHUNK];
            let ok = n.flash.read(sector, val_offset + done, &mut stored[..size]);
            n.ensure(ok, None);
            n.fetch(data, done, &mut new[..size]);
            if stored[..size] != new[..size] {
                return false;
            }
            done += size as u32;
        }
        true
    }

    fn next_counter(n: &mut Norcow<F, Self>, key: u16, count: &mut u32) -> bool {
        let sector = n.active_sector;
        let Some(item) = n.find_item(sector, key) else {
            *count = 0;
            return n.set_counter(key, 0);
        };

        if item.len != 4 {
            return false;
        }

        let stored = n.read_item_word(sector, item.val_offset);
        *count = stored.wrapping_add(1);
        if *count < stored {
            // Value overflow.
            return false;
        }
        n.set_counter(key, *count)
    }

    fn update_bytes(n: &mut Norcow<F, Self>, key: u16, data: Data<'_>, len: u16) -> bool {
        let sector = n.write_sector;
        let Some(item) = n.find_item(sector, key) else {
            return false;
        };
        let allocated = u32::from(item.len);

        if allocated <= SMALL_ITEM_SIZE {
            // Small items are not updated in place.
            return false;
        }

        match n.layout.key {
            // Another update is in progress.
            Some(other) if other != key => return false,
            Some(_) => {}
            None => {
                n.layout.buffer = [0xFF; BLOCK];
                n.layout.key = Some(key);
                n.layout.filled = 0;
                n.layout.flashed = 0;
            }
        }

        let st = &n.layout;
        if u32::from(st.flashed) + u32::from(st.filled) + u32::from(len) > allocated {
            return false;
        }

        let mut remaining = len;
        let mut done = 0u32;
        let mut flash_offset = item.val_offset + u32::from(n.layout.flashed);

        n.unlock();
        while remaining > 0 {
            let filled = usize::from(n.layout.filled);
            let count = usize::from(remaining).min(BLOCK - filled);
            let mut chunk = [0u8; BLOCK];
            n.fetch(data, done, &mut chunk[..count]);
            n.layout.buffer[filled..filled + count].copy_from_slice(&chunk[..count]);
            done += count as u32;
            // Both fit in u16: `count <= 16` and `count <= remaining`.
            n.layout.filled += count as u16;
            remaining -= count as u16;

            let filled = usize::from(n.layout.filled);
            let all_data_received =
                u32::from(n.layout.filled) + u32::from(n.layout.flashed) == allocated;
            let block_full = filled == BLOCK;

            if block_full || all_data_received {
                if !block_full {
                    // All data has been received, add the valid flag.
                    n.layout.buffer[filled] = VALID_FLAG;
                }

                let words = to_words(&n.layout.buffer);
                n.write_block(sector, flash_offset, &words);
                flash_offset += Self::BLOCK_SIZE;

                if block_full && all_data_received {
                    // The valid flag did not fit, write it in the next block.
                    let mut flag_block = [0xFFu8; BLOCK];
                    flag_block[0] = VALID_FLAG;
                    n.write_block(sector, flash_offset, &to_words(&flag_block));
                    flash_offset += Self::BLOCK_SIZE;
                }

                n.layout.filled = 0;
                // Same as C (uint16_t): wraps only when it is reset below.
                n.layout.flashed = n.layout.flashed.wrapping_add(BLOCK as u16);
                n.layout.buffer = [0xFF; BLOCK];

                if all_data_received {
                    n.layout.key = None;
                    n.layout.flashed = 0;
                }
            }
        }
        n.lock();
        true
    }
}
