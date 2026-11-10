//! NORCOW ("NOR Copy-On-Write") is the flash key-value store underneath the
//! storage.
//!
//! A Rust port of `storage/norcow.c` together with `norcow_bitwise.h` and
//! `norcow_blockwise.h`. The flash format is unchanged, byte for byte, and so
//! is the behavior of every operation of `storage/norcow.h`, including the
//! corner cases that existing devices may depend on (see the comments marked
//! "Same as C").
//!
//! * [`Norcow`] holds the sector bookkeeping and implements the operations
//!   that do not depend on the item layout. It addresses flash only through
//!   sector offsets, never through pointers.
//! * [`Layout`] implementations ([`Bitwise`], [`Blockwise`]) encode and
//!   decode items for the two kinds of flash the firmware runs on.
//!
//! # Flash format
//!
//! Each sector starts with the magic `NRC2` and the bitwise complement of the
//! norcow version, followed by items. Version 0 sectors start with the magic
//! `NRCW` and no version. An item is a 16-bit key, a 16-bit length and the
//! value; see the layout modules for details. Deleting an item overwrites it
//! with zeros, which reads back as key `0x0000`. Unwritten flash reads as key
//! `0xFFFF` and terminates the item list. When the write sector is full, the
//! live items are copied to the next sector ("compaction").

use core::ffi::CStr;

mod layout;

#[cfg(test)]
mod tests;

pub use layout::{Bitwise, Blockwise, Layout, LayoutParams};

/// Magic at the start of a sector, `NRC2` in little endian.
pub const NORCOW_MAGIC: u32 = 0x3243_524e;
/// Magic at the start of a version 0 sector, `NRCW` in little endian.
pub const NORCOW_MAGIC_V0: u32 = 0x5743_524e;

const MAGIC_LEN: u32 = 4;
const VERSION_LEN: u32 = 4;

/// Key that marks unwritten flash. It cannot be stored.
pub const KEY_FREE: u16 = 0xFFFF;
/// Key of a deleted item.
pub const KEY_DELETED: u16 = 0x0000;

const KEY_LEN: u32 = 2;
const LEN_LEN: u32 = 2;

/// Length of the sector header that is preserved across erasures. Only 0 is
/// supported; `storage_rs_glue.c` asserts that the C configuration agrees.
const HEADER_LEN: u32 = 0;

/// Flash memory and build configuration that NORCOW runs on.
///
/// Offsets are relative to the start of a norcow sector (a `flash_area_t` in
/// C). Methods that return `bool` report whether the flash driver succeeded;
/// NORCOW decides whether a failure is fatal.
pub trait Flash {
    /// Number of norcow sectors (`NORCOW_SECTOR_COUNT`).
    fn sector_count(&self) -> u8;
    /// Size of each norcow sector in bytes (`NORCOW_SECTOR_SIZE`).
    fn sector_size(&self) -> u32;
    /// Current norcow version (`NORCOW_VERSION`).
    fn norcow_version(&self) -> u32;
    /// Whether wiping may leave the inactive sectors alone. Only allowed in
    /// non-production builds with `STORAGE_INSECURE_TESTING_MODE`.
    fn skip_inactive_wipe(&self) -> bool {
        false
    }

    /// Whether `len` bytes at `offset` are addressable, with the semantics of
    /// `flash_area_get_address() != NULL`: `offset` must lie inside the
    /// sector even when `len` is 0.
    fn is_valid(&self, sector: u8, offset: u32, len: u32) -> bool;
    /// Copies `buf.len()` bytes at `offset` into `buf`. Returns `false`,
    /// leaving `buf` untouched, if the range is not valid.
    fn read(&self, sector: u8, offset: u32, buf: &mut [u8]) -> bool;

    fn erase(&mut self, sector: u8) -> bool;
    fn unlock(&mut self) -> bool;
    fn lock(&mut self) -> bool;
    /// Writes one flash block. `block` holds `FLASH_BLOCK_WORDS` words.
    fn write_block(&mut self, sector: u8, offset: u32, block: &[u32]) -> bool;

    /// Stops the device. Equivalent of a failed `ensure()` in C.
    fn fatal(&self, msg: Option<&'static CStr>) -> !;
}

/// Flash that can program single bytes and words (`FLASH_BIT_ACCESS`).
pub trait BitFlash: Flash {
    fn write_byte(&mut self, sector: u8, offset: u32, data: u8) -> bool;
    fn write_word(&mut self, sector: u8, offset: u32, data: u32) -> bool;
}

/// Memory that a value is copied from when it is written to flash.
///
/// Values are copied in small chunks right before each flash write, the same
/// way `norcow.c` reads its input byte by byte. This keeps working when the
/// source is itself in flash, which `storage.c` relies on during upgrades.
pub trait Source {
    /// Number of bytes available.
    fn size(&self) -> usize;
    /// Fills `dst` with the bytes at `offset`. Callers guarantee that
    /// `offset + dst.len() <= self.size()`.
    fn copy_to(&self, offset: usize, dst: &mut [u8]);
}

impl Source for &[u8] {
    fn size(&self) -> usize {
        self.len()
    }

    fn copy_to(&self, offset: usize, dst: &mut [u8]) {
        dst.copy_from_slice(&self[offset..offset + dst.len()]);
    }
}

/// Where the bytes of an item being written come from. Internal to the
/// [`Layout`] implementations.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Data<'a> {
    /// Reserve space only; the value is written later with
    /// [`Norcow::update_bytes`].
    Alloc,
    /// Memory outside of norcow's control.
    Source(&'a dyn Source),
    /// An item in another sector (compaction).
    Flash { sector: u8, offset: u32 },
}

/// One decoded item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub key: u16,
    /// Offset of the value within the sector.
    pub val_offset: u32,
    pub len: u16,
    /// Offset where the next item starts.
    pub(crate) next: u32,
}

/// Location of a stored value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value {
    pub sector: u8,
    pub offset: u32,
    pub len: u16,
}

/// The NORCOW store: sector bookkeeping plus layout-specific state.
pub struct Norcow<F, L> {
    flash: F,
    /// Sector that items are read from.
    active_sector: u8,
    /// Sector that items are written to. Differs from `active_sector` only
    /// while a storage upgrade is in progress.
    write_sector: u8,
    /// Norcow version of `active_sector`. See `init()` for a caveat.
    active_version: u32,
    /// Offset of the first free byte in `write_sector`.
    free_offset: u32,
    layout: L,
}

impl<F, L> Norcow<F, L> {
    /// Creates an uninitialized store. Call [`Norcow::init`] before use.
    pub const fn new(flash: F, layout: L) -> Self {
        Self {
            flash,
            active_sector: 0,
            write_sector: 0,
            active_version: 0,
            free_offset: 0,
            layout,
        }
    }

    pub fn flash(&self) -> &F {
        &self.flash
    }

    pub fn active_sector(&self) -> u8 {
        self.active_sector
    }

    pub fn active_version(&self) -> u32 {
        self.active_version
    }
}

impl<F: Flash, L: Layout<F>> Norcow<F, L> {
    // ----------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------

    /// `FLASH_ALIGN()`.
    pub(crate) const fn align(x: u32) -> u32 {
        let mask = L::BLOCK_SIZE - 1;
        (x + mask) & !mask
    }

    /// `FLASH_IS_ALIGNED()`.
    pub(crate) const fn is_aligned(x: u32) -> bool {
        x & (L::BLOCK_SIZE - 1) == 0
    }

    /// Offset where items start in a current-version sector.
    pub(crate) const fn storage_start() -> u32 {
        Self::align(HEADER_LEN + MAGIC_LEN + VERSION_LEN)
    }

    /// `ensure()`: stops the device unless `ok`.
    pub(crate) fn ensure(&self, ok: bool, msg: Option<&'static CStr>) {
        if !ok {
            self.flash.fatal(msg)
        }
    }

    pub(crate) fn unlock(&mut self) {
        let ok = self.flash.unlock();
        self.ensure(ok, None);
    }

    pub(crate) fn lock(&mut self) {
        let ok = self.flash.lock();
        self.ensure(ok, None);
    }

    pub(crate) fn write_block(&mut self, sector: u8, offset: u32, block: &[u32]) {
        let ok = self.flash.write_block(sector, offset, block);
        self.ensure(ok, None);
    }

    pub(crate) fn read_bytes<const N: usize>(&self, sector: u8, offset: u32) -> Option<[u8; N]> {
        let mut buf = [0u8; N];
        self.flash.read(sector, offset, &mut buf).then_some(buf)
    }

    pub(crate) fn read_u16(&self, sector: u8, offset: u32) -> Option<u16> {
        self.read_bytes(sector, offset).map(u16::from_ne_bytes)
    }

    pub(crate) fn read_u32(&self, sector: u8, offset: u32) -> Option<u32> {
        self.read_bytes(sector, offset).map(u32::from_ne_bytes)
    }

    /// Reads a word of an item that was already validated by `read_item()`.
    pub(crate) fn read_item_word(&self, sector: u8, offset: u32) -> u32 {
        match self.read_u32(sector, offset) {
            Some(word) => word,
            None => self.flash.fatal(None),
        }
    }

    /// Copies `dst.len()` bytes at `offset` of `data` into `dst`.
    fn fetch(&self, data: Data<'_>, offset: u32, dst: &mut [u8]) {
        match data {
            Data::Source(src) => src.copy_to(offset as usize, dst),
            Data::Flash {
                sector,
                offset: base,
            } => {
                let ok = self.flash.read(sector, base + offset, dst);
                self.ensure(ok, None);
            }
            Data::Alloc => self.flash.fatal(None),
        }
    }

    // ----------------------------------------------------------------------
    // Sector management
    // ----------------------------------------------------------------------

    /// Erases a sector, and writes the magic and version if `set_magic`.
    fn erase_sector(&mut self, sector: u8, set_magic: bool) {
        let ok = self.flash.erase(sector);
        self.ensure(ok, Some(c"erase failed"));

        if set_magic {
            let version = self.flash.norcow_version();
            self.unlock();
            if L::BLOCK_WORDS == 1 {
                self.write_block(sector, HEADER_LEN, &[NORCOW_MAGIC]);
                let ok = self
                    .flash
                    .write_block(sector, HEADER_LEN + MAGIC_LEN, &[!version]);
                self.ensure(ok, Some(c"set version failed"));
            } else {
                // Same as C: the rest of the block is zero.
                let mut block = [0u32; layout::MAX_BLOCK_WORDS];
                block[0] = NORCOW_MAGIC;
                block[1] = !version;
                let ok = self
                    .flash
                    .write_block(sector, HEADER_LEN, &block[..L::BLOCK_WORDS]);
                self.ensure(ok, Some(c"set magic and version failed"));
            }
            self.lock();
        }
    }

    /// Returns the offset where items start and the norcow version of a
    /// sector, or `None` if the sector has no valid magic.
    fn find_start_offset(&self, sector: u8) -> Option<(u32, u32)> {
        let head: [u8; 8] = self.read_bytes(sector, HEADER_LEN)?;
        let [m0, m1, m2, m3, v0, v1, v2, v3] = head;
        let magic = u32::from_ne_bytes([m0, m1, m2, m3]);
        let version = u32::from_ne_bytes([v0, v1, v2, v3]);
        if magic == NORCOW_MAGIC {
            Some((Self::storage_start(), !version))
        } else if magic == NORCOW_MAGIC_V0 {
            Some((HEADER_LEN + MAGIC_LEN, 0))
        } else {
            None
        }
    }

    /// Finds the last instance of `key` in a sector.
    pub(crate) fn find_item(&self, sector: u8, key: u16) -> Option<Item> {
        let (mut offset, _) = self.find_start_offset(sector)?;
        let mut found = None;
        // Same as C: `key` is compared against deleted items too.
        while let Some(item) = L::read_item(self, sector, offset) {
            if item.key == key {
                found = Some(item);
            }
            offset = item.next;
        }
        found
    }

    /// Returns the offset of the first byte after the last item of a sector.
    fn find_free_offset(&self, sector: u8) -> u32 {
        let Some((mut offset, _)) = self.find_start_offset(sector) else {
            // Same as C, which returns `secfalse` here.
            return 0;
        };
        while let Some(item) = L::read_item(self, sector, offset) {
            offset = item.next;
        }
        offset
    }

    /// Copies the live items of the active sector to the next sector and
    /// makes it the active sector.
    fn compact(&mut self) {
        let Some((mut offset_r, _)) = self.find_start_offset(self.active_sector) else {
            return;
        };

        let read_sector = self.active_sector;
        let write_sector = (read_sector + 1) % self.flash.sector_count();
        self.write_sector = write_sector;
        self.erase_sector(write_sector, true);
        let mut offset_w = Self::storage_start();

        while let Some(item) = L::read_item(self, read_sector, offset_r) {
            offset_r = item.next;
            if item.key == KEY_DELETED {
                continue;
            }
            let data = Data::Flash {
                sector: read_sector,
                offset: item.val_offset,
            };
            match L::write_item(self, write_sector, offset_w, item.key, data, item.len) {
                Some(pos) => offset_w = pos,
                None => self.flash.fatal(Some(c"compaction write failed")),
            }
        }

        self.erase_sector(read_sector, false);
        self.active_sector = write_sector;
        self.active_version = self.flash.norcow_version();
        self.free_offset = self.find_free_offset(write_sector);
    }

    // ----------------------------------------------------------------------
    // Public interface (storage/norcow.h)
    // ----------------------------------------------------------------------

    /// Finds the active sector and prepares the write sector. Returns the
    /// norcow version of the stored data, which is below the current version
    /// if `storage.c` has to upgrade it.
    pub fn init(&mut self) -> u32 {
        let mut found = false;
        let mut norcow_version = 0;
        self.active_sector = 0;

        // The active sector has a valid magic and the highest version.
        for sector in 0..self.flash.sector_count() {
            if let Some((_, version)) = self.find_start_offset(sector) {
                // Same as C: `active_version` ends up being the version of the
                // last sector with a valid magic, not necessarily the version
                // of the sector that is selected as active.
                self.active_version = version;
                if version >= norcow_version {
                    found = true;
                    self.active_sector = sector;
                    norcow_version = version;
                }
            }
        }

        let current = self.flash.norcow_version();
        if !found || norcow_version > current {
            // No valid sector or a downgrade.
            self.wipe();
            norcow_version = current;
        } else if norcow_version < current {
            // Prepare the write sector for the storage upgrade.
            self.write_sector = (self.active_sector + 1) % self.flash.sector_count();
            self.erase_sector(self.write_sector, true);
            self.free_offset = self.find_free_offset(self.write_sector);
        } else {
            self.write_sector = self.active_sector;
            self.free_offset = self.find_free_offset(self.write_sector);
        }
        norcow_version
    }

    /// Erases all sectors and starts over with an empty active sector.
    pub fn wipe(&mut self) {
        // Erase the active sector first, because it contains sensitive data.
        self.erase_sector(self.active_sector, true);

        if !self.flash.skip_inactive_wipe() {
            for sector in 0..self.flash.sector_count() {
                if sector != self.active_sector {
                    self.erase_sector(sector, false);
                }
            }
        }
        self.active_version = self.flash.norcow_version();
        self.write_sector = self.active_sector;
        self.free_offset = Self::storage_start();
    }

    /// Looks up the value of `key` in the active sector.
    pub fn get(&self, key: u16) -> Option<Value> {
        self.find_item(self.active_sector, key).map(|item| Value {
            sector: self.active_sector,
            offset: item.val_offset,
            len: item.len,
        })
    }

    /// Copies a value found by [`Norcow::get`] into `buf`, which must have
    /// room for `value.len` bytes. Returns the copied bytes.
    pub fn read_value<'b>(&self, value: &Value, buf: &'b mut [u8]) -> Option<&'b [u8]> {
        let out = buf.get_mut(..usize::from(value.len))?;
        self.flash
            .read(value.sector, value.offset, out)
            .then_some(&*out)
    }

    /// Returns the next live item of the active sector at or after `offset`
    /// and advances `offset` past it. Start with `offset == 0`.
    pub fn get_next(&self, offset: &mut u32) -> Option<Item> {
        let sector = self.active_sector;
        if *offset == 0 {
            *offset = self.find_start_offset(sector)?.0;
        }

        loop {
            let item = L::read_item(self, sector, *offset)?;
            *offset = item.next;

            if item.key == KEY_DELETED {
                continue;
            }

            if self.active_version != 0 {
                return Some(item);
            }

            // Version 0 did not delete overwritten items. Skip the item if a
            // newer instance of it follows.
            let mut offset_r = *offset;
            loop {
                match L::read_item(self, sector, offset_r) {
                    None => return Some(item),
                    Some(newer) if newer.key == item.key => break,
                    Some(other) => offset_r = other.next,
                }
            }
        }
    }

    /// Stores `data` under `key`. Equivalent of `norcow_set(key, val, len)`.
    pub fn set(&mut self, key: u16, data: &[u8]) -> bool {
        let Ok(len) = u16::try_from(data.len()) else {
            return false;
        };
        let mut found = false;
        self.set_ex(key, Some(&data), len, &mut found)
    }

    /// Reserves `len` bytes for `key` to be filled with
    /// [`Norcow::update_bytes`]. Equivalent of `norcow_set(key, NULL, len)`.
    pub fn allocate(&mut self, key: u16, len: u16) -> bool {
        let mut found = false;
        self.set_ex(key, None, len, &mut found)
    }

    /// Stores `len` bytes of `src` under `key`, or reserves `len` bytes if
    /// `src` is `None`. `found` is set to whether `key` existed before,
    /// unless `key` is invalid.
    pub fn set_ex(
        &mut self,
        key: u16,
        src: Option<&dyn Source>,
        len: u16,
        found: &mut bool,
    ) -> bool {
        let data = match src {
            // Misuse; C could not check this.
            Some(src) if src.size() < usize::from(len) => return false,
            Some(src) => Data::Source(src),
            None => Data::Alloc,
        };
        self.set_data(key, data, len, found)
    }

    fn set_data(&mut self, key: u16, data: Data<'_>, len: u16, found: &mut bool) -> bool {
        // Key 0xFFFF is used as a marker to indicate that the entry is not set.
        if key == KEY_FREE {
            return false;
        }

        let sector = self.write_sector;
        let old = self.find_item(sector, key);
        *found = old.is_some();

        if let Some(old) = old {
            // Try to update the entry in place if it already exists.
            if L::try_overwrite(self, sector, old.val_offset, old.len, data, len) {
                return true;
            }
            L::delete_item(self, sector, old.len, old.val_offset);
        }

        // Compact if there is not enough free space.
        if self.free_offset + Self::align(L::MAX_PREFIX_LEN + u32::from(len))
            > self.flash.sector_size()
        {
            self.compact();
        }

        let (sector, offset) = (self.write_sector, self.free_offset);
        match L::write_item(self, sector, offset, key, data, len) {
            Some(pos) => {
                self.free_offset = pos;
                true
            }
            None => false,
        }
    }

    /// Deletes `key` from the write sector.
    pub fn delete(&mut self, key: u16) -> bool {
        if key == KEY_FREE {
            return false;
        }
        let sector = self.write_sector;
        let Some(item) = self.find_item(sector, key) else {
            return false;
        };
        L::delete_item(self, sector, item.len, item.val_offset);
        true
    }

    /// Stores a counter: the count, followed by the layout's tally words,
    /// all ones.
    pub fn set_counter(&mut self, key: u16, count: u32) -> bool {
        let mut value = [0xFFu8; 4 * (1 + layout::MAX_COUNTER_TAIL_WORDS)];
        value[..4].copy_from_slice(&count.to_ne_bytes());
        self.set(key, &value[..4 * (1 + L::COUNTER_TAIL_WORDS)])
    }

    /// Increments a counter, creating it with value 0 if it does not exist.
    ///
    /// Same as C: `count` is written on some failures too.
    pub fn next_counter(&mut self, key: u16, count: &mut u32) -> bool {
        let mut written = None;
        let ret = L::next_counter(self, key, &mut written);
        if let Some(value) = written {
            *count = value;
        }
        ret
    }

    /// Like [`Norcow::next_counter`], but reports whether `count` was
    /// written (C writes it on some failures too).
    pub fn next_counter_opt(&mut self, key: u16, count: &mut Option<u32>) -> bool {
        L::next_counter(self, key, count)
    }

    /// Writes the next `data.len()` bytes of a value reserved with
    /// [`Norcow::allocate`].
    pub fn update_bytes(&mut self, key: u16, data: &[u8]) -> bool {
        let Ok(len) = u16::try_from(data.len()) else {
            return false;
        };
        L::update_bytes(self, key, Data::Source(&data), len)
    }

    /// Writes the next `src.size()` bytes of a value reserved with
    /// [`Norcow::allocate`].
    pub fn update_bytes_from(&mut self, key: u16, src: &dyn Source) -> bool {
        let Ok(len) = u16::try_from(src.size()) else {
            return false;
        };
        L::update_bytes(self, key, Data::Source(src), len)
    }

    /// Writes the next `len` bytes of a value reserved with
    /// [`Norcow::allocate`], copying them from `offset` within a stored value.
    /// Used by storage upgrades, which rewrite values in place.
    pub fn update_bytes_copy(&mut self, key: u16, value: &Value, offset: u32, len: u16) -> bool {
        if offset + u32::from(len) > u32::from(value.len) {
            return false;
        }
        let data = Data::Flash {
            sector: value.sector,
            offset: value.offset + offset,
        };
        L::update_bytes(self, key, data, len)
    }

    /// Stores a copy of a value found by [`Norcow::get`] or
    /// [`Norcow::get_next`] under `key`. Used by storage upgrades, which copy
    /// items from the old sector to the new one.
    pub fn set_copy(&mut self, key: u16, value: &Value) -> bool {
        let data = Data::Flash {
            sector: value.sector,
            offset: value.offset,
        };
        let mut found = false;
        self.set_data(key, data, value.len, &mut found)
    }

    /// Location of the value of an item returned by [`Norcow::get_next`].
    pub fn item_value(&self, item: &Item) -> Value {
        Value {
            sector: self.active_sector,
            offset: item.val_offset,
            len: item.len,
        }
    }

    /// Copies `buf.len()` bytes at `offset` within a stored value into `buf`.
    pub fn read_at(&self, value: &Value, offset: u32, buf: &mut [u8]) -> bool {
        match u32::try_from(buf.len()) {
            Ok(len) if offset + len <= u32::from(value.len) => {
                self.flash.read(value.sector, value.offset + offset, buf)
            }
            _ => false,
        }
    }

    /// Reads a stored value of exactly `N` bytes.
    pub fn read_exact<const N: usize>(&self, value: &Value) -> Option<[u8; N]> {
        let mut buf = [0u8; N];
        (usize::from(value.len) == N && self.read_at(value, 0, &mut buf)).then_some(buf)
    }

    /// Finishes a storage upgrade: drops the old sector.
    pub fn upgrade_finish(&mut self) -> bool {
        self.erase_sector(self.active_sector, false);
        self.active_sector = self.write_sector;
        self.active_version = self.flash.norcow_version();
        true
    }
}
