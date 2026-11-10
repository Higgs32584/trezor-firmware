//! Host tests on an in-memory flash.
//!
//! `RamFlash` enforces the programming rules of the flash simulator in
//! `storage/tests/c/flash.c`: bits only go from 1 to 0, writes are aligned to
//! their size, and a block can only be written if it is erased, if it becomes
//! all zeros, or if it does not change. It also checks that writes only
//! happen while the flash is unlocked.
//!
//! The byte-exact compatibility with the C implementation and the Python
//! model is checked by the storage test suite (`storage/tests`), which runs
//! against this crate when built with `NORCOW_IMPL=rust`.

use std::ffi::CStr;

use crate::*;

const SECTOR_SIZE: u32 = 0x10000;
const VERSION: u32 = 6;

#[derive(Clone)]
struct RamFlash {
    sectors: Vec<Vec<u8>>,
    block_words: usize,
    version: u32,
    unlocked: bool,
}

impl RamFlash {
    fn new(block_words: usize) -> Self {
        Self {
            sectors: vec![vec![0xFF; SECTOR_SIZE as usize]; 2],
            block_words,
            version: VERSION,
            unlocked: false,
        }
    }

    fn program(&mut self, sector: u8, offset: u32, data: &[u8]) -> bool {
        assert!(self.unlocked, "write to locked flash");
        // Sizes are 1, 4 or 16 bytes.
        if offset as usize & (data.len() - 1) != 0 {
            return false;
        }
        let start = offset as usize;
        let Some(flash) = self.sectors[sector as usize].get_mut(start..start + data.len()) else {
            return false;
        };
        if data.iter().zip(flash.iter()).any(|(&d, &f)| d & !f != 0) {
            return false;
        }
        flash.copy_from_slice(data);
        true
    }

    fn bytes(&self, sector: u8, offset: u32, len: usize) -> &[u8] {
        &self.sectors[sector as usize][offset as usize..offset as usize + len]
    }
}

impl Flash for RamFlash {
    fn sector_count(&self) -> u8 {
        self.sectors.len() as u8
    }

    fn sector_size(&self) -> u32 {
        SECTOR_SIZE
    }

    fn norcow_version(&self) -> u32 {
        self.version
    }

    fn is_valid(&self, sector: u8, offset: u32, len: u32) -> bool {
        sector < self.sector_count() && offset < SECTOR_SIZE && len <= SECTOR_SIZE - offset
    }

    fn read(&self, sector: u8, offset: u32, buf: &mut [u8]) -> bool {
        if !self.is_valid(sector, offset, buf.len() as u32) {
            return false;
        }
        buf.copy_from_slice(self.bytes(sector, offset, buf.len()));
        true
    }

    fn erase(&mut self, sector: u8) -> bool {
        self.sectors[sector as usize].fill(0xFF);
        true
    }

    fn unlock(&mut self) -> bool {
        assert!(!self.unlocked, "flash unlocked twice");
        self.unlocked = true;
        true
    }

    fn lock(&mut self) -> bool {
        assert!(self.unlocked, "flash locked twice");
        self.unlocked = false;
        true
    }

    fn write_block(&mut self, sector: u8, offset: u32, block: &[u32]) -> bool {
        assert_eq!(block.len(), self.block_words);
        let new: Vec<u8> = block.iter().flat_map(|w| w.to_ne_bytes()).collect();
        if self.block_words > 1 {
            if !self.is_valid(sector, offset, new.len() as u32) {
                return false;
            }
            let old = self.bytes(sector, offset, new.len());
            let old_all_ff = old.iter().all(|&b| b == 0xFF);
            let new_all_00 = new.iter().all(|&b| b == 0x00);
            if !(old_all_ff || new_all_00 || old == new.as_slice()) {
                return false;
            }
        }
        self.program(sector, offset, &new)
    }

    fn fatal(&self, msg: Option<&'static CStr>) -> ! {
        panic!("fatal error: {msg:?}")
    }
}

impl BitFlash for RamFlash {
    fn write_byte(&mut self, sector: u8, offset: u32, data: u8) -> bool {
        self.program(sector, offset, &[data])
    }

    fn write_word(&mut self, sector: u8, offset: u32, data: u32) -> bool {
        self.program(sector, offset, &data.to_ne_bytes())
    }
}

trait TestLayout: Layout<RamFlash> + Default {}
impl<L: Layout<RamFlash> + Default> TestLayout for L {}

fn fresh<L: TestLayout>() -> Norcow<RamFlash, L> {
    let mut n = Norcow::new(RamFlash::new(L::BLOCK_WORDS), L::default());
    assert_eq!(n.init(), VERSION);
    n
}

/// Reopens the store on the same flash, as after a reboot.
fn reopen<L: TestLayout>(n: &Norcow<RamFlash, L>) -> Norcow<RamFlash, L> {
    let mut reopened = Norcow::new(n.flash().clone(), L::default());
    assert_eq!(reopened.init(), n.flash().version);
    reopened
}

fn get_vec<L: TestLayout>(n: &Norcow<RamFlash, L>, key: u16) -> Option<Vec<u8>> {
    let value = n.get(key)?;
    let mut buf = vec![0; usize::from(value.len)];
    Some(n.read_value(&value, &mut buf).unwrap().to_vec())
}

fn items<L: TestLayout>(n: &Norcow<RamFlash, L>) -> Vec<(u16, Vec<u8>)> {
    let mut offset = 0;
    let mut out = Vec::new();
    while let Some(item) = n.get_next(&mut offset) {
        let value = Value {
            sector: n.active_sector(),
            offset: item.val_offset,
            len: item.len,
        };
        let mut buf = vec![0; usize::from(item.len)];
        n.read_value(&value, &mut buf).unwrap();
        out.push((item.key, buf));
    }
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

const LENGTHS: &[usize] = &[
    0, 1, 2, 3, 4, 5, 11, 12, 13, 14, 15, 16, 17, 18, 31, 32, 33, 100, 1000, 4000,
];

// --------------------------------------------------------------------------
// Tests for both layouts
// --------------------------------------------------------------------------

macro_rules! both_layouts {
    ($($name:ident),* $(,)?) => {
        mod bitwise {
            $( #[test] fn $name() { super::$name::<crate::Bitwise>(); } )*
        }
        mod blockwise {
            $( #[test] fn $name() { super::$name::<crate::Blockwise>(); } )*
        }
    };
}

both_layouts!(
    fresh_flash_is_wiped,
    set_get_roundtrip,
    same_value_is_kept_in_place,
    changed_value_replaces_item,
    delete_removes_item,
    free_key_is_rejected,
    compaction_keeps_latest_values,
    counters_increment,
    counter_overflow_fails,
    update_bytes_fills_allocated_value,
    update_bytes_rejects_overflow,
    get_next_skips_deleted,
    downgrade_wipes,
    upgrade_copies_items,
);

fn fresh_flash_is_wiped<L: TestLayout>() {
    let n = fresh::<L>();
    let header = n.flash().bytes(0, 0, 8);
    assert_eq!(header, [0x4e, 0x52, 0x43, 0x32, 0xf9, 0xff, 0xff, 0xff]);
    if L::BLOCK_WORDS == 4 {
        assert_eq!(n.flash().bytes(0, 8, 8), [0; 8]);
    }
    assert!(n.flash().sectors[1].iter().all(|&b| b == 0xFF));
    assert_eq!(n.active_sector(), 0);
    assert_eq!(items(&n), vec![]);
}

fn set_get_roundtrip<L: TestLayout>() {
    let mut n = fresh::<L>();
    for (i, &len) in LENGTHS.iter().enumerate() {
        let key = 0x0100 + i as u16;
        assert!(n.set(key, &pattern(len, i as u8)));
    }
    for n in [&n, &reopen(&n)] {
        for (i, &len) in LENGTHS.iter().enumerate() {
            let key = 0x0100 + i as u16;
            assert_eq!(get_vec(n, key), Some(pattern(len, i as u8)), "len {len}");
        }
        assert_eq!(get_vec(n, 0x0200), None);
    }
}

fn same_value_is_kept_in_place<L: TestLayout>() {
    let mut n = fresh::<L>();
    assert!(n.set(0x0101, b"same value 12345"));
    let before = n.flash().sectors.clone();
    let mut found = false;
    let value: &[u8] = b"same value 12345";
    assert!(n.set_ex(0x0101, Some(&value), value.len() as u16, &mut found));
    assert!(found);
    assert_eq!(n.flash().sectors, before);
}

fn changed_value_replaces_item<L: TestLayout>() {
    let mut n = fresh::<L>();
    for len in [3, 20] {
        let key = 0x0100 + len as u16;
        assert!(n.set(key, &vec![0x00; len]));
        assert!(n.set(key, &vec![0xAA; len]));
        assert!(n.set(key, &vec![0xAB; len + 1]));
        assert_eq!(get_vec(&n, key), Some(vec![0xAB; len + 1]));
    }
    let reopened = reopen(&n);
    assert_eq!(
        items(&reopened),
        vec![(0x0103, vec![0xAB; 4]), (0x0114, vec![0xAB; 21])]
    );
}

fn delete_removes_item<L: TestLayout>() {
    let mut n = fresh::<L>();
    for &len in LENGTHS {
        let key = 0x0300 + len as u16;
        assert!(n.set(key, &pattern(len, 7)));
        assert!(n.delete(key));
        assert!(!n.delete(key));
        assert_eq!(get_vec(&n, key), None);
    }
    assert!(!n.delete(0x0123));
    assert_eq!(items(&reopen(&n)), vec![]);
}

fn free_key_is_rejected<L: TestLayout>() {
    let mut n = fresh::<L>();
    let mut found = true;
    let value: &[u8] = b"x";
    assert!(!n.set_ex(KEY_FREE, Some(&value), 1, &mut found));
    assert!(found, "found must be left alone");
    assert!(!n.delete(KEY_FREE));
}

fn compaction_keeps_latest_values<L: TestLayout>() {
    let mut n = fresh::<L>();
    assert!(n.set(0x0101, b"stays"));
    assert!(n.set(0x0102, &pattern(500, 1)));
    let mut switched = 0;
    let mut sector = n.active_sector();
    for round in 0..400u32 {
        let value = pattern(1000 + (round % 7) as usize, round as u8);
        assert!(n.set(0x0103, &value));
        assert!(n.set_counter(0x0104, round));
        if n.active_sector() != sector {
            sector = n.active_sector();
            switched += 1;
        }
        assert_eq!(get_vec(&n, 0x0103), Some(value));
    }
    assert!(switched >= 4, "compacted only {switched} times");
    for n in [&n, &reopen(&n)] {
        assert_eq!(get_vec(n, 0x0101), Some(b"stays".to_vec()));
        assert_eq!(get_vec(n, 0x0102), Some(pattern(500, 1)));
        // Written in the last round, 399.
        assert_eq!(get_vec(n, 0x0103), Some(pattern(1000, 143)));
        let mut count = 0;
        assert!(n.flash().is_valid(n.active_sector(), 0, 1));
        let mut copy = Norcow::new(n.flash().clone(), L::default());
        copy.init();
        assert!(copy.next_counter(0x0104, &mut count));
        assert_eq!(count, 400);
    }
    // The inactive sector is erased.
    let inactive = 1 - n.active_sector() as usize;
    assert!(n.flash().sectors[inactive].iter().all(|&b| b == 0xFF));
}

fn counters_increment<L: TestLayout>() {
    let mut n = fresh::<L>();
    let mut count = 99;
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, 0);
    for expected in 1..=200 {
        assert!(n.next_counter(0x8101, &mut count));
        assert_eq!(count, expected);
    }
    assert!(n.set_counter(0x8101, 1000));
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, 1001);
    let len = get_vec(&n, 0x8101).unwrap().len();
    assert_eq!(len, 4 * (1 + L::COUNTER_TAIL_WORDS));

    let mut n = reopen(&n);
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, 1002);

    // Not a counter.
    assert!(n.set(0x8102, b"abc"));
    assert!(!n.next_counter(0x8102, &mut count));
}

fn counter_overflow_fails<L: TestLayout>() {
    let mut n = fresh::<L>();
    assert!(n.set_counter(0x8101, u32::MAX - 1));
    let mut count = 0;
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, u32::MAX);
    assert!(!n.next_counter(0x8101, &mut count));
}

fn update_bytes_fills_allocated_value<L: TestLayout>() {
    for &len in &[13usize, 15, 16, 17, 31, 32, 33, 47, 48, 100, 1000] {
        for chunks in [&[1usize][..], &[3, 16, 5], &[16], &[15, 2], &[64]] {
            let mut n = fresh::<L>();
            let value = pattern(len, len as u8);
            assert!(n.allocate(0x0101, len as u16));
            assert!(n.set(0x0102, b"neighbor"));
            let mut done = 0;
            let mut i = 0;
            while done < len {
                let size = chunks[i % chunks.len()].min(len - done);
                assert!(n.update_bytes(0x0101, &value[done..done + size]));
                done += size;
                i += 1;
            }
            for n in [&n, &reopen(&n)] {
                assert_eq!(get_vec(n, 0x0101), Some(value.clone()), "{len} {chunks:?}");
                assert_eq!(get_vec(n, 0x0102), Some(b"neighbor".to_vec()));
            }
            // The update is over: a new one can start on another key.
            assert!(n.allocate(0x0103, 20));
            assert!(n.update_bytes(0x0103, &[1; 20]));
            assert_eq!(get_vec(&n, 0x0103), Some(vec![1; 20]));
        }
    }
}

fn update_bytes_rejects_overflow<L: TestLayout>() {
    let mut n = fresh::<L>();
    assert!(n.allocate(0x0101, 20));
    assert!(!n.update_bytes(0x0101, &[0; 21]));
    assert!(!n.update_bytes(0x0199, &[0; 1]));
}

fn get_next_skips_deleted<L: TestLayout>() {
    let mut n = fresh::<L>();
    assert!(n.set(0x0101, b"a"));
    assert!(n.set(0x0102, &pattern(30, 2)));
    assert!(n.set(0x0103, b"c"));
    assert!(n.delete(0x0102));
    // 'a' -> 'b' sets a bit, so the value cannot be overwritten in place.
    assert!(n.set(0x0101, b"b"));
    assert_eq!(
        items(&n),
        vec![(0x0103, b"c".to_vec()), (0x0101, b"b".to_vec())]
    );
}

fn downgrade_wipes<L: TestLayout>() {
    let mut flash = RamFlash::new(L::BLOCK_WORDS);
    flash.version = VERSION + 1;
    let mut newer = Norcow::new(flash, L::default());
    newer.init();
    assert!(newer.set(0x0101, b"from the future"));

    let mut flash = newer.flash().clone();
    flash.version = VERSION;
    let mut n = Norcow::new(flash, L::default());
    assert_eq!(n.init(), VERSION);
    assert_eq!(items(&n), vec![]);
}

fn upgrade_copies_items<L: TestLayout>() {
    let mut flash = RamFlash::new(L::BLOCK_WORDS);
    flash.version = VERSION - 1;
    let mut old = Norcow::new(flash, L::default());
    old.init();
    assert!(old.set(0x0101, b"one"));
    assert!(old.set(0x0102, &pattern(40, 2)));

    let mut flash = old.flash().clone();
    flash.version = VERSION;
    let mut n = Norcow::new(flash, L::default());
    assert_eq!(n.init(), VERSION - 1);
    // Reads come from the old sector until the upgrade is finished.
    assert_eq!(get_vec(&n, 0x0101), Some(b"one".to_vec()));
    let old_items = items(&n);
    for (key, value) in &old_items {
        assert!(n.set(*key, value));
    }
    assert!(n.set(0x0103, b"new"));
    assert!(n.upgrade_finish());
    assert_eq!(n.active_sector(), 1);
    assert_eq!(n.active_version(), VERSION);
    let reopened = reopen(&n);
    assert_eq!(
        items(&reopened),
        vec![
            (0x0101, b"one".to_vec()),
            (0x0102, pattern(40, 2)),
            (0x0103, b"new".to_vec()),
        ]
    );
}

// --------------------------------------------------------------------------
// Exact flash format
// --------------------------------------------------------------------------

#[test]
fn bitwise_format() {
    let mut n = fresh::<Bitwise>();
    assert!(n.set(0x0102, b"abc"));
    assert_eq!(
        n.flash().bytes(0, 8, 8),
        [0x02, 0x01, 0x03, 0x00, b'a', b'b', b'c', 0x00]
    );
    assert!(n.allocate(0x0103, 5));
    // The value is skipped, the padding is written.
    assert_eq!(
        n.flash().bytes(0, 16, 12),
        [
            0x03, 0x01, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
        ]
    );
    assert!(n.delete(0x0102));
    assert_eq!(n.flash().bytes(0, 8, 8), [0, 0, 3, 0, 0, 0, 0, 0]);

    // A counter is the count and two words of tally bits.
    assert!(n.set_counter(0x8101, 7));
    let mut count = 0;
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, 8);
    assert_eq!(
        n.flash().bytes(0, 28, 16),
        [
            0x01, 0x81, 12, 0, 7, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF
        ]
    );
}

#[test]
fn blockwise_format() {
    let mut n = fresh::<Blockwise>();
    // Small item: one block, padded with zeros.
    assert!(n.set(0x0102, b"abc"));
    let mut expected = [0u8; 16];
    expected[..7].copy_from_slice(&[0x02, 0x01, 0x03, 0x00, b'a', b'b', b'c']);
    assert_eq!(n.flash().bytes(0, 16, 16), expected);

    // Large item: header block, value, valid flag, padded with 0xFF.
    let value = pattern(13, 0);
    assert!(n.set(0x0103, &value));
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&[0x03, 0x01, 13, 0x00]);
    assert_eq!(n.flash().bytes(0, 32, 16), header);
    let mut block = [0xFFu8; 16];
    block[..13].copy_from_slice(&value);
    assert_eq!(n.flash().bytes(0, 48, 16), block);

    // A value of 15 bytes leaves room for the flag in its last block, a value
    // of 16 bytes needs another block for it.
    assert!(n.set(0x0104, &pattern(16, 0)));
    assert_eq!(n.flash().bytes(0, 80, 16), pattern(16, 0));
    let mut flag = [0xFFu8; 16];
    flag[0] = 0xFF;
    assert_eq!(n.flash().bytes(0, 96, 16), flag);
    assert_eq!(n.get(0x0105), None);

    // Deleting a small item zeroes its block; deleting a large item zeroes
    // its value and flag but keeps the header block.
    assert!(n.delete(0x0102));
    assert_eq!(n.flash().bytes(0, 16, 16), [0; 16]);
    assert!(n.delete(0x0103));
    assert_eq!(n.flash().bytes(0, 32, 16), header);
    assert_eq!(n.flash().bytes(0, 48, 16), [0; 16]);

    // Deleted large items are still skipped correctly.
    assert_eq!(items(&n), vec![(0x0104, pattern(16, 0))]);
    assert_eq!(items(&reopen(&n)), vec![(0x0104, pattern(16, 0))]);
}

#[test]
fn blockwise_small_item_cannot_be_updated() {
    let mut n = fresh::<Blockwise>();
    assert!(n.allocate(0x0101, 12));
    assert!(!n.update_bytes(0x0101, &[1; 12]));
}

#[test]
fn blockwise_update_is_exclusive() {
    let mut n = fresh::<Blockwise>();
    assert!(n.allocate(0x0101, 40));
    assert!(n.allocate(0x0102, 40));
    assert!(n.update_bytes(0x0101, &[1; 10]));
    // Another key cannot start while the first update is unfinished.
    assert!(!n.update_bytes(0x0102, &[2; 10]));
    assert!(n.update_bytes(0x0101, &[1; 30]));
    assert!(n.update_bytes(0x0102, &[2; 40]));
    assert_eq!(get_vec(&n, 0x0101), Some(vec![1; 40]));
    assert_eq!(get_vec(&n, 0x0102), Some(vec![2; 40]));
}

#[test]
fn bitwise_tally_counter_rewrites_when_exhausted() {
    let mut n = fresh::<Bitwise>();
    assert!(n.set_counter(0x8101, 0));
    let free_before = n.free_offset;
    let mut count = 0;
    // 64 increments only clear tally bits.
    for expected in 1..=64 {
        assert!(n.next_counter(0x8101, &mut count));
        assert_eq!(count, expected);
    }
    assert_eq!(n.free_offset, free_before);
    // The next one writes a new item.
    assert!(n.next_counter(0x8101, &mut count));
    assert_eq!(count, 65);
    assert!(n.free_offset > free_before);
}

/// Version 0 overwrote items by appending them, without deleting the old
/// instance. `get_next()` reports only the newest instance.
#[test]
fn version_0_sector_reports_newest_instances() {
    let mut flash = RamFlash::new(1);
    let mut raw = vec![0x4e, 0x52, 0x43, 0x57]; // NRCW
    for (key, value) in [(0x0101u16, &b"old"[..]), (0x0102, b"b"), (0x0101, b"new")] {
        raw.extend_from_slice(&key.to_le_bytes());
        raw.extend_from_slice(&(value.len() as u16).to_le_bytes());
        raw.extend_from_slice(value);
        while raw.len() % 4 != 0 {
            raw.push(0);
        }
    }
    flash.sectors[0][..raw.len()].copy_from_slice(&raw);

    let mut n = Norcow::new(flash, Bitwise::new());
    assert_eq!(n.init(), 0);
    assert_eq!(n.active_version(), 0);
    assert_eq!(get_vec(&n, 0x0101), Some(b"new".to_vec()));
    assert_eq!(
        items(&n),
        vec![(0x0102, b"b".to_vec()), (0x0101, b"new".to_vec())]
    );
    // The write sector is prepared for the upgrade.
    assert_eq!(n.flash().bytes(1, 0, 4), [0x4e, 0x52, 0x43, 0x32]);
}

#[test]
fn full_sector_without_space_fails() {
    let mut n = fresh::<Blockwise>();
    // Larger than a sector.
    let mut found = false;
    assert!(!n.set_ex(0x0101, None, u16::MAX, &mut found));
}
