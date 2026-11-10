# trezor-storage

Rust implementation of the Trezor storage: the NORCOW flash key-value store,
PIN verification, key derivation, encryption of protected values, the storage
authentication tag, the PIN failure logs, the wipe code and upgrades from all
older storage versions. It replaces `storage/storage.c`, `norcow.c`, the
`norcow_*.h` and `pinlogs_*.h` headers and `storage_utils.c` in Trezor Core.

The C ABI of `storage/storage.h` is unchanged, and so are the flash format,
the key derivation and the sequence of random numbers drawn. Existing devices
keep their data, and the callers of the storage do not change.

Trezor One (`legacy/`) has no Rust toolchain and keeps using the C storage,
which also stays the reference for the tests.

## Layout

- `src/norcow/`: the flash store, in plain safe Rust over the `Flash` trait,
  with unit tests on an in-memory flash.
- `src/storage/`: `storage.c` (`mod.rs`), the PIN logs (`pinlogs.rs`) and
  the format upgrades (`upgrade.rs`). Functions keep the names of their C
  counterparts.
- `src/sys.rs`: safe wrappers around the C code the storage depends on: the
  crypto library, RNG, MPU, flash driver, Optiga, Tropic and the hardware key.
- `src/ffi.rs`: the C ABI of `storage.h`, the global state and the UI
  progress reporting.
- `../../storage/storage_rs_glue.c`: compiled in place of the C storage. It
  passes the build configuration to Rust and wraps functions that are macros
  or `static inline` on some platforms.

`unsafe` code is confined to `sys.rs` and `ffi.rs`.

## Configuration

| Feature | C configuration |
| --- | --- |
| `bitwise` / `blockwise` | `FLASH_BIT_ACCESS` / `FLASH_BLOCK_WORDS == 4` |
| `optiga` | `USE_OPTIGA` |
| `tropic` | `USE_TROPIC` (and `STRETCHED_PIN_COUNT > 1`) |
| `hwkey` | `USE_STORAGE_HWKEY` (ignored with `emulator`) |
| `emulator` | `TREZOR_EMULATOR` |

The glue defines a marker symbol for each option, and the Rust code
references the markers of the options it was built with, so a mismatch fails
at link time. Numeric settings (`NORCOW_MIN_VERSION`, `PIN_ITER_COUNT`, the
sector layout) are read from the glue, so the C headers stay the single
source of truth. Upgrade paths that C leaves out with
`#if NORCOW_MIN_VERSION` are skipped at run time with the same conditions.

## Security properties kept from the C code

- Security decisions use the multi-bit `secbool` values.
- Loops are checked for completion, comparisons are repeated after random
  delays (`wait_random()`), and the counters that C declares `volatile` are
  accessed through volatile reads and writes.
- PIN logs are read from flash at every check, like the C code reads them
  through a pointer to flash.
- Every inconsistency goes through the same fault handler, which uses the
  PIN failure counter as a fault counter and wipes the storage on repeated
  faults.
- Keys, PINs and intermediate secrets are wiped with `memzero()`, and the
  crypto contexts are initialized in place and wiped when dropped.

## What Rust adds

- Flash is read through bounds-checked copies; the logic never handles
  pointers into flash.
- Values passed in from C are length-checked, and null pointers where C would
  have crashed are fatal errors instead of undefined behavior.
- The state lives in `Cell`s and `RefCell`s that are only borrowed briefly,
  never across the UI callback or a secure element call. Like the C code,
  the storage can be called again while an operation waits in the UI
  callback (the app reads settings to draw the screen), and stays usable if
  the task in the callback is terminated. Overlapping borrows, which would
  be aliasing bugs in C, are fatal errors.
- The off-by-one sector check of the C code (`sector <= NORCOW_SECTOR_COUNT`,
  trezor/trezor-firmware#6262) is a strict check.

## Testing

```sh
cargo test                     # norcow unit tests, both layouts
cargo clippy --features bitwise,emulator
cargo clippy --features blockwise,optiga,tropic,hwkey
```

The storage test suite compares the flash contents with a Python model byte
for byte, including upgrades from older storage versions. To run it against
this crate:

```sh
make -C storage/tests clean
make -C storage/tests build STORAGE_IMPL=rust
make -C storage/tests tests_all
```

The configurations with secure elements are covered by the device tests on
the emulators: T3T1 (Optiga) and T3W1 (Optiga and Tropic). The hardware key
exists only on STM32U5 hardware.
