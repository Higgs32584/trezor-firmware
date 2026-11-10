# trezor-norcow

Rust implementation of NORCOW, the flash key-value store under the Trezor
storage. It replaces `storage/norcow.c` (with `norcow_bitwise.h` and
`norcow_blockwise.h`) in Trezor Core. This is the first stage of moving
`storage/` to Rust.

The flash format and the behavior of the C API in `storage/norcow.h` are
unchanged, so existing devices keep their data and `storage.c` is unaware of
the switch.

## Layout

- `src/lib.rs`: `Norcow`, the sector bookkeeping and all operations that do
  not depend on the item layout. It addresses flash by sector offsets only.
- `src/layout.rs`: the `Bitwise` (STM32F4, emulators) and `Blockwise`
  (STM32U5) item encodings.
- `src/ffi.rs`: the C ABI of `norcow.h`, on top of the C flash driver
  (`flash_area_*`). This is the only module with `unsafe` code. It is enabled
  by the `bitwise` or `blockwise` feature.
- `../../storage/norcow_rs_glue.c`: compiled in place of `norcow.c`. It passes
  `norcow_config.h` to Rust and defines a marker symbol for the flash layout,
  so a feature/configuration mismatch fails at link time.

## What Rust adds over the C code

- Flash reads are bounds-checked copies through `flash_area_get_address()`.
  The logic never computes pointers into flash or subtracts them.
- Values passed in from C are read through a length-checked wrapper, right
  before each flash write, as the C code did.
- Out-parameters, null data and sector indices are checked; misuse is a
  fatal error instead of undefined behavior.
- The global state lives in a `RefCell`, so re-entrancy is a fatal error
  instead of corrupted state.

Behavior that existing devices may depend on is kept as is, including some
oddities. These are marked "Same as C" in the code.

## Testing

```sh
cargo test                     # unit tests on an in-memory flash, both layouts
cargo clippy --features bitwise
cargo clippy --features blockwise
```

The storage test suite compares the flash contents with a Python model byte
for byte, and covers storage upgrades from older formats. To run it against
this crate:

```sh
make -C storage/tests clean
make -C storage/tests build NORCOW_IMPL=rust
make -C storage/tests tests_all
```

## Remaining stages

1. NORCOW (this crate).
2. PIN logs (`pinlogs_bitwise.h`, `pinlogs_blockwise.h`).
3. `storage.c`: key derivation, encryption, PIN verification and upgrades,
   including the fault-injection countermeasures and the Optiga and Tropic
   paths.

Trezor One (`legacy/`) has no Rust toolchain and keeps using `norcow.c`.
