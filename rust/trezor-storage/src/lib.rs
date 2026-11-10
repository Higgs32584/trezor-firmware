//! The Trezor storage in Rust: a port of `storage/` (`storage.c`, `norcow.c`,
//! the PIN log headers and `storage_utils.c`).
//!
//! * [`norcow`]: the flash key-value store. Plain safe Rust over the
//!   [`norcow::Flash`] trait, with unit tests on an in-memory flash.
//! * `storage`: PIN verification, key derivation, encryption, the storage
//!   authentication tag, PIN logs and format upgrades.
//! * `sys`: safe wrappers around the C code the storage depends on (crypto
//!   library, RNG, MPU, flash driver, secure elements).
//! * `ffi`: the C ABI of `storage/storage.h`.
//!
//! `unsafe` code is confined to `sys` and `ffi`. The flash format, the key
//! derivation and the sequence of random numbers drawn are the same as in C;
//! the storage test suite (`storage/tests`, `STORAGE_IMPL=rust`) checks the
//! flash contents byte for byte against a Python model.
//!
//! Everything but [`norcow`] needs one of the layout features, which select
//! the build configuration together with `optiga`, `tropic`, `hwkey` and
//! `emulator`. They must match the C configuration; `storage_rs_glue.c`
//! makes a mismatch fail at link time.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod norcow;

#[cfg(feature = "ffi")]
mod ffi;
// Each build configuration uses a different subset, like the `#if` blocks
// of the C code.
#[cfg(feature = "ffi")]
#[allow(dead_code, unused_labels, unused_assignments)]
mod storage;
#[cfg(feature = "ffi")]
#[allow(dead_code)]
mod sys;
