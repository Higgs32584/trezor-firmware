#![no_std]
#![no_main]

// force pull in Rust generated symbols (incl. the panic handler)
use sec as _; // incl. the Rust norcow used by storage.c
use sys as _;
use trezor_lib as _;
