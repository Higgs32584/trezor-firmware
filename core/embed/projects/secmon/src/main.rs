#![no_std]
#![no_main]

// force pull in Rust generated symbols (incl. the panic handler)
use sec as _; // incl. the Rust storage (trezor-storage)
use sys as _;
