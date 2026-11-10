/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Glue for the Rust implementation of the storage (rust/trezor-storage).
//
// Compile this file instead of storage.c and norcow.c, with the same flags,
// and link the trezor-storage crate built with the features that match the
// configuration: a flash layout (`bitwise` with FLASH_BIT_ACCESS, `blockwise`
// with FLASH_BLOCK_WORDS == 4), `optiga` (USE_OPTIGA), `tropic`
// (USE_TROPIC), `hwkey` (USE_STORAGE_HWKEY) and `emulator`
// (TREZOR_EMULATOR).
//
// The glue hands the configuration to Rust, so that the C headers stay the
// single source of truth, and wraps the functions that are macros or static
// inline functions on some platforms.

#include <stdbool.h>
#include <stdint.h>

#include <sec/rng_strong.h>
#include <sys/mpu.h>

#include "chacha20poly1305/rfc7539.h"
#include "common.h"
#include "flash_area.h"
#include "norcow.h"
#include "options.h"
#include "pbkdf2.h"
#include "rand.h"
#include "random_delays.h"
#include "storage.h"
#include "storage_utils.h"
#include "time_estimate.h"

#if USE_OPTIGA
#include "optiga.h"
#endif

#if USE_TROPIC
#include <sec/tropic.h>
#endif

#ifdef USE_STORAGE_HWKEY
#include "secure_aes.h"
#endif

// Same as in storage.c: an undefined NORCOW_MIN_VERSION evaluates to 0 in
// the `#if` conditions there.
#ifndef NORCOW_MIN_VERSION
#define NORCOW_MIN_VERSION 0
#endif

_Static_assert(NORCOW_HEADER_LEN == 0,
               "the Rust storage does not support sector headers");
_Static_assert(NORCOW_SECTOR_COUNT >= 1 && NORCOW_SECTOR_COUNT <= 255,
               "invalid NORCOW_SECTOR_COUNT");

// Sizes of the opaque crypto contexts reserved by the Rust code (sys.rs).
_Static_assert(sizeof(PBKDF2_HMAC_SHA256_CTX) <= 192 &&
                   _Alignof(PBKDF2_HMAC_SHA256_CTX) <= 8,
               "PBKDF2_HMAC_SHA256_CTX does not fit the Rust buffer");
_Static_assert(sizeof(chacha20poly1305_ctx) <= 256 &&
                   _Alignof(chacha20poly1305_ctx) <= 8,
               "chacha20poly1305_ctx does not fit the Rust buffer");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The Rust side references the marker of each option it was built with, so
// a mismatch fails at link time.

#if defined FLASH_BIT_ACCESS && FLASH_BLOCK_WORDS == 1
const uint8_t storage_rs_cfg_layout_bitwise = 1;
#elif !defined FLASH_BIT_ACCESS && FLASH_BLOCK_WORDS == 4
const uint8_t storage_rs_cfg_layout_blockwise = 1;
#else
#error "Flash configuration not supported by the Rust storage"
#endif

#if USE_OPTIGA
const uint8_t storage_rs_cfg_optiga_1 = 1;
#else
const uint8_t storage_rs_cfg_optiga_0 = 1;
#endif

#if USE_TROPIC
const uint8_t storage_rs_cfg_tropic_1 = 1;
#else
const uint8_t storage_rs_cfg_tropic_0 = 1;
#endif

#ifdef USE_STORAGE_HWKEY
const uint8_t storage_rs_cfg_hwkey_1 = 1;
#else
const uint8_t storage_rs_cfg_hwkey_0 = 1;
#endif

#ifdef TREZOR_EMULATOR
const uint8_t storage_rs_cfg_emulator_1 = 1;
#else
const uint8_t storage_rs_cfg_emulator_0 = 1;
#endif

const uint8_t storage_rs_sector_count = NORCOW_SECTOR_COUNT;
const uint32_t storage_rs_sector_size = NORCOW_SECTOR_SIZE;
const uint32_t storage_rs_norcow_version = NORCOW_VERSION;
const uint32_t storage_rs_norcow_min_version = NORCOW_MIN_VERSION;
const uint32_t storage_rs_pin_max_tries = PIN_MAX_TRIES;
const uint32_t storage_rs_stretched_pin_count = STRETCHED_PIN_COUNT;
const uint32_t storage_rs_storage_salt_size = STORAGE_SALT_SIZE;

// Same condition as PIN_ITER_COUNT in storage.c.
#if (STORAGE_INSECURE_TESTING_MODE && !PRODUCTION) || STRETCHED_PIN_COUNT > 1
const uint32_t storage_rs_pin_iter_count = 1;
#else
const uint32_t storage_rs_pin_iter_count = 20000;
#endif

#if STORAGE_INSECURE_TESTING_MODE && !PRODUCTION
const uint8_t storage_rs_skip_inactive_wipe = 1;
#else
const uint8_t storage_rs_skip_inactive_wipe = 0;
#endif

// The PIN value corresponding to an empty PIN (storage.h).
const uint8_t *PIN_EMPTY = (const uint8_t *)"";

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

const flash_area_t *storage_rs_area(uint8_t sector) {
  ensure(sectrue * (sector < NORCOW_SECTOR_COUNT), "invalid sector");
  return &STORAGE_AREAS[sector];
}

void storage_rs_fatal(const char *msg, const char *file, int line) {
  __fatal_error(msg, file, line);
  // __fatal_error() does not return, but it is not declared noreturn on every
  // platform and the Rust side relies on this function not returning.
  for (;;) {
  }
}

uint32_t storage_rs_random32(void) { return random32(); }

void storage_rs_rng_fill_buffer_strong(void *buffer, size_t buffer_size) {
  rng_fill_buffer_strong(buffer, buffer_size);
}

void storage_rs_rng_fill_buffer_strong_time(uint32_t *time_ms) {
  rng_fill_buffer_strong_time(time_ms);
}

void storage_rs_rng_fill_buffer(void *buffer, size_t buffer_size) {
  (void)rng_fill_buffer(buffer, buffer_size);
}

uint32_t storage_rs_ticks_ms(void) { return hal_ticks_ms(); }

void storage_rs_delay(uint32_t ms) { hal_delay(ms); }

int storage_rs_mpu_reconfig(void) {
  return (int)mpu_reconfig(MPU_MODE_STORAGE);
}

void storage_rs_mpu_restore(int mode) {
  mpu_mode_t mpu_mode = (mpu_mode_t)mode;
  mpu_restore(mpu_mode);
}

#ifdef USE_STORAGE_HWKEY
secbool storage_rs_secure_aes_encrypt(const uint8_t *input, uint8_t *output,
                                      size_t size, bool privileged) {
  return secure_aes_ecb_encrypt_hw(
      input, size, output,
      privileged ? SECURE_AES_KEY_XORK_SP : SECURE_AES_KEY_XORK_SN);
}
#endif
