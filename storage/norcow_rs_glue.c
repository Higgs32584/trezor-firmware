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

// Glue for the Rust implementation of norcow (rust/trezor-norcow).
//
// Compile this file instead of norcow.c, with the same flags, and link the
// trezor-norcow crate built with the layout feature that matches the flash:
// `bitwise` with FLASH_BIT_ACCESS, `blockwise` with FLASH_BLOCK_WORDS == 4.
//
// The glue hands the configuration from norcow_config.h to Rust, so that it
// keeps a single source of truth, and wraps the C fatal error handler.

#include "common.h"
#include "flash_area.h"
#include "norcow.h"
#include "options.h"
#include "storage_utils.h"

_Static_assert(NORCOW_HEADER_LEN == 0,
               "the Rust norcow does not support sector headers");
_Static_assert(NORCOW_SECTOR_COUNT >= 1 && NORCOW_SECTOR_COUNT <= 255,
               "invalid NORCOW_SECTOR_COUNT");

// The Rust side references the symbol of the layout it was built for, so a
// mismatch fails at link time.
#if defined FLASH_BIT_ACCESS && FLASH_BLOCK_WORDS == 1
const uint8_t norcow_rs_layout_bitwise = 1;
#elif !defined FLASH_BIT_ACCESS && FLASH_BLOCK_WORDS == 4
const uint8_t norcow_rs_layout_blockwise = 1;
#else
#error "Flash configuration not supported by the Rust norcow"
#endif

const uint8_t norcow_rs_sector_count = NORCOW_SECTOR_COUNT;
const uint32_t norcow_rs_sector_size = NORCOW_SECTOR_SIZE;
const uint32_t norcow_rs_version = NORCOW_VERSION;

#if STORAGE_INSECURE_TESTING_MODE && !PRODUCTION
const uint8_t norcow_rs_skip_inactive_wipe = 1;
#else
const uint8_t norcow_rs_skip_inactive_wipe = 0;
#endif

const flash_area_t *norcow_rs_area(uint8_t sector) {
  ensure(sectrue * (sector < NORCOW_SECTOR_COUNT), "invalid sector");
  return &STORAGE_AREAS[sector];
}

void norcow_rs_fatal(const char *msg) {
  ensure(secfalse, msg);
  // ensure() does not return on failure, but it is not declared noreturn on
  // every platform and the Rust side relies on this function not returning.
  for (;;) {
  }
}
