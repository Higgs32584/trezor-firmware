.PHONY: clean rust-norcow

# Implementation of norcow to test: `c` (storage/norcow.c) or `rust`
# (rust/trezor-norcow through storage/norcow_rs_glue.c).
NORCOW_IMPL ?= c

CC = cc

CFLAGS = -Wall -Wshadow -Wextra -Wpedantic -Werror -Wno-missing-braces
CFLAGS += -fPIC
CFALGS += -fsanitize=address,undefined
CFLAGS += -DTREZOR_MODEL_T2T1
CFLAGS += -DTREZOR_EMULATOR
CFLAGS += -DUSE_INSECURE_PRNG
CFLAGS += -DCONFIDENTIAL=""

LIBS =
INC = -I ../../../crypto -I ../.. -I .
BASE = ../../../

SRC  = storage/tests/c/flash.c
SRC += storage/tests/c/common.c
SRC += storage/tests/c/random_delays.c
SRC += storage/tests/c/test_layout.c
SRC += storage/flash_area.c
SRC += storage/storage.c
SRC += storage/storage_utils.c
ifeq ($(NORCOW_IMPL),rust)
SRC += storage/norcow_rs_glue.c
else ifeq ($(NORCOW_IMPL),c)
SRC += storage/norcow.c
else
$(error NORCOW_IMPL must be `c` or `rust`)
endif
SRC += crypto/pbkdf2.c
SRC += crypto/rand.c
SRC += crypto/rand_insecure.c
SRC += crypto/chacha20poly1305/rfc7539.c
SRC += crypto/chacha20poly1305/chacha20poly1305.c
SRC += crypto/chacha20poly1305/poly1305-donna.c
SRC += crypto/chacha20poly1305/chacha_merged.c
SRC += crypto/hmac.c
SRC += crypto/sha2.c
SRC += crypto/memzero.c
SRC += crypto/consteq.c
SRC += crypto/fault_handler_noop.c

OBJ = $(SRC:%.c=build/%.o)
OBJ_QW = $(SRC:%.c=build_qw/%.o)

OUT = libtrezor-storage.so
OUT_QW = libtrezor-storage-qw.so

.DEFAULT_GOAL := $(OUT)

# Relink when NORCOW_IMPL changes.
IMPL_STAMP = build/norcow_impl.$(NORCOW_IMPL)
IMPL_STAMP_QW = build_qw/norcow_impl.$(NORCOW_IMPL)

ifeq ($(NORCOW_IMPL),rust)
RUST_NORCOW = $(BASE)rust/trezor-norcow/Cargo.toml
RUST_LIB = rust-build/bitwise/release/libtrezor_norcow.a
RUST_LIB_QW = rust-build/blockwise/release/libtrezor_norcow.a
# The staticlib links std.
LIBS += -lpthread -ldl -lm

# Cargo decides whether the library is up to date.
rust-norcow:
	cargo rustc --manifest-path $(RUST_NORCOW) --release --lib \
		--crate-type staticlib --features bitwise,std --target-dir rust-build/bitwise
	cargo rustc --manifest-path $(RUST_NORCOW) --release --lib \
		--crate-type staticlib --features blockwise,std --target-dir rust-build/blockwise

$(RUST_LIB) $(RUST_LIB_QW): rust-norcow
endif

$(OUT): $(OBJ) $(IMPL_STAMP) $(RUST_LIB)
	$(CC) $(CFLAGS) -DFLASH_BIT_ACCESS -DFLASH_BLOCK_WORDS=1 $(OBJ) $(RUST_LIB) $(LIBS) -shared -o $(OUT)

$(OUT_QW): $(OBJ_QW) $(IMPL_STAMP_QW) $(RUST_LIB_QW)
	$(CC) $(CFLAGS) -DFLASH_BLOCK_WORDS=4 $(OBJ_QW) $(RUST_LIB_QW) $(LIBS) -shared -o $(OUT_QW)

build/norcow_impl.%:
	mkdir -p $(@D)
	rm -f $(@D)/norcow_impl.*
	touch $@

build_qw/norcow_impl.%:
	mkdir -p $(@D)
	rm -f $(@D)/norcow_impl.*
	touch $@

build/crypto/chacha20poly1305/chacha_merged.o: $(BASE)crypto/chacha20poly1305/chacha_merged.c
	mkdir -p $(@D)

	$(CC) $(CFLAGS) $(INC) -c $< -o $@
build_qw/crypto/chacha20poly1305/chacha_merged.o: $(BASE)crypto/chacha20poly1305/chacha_merged.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

# build object files from C sources with headers
build/%.o: $(BASE)%.c $(BASE)%.h
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -DFLASH_BIT_ACCESS -DFLASH_BLOCK_WORDS=1 $(INC) -c $< -o $@

# build object files from C sources without headers
build/%.o: $(BASE)%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -DFLASH_BIT_ACCESS -DFLASH_BLOCK_WORDS=1 $(INC) -c $< -o $@

# build object files from C sources with headers
build_qw/%.o: $(BASE)%.c $(BASE)%.h
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -DFLASH_BLOCK_WORDS=4  $(INC) -c $< -o $@

# build object files from C sources without headers
build_qw/%.o: $(BASE)%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -DFLASH_BLOCK_WORDS=4  $(INC) -c $< -o $@

clean:
	rm -f $(OUT) $(OUT_QW) $(OBJ) $(OBJ_QW) build/norcow_impl.* build_qw/norcow_impl.*
	rm -rf rust-build
