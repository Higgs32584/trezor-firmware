.PHONY: clean rust-storage

# Implementation of the storage to test: `c` (storage.c, norcow.c) or `rust`
# (rust/trezor-storage through storage/storage_rs_glue.c).
STORAGE_IMPL ?= c

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
SRC += storage/storage_utils.c
ifeq ($(STORAGE_IMPL),rust)
SRC += storage/storage_rs_glue.c
else ifeq ($(STORAGE_IMPL),c)
SRC += storage/storage.c
SRC += storage/norcow.c
else
$(error STORAGE_IMPL must be `c` or `rust`)
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

# Relink when STORAGE_IMPL changes.
IMPL_STAMP = build/storage_impl.$(STORAGE_IMPL)
IMPL_STAMP_QW = build_qw/storage_impl.$(STORAGE_IMPL)

ifeq ($(STORAGE_IMPL),rust)
RUST_STORAGE = $(BASE)rust/trezor-storage/Cargo.toml
RUST_LIB = rust-build/bitwise/release/libtrezor_storage.a
RUST_LIB_QW = rust-build/blockwise/release/libtrezor_storage.a
# The staticlib links std.
LIBS += -lpthread -ldl -lm

# Same configuration as CFLAGS: emulator, no secure elements, no hardware
# key. Cargo decides whether the library is up to date.
rust-storage:
	cargo rustc --manifest-path $(RUST_STORAGE) --release --lib \
		--crate-type staticlib --features bitwise,emulator,std \
		--target-dir rust-build/bitwise
	cargo rustc --manifest-path $(RUST_STORAGE) --release --lib \
		--crate-type staticlib --features blockwise,emulator,std \
		--target-dir rust-build/blockwise

$(RUST_LIB) $(RUST_LIB_QW): rust-storage

# The storage API is only called from Python, so nothing references it at
# link time: keep the whole archive.
RUST_LINK = -Wl,--whole-archive $(RUST_LIB) -Wl,--no-whole-archive
RUST_LINK_QW = -Wl,--whole-archive $(RUST_LIB_QW) -Wl,--no-whole-archive
endif

$(OUT): $(OBJ) $(IMPL_STAMP) $(RUST_LIB)
	$(CC) $(CFLAGS) -DFLASH_BIT_ACCESS -DFLASH_BLOCK_WORDS=1 $(OBJ) $(RUST_LINK) $(LIBS) -shared -o $(OUT)

$(OUT_QW): $(OBJ_QW) $(IMPL_STAMP_QW) $(RUST_LIB_QW)
	$(CC) $(CFLAGS) -DFLASH_BLOCK_WORDS=4 $(OBJ_QW) $(RUST_LINK_QW) $(LIBS) -shared -o $(OUT_QW)

build/storage_impl.%:
	mkdir -p $(@D)
	rm -f $(@D)/storage_impl.*
	touch $@

build_qw/storage_impl.%:
	mkdir -p $(@D)
	rm -f $(@D)/storage_impl.*
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
	rm -f $(OUT) $(OUT_QW) $(OBJ) $(OBJ_QW) build/*_impl.* build_qw/*_impl.*
	rm -rf rust-build
