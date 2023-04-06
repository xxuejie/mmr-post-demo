#!/bin/bash
set -ex

cargo build --release --package tx-generator
cargo build --release --package rust-baseline-verifier --target=riscv64imac_zba_zbb_zbc_zbs-unknown-ckb-elf

riscv64-ckb-elf-gcc c/ckb_mmr_entry.c -o c_verifier \
  -O3 -nostdlib -nostdinc -g \
  -I c -I c/ckb-c-stdlib -I c/ckb-c-stdlib/libc \
  -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
