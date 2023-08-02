#!/bin/bash
set -ex

cd clang-rv-cc
cargo build --release
cd ..

cargo build --release --package tx-generator

export RUSTFLAGS='-C target-feature=+zba,+zbb,+zbc,+zbs'
export TARGET_CC=$(pwd)/clang-rv-cc/clang
export TARGET_CFLAGS='-march=rv64imc_zba_zbb_zbc_zbs'
cargo build --release --package rust-baseline-verifier --target=riscv64imac-unknown-none-elf
cargo build --release --package rust-compiled-verifier --target=riscv64imac-unknown-none-elf
unset TARGET_CFLAGS
unset TARGET_CC
unset RUSTFLAGS

clang-rv-cc/clang --target=riscv64 -march=rv64imc_zba_zbb_zbc_zbs \
  c/ckb_mmr_entry.c -o c_verifier \
  -O3 -nostdlib -nostdinc -g \
  -I c -I c/ckb-c-stdlib -I c/ckb-c-stdlib/libc \
  -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
