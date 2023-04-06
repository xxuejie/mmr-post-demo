#!/bin/bash
set -ex

cargo build --release --package tx-generator
rustup target add riscv64imac-unknown-none-elf
cargo build --release --package rust-baseline-verifier --target=riscv64imac-unknown-none-elf
