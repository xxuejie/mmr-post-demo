#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::{format, vec::Vec};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_merkle_mountain_range::{Merge, MerkleProof, Result};
use ckb_std::{
    ckb_constants::Source,
    default_alloc,
    syscalls::{debug, load_witness},
};

ckb_std::entry!(program_entry);
default_alloc!();

#[derive(Clone, Debug, PartialEq)]
struct VariableBytes(Vec<u8>);

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build()
}

#[derive(Debug)]
struct Blake2bHash;

impl Merge for Blake2bHash {
    type Item = VariableBytes;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item> {
        let mut hasher = new_blake2b();
        hasher.update(&lhs.0[..]);
        hasher.update(&rhs.0[..]);
        let mut hash = Vec::new();
        hash.resize(32, 0);
        hasher.finalize(&mut hash);
        Ok(VariableBytes(hash))
    }
}

pub fn program_entry() -> i8 {
    let mut root_buffer = [0u8; 32];
    let root_length = match load_witness(&mut root_buffer, 0, 0, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading root error {:?}", e));
            return -1;
        }
    };
    assert!(root_length == 32);
    let root = VariableBytes(root_buffer.to_vec());

    let mut proof_buffer = [0u8; 32 * 1024];
    let proof_length = match load_witness(&mut proof_buffer, 0, 1, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading proof error {:?}", e));
            return -1;
        }
    };
    let merkle_proof: MerkleProof<VariableBytes, Blake2bHash> = {
        assert!(proof_length >= 8);
        let mmr_size = {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&proof_buffer[0..8]);
            u64::from_le_bytes(buf)
        };

        let mut i = 8;
        let mut items = Vec::new();
        while i < proof_length {
            assert!(proof_length >= i + 2);
            let len = {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&proof_buffer[i..i + 2]);
                u16::from_le_bytes(buf) as usize
            };
            assert!(proof_length >= i + 2 + len);
            let mut buf = Vec::new();
            buf.resize(len, 0);
            buf.copy_from_slice(&proof_buffer[i + 2..i + 2 + len]);
            items.push(VariableBytes(buf));
            i += 2 + len;
        }
        MerkleProof::new(mmr_size, items)
    };

    let mut leaves_buffer = [0u8; 32 * 1024];
    let leaves_length = match load_witness(&mut leaves_buffer, 0, 2, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading leaves error {:?}", e));
            return -1;
        }
    };
    let leaves: Vec<(u64, VariableBytes)> = {
        let mut i = 0;
        let mut leaves = Vec::new();
        while i < leaves_length {
            assert!(leaves_length >= i + 10);
            let pos = {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&leaves_buffer[i..i + 8]);
                u64::from_le_bytes(buf)
            };
            let len = {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&leaves_buffer[i + 8..i + 10]);
                u16::from_le_bytes(buf) as usize
            };
            assert!(leaves_length >= i + 10 + len);
            let mut buf = Vec::new();
            buf.resize(len, 0);
            buf.copy_from_slice(&leaves_buffer[i + 10..i + 10 + len]);
            leaves.push((pos, VariableBytes(buf)));
            i += 10 + len;
        }
        leaves
    };

    let result = merkle_proof.verify(root, leaves).expect("verify");
    assert!(result);

    0
}
