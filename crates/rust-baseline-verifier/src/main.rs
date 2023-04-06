#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![feature(new_uninit)]

use alloc::{boxed::Box, format, vec::Vec};
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
enum VariableBytes {
    Hash(Box<[u8; 32]>),
    Dynamic(&'static [u8]),
}

impl VariableBytes {
    fn as_bytes(&self) -> &[u8] {
        match self {
            VariableBytes::Hash(d) => &d[..],
            VariableBytes::Dynamic(d) => &d,
        }
    }
}

const HASH_BUILDER: Blake2bBuilder = Blake2bBuilder::new_with_personal(32, *b"ckb-default-hash");

#[derive(Debug)]
struct Blake2bHash;

impl Merge for Blake2bHash {
    type Item = VariableBytes;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item> {
        let mut hasher = Blake2b::uninit();
        HASH_BUILDER.build_from_ref(&mut hasher);
        hasher.update(&lhs.as_bytes());
        hasher.update(&rhs.as_bytes());
        let mut hash: Box<[u8; 32]> = unsafe { Box::new_uninit().assume_init() };
        hasher.finalize_from_ref(&mut hash[..]);
        Ok(VariableBytes::Hash(hash))
    }
}

static mut _ROOT_BUFFER: [u8; 32] = [0u8; 32];
fn root_buffer() -> &'static mut [u8] {
    unsafe { &mut _ROOT_BUFFER }
}

static mut _PROOF_BUFFER: [u8; 32 * 1024] = [0u8; 32 * 1024];
fn proof_buffer() -> &'static mut [u8] {
    unsafe { &mut _PROOF_BUFFER }
}

static mut _LEAVES_BUFFER: [u8; 32 * 1024] = [0u8; 32 * 1024];
fn leaves_buffer() -> &'static mut [u8] {
    unsafe { &mut _LEAVES_BUFFER }
}

pub fn program_entry() -> i8 {
    let root_length = match load_witness(root_buffer(), 0, 0, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading root error {:?}", e));
            return -1;
        }
    };
    assert!(root_length == 32);
    let root = VariableBytes::Dynamic(root_buffer());

    let proof_length = match load_witness(proof_buffer(), 0, 1, Source::Input) {
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
            buf.copy_from_slice(&proof_buffer()[0..8]);
            u64::from_le_bytes(buf)
        };

        let mut i = 8;
        let mut items = Vec::new();
        while i < proof_length {
            assert!(proof_length >= i + 2);
            let len = {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&proof_buffer()[i..i + 2]);
                u16::from_le_bytes(buf) as usize
            };
            assert!(proof_length >= i + 2 + len);
            items.push(VariableBytes::Dynamic(&proof_buffer()[i + 2..i + 2 + len]));
            i += 2 + len;
        }
        MerkleProof::new(mmr_size, items)
    };

    let leaves_length = match load_witness(leaves_buffer(), 0, 2, Source::Input) {
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
                buf.copy_from_slice(&leaves_buffer()[i..i + 8]);
                u64::from_le_bytes(buf)
            };
            let len = {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&leaves_buffer()[i + 8..i + 10]);
                u16::from_le_bytes(buf) as usize
            };
            assert!(leaves_length >= i + 10 + len);
            leaves.push((
                pos,
                VariableBytes::Dynamic(&leaves_buffer()[i + 10..i + 10 + len]),
            ));
            i += 10 + len;
        }
        leaves
    };

    let result = merkle_proof.verify(root, leaves).expect("verify");
    assert!(result);

    0
}
