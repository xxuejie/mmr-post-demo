#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![feature(new_uninit)]

use alloc::{boxed::Box, format, vec::Vec};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_merkle_mountain_range::{
    compiled_proof::{verify, Packable, PackedLeaves, PackedMerkleProof},
    Error, Merge, Result,
};
use ckb_std::{
    ckb_constants::Source,
    default_alloc,
    syscalls::{debug, load_witness},
};
use core::mem::MaybeUninit;

ckb_std::entry!(program_entry);
default_alloc!();

#[derive(Clone, Debug, PartialEq)]
enum VariableBytes {
    Hash(Box<[u8; 32]>),
    Dynamic(Vec<u8>),
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

impl Packable for VariableBytes {
    fn pack(&self) -> Result<Vec<u8>> {
        let d = self.as_bytes();
        if d.len() > u16::MAX as usize {
            return Err(Error::UnpackEof);
        }
        let mut ret = Vec::new();
        ret.resize(d.len() + 2, 0);
        ret[0..2].copy_from_slice(&(d.len() as u16).to_le_bytes());
        ret[2..].copy_from_slice(d);
        Ok(ret)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 2 {
            return Err(Error::UnpackEof);
        }
        let len = {
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&data[0..2]);
            u16::from_le_bytes(buf)
        } as usize;
        if data.len() < 2 + len {
            return Err(Error::UnpackEof);
        }
        if len == 32 {
            let mut d: Box<[u8; 32]> = unsafe { Box::new_uninit().assume_init() };
            d.copy_from_slice(&data[2..2 + len]);
            Ok((VariableBytes::Hash(d), 2 + len))
        } else {
            let mut r = Vec::new();
            r.resize(len, 0);
            r.copy_from_slice(&data[2..2 + len]);
            Ok((VariableBytes::Dynamic(r), 2 + len))
        }
    }
}

static mut _PROOF_BUFFER: [u8; 32 * 1024] = [0u8; 32 * 1024];
fn proof_buffer() -> &'static mut [u8] {
    unsafe { &mut _PROOF_BUFFER }
}

pub fn program_entry() -> i8 {
    let mut root_buffer: Box<[u8; 32]> = unsafe { Box::new_uninit().assume_init() };
    let root_length = match load_witness(&mut root_buffer[..], 0, 0, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading root error {:?}", e));
            return -1;
        }
    };
    assert!(root_length == 32);
    let root = VariableBytes::Hash(root_buffer);

    let proof_length = match load_witness(proof_buffer(), 0, 3, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading proof error {:?}", e));
            return -1;
        }
    };
    assert!(proof_length >= 8);
    let mmr_size = {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&proof_buffer()[0..8]);
        u64::from_le_bytes(buf)
    };
    let mut packed_proof = PackedMerkleProof::new(&proof_buffer()[8..proof_length]);

    #[allow(invalid_value)]
    let mut leaves_buffer: [u8; 32 * 1024] = unsafe { MaybeUninit::uninit().assume_init() };
    let leaves_length = match load_witness(&mut leaves_buffer, 0, 2, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading leaves error {:?}", e));
            return -1;
        }
    };
    let mut packed_leaves = PackedLeaves::new(&leaves_buffer[0..leaves_length]);

    let result =
        verify::<_, Blake2bHash, _, _>(&mut packed_proof, root, mmr_size, &mut packed_leaves)
            .expect("verify");
    assert!(result);

    0
}
