use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::JsonBytes;
use ckb_merkle_mountain_range::{
    compiled_proof::{pack_compiled_merkle_proof, pack_leaves, Packable, ValueMerge},
    util::MemStore,
    Error, MMRStoreReadOps, Merge, Result, MMR,
};
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::H256;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, RngCore, SeedableRng};
use serde_json::{from_str, to_string_pretty};
use std::time::SystemTime;

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

impl Packable for VariableBytes {
    fn pack(&self) -> Result<Vec<u8>> {
        if self.0.len() > u16::MAX as usize {
            return Err(Error::UnpackEof);
        }
        let mut ret = Vec::new();
        ret.resize(self.0.len() + 2, 0);
        ret[0..2].copy_from_slice(&(self.0.len() as u16).to_le_bytes());
        ret[2..].copy_from_slice(&self.0);
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
        let mut r = Vec::new();
        r.resize(len, 0);
        r.copy_from_slice(&data[2..2 + len]);
        Ok((VariableBytes(r), 2 + len))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!(
            "Usage: {} <output json filename> <verifier binaries ...>",
            args[0]
        );
        return;
    }

    let seed: u64 = match std::env::var("SEED") {
        Ok(val) => str::parse(&val).expect("parsing number"),
        Err(_) => SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };
    println!("Seed: {}", seed);

    let mut rng = StdRng::seed_from_u64(seed);

    let store = MemStore::default();
    let mut mmr = MMR::<_, Blake2bHash, _>::new(0, &store);

    let position = rng.gen_range(1000..3000);
    let leafs = rng.gen_range(1..100);

    println!("Total leafs: {}, tested leafs: {}", position, leafs);
    let positions: Vec<u64> = (0..position)
        .map(|_i| {
            let mut data = [0u8; 32];
            rng.fill_bytes(&mut data[..]);

            mmr.push(VariableBytes(data.to_vec())).expect("push")
        })
        .collect();
    let mmr_size = mmr.mmr_size();
    mmr.commit().expect("commit");
    println!("MMR size: {}", mmr_size);

    let chosen = {
        let mut source: Vec<u64> = positions.clone();
        source.shuffle(&mut rng);
        let mut r = source[0..leafs].to_vec();
        r.sort();
        r
    };

    let mmr = MMR::<_, Blake2bHash, _>::new(mmr_size, &store);
    let root = mmr.get_root().expect("get_root");
    let proof = mmr.gen_proof(chosen.clone()).expect("gen proof");

    let leaves: Vec<_> = chosen
        .iter()
        .map(|i| {
            let value = (&store)
                .get_elem(*i)
                .expect("get_elem")
                .expect("item missing");
            (*i, value)
        })
        .collect();

    let proof_bytes: Vec<u8> = {
        let mut data = vec![];
        data.extend(proof.mmr_size().to_le_bytes());
        for item in proof.proof_items() {
            data.extend(item.pack().expect("pack"));
        }
        data
    };

    let leaves_bytes: Vec<u8> = pack_leaves(&leaves).expect("pack");

    println!(
        "Proof bytes: {}, leaf bytes: {} leaves: {}",
        proof_bytes.len(),
        leaves_bytes.len(),
        leaves.len(),
    );

    let mmr_size = proof.mmr_size();
    let compiled_proof = proof.compile::<ValueMerge<_>>(chosen).expect("compile");
    let compiled_proof_bytes: Vec<u8> = {
        let mut data = vec![];
        data.extend(mmr_size.to_le_bytes());
        data.extend(pack_compiled_merkle_proof(&compiled_proof).expect("pack compiled proof"));
        data
    };

    let mut tx: ReprMockTransaction =
        from_str(&String::from_utf8_lossy(include_bytes!("./dummy_tx.json"))).expect("json");

    tx.tx.witnesses[0] = JsonBytes::from_vec(root.0);
    tx.tx.witnesses[1] = JsonBytes::from_vec(proof_bytes);
    tx.tx.witnesses[2] = JsonBytes::from_vec(leaves_bytes);
    tx.tx.witnesses[3] = JsonBytes::from_vec(compiled_proof_bytes);

    for (i, arg) in args[2..].iter().enumerate() {
        let binary = std::fs::read(arg).expect("read");
        let hash = blake2b_256(&binary).to_vec();

        tx.mock_info.inputs[i].output.lock.code_hash = H256::from_slice(&hash).expect("H256");
        tx.mock_info.cell_deps[i].data = JsonBytes::from_vec(binary);
    }

    let json = to_string_pretty(&tx).expect("json");
    std::fs::write(&args[1], &json).expect("write");
}
