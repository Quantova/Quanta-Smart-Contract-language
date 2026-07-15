//! Asset operation lowering. An asset amount is a stored balance, so split, merge, mint, and burn

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn memory_with(cc: &CompiledContract, entry: usize, values: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    for slot in &cc.entries[entry].args {
        let value = values
            .iter()
            .find(|(k, _)| *k == slot.key)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    mem
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<u64, u64>,
    mem: &[u8],
) -> Result<BTreeMap<u64, u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 300_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

const MERGE: &str = "contract Merge {\n\
  state { pool: Q_Asset<QTOV>; }\n\
  entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) { pool.merge(funds); }\n\
}\n";

#[test]
fn merge_adds_the_incoming_amount_to_the_pooled_balance() {
    let cc = compile(MERGE);
    let mut storage = BTreeMap::new();
    storage.insert(0u64, 100u64); // the pool balance slot
    let mem = memory_with(&cc, 0, &[("funds", 5)]);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(out.get(&0), Some(&105), "the pool must absorb the merge");
}

#[test]
fn merge_overflow_reverts_and_keeps_state() {
    let cc = compile(MERGE);
    let mut storage = BTreeMap::new();
    storage.insert(0u64, u64::MAX);
    let mem = memory_with(&cc, 0, &[("funds", 1)]);
    assert_eq!(
        run(&cc, storage, &mem),
        Err(Fault::Overflow),
        "a merge that overflows the balance must fault"
    );
}

const SPLIT: &str = "contract Split {\n\
  state { reserve: Q_Asset<QTOV>; pool: Q_Asset<QTOV>; }\n\
  entry moveover(req: MoveReq) writes(reserve, pool) conserves QTOV {\n\
    let part = reserve.split(req.amount);\n\
    pool.merge(part);\n\
  }\n\
}\n";

#[test]
fn split_moves_a_balance_between_two_asset_fields_conserving_total() {
    let cc = compile(SPLIT);
    let mut storage = BTreeMap::new();
    storage.insert(0u64, 100u64); // reserve
    storage.insert(1u64, 10u64); // pool
    let mem = memory_with(&cc, 0, &[("req.amount", 30)]);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(out.get(&0), Some(&70), "reserve loses the split amount");
    assert_eq!(out.get(&1), Some(&40), "pool gains the split amount");
}

#[test]
fn splitting_more_than_is_held_reverts() {
    let cc = compile(SPLIT);
    let mut storage = BTreeMap::new();
    storage.insert(0u64, 20u64);
    storage.insert(1u64, 10u64);
    let mem = memory_with(&cc, 0, &[("req.amount", 30)]);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::Overflow),
        "a split larger than the balance must fault"
    );
}

const MINT: &str = "contract Minter {\n\
  asset TKN;\n\
  state { owner: Q_Address; vault: Q_Asset<TKN>; supply: u128; }\n\
  entry issue(order: MintOrder signed by owner)\n\
    mints TKN writes(vault, supply)\n\
    limits supply + order.amount <= 1000000000\n\
  {\n\
    supply += order.amount;\n\
    vault.merge(mint(order.amount));\n\
  }\n\
}\n";

// Seed the argument words and a valid module lattice signature region for the `issue` entry.
fn signed_mint_memory(cc: &CompiledContract, amount: u64) -> Vec<u8> {
    let region_off = 8192usize;
    let (pk, sk) = ml_dsa::keygen(&[7u8; 32]);
    let payload = b"mint order";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);

    let mut mem = vec![0u8; region_off + region.len()];
    let mut put = |key: &str, value: u64| {
        if let Some(slot) = cc.entries[0].args.iter().find(|s| s.key == key) {
            let at = slot.offset as usize;
            mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
    };
    put("order#scheme", 1);
    put("order#ptr", region_off as u64);
    put("order#len", region.len() as u64);
    put("order.amount", amount);
    mem[region_off..].copy_from_slice(&region);
    mem
}

#[test]
fn a_signed_mint_creates_supply_and_credits_the_vault() {
    let cc = compile(MINT);
    let mem = signed_mint_memory(&cc, 500);
    let mut storage = BTreeMap::new();
    storage.insert(1u64, 0u64); // vault
    storage.insert(2u64, 0u64); // supply
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(out.get(&2), Some(&500), "supply grows by the minted amount");
    assert_eq!(
        out.get(&1),
        Some(&500),
        "the vault receives the minted asset"
    );
}
