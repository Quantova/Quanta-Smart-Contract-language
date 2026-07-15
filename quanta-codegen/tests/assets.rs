//! Asset operation lowering. An asset amount is a stored balance, so split, merge, mint, and burn

use std::collections::BTreeMap;

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
