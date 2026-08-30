// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

mod common;
use common::slot_key;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

const CAPPED: &str = "contract Capped {\n\
  state { total: u64; }\n\
  entry add(amount: u64) writes(total) {\n\
    total = checked(total + amount);\n\
    emit Added(total);\n\
  }\n\
  invariant total <= 100;\n\
  event Added(value: u64);\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn memory_with(cc: &CompiledContract, values: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    for slot in &cc.entries[0].args {
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
    total: u64,
    amount: u64,
) -> (Result<(), Fault>, BTreeMap<[u8; 32], u64>) {
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), total);
    let mem = memory_with(cc, &[("amount", amount)]);
    let outcome = Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(storage.clone())
        .with_memory(&mem)
        .run();
    match outcome {
        Ok(out) => (Ok(()), out.storage),
        Err(f) => (Err(f), storage),
    }
}

#[test]
fn a_call_within_the_invariant_commits() {
    let cc = compile(CAPPED);
    let (result, storage) = run(&cc, 10, 5);
    assert!(result.is_ok(), "the invariant holds so the call commits");
    assert_eq!(storage.get(&slot_key(0)), Some(&15), "total is written");
}

#[test]
fn a_call_that_breaks_the_invariant_reverts() {
    let cc = compile(CAPPED);
    let (result, storage) = run(&cc, 90, 50);
    assert_eq!(
        result,
        Err(Fault::DivByZero),
        "the broken invariant reverts"
    );
    assert_eq!(
        storage.get(&slot_key(0)),
        Some(&90),
        "state is unchanged after a revert"
    );
}
