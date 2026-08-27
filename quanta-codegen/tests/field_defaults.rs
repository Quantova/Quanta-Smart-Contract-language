// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::{selector, GENESIS_SIGNATURE};
use qtv_vm::interp::Interpreter;
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::slot_key;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn run_genesis(cc: &CompiledContract) -> BTreeMap<[u8; 32], u64> {
    let gsel = selector(GENESIS_SIGNATURE);
    let mem = vec![0u8; 4096];
    Interpreter::for_entry(&cc.container, gsel, 200_000)
        .expect("the genesis selector resolves")
        .with_memory(&mem)
        .run()
        .expect("genesis halts")
        .storage
}

#[test]
fn a_default_reaches_storage_when_genesis_does_not_set_it() {
    let cc = compile(
        "contract Vaulty {\n\
         state { owner: Q_Address; cap: u64 = 50000; opened: u8 = 1; }\n\
         genesis { owner = deployer; }\n\
         entry touch(step: u64) writes(cap) { cap = checked(cap + step); }\n\
         }\n",
    );
    let storage = run_genesis(&cc);
    assert_eq!(storage.get(&slot_key(4)), Some(&50000), "cap takes its default, not zero");
    assert_eq!(storage.get(&slot_key(5)), Some(&1), "opened takes its default, not zero");
}

#[test]
fn defaults_seed_storage_even_without_a_genesis_block() {
    let cc = compile(
        "contract Defs {\n\
         state { a: u64 = 7; b: u64 = 42; }\n\
         entry touch(step: u64) writes(a) { a = checked(a + step); }\n\
         }\n",
    );
    let storage = run_genesis(&cc);
    assert_eq!(storage.get(&slot_key(0)), Some(&7), "a takes its default");
    assert_eq!(storage.get(&slot_key(1)), Some(&42), "b takes its default");
}

#[test]
fn an_explicit_genesis_assignment_overrides_a_default() {
    let cc = compile(
        "contract Over {\n\
         state { x: u64 = 99; }\n\
         genesis { x = 5; }\n\
         entry touch(step: u64) writes(x) { x = checked(x + step); }\n\
         }\n",
    );
    let storage = run_genesis(&cc);
    assert_eq!(storage.get(&slot_key(0)), Some(&5), "the genesis assignment wins over the default");
}
