// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A `limits` clause and a `denies` clause lower to real runtime traps rather than to nothing. A

use std::collections::BTreeMap;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::slot_key;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn memory_with(cc: &CompiledContract, entry: usize, values: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
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
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

const DENY: &str = "contract Gate { state { flag: u64; hits: u64; } \
    entry act(x: u64) reads(flag) writes(hits) denies flag == 1 { hits = x; } }";

const DENY_BARE: &str = "contract Gate { state { flag: u64; hits: u64; } \
    entry act(x: u64) reads(flag) writes(hits) { hits = x; } }";

const LIMIT: &str = "contract Cap { state { cap: u64; out: u64; } \
    entry take(x: u64) reads(cap) writes(out) limits x <= cap { out = x; } }";

const LIMIT_BARE: &str = "contract Cap { state { cap: u64; out: u64; } \
    entry take(x: u64) reads(cap) writes(out) { out = x; } }";

#[test]
fn a_denies_clause_grows_the_container_over_the_same_entry_without_it() {
    let with = compile(DENY);
    let without = compile(DENY_BARE);
    assert!(
        with.container.code.len() > without.container.code.len(),
        "the denies clause must emit instructions, was {} vs {}",
        with.container.code.len(),
        without.container.code.len()
    );
}

#[test]
fn a_limits_clause_grows_the_container_over_the_same_entry_without_it() {
    let with = compile(LIMIT);
    let without = compile(LIMIT_BARE);
    assert!(
        with.container.code.len() > without.container.code.len(),
        "the limits clause must emit instructions, was {} vs {}",
        with.container.code.len(),
        without.container.code.len()
    );
}

#[test]
fn a_denies_clause_reverts_when_its_condition_holds() {
    let cc = compile(DENY);
    let mem = memory_with(&cc, 0, &[("x", 7)]);

    // flag is zero, so the denied condition is false and the entry runs.
    let mut open = BTreeMap::new();
    open.insert(slot_key(0), 0u64);
    assert_eq!(
        run(&cc, open, &mem).expect("an undenied call halts").get(&slot_key(1)),
        Some(&7),
        "an undenied call writes its state"
    );

    // flag is one, so the denied condition holds and the entry reverts to the trap.
    let mut denied = BTreeMap::new();
    denied.insert(slot_key(0), 1u64);
    assert_eq!(
        run(&cc, denied, &mem),
        Err(Fault::DivByZero),
        "a denied call reverts at the trap"
    );
}

#[test]
fn a_limits_clause_reverts_when_the_bound_is_broken() {
    let cc = compile(LIMIT);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 10u64); // cap

    // x within the cap passes.
    let ok = memory_with(&cc, 0, &[("x", 5)]);
    assert_eq!(
        run(&cc, storage.clone(), &ok)
            .expect("a bounded call halts")
            .get(&slot_key(1)),
        Some(&5),
        "a value under the cap writes its state"
    );

    // x above the cap breaks the limit and reverts.
    let over = memory_with(&cc, 0, &[("x", 20)]);
    assert_eq!(
        run(&cc, storage, &over),
        Err(Fault::DivByZero),
        "a value over the cap reverts at the trap"
    );
}
