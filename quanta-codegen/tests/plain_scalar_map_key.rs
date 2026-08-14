// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

const GAS: u64 = 4_000_000;

const SRC: &str = "contract C { state { total: u64; m: Map<u64, u64>; } \
    entry act(order: M) writes(total, m) { \
      total = wrapping(total + order.k); \
      m.credit(order.k, order.v); \
    } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ent<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn run(cc: &CompiledContract, name: &str, kv: &[(&str, u64)]) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let e = ent(cc, name);
    let mut mem = vec![0u8; 8192];
    for s in &e.args {
        if let Some((_, v)) = kv.iter().find(|(k, _)| *k == s.key) {
            let at = s.offset as usize;
            mem[at..at + 8].copy_from_slice(&v.to_be_bytes());
        }
    }
    let sel: [u8; SELECTOR_BYTES] = e.selector;
    Interpreter::for_entry(&cc.container, sel, GAS)
        .expect("entry")
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn slot_of(storage: &BTreeMap<[u8; 32], u64>, value: u64) -> Option<[u8; 32]> {
    storage.iter().find(|(_, &v)| v == value).map(|(k, _)| *k)
}

#[test]
fn the_ledger_key_does_not_depend_on_the_credited_amount() {
    let cc = compile(SRC);
    let a = run(&cc, "act", &[("order.k", 42), ("order.v", 100)]).expect("run a");
    let b = run(&cc, "act", &[("order.k", 42), ("order.v", 200)]).expect("run b");
    let ka = slot_of(&a, 100).expect("balance a stored");
    let kb = slot_of(&b, 200).expect("balance b stored");
    assert_eq!(ka, kb, "the same key must credit the same slot regardless of the amount");
}

#[test]
fn distinct_keys_credit_distinct_slots() {
    let cc = compile(SRC);
    let a = run(&cc, "act", &[("order.k", 1), ("order.v", 100)]).expect("run a");
    let b = run(&cc, "act", &[("order.k", 2), ("order.v", 100)]).expect("run b");
    assert_ne!(
        slot_of(&a, 100).expect("a"),
        slot_of(&b, 100).expect("b"),
        "different keys must credit different slots"
    );
}
