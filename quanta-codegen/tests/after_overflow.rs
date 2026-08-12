// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An overflowing `after` time gate must fault and revert, not wrap the window open.

use qtv_vm::interp::Interpreter;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;

mod common;
use common::slot_key;

const GAS: u64 = 2_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn put_arg(mem: &mut [u8], e: &EntryArtifact, key: &str, value: u64) {
    let slot = e.args.iter().find(|s| s.key == key).expect("argument");
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn run(
    cc: &CompiledContract,
    e: &EntryArtifact,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, qtv_vm::interp::Fault> {
    Interpreter::for_entry(&cc.container, e.selector, GAS)
        .expect("entry")
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

// opened is field zero, done is field one. The window opens one hour after opened.
const TIMED: &str =
    "contract T { state { opened: u64; done: u64; } genesis { opened = 0; done = 0; } \
     entry act() writes(done) reads(opened) after 1 hours from opened denies opened == 0 { done = 1; } }";

#[test]
fn an_overflowing_base_reverts_instead_of_opening_the_gate() {
    let cc = compile(TIMED);
    let act = entry(&cc, "act");

    let mut storage = BTreeMap::new();
    // opened just below the top of the word, so opened + 3600 seconds overflows.
    storage.insert(slot_key(0), u64::MAX - 100);

    // A small consensus time: if the threshold had wrapped, now would clear it and the body would run.
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, act, "@time", 50);
    let out = run(&cc, act, storage, &mem);
    // The checked add faults on the overflow, so the call reverts and the write to done never lands.
    assert!(out.is_err(), "an overflowing base + duration reverts rather than opening the gate");
}

#[test]
fn a_base_that_does_not_overflow_still_gates_correctly() {
    let cc = compile(TIMED);
    let act = entry(&cc, "act");

    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 100); // window opens at 100 + 3600 = 3700.

    // One second early reverts on the time check.
    let mut early = vec![0u8; 4096];
    put_arg(&mut early, act, "@time", 3699);
    assert!(run(&cc, act, storage.clone(), &early).is_err(), "before the window the gate reverts");

    // At the window the body runs.
    let mut open = vec![0u8; 4096];
    put_arg(&mut open, act, "@time", 3700);
    let out = run(&cc, act, storage, &open).expect("at the window the entry halts");
    assert_eq!(out.get(&slot_key(1)), Some(&1), "the body ran once the window opened");
}
