// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;

mod common;
use common::slot_key;

const GAS: u64 = 2_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("the source parses");
    quanta_typeck::check(&program).expect("the source type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("the contract compiles")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries
        .iter()
        .find(|e| e.name == name)
        .expect("the entry")
}

fn put_arg(mem: &mut [u8], e: &EntryArtifact, key: &str, value: u64) {
    let slot = e.args.iter().find(|s| s.key == key).expect("the argument");
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn run(
    cc: &CompiledContract,
    e: &EntryArtifact,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::for_entry(&cc.container, e.selector, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

const TIMED: &str =
    "contract T { state { opened: u64; done: u64; } genesis { opened = 0; done = 0; } \
     entry act() writes(done) reads(opened) after 1 hours from opened denies opened == 0 { done = 1; } }";

#[test]
fn an_after_guard_reverts_before_its_window_and_passes_after() {
    let cc = compile(TIMED);
    let act = entry(&cc, "act");
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 100);

    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, act, "@time", 3699);
    assert!(
        run(&cc, act, storage.clone(), &mem).is_err(),
        "the entry reverts before its window opens"
    );

    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, act, "@time", 3700);
    let out = run(&cc, act, storage, &mem).expect("the entry halts at the window");
    assert_eq!(
        out.get(&slot_key(1)),
        Some(&1),
        "the body ran once the window opened"
    );
}

const CONFIGURABLE: &str =
    "contract Vesting { state { deposit_time: u64; cooldown: u64; released: u64; } \
     genesis { deposit_time = 0; cooldown = 0; released = 0; } \
     entry release() writes(released) reads(deposit_time, cooldown) \
     after cooldown from deposit_time denies deposit_time == 0 denies cooldown == 0 { released = 1; } }";

#[test]
fn an_expression_target_still_honours_its_from_anchor() {
    let cc = compile(CONFIGURABLE);
    let release = entry(&cc, "release");
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 1_000_000);
    storage.insert(slot_key(1), 604_800);

    let mut early = vec![0u8; 4096];
    put_arg(&mut early, release, "@time", 700_000);
    assert!(
        run(&cc, release, storage.clone(), &early).is_err(),
        "a time below deposit_time plus cooldown reverts even though it clears the bare cooldown"
    );

    let mut open = vec![0u8; 4096];
    put_arg(&mut open, release, "@time", 1_604_800);
    let out = run(&cc, release, storage, &open).expect("the entry halts at the anchored window");
    assert_eq!(
        out.get(&slot_key(2)),
        Some(&1),
        "the body ran once the anchored window opened"
    );
}
