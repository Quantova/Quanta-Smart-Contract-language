// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::slot_key;

const RESERVE_SLOT: u64 = 4;
const GAS: u64 = 4_000_000;

const SRC: &str = include_str!("../../examples/Vault.qs");

fn compiled() -> CompiledContract {
    let program = quanta_parser::parse(SRC).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn deposit(cc: &CompiledContract, reserve: u64, funds: u64) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "deposit").selector;
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(RESERVE_SLOT), reserve);
    let mut mem = vec![0u8; 4096];
    let off = entry(cc, "deposit").args.iter().find(|s| s.key == "funds").expect("funds arg").offset as usize;
    mem[off..off + 8].copy_from_slice(&funds.to_be_bytes());
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn reserve(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(RESERVE_SLOT)).copied().unwrap_or(0)
}

#[test]
fn a_deposit_funds_an_empty_reserve() {
    let cc = compiled();
    let after = deposit(&cc, 0, 25_000).expect("a deposit into an empty reserve halts");
    assert_eq!(reserve(&after), 25_000, "the reserve holds the deposited amount so the vault can pay out");
}

#[test]
fn deposits_accumulate_in_the_reserve() {
    let cc = compiled();
    let after = deposit(&cc, 10_000, 5_000).expect("a top up halts");
    assert_eq!(reserve(&after), 15_000, "a second deposit adds to the standing reserve");
}

#[test]
fn a_deposit_that_overflows_the_reserve_reverts() {
    let cc = compiled();
    assert_eq!(
        deposit(&cc, u64::MAX, 1),
        Err(Fault::Overflow),
        "a deposit that would overflow the reserve balance reverts"
    );
}
