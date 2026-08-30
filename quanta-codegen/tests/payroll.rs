// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::slot_key;

const TREASURY_SLOT: u64 = 4;
const GAS: u64 = 4_000_000;

const SRC: &str = include_str!("../../examples/Payroll.qs");

fn compiled() -> CompiledContract {
    let program = quanta_parser::parse(SRC).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn fund(
    cc: &CompiledContract,
    treasury: u64,
    funds: u64,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "fund").selector;
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(TREASURY_SLOT), treasury);
    let mut mem = vec![0u8; 4096];
    let off = entry(cc, "fund")
        .args
        .iter()
        .find(|s| s.key == "funds")
        .expect("funds arg")
        .offset as usize;
    mem[off..off + 8].copy_from_slice(&funds.to_be_bytes());
    let voff = entry(cc, "fund")
        .args
        .iter()
        .find(|s| s.key == "@value")
        .expect("value arg")
        .offset as usize;
    mem[voff..voff + 8].copy_from_slice(&funds.to_be_bytes());
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn treasury(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(TREASURY_SLOT)).copied().unwrap_or(0)
}

#[test]
fn a_fund_credits_an_empty_treasury() {
    let cc = compiled();
    let after = fund(&cc, 0, 400_000).expect("funding an empty treasury halts");
    assert_eq!(
        treasury(&after),
        400_000,
        "the treasury holds the funded amount so payroll can be paid"
    );
}

#[test]
fn funds_accumulate_in_the_treasury() {
    let cc = compiled();
    let after = fund(&cc, 100_000, 50_000).expect("a top up halts");
    assert_eq!(
        treasury(&after),
        150_000,
        "a second funding adds to the standing treasury"
    );
}

#[test]
fn a_fund_that_overflows_the_treasury_reverts() {
    let cc = compiled();
    assert_eq!(
        fund(&cc, u64::MAX, 1),
        Err(Fault::Overflow),
        "a funding that would overflow the treasury balance reverts"
    );
}
