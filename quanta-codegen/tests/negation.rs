// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;

mod common;
use common::slot_key;

const GAS: u64 = 2_000_000;
const HI: u64 = 1 << 56;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("the source parses");
    quanta_typeck::check(&program).expect("the source type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("the contract compiles")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("the entry")
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

const WRAPPING: &str = "contract Neg { state { total: u64; } \
    entry neg(amount: u64) writes(total) { total = wrapping(-amount); } }";

const CHECKED: &str = "contract Neg { state { total: u64; } \
    entry neg(amount: u64) writes(total) { total = checked(-amount); } }";

const WIDE: &str = "contract Neg { state { total: u128; } genesis { total = 0; } \
    entry neg() writes(total) { total = wrapping(-total); } }";

#[test]
fn a_wrapping_negation_is_the_twos_complement() {
    let cc = compile(WRAPPING);
    let e = entry(&cc, "neg");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "amount", 5);
    let out = run(&cc, e, BTreeMap::new(), &mem).expect("the negation halts");
    assert_eq!(
        out.get(&slot_key(0)),
        Some(&(u64::MAX - 4)),
        "negating five wrapping is two to the sixty four minus five"
    );
}

#[test]
fn a_checked_negation_of_zero_is_zero() {
    let cc = compile(CHECKED);
    let e = entry(&cc, "neg");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "amount", 0);
    let out = run(&cc, e, BTreeMap::new(), &mem).expect("negating zero halts");
    assert_eq!(out.get(&slot_key(0)).copied().unwrap_or(0), 0, "negating zero is zero");
}

#[test]
fn a_checked_negation_of_a_positive_reverts() {
    let cc = compile(CHECKED);
    let e = entry(&cc, "neg");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "amount", 1);
    assert_eq!(
        run(&cc, e, BTreeMap::new(), &mem),
        Err(Fault::Overflow),
        "a checked negation of a positive unsigned underflows and reverts"
    );
}

#[test]
fn a_wide_wrapping_negation_borrows_across_both_words() {
    let cc = compile(WIDE);
    let e = entry(&cc, "neg");
    let mem = vec![0u8; 4096];
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 5);
    let out = run(&cc, e, storage, &mem).expect("the wide negation halts");
    assert_eq!(
        out.get(&slot_key(0)),
        Some(&(u64::MAX - 4)),
        "the low word is two to the one twenty eight minus five, low half"
    );
    assert_eq!(
        out.get(&slot_key(HI)),
        Some(&u64::MAX),
        "the high word borrows to its maximum"
    );
}
