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

const ADD: &str =
    "contract W { state { total: u128; cap: u128; } genesis { total = 0; cap = 0; } \
     entry add(amount: u64) writes(total) reads(cap) limits total + amount <= cap \
     { guard total <= cap; total += amount; } }";

const SUB: &str =
    "contract W { state { total: u128; } genesis { total = 0; } \
     entry take(amount: u64) writes(total) { total -= amount; } }";

const LIT: &str =
    "contract W { state { total: u128; } genesis { total = 0; } \
     entry set() writes(total) { total = 20_000_000_000_000_000_000; } }";

#[test]
fn a_wide_literal_stores_across_both_words() {
    let cc = compile(LIT);
    let set = entry(&cc, "set");
    let mem = vec![0u8; 4096];
    let out = run(&cc, set, BTreeMap::new(), &mem).expect("the set halts");
    assert_eq!(out.get(&slot_key(0)), Some(&1_553_255_926_290_448_384));
    assert_eq!(out.get(&slot_key(HI)), Some(&1));
}

#[test]
fn a_low_word_add_carries_into_the_high_word() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 5);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), u64::MAX);
    storage.insert(slot_key(1 | HI), 100);
    let out = run(&cc, add, storage, &mem).expect("the add halts");
    assert_eq!(out.get(&slot_key(0)), Some(&4), "the low word wraps to four");
    assert_eq!(out.get(&slot_key(HI)), Some(&1), "the carry lands in the high word");
}

#[test]
fn a_low_word_sub_borrows_from_the_high_word() {
    let cc = compile(SUB);
    let take = entry(&cc, "take");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, take, "amount", 5);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 0);
    storage.insert(slot_key(HI), 1);
    let out = run(&cc, take, storage, &mem).expect("the subtract halts");
    assert_eq!(out.get(&slot_key(0)), Some(&(u64::MAX - 4)), "the low word borrows down");
    assert_eq!(out.get(&slot_key(HI)).copied().unwrap_or(0), 0, "the high word is spent");
}

#[test]
fn a_checked_overflow_reverts() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 1);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), u64::MAX);
    storage.insert(slot_key(HI), u64::MAX);
    storage.insert(slot_key(1), u64::MAX);
    storage.insert(slot_key(1 | HI), u64::MAX);
    assert!(
        run(&cc, add, storage, &mem).is_err(),
        "a wide overflow reverts rather than wrapping"
    );
}

const MUL: &str =
    "contract W { state { total: u128; } genesis { total = 0; } \
     entry wscale(factor: u64) writes(total) { total = wrapping(total * factor); } \
     entry cscale(factor: u64) writes(total) { total = checked(total * factor); } }";

#[test]
fn a_wrapping_multiply_stays_in_the_low_word() {
    let cc = compile(MUL);
    let e = entry(&cc, "wscale");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "factor", 6);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 7);
    let out = run(&cc, e, storage, &mem).expect("the multiply halts");
    assert_eq!(out.get(&slot_key(0)), Some(&42), "seven times six is forty two");
    assert_eq!(
        out.get(&slot_key(HI)).copied().unwrap_or(0),
        0,
        "no carry into the high word"
    );
}

#[test]
fn a_wrapping_multiply_carries_into_the_high_word() {
    let cc = compile(MUL);
    let e = entry(&cc, "wscale");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "factor", 4);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 1u64 << 63);
    let out = run(&cc, e, storage, &mem).expect("the multiply halts");
    assert_eq!(
        out.get(&slot_key(0)).copied().unwrap_or(0),
        0,
        "the low word product is zero"
    );
    assert_eq!(out.get(&slot_key(HI)), Some(&2), "the product lands two in the high word");
}

#[test]
fn a_checked_multiply_without_overflow_passes() {
    let cc = compile(MUL);
    let e = entry(&cc, "cscale");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "factor", 5);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 3);
    let out = run(&cc, e, storage, &mem).expect("the checked multiply halts");
    assert_eq!(out.get(&slot_key(0)), Some(&15), "three times five is fifteen");
    assert_eq!(
        out.get(&slot_key(HI)).copied().unwrap_or(0),
        0,
        "no high word"
    );
}

#[test]
fn a_checked_multiply_overflow_reverts() {
    let cc = compile(MUL);
    let e = entry(&cc, "cscale");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "factor", 1u64 << 63);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(HI), 2);
    assert!(
        run(&cc, e, storage, &mem).is_err(),
        "a product at or above two to the one hundred twenty eighth reverts"
    );
}

#[test]
fn a_two_word_limit_orders_the_full_value() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");

    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 10);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 100);
    storage.insert(slot_key(1 | HI), 1);
    assert!(
        run(&cc, add, storage, &mem).is_ok(),
        "a total below the wide cap passes"
    );

    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 10);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(HI), 1);
    storage.insert(slot_key(1), u64::MAX);
    assert!(
        run(&cc, add, storage, &mem).is_err(),
        "a total above the cap in the high word reverts"
    );
}
