//! Two word arithmetic for u128 state fields, run end to end in the interpreter. A carry crosses the

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;

const GAS: u64 = 2_000_000;
/// Matches the code generator's high word offset for a two word scalar field.
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
    storage: BTreeMap<u64, u64>,
    mem: &[u8],
) -> Result<BTreeMap<u64, u64>, Fault> {
    Interpreter::for_entry(&cc.container, e.selector, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

// total is field zero (low at slot 0, high at 0 | HI); cap is field one (low at slot 1, high at 1 | HI).
const ADD: &str =
    "contract W { state { total: u128; cap: u128; } genesis { total = 0; cap = 0; } \
     entry add(amount: u64) writes(total) reads(cap) limits total + amount <= cap \
     { guard total <= cap; total += amount; } }";

const SUB: &str =
    "contract W { state { total: u128; } genesis { total = 0; } \
     entry take(amount: u64) writes(total) { total -= amount; } }";

#[test]
fn a_low_word_add_carries_into_the_high_word() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 5);
    let mut storage = BTreeMap::new();
    // The low word is at its maximum, so adding five carries into the high word. The cap is far above
    // in the high word so the limits clause passes.
    storage.insert(0, u64::MAX);
    storage.insert(1 | HI, 100);
    let out = run(&cc, add, storage, &mem).expect("the add halts");
    assert_eq!(out.get(&0), Some(&4), "the low word wraps to four");
    assert_eq!(out.get(&HI), Some(&1), "the carry lands in the high word");
}

#[test]
fn a_low_word_sub_borrows_from_the_high_word() {
    let cc = compile(SUB);
    let take = entry(&cc, "take");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, take, "amount", 5);
    let mut storage = BTreeMap::new();
    // The value is one in the high word and zero in the low, so subtracting five borrows down.
    storage.insert(0, 0);
    storage.insert(HI, 1);
    let out = run(&cc, take, storage, &mem).expect("the subtract halts");
    assert_eq!(out.get(&0), Some(&(u64::MAX - 4)), "the low word borrows down");
    assert_eq!(out.get(&HI).copied().unwrap_or(0), 0, "the high word is spent");
}

#[test]
fn a_checked_overflow_reverts() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 1);
    let mut storage = BTreeMap::new();
    // The whole two word value is at its maximum, so the wide sum in the limits clause overflows and
    // reverts rather than wrapping.
    storage.insert(0, u64::MAX);
    storage.insert(HI, u64::MAX);
    storage.insert(1, u64::MAX);
    storage.insert(1 | HI, u64::MAX);
    assert!(
        run(&cc, add, storage, &mem).is_err(),
        "a wide overflow reverts rather than wrapping"
    );
}

#[test]
fn a_two_word_limit_orders_the_full_value() {
    let cc = compile(ADD);
    let add = entry(&cc, "add");

    // The cap has a nonzero high word, so a total that fits in the low word is under it and the limits
    // clause passes.
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 10);
    let mut storage = BTreeMap::new();
    storage.insert(0, 100);
    storage.insert(1 | HI, 1);
    assert!(
        run(&cc, add, storage, &mem).is_ok(),
        "a total below the wide cap passes"
    );

    // The total is larger in the high word even though its low word is smaller, so it is above the
    // cap and the guard reverts. This is the case a low word only compare would get wrong.
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, add, "amount", 10);
    let mut storage = BTreeMap::new();
    storage.insert(HI, 1);
    storage.insert(1, u64::MAX);
    assert!(
        run(&cc, add, storage, &mem).is_err(),
        "a total above the cap in the high word reverts"
    );
}
