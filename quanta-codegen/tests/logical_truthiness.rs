// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `&&`, `||`, and `!` are logical over truthiness, not bitwise. An operand may be a raw non boolean
//! word (an Unknown typed message field is one), so the lowering must canonicalize before combining,
//! or a `denies`/`guard` clause built from such operands would gate on the wrong value.

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::slot_key;

const GAS: u64 = 2_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ent<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn mem_with(cc: &CompiledContract, name: &str, vals: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    for s in &ent(cc, name).args {
        let v = vals.iter().find(|(k, _)| *k == s.key).map(|(_, v)| *v).unwrap_or(0);
        let at = s.offset as usize;
        mem[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    mem
}

fn run(cc: &CompiledContract, name: &str, mem: &[u8]) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let e = ent(cc, name);
    let sel: [u8; SELECTOR_BYTES] = e.selector;
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

// `denies A && B` must fire whenever both operands are truthy, even when the bitwise `A & B` is zero
// (2 & 1 == 0). The operands here are Unknown typed message fields, raw caller supplied words.
const DENY_AND: &str = "contract Deny { state { hits: u64; } \
    entry act(order: Flags) writes(hits) denies order.a && order.b { hits += 1; } }";

#[test]
fn denies_over_truthy_non_one_operands_fires() {
    let cc = compile(DENY_AND);
    // both truthy, bitwise and is zero: the deny must still fire and revert, leaving no write.
    let mem = mem_with(&cc, "act", &[("order.a", 2), ("order.b", 1)]);
    assert!(run(&cc, "act", &mem).is_err(), "a && b with a=2,b=1 is truthy, the deny must fire");
    // one operand zero: the deny must not fire, the body runs.
    let mem = mem_with(&cc, "act", &[("order.a", 2), ("order.b", 0)]);
    let out = run(&cc, "act", &mem).expect("a false operand leaves the deny unfired");
    assert_eq!(out.get(&slot_key(0)), Some(&1), "the body ran when the deny did not fire");
}

// `guard A || B` passes when either operand is truthy; the truthy value it yields must be a clean
// boolean so a later bitwise combine over it is not corrupted.
const GUARD_OR: &str = "contract Or { state { hits: u64; } \
    entry act(order: Flags) writes(hits) { guard order.a || order.b; hits += 1; } }";

#[test]
fn guard_over_truthy_non_one_operands_passes() {
    let cc = compile(GUARD_OR);
    let mem = mem_with(&cc, "act", &[("order.a", 2), ("order.b", 0)]);
    let out = run(&cc, "act", &mem).expect("a truthy left passes the guard");
    assert_eq!(out.get(&slot_key(0)), Some(&1));
    let mem = mem_with(&cc, "act", &[("order.a", 0), ("order.b", 0)]);
    assert!(run(&cc, "act", &mem).is_err(), "both false fails the guard and reverts");
}

// `guard !A` must fail whenever A is truthy, including A > 1 where a bitwise xor with one would leave
// a truthy value and wrongly pass the guard.
const GUARD_NOT: &str = "contract Not { state { hits: u64; } \
    entry act(order: Flags) writes(hits) { guard !order.a; hits += 1; } }";

#[test]
fn not_of_a_truthy_non_one_operand_is_false() {
    let cc = compile(GUARD_NOT);
    // a = 2 is truthy, so !a is false, so the guard must fail and revert.
    let mem = mem_with(&cc, "act", &[("order.a", 2)]);
    assert!(run(&cc, "act", &mem).is_err(), "!2 is false, the guard must fail");
    // a = 0 is false, so !a is true, so the guard passes.
    let mem = mem_with(&cc, "act", &[("order.a", 0)]);
    let out = run(&cc, "act", &mem).expect("!0 is true, the guard passes");
    assert_eq!(out.get(&slot_key(0)), Some(&1));
}

// A non-canonical `||` result must not corrupt an outer `&&`: (a || b) && c with a=2,c=1 is truthy.
const NESTED: &str = "contract Nest { state { hits: u64; } \
    entry act(order: Flags) writes(hits) denies (order.a || order.b) && order.c { hits += 1; } }";

#[test]
fn a_nested_or_result_feeds_a_bitwise_and_correctly() {
    let cc = compile(NESTED);
    // (2 || 0) && 1 is truthy, the deny must fire; a raw `2 & 1` would be zero and wrongly proceed.
    let mem = mem_with(&cc, "act", &[("order.a", 2), ("order.b", 0), ("order.c", 1)]);
    assert!(run(&cc, "act", &mem).is_err(), "(a||b) && c truthy, the deny must fire");
    // c = 0 makes the whole thing false, the deny does not fire.
    let mem = mem_with(&cc, "act", &[("order.a", 2), ("order.b", 0), ("order.c", 0)]);
    let out = run(&cc, "act", &mem).expect("c false leaves the deny unfired");
    assert_eq!(out.get(&slot_key(0)), Some(&1));
}
