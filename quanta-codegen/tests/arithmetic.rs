// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Conformance vectors for the arithmetic forms. The checked form lowers to the checked add opcode

use std::collections::BTreeMap;

mod common;
use common::slot_key;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::compile_contract;

const CHECKED: &str = "contract Adder {\n\
  state { total: u64; }\n\
  entry add(amount: u64) writes(total) { total = checked(total + amount); }\n\
}\n";

const WRAPPING: &str = "contract Adder {\n\
  state { total: u64; }\n\
  entry add(amount: u64) writes(total) { total = wrapping(total + amount); }\n\
}\n";

const BARE: &str = "contract Adder {\n\
  state { total: u64; }\n\
  entry add(amount: u64) writes(total) { total = total + amount; }\n\
}\n";

// Run the single entry with a seeded total and amount, returning the outcome and the total seen on a
// clean halt.
fn run(src: &str, total: u64, amount: u64) -> Result<u64, Fault> {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");

    let mut mem = vec![0u8; 4096];
    let at = cc.entries[0]
        .args
        .iter()
        .find(|slot| slot.key == "amount")
        .expect("the amount argument")
        .offset as usize;
    mem[at..at + 8].copy_from_slice(&amount.to_be_bytes());

    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), total);

    Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| *out.storage.get(&slot_key(0)).expect("total slot"))
}

#[test]
fn the_checked_form_commits_within_range() {
    assert_eq!(run(CHECKED, 10, 5), Ok(15));
}

#[test]
fn the_checked_form_reverts_on_overflow() {
    assert_eq!(
        run(CHECKED, u64::MAX, 1),
        Err(Fault::Overflow),
        "a checked add reverts when it overflows"
    );
}

#[test]
fn the_wrapping_form_takes_the_modular_result() {
    assert_eq!(
        run(WRAPPING, u64::MAX, 1),
        Ok(0),
        "a wrapping add wraps rather than reverts"
    );
}

#[test]
fn a_bare_unbounded_addition_has_no_lowering() {
    // The type checker rejects a bare unbounded addition into a stored integer, so code generation
    // never receives it and there is no lowering at all.
    let program = quanta_parser::parse(BARE).expect("parse");
    assert!(
        quanta_typeck::check(&program).is_err(),
        "a bare unbounded addition must not type check, so it cannot be lowered"
    );
}
