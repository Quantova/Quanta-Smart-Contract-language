// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::slot_key;

const AND_SKIP: &str = "contract AndSkip { state { out: u64; } \
    entry act(z: u64) writes(out) denies (z == 1) && ((1 / z) > 0) { out = 5; } }";

const OR_SKIP: &str = "contract OrSkip { state { out: u64; } \
    entry act(z: u64) writes(out) { guard (z == 0) || ((1 / z) > 0); out = 5; } }";

const FAULTS: &str = "contract Faults { state { out: u64; } \
    entry act(z: u64) writes(out) { guard (1 / z) > 0; out = 5; } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn memory_with(cc: &CompiledContract, z: u64) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    let off = cc.entries[0]
        .args
        .iter()
        .find(|s| s.key == "z")
        .expect("z argument")
        .offset as usize;
    mem[off..off + 8].copy_from_slice(&z.to_be_bytes());
    mem
}

fn run(cc: &CompiledContract, z: u64) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let mem = memory_with(cc, z);
    Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn and_skips_a_faulting_right_operand_when_the_left_is_false() {
    let cc = compile(AND_SKIP);
    let storage = run(&cc, 0).expect("a false left skips the divide by zero on the right");
    assert_eq!(
        storage.get(&slot_key(0)),
        Some(&5),
        "the body ran, so the right was skipped"
    );
}

#[test]
fn or_skips_a_faulting_right_operand_when_the_left_is_true() {
    let cc = compile(OR_SKIP);
    let storage = run(&cc, 0).expect("a true left skips the divide by zero on the right");
    assert_eq!(
        storage.get(&slot_key(0)),
        Some(&5),
        "the body ran, so the right was skipped"
    );
}

#[test]
fn or_evaluates_the_right_operand_when_the_left_does_not_decide() {
    let cc = compile(OR_SKIP);
    let storage = run(&cc, 1).expect("a false left evaluates the right");
    assert_eq!(
        storage.get(&slot_key(0)),
        Some(&5),
        "the right decided the guard and the body ran"
    );
}

#[test]
fn the_divide_by_zero_on_the_right_is_a_real_fault_when_reached() {
    let cc = compile(FAULTS);
    assert_eq!(
        run(&cc, 0),
        Err(Fault::DivByZero),
        "dividing by zero faults when nothing skips it"
    );
}
