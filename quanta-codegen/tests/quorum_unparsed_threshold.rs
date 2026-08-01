// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A quorum parameter that names a threshold or set the lowering cannot read as `M of N, set` must be
//! refused, never compiled into an entry that carries no signature verification at all.

use qtv_vm::isa::{decode, OpCode};
use quanta_codegen::{compile_contract, CompiledContract};

fn try_compile(spec: &str) -> Result<CompiledContract, String> {
    let src = format!(
        "contract C {{ state {{ board: GuardianSet<3>; counter: u64; }} \
         entry act(approvals: Quorum<{spec}>) writes(counter) {{ counter = checked(counter + 1); }} }}"
    );
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).map_err(|e| e.to_string())
}

fn verifies(cc: &CompiledContract) -> bool {
    let code = &cc.container.code;
    let mut pc = 0;
    while pc < code.len() {
        let (instr, len) = decode(code, pc).expect("decode");
        if matches!(instr.opcode(), OpCode::VerifyMl | OpCode::VerifySlh) {
            return true;
        }
        pc += len;
    }
    false
}

fn no_unsigned_entry(spec: &str) {
    match try_compile(spec) {
        Err(_) => {}
        Ok(cc) => assert!(
            verifies(&cc),
            "a Quorum<{spec}> entry compiled with no signature verification, so an unsigned caller can drive it"
        ),
    }
}

#[test]
fn a_well_formed_quorum_emits_verification() {
    let cc = try_compile("2 of 3, board").expect("a real quorum compiles");
    assert!(verifies(&cc), "the control quorum must emit a verify");
}

#[test]
fn an_overflowing_threshold_is_not_silently_unverified() {
    // 29 nines exceed u64, so the threshold cannot be read back as a number.
    no_unsigned_entry("99999999999999999999999999999 of 3, board");
}

#[test]
fn an_overflowing_set_size_is_not_silently_unverified() {
    no_unsigned_entry("2 of 99999999999999999999999999999, board");
}

#[test]
fn a_quorum_with_no_set_is_not_silently_unverified() {
    no_unsigned_entry("2 of 3");
}
