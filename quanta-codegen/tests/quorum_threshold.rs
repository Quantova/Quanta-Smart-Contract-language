// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::compile_contract;

fn try_compile(spec: &str) -> Result<quanta_codegen::CompiledContract, String> {
    let src = format!(
        "contract C {{ state {{ board: GuardianSet<3>; counter: u64; }} \
         entry act(approvals: Quorum<{spec}, board>) writes(counter) {{ counter = checked(counter + 1); }} }}"
    );
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).map_err(|e| e.to_string())
}

#[test]
fn a_zero_threshold_quorum_is_refused() {
    let err = try_compile("0 of 3").expect_err("a zero threshold quorum must be refused at compile time");
    assert!(err.contains("threshold"), "the rejection names the threshold: {err}");
}

#[test]
fn a_threshold_above_the_set_size_is_refused() {
    let err = try_compile("4 of 3").expect_err("a threshold above the set size must be refused");
    assert!(err.contains("threshold"), "the rejection names the threshold: {err}");
}

#[test]
fn a_met_threshold_still_compiles() {
    try_compile("2 of 3").expect("a real threshold still compiles");
    try_compile("1 of 3").expect("a single signer threshold still compiles");
    try_compile("3 of 3").expect("a full set threshold still compiles");
}

#[test]
fn the_no_signature_bypass_cannot_be_built() {
    let cc = try_compile("0 of 3");
    assert!(
        cc.is_err(),
        "the fail open zero threshold entry must not compile, so no unsigned caller can drive it"
    );
}
