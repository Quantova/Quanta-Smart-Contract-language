// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::{compile_contract, CodegenError};

const OVERSIZED_CODE: &str = "contract Rot {\n\
  state { board: GuardianSet<32>; hits: u64; }\n\
  entry rotate(new_board: GuardianSet<32>, approvals: Quorum<2 of 32, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
  entry bump() writes(hits) { hits = 1; }\n\
}\n";

const OVERSIZED_ACCESS: &str = "contract Slots {\n\
  state { b1: GuardianSet<256>; b2: GuardianSet<256>; b3: GuardianSet<256>; \
          b4: GuardianSet<256>; n: u64; }\n\
  entry bump() writes(n) { n = 1; }\n\
}\n";

const MODEST: &str = "contract Small {\n\
  state { board: GuardianSet<4>; hits: u64; }\n\
  entry rotate(new_board: GuardianSet<4>, approvals: Quorum<2 of 4, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
  entry bump() writes(hits) { hits = 1; }\n\
}\n";

fn rejection(src: &str) -> String {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    match compile_contract(&program.contracts[0]) {
        Err(CodegenError::Rejected { what, .. }) => what,
        Err(other) => panic!("expected a rejection, got: {other}"),
        Ok(_) => panic!("a container the virtual machine cannot load must not be emitted"),
    }
}

#[test]
fn a_contract_larger_than_the_code_cap_is_refused() {
    let what = rejection(OVERSIZED_CODE);
    assert!(
        what.contains("code is larger than"),
        "expected a code size rejection, got: {what}"
    );
}

#[test]
fn an_entry_naming_more_slots_than_the_cap_is_refused() {
    let what = rejection(OVERSIZED_ACCESS);
    assert!(
        what.contains("state slots"),
        "expected an access list rejection, got: {what}"
    );
}

#[test]
fn a_contract_within_both_caps_still_compiles() {
    let program = quanta_parser::parse(MODEST).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let compiled = compile_contract(&program.contracts[0]).expect("compile");
    compiled
        .container
        .verify()
        .expect("an emitted container must load");
}
