// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::compile_contract;

const BIG_BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<200>; }\n\
  entry rotate(new_board: GuardianSet<200>, approvals: Quorum<100 of 200, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
}\n";

const SMALL_BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<3>; }\n\
  entry rotate(new_board: GuardianSet<3>, approvals: Quorum<2 of 3, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
}\n";

#[test]
fn a_wide_argument_region_is_refused_before_it_overruns_the_scratch_floor() {
    let program = quanta_parser::parse(BIG_BOARD).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let err = compile_contract(&program.contracts[0]).expect_err("the oversized board must be refused");
    let text = format!("{err:?}");
    assert!(
        text.contains("scratch memory floor"),
        "the rejection names the overrun, got {text}"
    );
}

#[test]
fn a_sane_width_board_still_compiles() {
    let program = quanta_parser::parse(SMALL_BOARD).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("a sane width board compiles");
}
