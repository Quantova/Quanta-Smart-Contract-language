// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A caller argument region that would overrun the fixed asset local base is refused at codegen,
//! rather than silently letting an asset local write land inside a signed argument and corrupt
//! quorum authenticated data.

use quanta_codegen::compile_contract;

// A GuardianSet<200> parameter carries 200*32 = 6400 bytes, pushing the argument region well past the
// asset local base at 4096. Before the guard this silently miscompiled the quorum authenticated rotation.
const BIG_BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<200>; }\n\
  entry rotate(new_board: GuardianSet<200>, approvals: Quorum<100 of 200, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
}\n";

// The same shape at a sane width still compiles, proving the guard rejects only the overrun.
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
