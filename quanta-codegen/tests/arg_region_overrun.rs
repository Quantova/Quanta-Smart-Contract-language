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
    let err =
        compile_contract(&program.contracts[0]).expect_err("the oversized board must be refused");
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

fn many_sends(count: usize) -> String {
    let body: String = (0..count)
        .map(|_| "send_asset(caller, caller, 1); ")
        .collect();
    format!(
        "contract Spray {{ state {{ owner: Q_Address; }} \
         genesis {{ owner = deployer; }} \
         entry spray() {{ guard caller == owner; {body}}} }}"
    )
}

#[test]
fn an_entry_whose_working_memory_outgrows_the_machine_is_refused() {
    let program = quanta_parser::parse(&many_sends(400)).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let err = compile_contract(&program.contracts[0])
        .expect_err("the working memory would run past the machine's memory");
    let text = format!("{err:?}");
    assert!(
        text.contains("working memory"),
        "the rejection names the overrun, got {text}"
    );
}

#[test]
fn an_entry_with_a_few_sends_still_compiles() {
    let program = quanta_parser::parse(&many_sends(8)).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("a few sends compile");
}
