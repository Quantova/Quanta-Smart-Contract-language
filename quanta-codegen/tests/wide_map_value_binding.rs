// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A u128 order field credited to a `Map<_, u128>` must be recorded and lowered at the full sixteen
//! byte width, not silently narrowed to eight bytes.

use quanta_codegen::{compile_contract, CompiledContract};

const GIVE: &str = "contract Give {\n\
  state { owner: Q_Address; reg: Map<Q_Address, u128>; }\n\
  genesis { owner = deployer; }\n\
  entry give(order: GiveOrder signed by owner) writes(reg) {\n\
    reg.credit(order.to, order.amount);\n\
  }\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

#[test]
fn a_u128_field_credited_to_a_wide_map_is_recorded_at_full_width() {
    let cc = compile(GIVE);
    let slot = cc.entries[0]
        .args
        .iter()
        .find(|s| s.key == "order.amount")
        .expect("the amount argument");
    assert_eq!(slot.width, 16, "a u128 map value must not be narrowed to eight bytes");
}
