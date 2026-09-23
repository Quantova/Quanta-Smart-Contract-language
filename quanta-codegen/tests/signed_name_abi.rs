// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::{compile_contract, CompiledContract};

const BARE: &str = "contract N1 {\n\
  state { admin: Q_Address; names: Registry<Q_Name>; }\n\
  entry claim(label: Q_Name signed by admin) writes(names) { names.insert(label); }\n\
}\n";

const THROUGH_LEN: &str = "contract N2 {\n\
  state { admin: Q_Address; names: Registry<Q_Name>; }\n\
  entry claim(label: Q_Name signed by admin) writes(names) {\n\
    guard label.len > 2;\n\
    names.insert(label);\n\
  }\n\
}\n";

const NAME_WINDOW: u64 = 32;
const NAME_LEN: u64 = 8;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn signed_width(cc: &CompiledContract) -> u64 {
    let entry = &cc.entries[0];
    entry.signed_orders[0]
        .fields
        .iter()
        .map(|field| {
            entry
                .args
                .iter()
                .find(|slot| &slot.key == field)
                .unwrap_or_else(|| {
                    panic!("the descriptor names `{field}`, which is not an argument")
                })
                .width
        })
        .sum()
}

#[test]
fn a_signed_name_publishes_its_length_word() {
    let cc = compile(BARE);
    assert_eq!(
        cc.entries[0].signed_orders[0].fields,
        vec!["label".to_string(), "label#len".to_string()],
        "the published order must cover every word the verifier hashes"
    );
}

#[test]
fn the_published_order_covers_what_the_verifier_hashes() {
    for src in [BARE, THROUGH_LEN] {
        let cc = compile(src);
        assert_eq!(
            signed_width(&cc),
            NAME_WINDOW + NAME_LEN,
            "a signer following the descriptor must build the message the entry verifies"
        );
    }
}
