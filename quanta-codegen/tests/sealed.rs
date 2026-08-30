// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::interp::Interpreter;
use quanta_codegen::compile_contract;

mod common;
use common::slot_key;

const CONFIDENTIAL: &str = "contract Confidential {\n\
  state { total: u64; }\n\
  entry submit(bid: sealed u64) writes(total) {\n\
    total = checked(total + bid);\n\
    emit Recorded(total);\n\
  }\n\
  event Recorded(value: u64);\n\
}\n";

#[test]
fn a_sealed_parameter_type_checks_and_lowers_with_its_seal_recorded() {
    let program = quanta_parser::parse(CONFIDENTIAL).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");

    let cc = compile_contract(&program.contracts[0]).expect("a sealed parameter lowers");
    let submit = cc
        .entries
        .iter()
        .find(|e| e.name == "submit")
        .expect("the submit entry");
    assert_eq!(
        submit.sealed_params,
        vec!["bid".to_string()],
        "the artifact names the sealed parameter so the host decapsulates it"
    );
    assert!(
        submit.args.iter().any(|s| s.key == "bid"),
        "the opened value occupies an ordinary argument word"
    );
}

#[test]
fn the_opened_sealed_value_flows_as_an_ordinary_argument() {
    let program = quanta_parser::parse(CONFIDENTIAL).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let submit = cc
        .entries
        .iter()
        .find(|e| e.name == "submit")
        .expect("submit");

    let bid_off = submit
        .args
        .iter()
        .find(|s| s.key == "bid")
        .expect("bid arg")
        .offset as usize;
    let mut mem = vec![0u8; 4096];
    mem[bid_off..bid_off + 8].copy_from_slice(&40u64.to_be_bytes());

    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 2u64);

    let out = Interpreter::for_entry(&cc.container, submit.selector, 100_000)
        .expect("the submit selector resolves")
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .expect("the entry halts on the opened value");
    assert_eq!(
        out.storage.get(&slot_key(0)),
        Some(&42),
        "the opened bid adds into the running total like any argument"
    );
}
