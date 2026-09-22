// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::compile_contract;

fn compiled(src: &str) -> Vec<u8> {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0])
        .expect("compile")
        .container
        .code
}

#[test]
fn a_default_in_a_later_state_block_is_still_initialised() {
    let split = compiled(
        "contract M { state { a: u64 = 111; } state { paused: u64 = 222; } \
         entry poke(n: u64) writes(a) { a = n; } }",
    );
    let joined = compiled(
        "contract M { state { a: u64 = 111; paused: u64 = 222; } \
         entry poke(n: u64) writes(a) { a = n; } }",
    );
    assert_eq!(
        split.len(),
        joined.len(),
        "a split state block compiled to less code than the same fields in one block"
    );
}

#[test]
fn a_later_genesis_block_is_still_compiled() {
    let split = compiled(
        "contract B { state { x: u64; y: u64; } genesis { x = 11; } genesis { y = 22; } \
         entry poke(n: u64) writes(x) { x = n; } }",
    );
    let joined = compiled(
        "contract B { state { x: u64; y: u64; } genesis { x = 11; y = 22; } \
         entry poke(n: u64) writes(x) { x = n; } }",
    );
    assert_eq!(
        split.len(),
        joined.len(),
        "a split genesis block dropped its second body"
    );
}
