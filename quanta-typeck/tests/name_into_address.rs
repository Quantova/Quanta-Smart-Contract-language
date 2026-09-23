// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn refused(src: &str) -> String {
    let program = quanta_parser::parse(src).expect("parse");
    match quanta_typeck::check(&program) {
        Ok(()) => panic!("a name was accepted where an address is held"),
        Err(e) => e.message,
    }
}

fn accepted(src: &str) {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
}

#[test]
fn a_name_may_not_be_written_into_an_authority_address() {
    let message = refused(
        "contract A { state { owner: Q_Address; } \
         entry take(label: Q_Name) writes(owner) { owner = label; } }",
    );
    assert!(
        message.contains("a name cannot become an address"),
        "expected a name to address refusal, got: {message}"
    );
}

#[test]
fn a_name_still_keys_a_map() {
    accepted(
        "contract B { state { owner_of: Map<Q_Address, Q_Address>; } \
         entry claim(label: Q_Name) writes(owner_of) { owner_of.set(label, caller); } }",
    );
}
