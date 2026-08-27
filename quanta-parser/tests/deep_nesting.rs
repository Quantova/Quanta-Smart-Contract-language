// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn body(inner: &str) -> String {
    format!("contract C {{ state {{ a: u64; }} entry f() writes(a) {{ a = {inner}; }} }}")
}

#[test]
fn deeply_nested_parentheses_are_a_clean_error() {
    let n = 100_000;
    let src = body(&format!("{}1{}", "(".repeat(n), ")".repeat(n)));
    let err = quanta_parser::parse(&src).expect_err("deep nesting must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn deeply_nested_unary_is_a_clean_error() {
    let n = 100_000;
    let src = body(&format!("{}1", "!".repeat(n)));
    let err = quanta_parser::parse(&src).expect_err("deep unary must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn deeply_nested_generics_are_a_clean_error() {
    let n = 100_000;
    let inner = format!("{}u64{}", "Map<".repeat(n), ">".repeat(n));
    let src = format!("contract C {{ state {{ a: {inner}; }} }}");
    let err = quanta_parser::parse(&src).expect_err("deep generics must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn ordinary_nesting_still_parses() {
    let src = body("(((1 + 2) * 3) >> 1) + ((4 - 1) / 2)");
    quanta_parser::parse(&src).expect("ordinary nesting parses");
}

#[test]
fn a_flat_chain_within_the_limit_still_parses() {
    let terms: Vec<String> = (0..50).map(|_| "1".to_string()).collect();
    let src = body(&terms.join(" + "));
    quanta_parser::parse(&src).expect("a flat sum within the depth limit parses");
}
