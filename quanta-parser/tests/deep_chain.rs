// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn body(inner: &str) -> String {
    format!("contract C {{ state {{ a: u64; }} entry f() writes(a) {{ a = {inner}; }} }}")
}

#[test]
fn a_long_operator_chain_is_a_clean_error() {
    let n = 100_000;
    let mut s = String::from("1");
    for _ in 0..n {
        s.push_str("+1");
    }
    let err = quanta_parser::parse(&body(&s)).expect_err("a long operator chain must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn a_long_comparison_chain_is_a_clean_error() {
    let n = 100_000;
    let mut s = String::from("1");
    for _ in 0..n {
        s.push_str("<1");
    }
    let err = quanta_parser::parse(&body(&s)).expect_err("a long comparison chain must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn a_long_field_chain_is_a_clean_error() {
    let n = 100_000;
    let mut s = String::from("a");
    for _ in 0..n {
        s.push_str(".a");
    }
    let err = quanta_parser::parse(&body(&s)).expect_err("a long field chain must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn a_long_call_chain_is_a_clean_error() {
    let n = 100_000;
    let src = body(&format!("a{}", "()".repeat(n)));
    let err = quanta_parser::parse(&src).expect_err("a long call chain must be rejected");
    assert!(err.message.contains("nests deeper"));
}

#[test]
fn a_moderate_chain_the_backend_can_walk_still_parses() {
    let terms: Vec<String> = (0..40).map(|_| "1".to_string()).collect();
    quanta_parser::parse(&body(&terms.join(" + "))).expect("a moderate chain parses");
    quanta_parser::parse(&body("reserve.split(req.amount)")).expect("a real method chain parses");
}
