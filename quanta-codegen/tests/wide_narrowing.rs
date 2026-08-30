// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::compile_contract;

fn compile_error(src: &str) -> String {
    let program = quanta_parser::parse(src).expect("parses");
    quanta_typeck::check(&program).expect("type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    match compile_contract(&contract) {
        Ok(_) => panic!("the wide narrowing should be rejected"),
        Err(e) => format!("{e:?}"),
    }
}

fn compiles(src: &str) {
    let program = quanta_parser::parse(src).expect("parses");
    quanta_typeck::check(&program).expect("type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("compiles");
}

#[test]
fn dividing_a_wide_field_is_rejected() {
    let src =
        "contract W { state { total: u128; result: u128; } genesis { total = 0; result = 0; } \
               entry divide(d: u64) writes(result) reads(total) { result = total / d; } }";
    assert!(compile_error(src).contains("truncate"));
}

#[test]
fn a_wide_remainder_is_rejected() {
    let src =
        "contract W { state { total: u128; result: u128; } genesis { total = 0; result = 0; } \
               entry rem(d: u64) writes(result) reads(total) { result = total % d; } }";
    assert!(compile_error(src).contains("truncate"));
}

#[test]
fn shifting_a_wide_field_is_rejected() {
    let src =
        "contract W { state { total: u128; result: u128; } genesis { total = 0; result = 0; } \
               entry shift(n: u64) writes(result) reads(total) { result = total >> n; } }";
    assert!(compile_error(src).contains("truncate"));
}

#[test]
fn assigning_a_wide_field_to_a_narrow_field_is_rejected() {
    let src = "contract W { state { total: u128; small: u64; } genesis { total = 0; small = 0; } \
               entry narrow() writes(small) reads(total) { small = total; } }";
    assert!(compile_error(src).contains("high word"));
}

#[test]
fn reading_a_wide_map_value_as_one_word_is_rejected() {
    let src = "contract W { state { balances: Map<Q_Address, u128>; flag: u64; } \
               genesis { flag = 0; } \
               entry peek() reads(balances) writes(flag) { flag = balances.get(caller); } }";
    assert!(compile_error(src).contains("high word"));
}

#[test]
fn narrowing_a_wide_parameter_field_into_a_scalar_is_rejected() {
    let src = "contract W { state { total: u128; small: u64; } genesis { total = 0; small = 0; } \
               entry e(order: O) writes(total, small) \
               { total = checked(total + order.amount); small = order.amount; } }";
    assert!(compile_error(src).contains("high word"));
}

#[test]
fn a_wide_token_id_key_is_refused_rather_than_truncated() {
    let src = "contract W { state { seen: Map<Q_Id, u64>; } genesis {} \
               entry mark(w: u128, v: u64) writes(seen) { seen.set(w, v); } }";
    assert!(compile_error(src).contains("high word"));
}

#[test]
fn a_signed_integer_is_refused_rather_than_lowered_at_the_wrong_size() {
    let src = "contract W { state { total: i128; } genesis { total = 0; } \
               entry add(amount: i128) writes(total) { total = checked(total + amount); } }";
    assert!(compile_error(src).contains("i128"));
}

#[test]
fn narrow_division_still_compiles() {
    let src = "contract W { state { a: u64; result: u64; } genesis { a = 0; result = 0; } \
               entry divide(d: u64) writes(result) reads(a) { result = a / d; } }";
    compiles(src);
}

#[test]
fn a_wide_add_still_compiles() {
    let src = "contract W { state { total: u128; } genesis { total = 0; } \
               entry add(amount: u128) writes(total) { total = checked(total + amount); } }";
    compiles(src);
}
