// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn refused(src: &str) -> String {
    let program = quanta_parser::parse(src).expect("parse");
    match quanta_typeck::check(&program) {
        Ok(()) => panic!("the shadowed name was accepted"),
        Err(e) => format!("{e:?}"),
    }
}

// A local of the same name wins in the code generator, so the invariant reads the local
// and the cap it names is never loaded. The supply becomes unbounded.
#[test]
fn a_local_may_not_shadow_the_state_field_an_invariant_names() {
    let text = refused(
        "contract CappedToken { asset TKN; \
         state { owner: Q_Address; total_supply: u64; max_supply: u64 = 1000000; } \
         genesis { owner = deployer; } \
         invariant total_supply <= max_supply; \
         entry mint_to(order: MintOrder signed by owner) mints TKN writes(total_supply) { \
           let max_supply = order.amount; \
           total_supply = checked(total_supply + order.amount); \
         } }",
    );
    assert!(text.contains("max_supply"), "got {text}");
}

// The signed parameter is verified and then discarded for a public state field.
#[test]
fn a_parameter_may_not_shadow_a_state_field() {
    let text = refused(
        "contract Payer { state { owner: Q_Address; amount: u64; pool: Q_Asset<QTOV>; } \
         genesis { owner = deployer; } \
         entry payout(amount: u64 signed by owner) conserves QTOV writes(pool) { \
           send(caller, pool.split(amount)); \
         } }",
    );
    assert!(text.contains("amount"), "got {text}");
}

// One slot is allocated but the selector advertises two arguments.
#[test]
fn a_duplicate_parameter_name_is_refused() {
    let text = refused(
        "contract D { state { owner: Q_Address; } genesis { owner = deployer; } \
         entry pay(to: Q_Address, to: u64) { guard caller == owner; } }",
    );
    assert!(text.contains("more than once"), "got {text}");
}
