// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn rejected(src: &str) -> bool {
    match quanta_parser::parse(src) {
        Ok(program) => quanta_typeck::check(&program).is_err(),
        Err(_) => true,
    }
}

fn accepted(src: &str) -> bool {
    match quanta_parser::parse(src) {
        Ok(program) => quanta_typeck::check(&program).is_ok(),
        Err(_) => false,
    }
}

fn bank(credit: &str) -> String {
    format!(
        r#"import {{ Q_Asset }} from "quantova/primitives";
contract Bank {{
  state {{ vault: Q_Asset<TOK>; bal: Map<Q_Address, u128>; token: Q_Address; }}
  genesis {{ token = deployer; }}
  entry deposit(funds: Q_Asset<TOK>) conserves TOK reads(token) writes(vault, bal) {{
    guard in_asset == token;
    bal.credit(caller, {credit});
    vault.merge(funds);
  }}
  entry withdraw(n: u128) reads(token) writes(bal) {{
    bal.debit(caller, n);
    send_asset(token, caller, n);
  }}
}}"#
    )
}

#[test]
fn a_row_credited_with_exactly_what_was_paid_in_is_accepted() {
    assert!(accepted(&bank("funds.amount")));
}

#[test]
fn a_row_credited_with_a_multiple_of_what_was_paid_in_is_refused() {
    assert!(rejected(&bank("funds.amount * 2")));
}

#[test]
fn a_row_credited_with_a_constant_the_caller_never_paid_is_refused() {
    assert!(rejected(&bank("1000000")));
}

#[test]
fn a_row_credited_with_a_floor_above_what_was_paid_in_is_refused() {
    assert!(rejected(&bank("funds.amount + 1")));
}

#[test]
fn an_asset_handed_over_twice_once_wrapped_is_refused() {
    assert!(rejected(
        r#"import { Q_Asset } from "quantova/primitives";
contract Twice {
  state { vault: Q_Asset<TOK>; token: Q_Address; }
  genesis { token = deployer; }
  entry take(funds: Q_Asset<TOK>) conserves TOK reads(token) writes(vault) {
    guard in_asset == token;
    vault.merge(checked(funds));
    vault.merge(funds);
  }
}"#
    ));
}

#[test]
fn a_row_the_caller_wrote_for_itself_cannot_pay_the_caller_out() {
    assert!(rejected(
        r#"contract Park {
  state { token: Q_Address; owed: Map<Q_Address, u128>; }
  genesis { token = deployer; }
  entry park(n: u128) writes(owed) { guard owed.get(caller) == 0; owed.set(caller, n); }
  entry drain() reads(token, owed) writes(owed) {
    guard owed.get(caller) > 0;
    let n = owed.get(caller);
    owed.set(caller, 0);
    send_asset(token, caller, n);
  }
}"#
    ));
}
