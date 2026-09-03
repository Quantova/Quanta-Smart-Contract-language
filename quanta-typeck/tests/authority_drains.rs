// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Contracts that a caller could drain must not compile.
//!
//! Each of these was accepted by the analysis at one point and each hands an
//! attacker the contract's holdings. They are kept here as source so a future
//! loosening of the authority rules fails loudly instead of silently reopening a
//! drain.

fn rejected(src: &str) -> bool {
    match quanta_parser::parse(src) {
        Ok(program) => quanta_typeck::check(&program).is_err(),
        Err(_) => true,
    }
}

#[test]
fn a_zero_debit_of_an_unrelated_map_does_not_buy_authority_to_send() {
    assert!(rejected(
        r#"contract Drain1 {
  asset TOK;
  state { token: Q_Address; dust: Map<Q_Address, u64>; }
  genesis { token = deployer; }
  entry take(n: u64) reads(token) writes(dust) { dust.debit(caller, 0); send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn a_self_written_flag_is_not_a_trustworthy_authority_anchor() {
    assert!(rejected(
        r#"contract Drain2 {
  asset TOK;
  state { token: Q_Address; flags: Map<Q_Address, u64>; }
  genesis { token = deployer; }
  entry become_admin(v: u64) writes(flags) { flags.set(caller, v); }
  entry drain(n: u64) reads(token, flags) { guard flags.get(caller) == 1; send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn declaring_an_asset_param_does_not_authorise_sending_a_caller_named_amount() {
    assert!(rejected(
        r#"contract BSwap {
  asset TOK;
  state { token: Q_Address; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry swap(funds: Q_Asset<TOK>, n: u64) conserves TOK writes(vault) { guard funds.amount > 0; send_asset(token, caller, n); vault.merge(funds); }
}"#
    ));
}

#[test]
fn a_one_unit_payment_does_not_authorise_crediting_an_arbitrary_balance() {
    assert!(rejected(
        r#"contract CBuy {
  asset TOK;
  state { balances: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { }
  entry buy(funds: Q_Asset<TOK>, n: u64) writes(balances, vault) conserves TOK { guard funds.amount > 0; balances.credit(caller, n); vault.merge(funds); }
}"#
    ));
}

#[test]
fn membership_bought_for_one_unit_does_not_authorise_draining_the_vault() {
    assert!(rejected(
        r#"contract DClub {
  asset TOK;
  state { members: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { }
  entry join(funds: Q_Asset<TOK>) conserves TOK writes(members, vault) { members.credit(caller, funds.amount); vault.merge(funds); }
  entry payout(to: Q_Address, amount: u64) reads(members) writes(vault) { guard members.get(caller) > 0; send(to, vault.split(amount)); }
}"#
    ));
}
