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
  state { token: Q_Address; members: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry join(funds: Q_Asset<TOK>) conserves TOK writes(members, vault) { members.credit(caller, funds.amount); vault.merge(funds); }
  entry payout(to: Q_Address, amount: u64) reads(token, members) { guard members.get(caller) > 0; send_asset(token, to, amount); }
}"#
    ));
}

#[test]
fn a_zero_written_as_a_product_backs_no_authority_either() {
    assert!(rejected(
        r#"contract Tok {
  asset TOK;
  state { token: Q_Address; balances: Map<Q_Address, u64>; }
  genesis { token = deployer; }
  entry withdraw(n: u64) reads(token) writes(balances) { balances.debit(caller, n * 0); send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn a_flag_set_to_a_literal_is_not_a_trustworthy_anchor() {
    assert!(rejected(
        r#"contract Drain2b {
  asset TOK;
  state { token: Q_Address; flags: Map<Q_Address, u64>; }
  genesis { token = deployer; }
  entry become_admin() writes(flags) { flags.set(caller, 1); }
  entry drain(n: u64) reads(token, flags) { guard flags.get(caller) == 1; send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn parking_a_caller_named_amount_in_state_does_not_launder_it() {
    assert!(rejected(
        r#"contract Launder {
  asset TOK;
  state { token: Q_Address; pending: u128; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry drain(funds: Q_Asset<TOK>, n: u128) conserves TOK writes(pending, vault) { pending = n; send_asset(token, caller, pending); vault.merge(funds); }
}"#
    ));
}

#[test]
fn parking_an_address_in_state_does_not_launder_an_ownership_handover() {
    assert!(rejected(
        r#"contract Reg4 {
  state { owner_of: Map<u64, Q_Address>; stash: Q_Address; }
  genesis { stash = deployer; }
  entry steal(label: u64, to: Q_Address) writes(owner_of, stash) { stash = to; owner_of.set(label, stash); }
}"#
    ));
}

#[test]
fn a_first_claim_must_check_the_slot_is_free_before_taking_it() {
    assert!(rejected(
        r#"contract Reg3 {
  state { owner_of: Map<u64, Q_Address>; }
  entry claim(label: u64) writes(owner_of) { owner_of.set(label, caller); }
  entry transfer(label: u64, to: Q_Address) reads(owner_of) writes(owner_of) { guard owner_of.get(label) == caller; owner_of.set(label, to); }
}"#
    ));
}

#[test]
fn a_registry_that_guards_the_slot_before_claiming_it_still_compiles() {
    assert!(!rejected(
        r#"contract Reg5 {
  state { owner_of: Map<u64, Q_Address>; taken: Map<u64, u64>; }
  entry claim(label: u64) reads(taken) writes(owner_of, taken) { guard taken.get(label) == 0; owner_of.set(label, caller); taken.set(label, 1); }
}"#
    ));
}
