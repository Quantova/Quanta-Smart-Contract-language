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
  state { token: Q_Address; balances: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry buy(funds: Q_Asset<TOK>, n: u64) writes(balances, vault) conserves TOK { guard funds.amount > 0; balances.credit(caller, n); vault.merge(funds); }
  entry withdraw(amount: u64) reads(token) writes(balances) { balances.debit(caller, amount); send_asset(token, caller, amount); }
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

#[test]
fn a_tally_nothing_ever_pays_out_is_not_a_balance() {
    // Crediting a counter that no entry ever debits or pays out moves no value, so
    // refusing it only stops vote counts, reputation and statistics from existing.
    assert!(!rejected(
        r#"contract Dao {
  asset TOK;
  state { power: Map<Q_Address, u64>; votes: Map<u64, u64>; vault: Q_Asset<TOK>; }
  genesis { }
  entry join(funds: Q_Asset<TOK>) conserves TOK writes(power, vault) { power.credit(caller, funds.amount); vault.merge(funds); }
  entry vote(proposal: u64) reads(power) writes(votes) { votes.credit(proposal, power.get(caller)); }
}"#
    ));
}

#[test]
fn a_write_once_slot_is_a_sound_anchor() {
    // Vesting, subscriptions and commit reveal all need this: a write that can only
    // fill an empty row cannot overwrite anybody else's, so the map stays trustworthy.
    assert!(!rejected(
        r#"contract Vesting {
  asset TOK;
  state { token: Q_Address; total: Map<Q_Address, u64>; start: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry fund(funds: Q_Asset<TOK>, who: Q_Address) conserves TOK reads(start) writes(total, start, vault) { guard start.get(who) == 0; total.credit(who, funds.amount); start.set(who, now); vault.merge(funds); }
  entry claim(amount: u64) reads(token, total, start) writes(total) { guard now >= start.get(caller) + 2592000; total.debit(caller, amount); send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn resetting_a_vesting_clock_for_somebody_else_is_still_refused() {
    // The same contract without the write once guard lets anyone push a victim's
    // cliff forward forever, so it must stay rejected.
    assert!(rejected(
        r#"contract Vesting2 {
  asset TOK;
  state { token: Q_Address; total: Map<Q_Address, u64>; start: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry fund(funds: Q_Asset<TOK>, who: Q_Address) conserves TOK writes(total, start, vault) { total.credit(who, funds.amount); start.set(who, now); vault.merge(funds); }
  entry claim(amount: u64) reads(token, total, start) writes(total) { guard now >= start.get(caller) + 2592000; total.debit(caller, amount); send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn a_collateral_guard_against_a_computed_amount_binds_the_caller() {
    // Lending, tiered limits and fee bearing withdrawals all compare a caller's own
    // row against a computed amount. That has to count as binding the caller.
    assert!(!rejected(
        r#"contract Lend {
  asset TOK;
  state { token: Q_Address; deposited: Map<Q_Address, u64>; locked: Map<Q_Address, u64>; borrowed: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry supply(funds: Q_Asset<TOK>) conserves TOK writes(deposited, vault) { deposited.credit(caller, funds.amount); vault.merge(funds); }
  entry borrow(amount: u64) reads(token, deposited) writes(deposited, locked, borrowed) { guard deposited.get(caller) >= amount * 2; deposited.debit(caller, amount * 2); locked.credit(caller, amount * 2); borrowed.credit(caller, amount); send_asset(token, caller, amount); }
  entry repay(funds: Q_Asset<TOK>) conserves TOK writes(borrowed, vault) { borrowed.debit(caller, funds.amount); vault.merge(funds); }
}"#
    ));
}

#[test]
fn borrowing_without_locking_the_collateral_is_still_refused() {
    // The same shape with the collateral left untouched can be drawn against forever.
    assert!(rejected(
        r#"contract Lend2 {
  asset TOK;
  state { token: Q_Address; deposited: Map<Q_Address, u64>; borrowed: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry supply(funds: Q_Asset<TOK>) conserves TOK writes(deposited, vault) { deposited.credit(caller, funds.amount); vault.merge(funds); }
  entry borrow(amount: u64) reads(token, deposited) writes(borrowed) { guard deposited.get(caller) >= amount * 2; borrowed.credit(caller, amount); send_asset(token, caller, amount); }
  entry repay(funds: Q_Asset<TOK>) conserves TOK writes(borrowed, vault) { borrowed.debit(caller, funds.amount); vault.merge(funds); }
}"#
    ));
}

#[test]
fn an_auction_may_refund_the_previous_leader_from_state() {
    assert!(!rejected(
        r#"contract Auction {
  asset TOK;
  state { token: Q_Address; high: u64; leader: Q_Address; refund: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry bid(funds: Q_Asset<TOK>) conserves TOK writes(high, leader, refund, vault) { guard funds.amount > high; refund.credit(leader, high); high = funds.amount; leader = caller; vault.merge(funds); }
  entry reclaim(amount: u64) reads(token) writes(refund) { refund.debit(caller, amount); send_asset(token, caller, amount); }
}"#
    ));
}
