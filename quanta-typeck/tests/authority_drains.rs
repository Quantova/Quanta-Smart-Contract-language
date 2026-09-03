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

#[test]
fn a_disjunct_office_does_not_switch_the_membership_rule_off() {
    // `A || B` holds when either side does, so the membership half alone satisfies
    // it and the office half guarantees nothing.
    assert!(rejected(
        r#"contract Club {
  asset TOK;
  state { owner: Q_Address; token: Q_Address; members: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { owner = deployer; token = deployer; }
  entry payout(amount: u128) reads(token, members, owner) { guard members.get(caller) > 0 || owner == caller; send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn a_caller_inequality_does_not_switch_the_membership_rule_off() {
    assert!(rejected(
        r#"contract Club2 {
  asset TOK;
  state { treasury: Q_Address; token: Q_Address; members: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { treasury = deployer; token = deployer; }
  entry payout(amount: u128) reads(token, members, treasury) { guard members.get(caller) > 0; guard caller != treasury; send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn every_zero_shape_backs_nothing_not_just_a_product() {
    // A blacklist of zero spellings can never win. Only a form that cannot shrink
    // below the parameter backs an amount.
    for zero in [
        "amount - amount",
        "amount % 1",
        "amount / (amount + 1)",
        "amount >> 127",
        "amount * 0 + 0",
        "amount * 0",
    ] {
        let src = format!(
            r#"contract Z {{
  asset TOK;
  state {{ token: Q_Address; credits: Map<Q_Address, u128>; vault: Q_Asset<TOK>; }}
  genesis {{ token = deployer; }}
  entry take(amount: u128) reads(token) writes(credits) {{ credits.debit(caller, {zero}); send_asset(token, caller, amount); }}
}}"#
        );
        assert!(rejected(&src), "a debit of `{zero}` must back nothing");
    }
}

#[test]
fn reading_a_row_of_a_map_nobody_writes_earns_nothing() {
    // `seen` is never written, so it is zero for everyone and the +1 hands every
    // address a rank for free, which then passes as a protected anchor.
    assert!(rejected(
        r#"contract Vaultish {
  asset TOK;
  state { owner: Q_Address; token: Q_Address; ranks: Map<Q_Address, u64>; seen: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { owner = deployer; token = deployer; }
  entry enroll() reads(seen) writes(ranks) { ranks.set(caller, seen.get(caller) + 1); }
  entry payout(amount: u128) reads(token, ranks, owner) { guard ranks.get(caller) > 0 || owner == caller; send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn a_self_joined_membership_does_not_license_reassigning_a_registry() {
    assert!(rejected(
        r#"contract Reg {
  state { owner_of: Map<Q_Address, Q_Address>; members: Map<Q_Address, u64>; }
  entry join() writes(members) { members.set(caller, 1); }
  entry hand(label: Q_Address, to: Q_Address) reads(members) writes(owner_of) { guard members.get(caller) > 0; owner_of.set(label, to); }
}"#
    ));
}

#[test]
fn a_nested_field_still_counts_as_handing_over_a_parameter() {
    assert!(rejected(
        r#"contract Reg2 {
  state { owner_of: Map<Q_Address, Q_Address>; }
  entry hand(order: HandOrder) writes(owner_of) { owner_of.set(order.label, order.inner.to); }
}"#
    ));
}

#[test]
fn a_membership_guard_does_not_license_draining_the_native_pool() {
    // `send(caller, pool.split(n))` moves the native pool and never reaches the
    // asset path, so the same drain was allowed in native form.
    assert!(rejected(
        r#"contract A1 {
  state { pool: Q_Asset<QTOV>; stakes: Map<Q_Address, u128>; }
  entry stake(funds: Q_Asset<QTOV>) conserves QTOV writes(pool, stakes) { guard funds.amount > 0; pool.merge(funds); stakes.credit(caller, funds.amount); }
  entry drain(amount: u128) conserves QTOV reads(stakes) writes(pool) { guard stakes.get(caller) > 0; let out = pool.split(amount); send(caller, out); }
}"#
    ));
}

#[test]
fn an_amount_parked_in_a_self_written_row_by_another_entry_is_still_the_callers() {
    assert!(rejected(
        r#"contract Club3 {
  asset TOK;
  state { token: Q_Address; members: Map<Q_Address, u64>; request: Map<Q_Address, u128>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry request_payout(amount: u128) writes(request) { request.set(caller, amount); }
  entry take() reads(members, token, request) { guard members.get(caller) > 0; send_asset(token, caller, request.get(caller)); }
}"#
    ));
}

#[test]
fn a_guard_on_a_map_the_claim_never_restamps_is_not_a_check() {
    // `banned` is never written by anybody, so the guard is true for every label
    // forever and the name is seizable from its owner.
    assert!(rejected(
        r#"contract Names {
  state { owner_of: Map<Q_Address, Q_Address>; resolved_of: Map<Q_Address, Q_Address>; banned: Map<Q_Address, u64>; }
  entry claim(label: Q_Address) reads(banned) writes(owner_of) { guard banned.get(label) == 0; owner_of.set(label, caller); }
  entry set_resolved(label: Q_Address, target: Q_Address) reads(owner_of) writes(resolved_of) { guard owner_of.get(label) == caller; resolved_of.set(label, target); }
}"#
    ));
}

#[test]
fn an_owner_signed_allocation_with_a_real_debit_still_compiles() {
    // The sound shape of the same contract must keep working.
    assert!(!rejected(
        r#"contract Payouts {
  asset TOK;
  state { owner: Q_Address; token: Q_Address; owed: Map<Q_Address, u128>; vault: Q_Asset<TOK>; }
  genesis { owner = deployer; token = deployer; }
  entry allocate(order: AllocOrder signed by owner) writes(owed) { owed.set(order.who, order.amount); }
  entry withdraw(amount: u128) reads(owed, token) writes(owed) { guard amount > 0; guard owed.get(caller) >= amount; owed.debit(caller, amount); send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn a_denies_clause_excluding_one_account_is_not_an_office() {
    // `denies caller == treasury` rejects the treasury and grants nobody anything, so
    // it must not switch the membership rule off.
    assert!(rejected(
        r#"contract Club {
  asset TOK;
  state { treasury: Q_Address; token: Q_Address; members: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { treasury = deployer; token = deployer; }
  entry join() writes(members) { members.set(caller, 1); }
  entry payout(amount: u128) reads(token, members, treasury) denies caller == treasury { guard members.get(caller) > 0; send_asset(token, caller, amount); }
}"#
    ));
}

#[test]
fn the_canonical_owner_only_clause_still_compiles() {
    // `denies caller != owner` REQUIRES caller == owner. Reading it with the wrong
    // polarity made the standard owner only clause unbuildable.
    assert!(!rejected(
        r#"contract Payroll {
  asset TOK;
  state { owner: Q_Address; token: Q_Address; vault: Q_Asset<TOK>; }
  genesis { owner = deployer; token = deployer; }
  entry pay(to: Q_Address, amount: u128) reads(token, owner) denies caller != owner { send_asset(token, to, amount); }
}"#
    ));
}

#[test]
fn an_owner_check_written_with_a_negation_still_compiles() {
    assert!(!rejected(
        r#"contract Payroll2 {
  asset TOK;
  state { owner: Q_Address; token: Q_Address; vault: Q_Asset<TOK>; }
  genesis { owner = deployer; token = deployer; }
  entry pay(to: Q_Address, amount: u128) reads(token, owner) { guard !(caller != owner); send_asset(token, to, amount); }
}"#
    ));
}

#[test]
fn declaring_an_asset_parameter_is_not_payment_without_a_floor() {
    // `join(fee)` with no floor is satisfied by paying nothing, so the writer is still
    // self grantable and must not protect an ownership handover.
    assert!(rejected(
        r#"contract Reg {
  asset TOK;
  state { token: Q_Address; members: Map<Q_Address, u64>; owner_of: Map<Q_Address, Q_Address>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry join(fee: Q_Asset<TOK>) conserves TOK writes(members, vault) { members.set(caller, 1); vault.merge(fee); }
  entry hand(label: Q_Address, to: Q_Address) reads(members) writes(owner_of) { guard members.get(caller) > 0; owner_of.set(label, to); }
}"#
    ));
}

#[test]
fn a_guard_that_gates_nothing_does_not_protect_an_anchor() {
    assert!(rejected(
        r#"contract Reg2 {
  state { members: Map<Q_Address, u64>; owner_of: Map<Q_Address, Q_Address>; }
  entry join() writes(members) { guard 1 > 0; members.set(caller, 1); }
  entry hand(label: Q_Address, to: Q_Address) reads(members) writes(owner_of) { guard members.get(caller) > 0; owner_of.set(label, to); }
}"#
    ));
}

#[test]
fn a_write_once_self_join_is_still_a_self_grant() {
    // Write once stops you taking somebody else's slot. It does not stop you taking
    // your own, so a caller keyed write once join is a self grant with a limit of one.
    assert!(rejected(
        r#"contract Base {
  state { members: Map<Q_Address, u64>; owner_of: Map<Q_Address, Q_Address>; }
  entry join() reads(members) writes(members) { guard members.get(caller) == 0; members.set(caller, 1); }
  entry transfer_name(label: Q_Address, to: Q_Address) reads(members) writes(owner_of) { guard members.get(caller) > 0; owner_of.set(label, to); }
}"#
    ));
}

#[test]
fn adding_a_constant_to_a_read_does_not_earn_an_anchor() {
    // `seen.get(caller) + 1` is one for everybody when `seen` holds nothing, so the
    // read is decoration and the literal is the whole grant.
    assert!(rejected(
        r#"contract Loyalty {
  state { ranks: Map<Q_Address, u64>; seen: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
  entry fund(payment: Q_Asset<QTOV>) conserves QTOV writes(vault) { vault.merge(payment); }
  entry touch() writes(seen) { seen.set(caller, 0); }
  entry enroll() reads(seen) writes(ranks) { ranks.set(caller, seen.get(caller) + 1); }
  entry claim() conserves QTOV reads(ranks, vault) writes(vault) { guard ranks.get(caller) >= 1; let out = vault.split(1000); send(caller, out); }
}"#
    ));
}

#[test]
fn wrapping_arithmetic_never_backs_an_amount() {
    // `wrapping(n + (0 - n))` is zero. Add is only monotonic over trapping arithmetic.
    assert!(rejected(
        r#"contract W {
  asset TOK;
  state { token: Q_Address; credits: Map<Q_Address, u128>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry take(n: u128) reads(token) writes(credits) { credits.debit(caller, wrapping(n + (0 - n))); send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn over_collateralised_lending_is_buildable() {
    // The bound is stated as a guard against collateral the caller cannot write, and
    // it accounts for the debt already outstanding. Refusing this made lending, and
    // every other entitlement shaped contract, impossible to express.
    assert!(!rejected(
        r#"contract Lend {
  state { pool: Q_Asset<QTOV>; collateral: Map<Q_Address, u128>; debt: Map<Q_Address, u128>; }
  entry borrow(amount: u128) conserves QTOV reads(collateral, debt, pool) writes(pool, debt) { guard amount > 0; guard collateral.get(caller) >= (debt.get(caller) + amount) * 2; guard pool.amount >= amount; debt.credit(caller, amount); let out = pool.split(amount); send(caller, out); }
}"#
    ));
}

#[test]
fn vesting_against_an_allocation_is_buildable() {
    assert!(!rejected(
        r#"contract Vest {
  state { pool: Q_Asset<QTOV>; allocation: Map<Q_Address, u128>; claimed: Map<Q_Address, u128>; }
  entry claim(amount: u128) conserves QTOV reads(allocation, claimed, pool) writes(pool, claimed) limits claimed.get(caller) + amount <= allocation.get(caller) { guard amount > 0; guard pool.amount >= amount; claimed.credit(caller, amount); let out = pool.split(amount); send(caller, out); }
}"#
    ));
}

#[test]
fn a_priced_redemption_is_buildable() {
    // The multiplier is a configured price held in state, not a literal. Demanding a
    // literal made every priced purchase and every rate based charge unbuildable.
    assert!(!rejected(
        r#"contract Loyalty2 {
  state { pool: Q_Asset<QTOV>; points: Map<Q_Address, u128>; points_per_coin: u128; }
  genesis { points_per_coin = 250; }
  entry redeem(coins: u128) conserves QTOV reads(points, points_per_coin, pool) writes(points, pool) { guard coins > 0; guard points.get(caller) >= coins * points_per_coin; guard pool.amount >= coins; points.debit(caller, coins * points_per_coin); let out = pool.split(coins); send(caller, out); }
}"#
    ));
}

#[test]
fn a_delegated_office_with_a_spend_cap_is_buildable() {
    assert!(!rejected(
        r#"contract Treasury {
  state { treasury: Q_Asset<QTOV>; managers: Map<Q_Address, u64>; owner: Q_Address; spent_today: u128; daily_cap: u128; }
  genesis { owner = deployer; daily_cap = 1000000; }
  entry appoint(order: Appoint signed by owner) writes(managers) { managers.set(order.who, 1); }
  entry pay_invoice(to: Q_Address, amount: u128) conserves QTOV reads(managers, treasury) writes(treasury, spent_today) limits spent_today + amount <= daily_cap { guard managers.get(caller) > 0; guard treasury.amount >= amount; spent_today += amount; let out = treasury.split(amount); send(to, out); }
}"#
    ));
}

#[test]
fn a_credit_that_cancels_the_debit_backs_nothing() {
    // `bal.credit(caller, n); bal.debit(caller, n)` leaves the row byte identical and
    // the asset still leaves, so nothing on chain records value given up for it.
    assert!(rejected(
        r#"contract Club {
  asset TOK;
  state { token: Q_Address; bal: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry deposit(funds: Q_Asset<TOK>) conserves TOK writes(bal, vault) { guard funds.amount > 0; bal.credit(caller, funds.amount); vault.merge(funds); }
  entry withdraw(n: u64) reads(token, bal) writes(bal) { guard bal.get(caller) > 0; guard n > 0; bal.credit(caller, n); bal.debit(caller, n); send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn a_genuine_debit_still_backs_a_withdrawal() {
    // The same contract without the cancelling credit is the honest shape and must
    // keep working.
    assert!(!rejected(
        r#"contract Club2 {
  asset TOK;
  state { token: Q_Address; bal: Map<Q_Address, u64>; vault: Q_Asset<TOK>; }
  genesis { token = deployer; }
  entry deposit(funds: Q_Asset<TOK>) conserves TOK writes(bal, vault) { guard funds.amount > 0; bal.credit(caller, funds.amount); vault.merge(funds); }
  entry withdraw(n: u64) reads(token, bal) writes(bal) { guard bal.get(caller) >= n; guard n > 0; bal.debit(caller, n); send_asset(token, caller, n); }
}"#
    ));
}

#[test]
fn a_per_caller_counter_is_not_money() {
    // The simplest contract there is. `hits.credit(caller, 1)` is a visit counter, and
    // nothing can ever leave through it. Treating every address keyed integer map as a
    // ledger made this basic contract unbuildable, which is the plainest possible sign
    // the chain could not host ordinary applications.
    assert!(!rejected(
        r#"contract Counter {
  state { owner: Q_Address; hits: Map<Q_Address, u64>; total: u64; }
  genesis { owner = deployer; }
  entry bump() writes(hits, total) { hits.credit(caller, 1); total = total + 1; }
}"#
    ));
}

#[test]
fn a_counter_that_can_be_cashed_out_is_money_again() {
    // The same shape with a payout path is a balance, and forging it must be refused.
    assert!(rejected(
        r#"contract Counter2 {
  state { hits: Map<Q_Address, u64>; pool: Q_Asset<QTOV>; }
  entry bump() writes(hits) { hits.credit(caller, 1); }
  entry cash(n: u64) conserves QTOV reads(hits, pool) writes(hits, pool) { guard hits.get(caller) >= n; hits.debit(caller, n); let out = pool.split(n); send(caller, out); }
}"#
    ));
}

#[test]
fn a_token_with_approve_and_transfer_from_is_buildable() {
    // A token that lets a holder authorise a spender. `approve` writes the caller's
    // own allowance row and `transfer_from` spends it: both were refused, which meant
    // the chain could not host a token with delegated spending at all.
    assert!(!rejected(
        r#"contract Token {
  state { balances: Map<Q_Address, u128>; allowance: Map<Q_Address, u128>; total: u128; minter: Q_Address; }
  genesis { minter = deployer; }
  entry mint(to: Q_Address, amount: u128) reads(minter) writes(balances, total) { guard caller == minter; balances.credit(to, amount); total = checked(total + amount); }
  entry transfer(to: Q_Address, amount: u128) reads(balances) writes(balances) { guard balances.get(caller) >= amount; balances.debit(caller, amount); balances.credit(to, amount); }
  entry approve(amount: u128) writes(allowance) { allowance.set(caller, amount); }
  entry transfer_from(owner: Q_Address, to: Q_Address, amount: u128) reads(balances, allowance) writes(balances, allowance) { guard allowance.get(owner) >= amount; guard balances.get(owner) >= amount; allowance.debit(owner, amount); balances.debit(owner, amount); balances.credit(to, amount); }
}"#
    ));
}

#[test]
fn spending_a_permission_nobody_granted_is_still_refused() {
    // The same shape with the allowance grant made writable for ANY key: now anybody
    // can hand themselves permission over somebody else's balance.
    assert!(rejected(
        r#"contract Bad {
  state { balances: Map<Q_Address, u128>; allowance: Map<Q_Address, u128>; minter: Q_Address; }
  genesis { minter = deployer; }
  entry mint(to: Q_Address, amount: u128) reads(minter) writes(balances) { guard caller == minter; balances.credit(to, amount); }
  entry grant(who: Q_Address, amount: u128) writes(allowance) { allowance.set(who, amount); }
  entry transfer_from(owner: Q_Address, to: Q_Address, amount: u128) reads(balances, allowance) writes(balances, allowance) { guard allowance.get(owner) >= amount; guard balances.get(owner) >= amount; allowance.debit(owner, amount); balances.debit(owner, amount); balances.credit(to, amount); }
}"#
    ));
}

#[test]
fn a_transfer_from_that_does_not_conserve_is_still_refused() {
    // Debiting the owner and crediting MORE than was debited mints, whatever the
    // permission says.
    assert!(rejected(
        r#"contract Bad2 {
  state { balances: Map<Q_Address, u128>; allowance: Map<Q_Address, u128>; minter: Q_Address; }
  genesis { minter = deployer; }
  entry mint(to: Q_Address, amount: u128) reads(minter) writes(balances) { guard caller == minter; balances.credit(to, amount); }
  entry approve(amount: u128) writes(allowance) { allowance.set(caller, amount); }
  entry transfer_from(owner: Q_Address, to: Q_Address, amount: u128) reads(balances, allowance) writes(balances, allowance) { guard allowance.get(owner) >= amount; guard balances.get(owner) >= amount; allowance.debit(owner, amount); balances.debit(owner, amount); balances.credit(to, amount * 2); }
}"#
    ));
}
