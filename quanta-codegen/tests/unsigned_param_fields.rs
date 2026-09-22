// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::compile_contract;

const GENESIS_SENTINEL: u64 = u64::from_be_bytes(*b"QGENSNTL");

fn refused(src: &str) -> bool {
    let program = quanta_parser::parse(src).expect("parse");
    if quanta_typeck::check(&program).is_err() {
        return true;
    }
    compile_contract(&program.contracts[0]).is_err()
}

#[test]
fn a_quorum_field_other_than_its_digest_is_refused() {
    let src = "contract T {\n\
      state { signers: GuardianSet<5>; vault: Q_Asset<QTOV>; }\n\
      genesis { signers = deploy_params.signers; }\n\
      entry disburse(approvals: Quorum<3 of 5, signers>) writes(vault) conserves QTOV {\n\
        send(approvals.to, vault.split(approvals.amount));\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn an_asset_field_other_than_its_amount_is_refused() {
    let src = "contract T {\n\
      state { vault: Q_Asset<QTOV>; last: Q_Address; }\n\
      entry deposit(funds: Q_Asset<QTOV>) writes(vault, last) conserves QTOV {\n\
        guard in_asset == native;\n\
        last = funds.owner;\n\
        vault.merge(funds);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_signed_order_cannot_pay_whoever_submits_it() {
    let src = "contract T {\n\
      state { admin: Q_Address; vault: Q_Asset<QTOV>; }\n\
      genesis { admin = deployer; }\n\
      entry claim(order: Claim signed by admin) writes(vault) conserves QTOV {\n\
        let out = vault.split(order.amount);\n\
        send(caller, out);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_signed_order_may_still_compare_the_caller_in_a_guard() {
    let src = "contract T {\n\
      state { admin: Q_Address; operator: Q_Address; count: u64; }\n\
      genesis { admin = deployer; operator = deployer; }\n\
      entry bump(order: Bump signed by admin) writes(count) {\n\
        guard caller == operator;\n\
        count = checked(count + order.step);\n\
      }\n\
    }\n";
    assert!(!refused(src));
}

#[test]
fn a_token_pin_cannot_stand_in_for_native_value() {
    let src = "contract T {\n\
      state { token: Q_Address; bal: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }\n\
      genesis { token = deployer; }\n\
      entry deposit(funds: Q_Asset<QTOV>) writes(bal, vault) conserves QTOV {\n\
        guard in_asset == token;\n\
        bal.credit(caller, funds.amount);\n\
        vault.merge(funds);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_token_pin_anyone_can_rewrite_is_refused() {
    let src = "contract T {\n\
      state { accepted: Q_Address; bal: Map<Q_Address, u64>; vault: Q_Asset<TKN>; }\n\
      genesis { accepted = deployer; }\n\
      entry set_accepted(t: Q_Address) writes(accepted) { accepted = t; }\n\
      entry deposit(funds: Q_Asset<TKN>) writes(bal, vault) conserves TKN {\n\
        guard in_asset == accepted;\n\
        bal.credit(caller, funds.amount);\n\
        vault.merge(funds);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_constant_subtraction_is_not_a_reduction_of_the_row() {
    let src = "contract Club {\n\
      state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }\n\
      entry join() writes(members) { members.set(caller, 2 - 1); }\n\
      entry take() reads(members) writes(vault) conserves QTOV {\n\
        guard members.get(caller) > 0;\n\
        let out = vault.split(100);\n\
        send(caller, out);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn value_sent_to_an_entry_without_an_asset_parameter_traps() {
    let src = "contract T {\n\
      state { count: u64; }\n\
      entry bump() writes(count) { count = checked(count + 1); }\n\
    }\n";
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let entry = cc.entries.iter().find(|e| e.name == "bump").expect("entry");
    let value_off = entry
        .args
        .iter()
        .find(|a| a.key == "@value")
        .expect("the value slot")
        .offset as usize;
    let run = |value: u64| {
        let mut mem = vec![0u8; 4096];
        mem[value_off..value_off + 8].copy_from_slice(&value.to_be_bytes());
        qtv_vm::interp::Interpreter::for_entry(&cc.container, entry.selector, 1_000_000)
            .expect("entry")
            .with_memory(&mem)
            .run()
            .is_ok()
    };
    assert!(run(0));
    assert!(!run(5));
}

#[test]
fn a_genesis_that_breaks_an_invariant_traps() {
    let src = "contract T {\n\
      state { drip: u64; }\n\
      invariant drip <= 1_000;\n\
      genesis { drip = deploy_params.drip; }\n\
    }\n";
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
    let slot = cc
        .deploy_params
        .iter()
        .find(|p| p.key == "deploy_params.drip")
        .expect("the drip parameter");
    let sentinel = cc
        .deploy_params
        .iter()
        .map(|p| p.offset + p.width)
        .max()
        .unwrap() as usize;
    let run = |drip: u64| {
        let mut mem = vec![0u8; 4096];
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&drip.to_be_bytes());
        mem[sentinel..sentinel + 8].copy_from_slice(&GENESIS_SENTINEL.to_be_bytes());
        qtv_vm::interp::Interpreter::for_entry(&cc.container, selector, 1_000_000)
            .expect("genesis")
            .with_memory(&mem)
            .run()
            .is_ok()
    };
    assert!(run(500));
    assert!(!run(5_000));
}

#[test]
fn an_event_logs_the_whole_name_window() {
    let src = "contract T {\n\
      state { count: u64; }\n\
      entry note(label: Q_Name) writes(count) {\n\
        count = checked(count + 1);\n\
        emit Noted(label);\n\
      }\n\
      event Noted(name: Q_Name);\n\
    }\n";
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let entry = cc.entries.iter().find(|e| e.name == "note").expect("entry");
    let off = |key: &str| {
        entry
            .args
            .iter()
            .find(|a| a.key == key)
            .unwrap_or_else(|| panic!("no {key}"))
            .offset as usize
    };
    let label = b"quantova-foundation";
    let mut mem = vec![0u8; 4096];
    mem[off("label")..off("label") + label.len()].copy_from_slice(label);
    mem[off("label#len")..off("label#len") + 8]
        .copy_from_slice(&(label.len() as u64).to_be_bytes());
    let out = qtv_vm::interp::Interpreter::for_entry(&cc.container, entry.selector, 50_000_000)
        .expect("entry")
        .with_memory(&mem)
        .run()
        .expect("the note runs");
    let logged = out
        .effects
        .iter()
        .find_map(|e| match e {
            qtv_vm::interp::Effect::Event { data, .. } => Some(data.clone()),
            _ => None,
        })
        .expect("an event");
    assert_eq!(&logged[..label.len()], label);
    assert_eq!(logged.len(), 32);
}

#[test]
fn two_names_are_not_compared_by_their_first_word() {
    let src = "contract T {\n\
      state { count: u64; }\n\
      entry pair(a: Q_Name, b: Q_Name) writes(count) {\n\
        guard a != b;\n\
        count = checked(count + 1);\n\
      }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_contract_declaring_two_assets_cannot_mint_an_unnamed_one() {
    let src = "contract T {\n\
      asset GOLD;\n\
      asset SILVER;\n\
      state { owner: Q_Address; }\n\
      genesis { owner = deployer; }\n\
      entry issue(to: Q_Address, n: u64) mints GOLD { guard caller == owner; mint_asset(to, n); }\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn an_event_name_declared_twice_is_refused() {
    let src = "contract T {\n\
      state { count: u64; }\n\
      entry bump() writes(count) { count = checked(count + 1); emit Bumped(count); }\n\
      event Bumped(value: u64);\n\
      event Bumped(value: u64, extra: u64);\n\
    }\n";
    assert!(refused(src));
}

#[test]
fn a_name_outside_lowercase_letters_digits_and_hyphen_traps() {
    let src = "contract T {\n\
      state { count: u64; }\n\
      entry note(label: Q_Name) writes(count) { count = checked(count + 1); }\n\
    }\n";
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let entry = cc.entries.iter().find(|e| e.name == "note").expect("entry");
    let off = |key: &str| {
        entry
            .args
            .iter()
            .find(|a| a.key == key)
            .unwrap_or_else(|| panic!("no {key}"))
            .offset as usize
    };
    let run = |label: &[u8]| {
        let mut mem = vec![0u8; 4096];
        mem[off("label")..off("label") + label.len()].copy_from_slice(label);
        mem[off("label#len")..off("label#len") + 8]
            .copy_from_slice(&(label.len() as u64).to_be_bytes());
        qtv_vm::interp::Interpreter::for_entry(&cc.container, entry.selector, 50_000_000)
            .expect("entry")
            .with_memory(&mem)
            .run()
            .is_ok()
    };
    assert!(run(b"quantova-1"));
    assert!(run(b"z9"));
    assert!(!run(b"Quantova"));
    assert!(!run(b"quant\x01ova"));
    assert!(!run(b"quant ova"));
    assert!(!run(b"quantov\xc3\xa0"));
}
