// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::{compile, CodegenError};

fn try_compile(src: &str) -> Result<(), CodegenError> {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile(&program).map(|_| ())
}

fn rejection(src: &str) -> String {
    match try_compile(src) {
        Err(CodegenError::Rejected { what, .. }) => what,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

const VULNERABLE_ROTATE: &str = "contract MultiSig {\n\
  state { signers: GuardianSet<5>; }\n\
  entry rotate(new_signers: GuardianSet<5>, approvals: Quorum<4 of 5, signers>)\n\
    writes(signers) after 24 hours from approvals.first { signers = new_signers; }\n\
}\n";

#[test]
fn the_shipped_quorum_anchor_bypass_no_longer_compiles() {
    let what = rejection(VULNERABLE_ROTATE);
    assert!(
        what.contains("approvals.first") && what.contains("no guardian signs"),
        "the quorum anchored time gate is rejected as unauthenticated: {what}"
    );
}

#[test]
fn any_other_quorum_pseudo_field_anchor_is_rejected() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(approvals: Quorum<2 of 3, board>) writes(flag)\n\
        after 24 hours from approvals.digest { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("approvals.digest"), "the digest pseudo field is rejected too: {what}");
}

#[test]
fn an_unsigned_param_field_anchor_is_rejected() {
    let src = "contract C {\n\
      state { flag: u64; }\n\
      entry act(order: Order) writes(flag)\n\
        after 1 hours from order.deadline { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(
        what.contains("order.deadline") && what.contains("no signature covers"),
        "a caller supplied field no signature covers is rejected: {what}"
    );
}

#[test]
fn a_bare_unsigned_param_anchor_is_rejected() {
    let src = "contract C {\n\
      state { flag: u64; }\n\
      entry act(deadline: u64) writes(flag) after deadline { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("deadline"), "a bare caller supplied parameter cannot anchor a delay: {what}");
}

#[test]
fn an_anchor_that_mixes_a_signed_field_with_a_pseudo_field_is_rejected() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(order: Order, approvals: Quorum<2 of 3, board>) writes(flag)\n\
        after 24 hours from order.start + approvals.first { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("approvals.first"), "the unauthenticated operand still rejects the whole anchor: {what}");
}

#[test]
fn a_quorum_pseudo_field_in_a_denies_gate_is_rejected() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(approvals: Quorum<2 of 3, board>) writes(flag)\n\
        denies approvals.first == 0 { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("approvals.first"), "a quorum field cannot gate a denies clause: {what}");
}

#[test]
fn a_quorum_pseudo_field_in_a_limits_gate_is_rejected() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(approvals: Quorum<2 of 3, board>) writes(flag)\n\
        limits approvals.first == 0 { flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("approvals.first"), "a quorum field cannot gate a limits clause: {what}");
}

#[test]
fn a_quorum_pseudo_field_in_a_guard_is_rejected() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(approvals: Quorum<2 of 3, board>) writes(flag)\n\
        { guard approvals.first == 0; flag = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("approvals.first"), "a quorum field cannot gate a guard: {what}");
}

#[test]
fn a_quorum_digest_in_an_event_still_compiles() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; flag: u64; }\n\
      entry act(approvals: Quorum<2 of 3, board>) writes(flag)\n\
        { flag = 1; emit Acted(approvals.digest); }\n\
      event Acted(digest: Q_Hash);\n\
    }\n";
    try_compile(src).expect("logging the quorum digest in an event is not a gate and compiles");
}

#[test]
fn a_state_field_anchor_still_compiles() {
    let src = "contract C {\n\
      state { opened: u64; done: u64; }\n\
      entry act() writes(done) reads(opened) after 1 hours from opened { done = 1; }\n\
    }\n";
    try_compile(src).expect("a delay anchored on state is authenticated and compiles");
}

#[test]
fn a_quorum_signed_order_field_anchor_still_compiles() {
    let src = "contract Board {\n\
      state { board: GuardianSet<3>; counter: u64; }\n\
      entry act(order: ActOrder, approvals: Quorum<2 of 3, board>) writes(counter)\n\
        after order.notbefore { counter = checked(counter + order.step); }\n\
    }\n";
    try_compile(src).expect("a quorum that signs the anchor field keeps compiling");
}

#[test]
fn a_state_anchor_written_from_a_caller_param_is_rejected() {
    let src = "contract C {\n\
      state { owner: Q_Address; anchor: u64; opened: u64; }\n\
      genesis { owner = deployer; }\n\
      entry set_anchor(t: u64) writes(anchor) { anchor = t; }\n\
      entry open(order: OpenOrder signed by owner) writes(opened)\n\
        after 24 hours from anchor denies anchor == 0 { opened = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(
        what.contains("`anchor`") && what.contains("pre-date the delay"),
        "an anchor a second entry writes from a caller value cannot back the delay: {what}"
    );
}

#[test]
fn a_state_anchor_advanced_by_a_caller_param_is_rejected() {
    let src = "contract C {\n\
      state { owner: Q_Address; anchor: u64; opened: u64; }\n\
      genesis { owner = deployer; }\n\
      entry push(t: u64) writes(anchor) { anchor = wrapping(anchor + t); }\n\
      entry open(order: OpenOrder signed by owner) writes(opened)\n\
        after 24 hours from anchor denies anchor == 0 { opened = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("`anchor`"), "an anchor moved by a caller value is rejected: {what}");
}

#[test]
fn a_state_anchor_seeded_from_a_deploy_param_is_rejected() {
    let src = "contract C {\n\
      state { owner: Q_Address; anchor: u64; opened: u64; }\n\
      genesis { owner = deployer; anchor = deploy_params.anchor; }\n\
      entry open(order: OpenOrder signed by owner) writes(opened)\n\
        after 24 hours from anchor denies anchor == 0 { opened = 1; }\n\
    }\n";
    let what = rejection(src);
    assert!(what.contains("`anchor`"), "a genesis seeded anchor from a deploy value is rejected: {what}");
}

#[test]
fn a_recorded_now_anchor_that_a_reset_clears_still_compiles() {
    let src = "contract C {\n\
      state { board: GuardianSet<3>; armed: u64; opened: u64; }\n\
      entry arm(approvals: Quorum<2 of 3, board>) writes(armed) { armed = now; }\n\
      entry open(approvals: Quorum<2 of 3, board>) writes(opened, armed)\n\
        after 24 hours from armed denies armed == 0 { opened = 1; armed = 0; }\n\
    }\n";
    try_compile(src).expect("recording the anchor with now and clearing it with a constant compiles");
}

#[test]
fn a_constant_default_anchor_still_compiles() {
    let src = "contract C {\n\
      state { owner: Q_Address; vault: Q_Asset<QTOV>; unlock: Time = 2027-12-31; }\n\
      genesis { owner = deployer; }\n\
      entry withdraw(order: WithdrawOrder signed by owner) conserves QTOV writes(vault)\n\
        after unlock { send(order.to, vault.split(order.amount)); }\n\
    }\n";
    try_compile(src).expect("a fixed constant unlock time is a safe anchor and compiles");
}
