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
