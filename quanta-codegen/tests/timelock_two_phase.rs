// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{put_addr_slots, signer_address, slot_key};

const GATE: &str = "contract Gate {\n\
  state { board: GuardianSet<1>; armed: u64; opened: u64; }\n\
  entry arm(approvals: Quorum<1 of 1, board>) writes(armed) { armed = now; }\n\
  entry open(approvals: Quorum<1 of 1, board>) writes(opened, armed)\n\
    after 1 hours from armed denies armed == 0 { opened = 1; armed = 0; }\n\
}\n";

const ARMED_SLOT: u64 = 4;
const OPENED_SLOT: u64 = 5;
const CONTRACT: [u8; 32] = [0x44; 32];
const SCHEME_ML: u8 = 1;
const GAS: u64 = 3_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries
        .iter()
        .find(|e| e.name == name)
        .expect("the entry")
}

fn arg_offset(e: &EntryArtifact, key: &str) -> usize {
    e.args
        .iter()
        .find(|s| s.key == key)
        .unwrap_or_else(|| panic!("no argument {key}"))
        .offset as usize
}

fn put_word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn message(selector: [u8; SELECTOR_BYTES], member: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg
}

fn ml_region(
    selector: [u8; SELECTOR_BYTES],
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    nonce: u64,
) -> Vec<u8> {
    let addr = signer_address(SCHEME_ML, pk);
    let msg = message(selector, &addr, nonce);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

fn call(e: &EntryArtifact, region: Vec<u8>, now: u64) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    mem[arg_offset(e, "@contract")..arg_offset(e, "@contract") + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(e, "@time"), now);
    let off = 8192usize;
    mem[off..off + region.len()].copy_from_slice(&region);
    put_word(
        &mut mem,
        arg_offset(e, "approvals#0#scheme"),
        SCHEME_ML as u64,
    );
    put_word(&mut mem, arg_offset(e, "approvals#0#ptr"), off as u64);
    put_word(&mut mem, arg_offset(e, "approvals#0#index"), 0);
    mem
}

fn run(
    cc: &CompiledContract,
    e: &EntryArtifact,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::for_entry(&cc.container, e.selector, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

fn guardian() -> ((ml_dsa::PublicKey, ml_dsa::SecretKey), [u8; 32]) {
    let key = ml_dsa::keygen(&[7u8; 32]);
    let addr = signer_address(SCHEME_ML, &key.0);
    (key, addr)
}

fn board_storage(addr: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, 0, addr);
    storage
}

#[test]
fn the_recorded_anchor_is_not_a_caller_argument() {
    let cc = compile(GATE);
    let open = entry(&cc, "open");
    assert!(
        open.args
            .iter()
            .all(|s| s.key != "armed" && s.key != "approvals.first"),
        "the delay anchor is host recorded state, not a caller supplied argument"
    );
}

#[test]
fn arm_then_open_after_the_delay_runs_end_to_end() {
    let cc = compile(GATE);
    let (key, addr) = guardian();
    let arm = entry(&cc, "arm");
    let open = entry(&cc, "open");

    let t: u64 = 10_000;
    let armed = call(arm, ml_region(arm.selector, &key.0, &key.1, 0), t);
    let after_arm = run(&cc, arm, board_storage(&addr), &armed).expect("the arm records the time");
    assert_eq!(
        after_arm.get(&slot_key(ARMED_SLOT)),
        Some(&t),
        "the arm recorded now under quorum"
    );

    let open_mem = call(open, ml_region(open.selector, &key.0, &key.1, 1), t + 3600);
    let out = run(&cc, open, after_arm.clone(), &open_mem)
        .expect("the open passes once the delay elapses");
    assert_eq!(
        out.get(&slot_key(OPENED_SLOT)),
        Some(&1),
        "the gated body ran"
    );
    assert_eq!(
        out.get(&slot_key(ARMED_SLOT)),
        Some(&0),
        "the arm is cleared after use"
    );
}

#[test]
fn open_before_the_delay_reverts() {
    let cc = compile(GATE);
    let (key, addr) = guardian();
    let arm = entry(&cc, "arm");
    let open = entry(&cc, "open");

    let t: u64 = 10_000;
    let armed = call(arm, ml_region(arm.selector, &key.0, &key.1, 0), t);
    let after_arm = run(&cc, arm, board_storage(&addr), &armed).expect("the arm records the time");

    let open_mem = call(open, ml_region(open.selector, &key.0, &key.1, 1), t + 3599);
    assert_eq!(
        run(&cc, open, after_arm.clone(), &open_mem),
        Err(Fault::DivByZero),
        "a valid quorum still cannot open one second before the recorded delay"
    );
    assert_eq!(
        after_arm.get(&slot_key(OPENED_SLOT)).copied().unwrap_or(0),
        0,
        "the gate is still closed"
    );
}

#[test]
fn a_valid_quorum_cannot_open_without_a_prior_arm() {
    let cc = compile(GATE);
    let (key, addr) = guardian();
    let open = entry(&cc, "open");

    let open_mem = call(
        open,
        ml_region(open.selector, &key.0, &key.1, 0),
        10_000_000,
    );
    assert_eq!(
        run(&cc, open, board_storage(&addr), &open_mem),
        Err(Fault::DivByZero),
        "with no armed anchor the delay cannot be skipped, there is nothing to forge"
    );
}
