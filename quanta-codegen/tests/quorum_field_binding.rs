// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{put_addr_slots, signer_address, slot_key};

const BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<3>; counter: u64; }\n\
  entry act(order: ActOrder, approvals: Quorum<2 of 3, board>) writes(counter) after order.notbefore {\n\
    counter = checked(counter + order.step);\n\
  }\n\
}\n";

const COUNTER_SLOT: u64 = 12;
const CONTRACT: [u8; 32] = [0x44; 32];
const SCHEME_ML: u8 = 1;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn arg_offset(cc: &CompiledContract, key: &str) -> usize {
    cc.entries[0]
        .args
        .iter()
        .find(|s| s.key == key)
        .unwrap_or_else(|| panic!("no argument {key}"))
        .offset as usize
}

fn put_word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn message(cc: &CompiledContract, member: &[u8; 32], nonce: u64, fields: &[u64]) -> Vec<u8> {
    let selector = cc.container.entries[0].selector;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for f in fields {
        msg.extend_from_slice(&f.to_be_bytes());
    }
    msg
}

fn ml_region(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let addr = signer_address(SCHEME_ML, pk);
    let msg = message(cc, &addr, nonce, fields);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

fn scratch(
    cc: &CompiledContract,
    members: &[(Vec<u8>, u64)],
    plain: [u64; 2],
    now: u64,
) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "@time"), now);
    put_word(&mut mem, arg_offset(cc, "order.notbefore"), plain[0]);
    put_word(&mut mem, arg_offset(cc, "order.step"), plain[1]);
    let mut cursor = 8192usize;
    for (i, (region, index)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_word(
            &mut mem,
            arg_offset(cc, &format!("approvals#{i}#scheme")),
            SCHEME_ML as u64,
        );
        put_word(
            &mut mem,
            arg_offset(cc, &format!("approvals#{i}#ptr")),
            off as u64,
        );
        put_word(
            &mut mem,
            arg_offset(cc, &format!("approvals#{i}#index")),
            *index,
        );
    }
    mem
}

fn board_storage(guardians: &[[u8; 32]; 3]) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    for (j, g) in guardians.iter().enumerate() {
        put_addr_slots(&mut storage, j as u64 * 4, g);
    }
    storage.insert(slot_key(COUNTER_SLOT), 10);
    storage
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 3_000_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

fn ml_guardians() -> (Vec<(ml_dsa::PublicKey, ml_dsa::SecretKey)>, [[u8; 32]; 3]) {
    let keys: Vec<_> = [1u8, 2, 3]
        .iter()
        .map(|s| ml_dsa::keygen(&[*s; 32]))
        .collect();
    let addrs = [
        signer_address(SCHEME_ML, &keys[0].0),
        signer_address(SCHEME_ML, &keys[1].0),
        signer_address(SCHEME_ML, &keys[2].0),
    ];
    (keys, addrs)
}

#[test]
fn a_quorum_over_the_whole_field_set_admits_the_entry() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let fields = [100u64, 1];
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &fields);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &fields);
    let mem = scratch(&cc, &[(m0, 0), (m1, 1)], [100, 1], 10_000);
    let out = run(&cc, board_storage(&addrs), &mem).expect("a met quorum over the fields admits");
    assert_eq!(
        out.get(&slot_key(COUNTER_SLOT)),
        Some(&11),
        "the gated body runs"
    );
}

#[test]
fn rewriting_the_gate_target_breaks_the_quorum() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let signed = [500u64, 1];
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &signed);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &signed);
    let mem = scratch(&cc, &[(m0, 0), (m1, 1)], [0, 1], 400);
    let storage = board_storage(&addrs);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a rewritten gate target breaks the quorum signatures"
    );
    assert_eq!(
        storage.get(&slot_key(COUNTER_SLOT)),
        Some(&10),
        "state is unchanged"
    );
}

#[test]
fn rewriting_a_body_field_breaks_the_quorum() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let signed = [100u64, 1];
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &signed);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &signed);
    let mem = scratch(&cc, &[(m0, 0), (m1, 1)], [100, 9], 10_000);
    let storage = board_storage(&addrs);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "an inflated body field breaks the quorum signatures"
    );
    assert_eq!(
        storage.get(&slot_key(COUNTER_SLOT)),
        Some(&10),
        "state is unchanged"
    );
}
