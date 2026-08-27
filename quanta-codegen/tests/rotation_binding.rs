// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{put_addr_slots, signer_address, slot_key};

const BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<3>; }\n\
  entry rotate(new_board: GuardianSet<3>, approvals: Quorum<2 of 3, board>) writes(board) {\n\
    board = new_board;\n\
  }\n\
}\n";

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

fn message(cc: &CompiledContract, member: &[u8; 32], nonce: u64, new_board: &[[u8; 32]; 3]) -> Vec<u8> {
    let selector = cc.container.entries[0].selector;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for addr in new_board {
        msg.extend_from_slice(addr);
    }
    msg
}

fn ml_region(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    nonce: u64,
    new_board: &[[u8; 32]; 3],
) -> Vec<u8> {
    let addr = signer_address(SCHEME_ML, pk);
    let msg = message(cc, &addr, nonce, new_board);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

fn scratch(cc: &CompiledContract, members: &[(Vec<u8>, u64)], submitted: &[[u8; 32]; 3]) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    let set_off = arg_offset(cc, "new_board");
    for (i, addr) in submitted.iter().enumerate() {
        mem[set_off + i * 32..set_off + i * 32 + 32].copy_from_slice(addr);
    }
    let mut cursor = 8192usize;
    for (i, (region, index)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#scheme")), SCHEME_ML as u64);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#ptr")), off as u64);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#index")), *index);
    }
    mem
}

fn board_storage(guardians: &[[u8; 32]; 3]) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    for (j, g) in guardians.iter().enumerate() {
        put_addr_slots(&mut storage, j as u64 * 4, g);
    }
    storage
}

fn read_board(storage: &BTreeMap<[u8; 32], u64>) -> [[u8; 32]; 3] {
    let mut out = [[0u8; 32]; 3];
    for (g, addr) in out.iter_mut().enumerate() {
        for w in 0..4 {
            let word = storage.get(&slot_key((g * 4 + w) as u64)).copied().unwrap_or(0);
            addr[w * 8..w * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
    }
    out
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
    let keys: Vec<_> = [1u8, 2, 3].iter().map(|s| ml_dsa::keygen(&[*s; 32])).collect();
    let addrs = [
        signer_address(SCHEME_ML, &keys[0].0),
        signer_address(SCHEME_ML, &keys[1].0),
        signer_address(SCHEME_ML, &keys[2].0),
    ];
    (keys, addrs)
}

fn new_membership() -> [[u8; 32]; 3] {
    [[0xA1; 32], [0xB2; 32], [0xC3; 32]]
}

#[test]
fn a_quorum_that_signs_the_new_set_rotates_the_board() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let new_board = new_membership();

    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &new_board);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &new_board);
    let mem = scratch(&cc, &[(m0, 0), (m1, 1)], &new_board);

    let out = run(&cc, board_storage(&addrs), &mem).expect("a quorum over the new set rotates");
    assert_eq!(read_board(&out), new_board, "the board is now the approved new set");
}

#[test]
fn substituting_a_different_new_set_breaks_the_quorum() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let approved = new_membership();

    let attacker = [[0xEE; 32], [0xEE; 32], [0xEE; 32]];
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &approved);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &approved);
    let mem = scratch(&cc, &[(m0, 0), (m1, 1)], &attacker);

    let storage = board_storage(&addrs);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a swapped new set is not carried by the quorum signatures"
    );
    assert_eq!(read_board(&storage), addrs, "the board is unchanged");
}

#[test]
fn rewriting_any_single_new_set_word_breaks_the_quorum() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let approved = new_membership();
    let set_off = arg_offset(&cc, "new_board");

    for word in 0..12usize {
        let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &approved);
        let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &approved);
        let mut mem = scratch(&cc, &[(m0, 0), (m1, 1)], &approved);
        mem[set_off + word * 8] ^= 0xFF;
        let storage = board_storage(&addrs);
        assert_eq!(
            run(&cc, storage.clone(), &mem),
            Err(Fault::DivByZero),
            "rewriting new set word {word} must revert"
        );
        assert_eq!(read_board(&storage), addrs, "the board is unchanged for word {word}");
    }
}
