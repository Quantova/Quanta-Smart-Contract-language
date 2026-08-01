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

const SIGNER_ADDR_SCRATCH: u64 = 40960;
const MSG_FIELDS_OFF: u64 = 88;

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
    Interpreter::new(&cc.container.code, &cc.container.consts, 6_000_000)
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

fn ml_msg_start() -> u64 {
    (ml_dsa::PUBLIC_KEY_BYTES + ml_dsa::SIGNATURE_BYTES) as u64
}

#[test]
fn an_honest_quorum_over_a_bounded_pointer_rotates_the_board() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let new_board = [[0xA1u8; 32], [0xB2; 32], [0xC3; 32]];

    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &new_board);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0, &new_board);

    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    let set_off = arg_offset(&cc, "new_board");
    for (i, a) in new_board.iter().enumerate() {
        mem[set_off + i * 32..set_off + i * 32 + 32].copy_from_slice(a);
    }
    place_member(&cc, &mut mem, 0, 8192, &m0, 0);
    place_member(&cc, &mut mem, 1, 8192 + m0.len() as u64, &m1, 1);

    let out = run(&cc, board_storage(&addrs), &mem).expect("an honest quorum rotates");
    assert_eq!(read_board(&out), new_board, "the board is the approved new set");
}

fn place_member(cc: &CompiledContract, mem: &mut [u8], i: usize, ptr: u64, region: &[u8], index: u64) {
    mem[ptr as usize..ptr as usize + region.len()].copy_from_slice(region);
    put_word(mem, arg_offset(cc, &format!("approvals#{i}#scheme")), SCHEME_ML as u64);
    put_word(mem, arg_offset(cc, &format!("approvals#{i}#ptr")), ptr);
    put_word(mem, arg_offset(cc, &format!("approvals#{i}#index")), index);
}

fn forge_attempt() -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let new_board = [[0xEEu8; 32], addrs[1], [0xEE; 32]];

    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0, &new_board);
    let (fpk, fsk) = ml_dsa::keygen(&[200u8; 32]);
    let m1 = ml_region(&cc, &fpk, &fsk, 0, &new_board);

    let ptr1 = SIGNER_ADDR_SCRATCH - ml_msg_start() - MSG_FIELDS_OFF - 32;

    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    let set_off = arg_offset(&cc, "new_board");
    for (i, a) in new_board.iter().enumerate() {
        mem[set_off + i * 32..set_off + i * 32 + 32].copy_from_slice(a);
    }
    place_member(&cc, &mut mem, 0, 8192, &m0, 0);
    place_member(&cc, &mut mem, 1, ptr1, &m1, 1);

    run(&cc, board_storage(&addrs), &mem)
}

#[test]
fn a_quorum_member_pointer_alias_over_the_signer_scratch_is_refused() {
    assert_eq!(
        forge_attempt(),
        Err(Fault::DivByZero),
        "a quorum-member pointer that aliases the derived-member scratch must revert, not forge a quorum"
    );
}
