// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Quorum binding. A `Quorum<M of N, set>` is constructed only from M valid signatures, each by a

use std::collections::BTreeMap;

use qtv_crypto::{ml_dsa, slh_dsa};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{put_addr_slots, signer_address, slot_key};

const BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<3>; counter: u64; }\n\
  entry act(approvals: Quorum<2 of 3, board>) writes(counter) {\n\
    counter = checked(counter + 1);\n\
  }\n\
}\n";

// The guardian set holds three guardians across the first twelve slots; counter follows it.
const COUNTER_SLOT: u64 = 12;
const CONTRACT: [u8; 32] = [0x44; 32];
const SCHEME_ML: u8 = 1;
const SCHEME_SLH: u8 = 2;

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

// The canonical quorum message the compiler rebuilds: the domain tag, the contract self address, the
// entry selector word, the member address, and the member's nonce. The `act` entry has no order fields.
fn message(cc: &CompiledContract, member: &[u8; 32], nonce: u64) -> Vec<u8> {
    let selector = cc.container.entries[0].selector;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg
}

fn ml_region(cc: &CompiledContract, pk: &[u8], sk: &ml_dsa::SecretKey, nonce: u64) -> Vec<u8> {
    let addr = signer_address(SCHEME_ML, pk);
    let msg = message(cc, &addr, nonce);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

fn slh_region(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &[u8; slh_dsa::SECRET_KEY_BYTES],
    nonce: u64,
) -> Vec<u8> {
    let addr = signer_address(SCHEME_SLH, pk);
    let msg = message(cc, &addr, nonce);
    let sig = slh_dsa::sign(sk, &msg, &[], &[4u8; 24]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

// Place each member's region and its scheme, pointer, and guardian index words.
fn scratch(cc: &CompiledContract, members: &[(u8, Vec<u8>, u64)]) -> Vec<u8> {
    // The member verify regions sit low in scratch, below the fixed scratch regions the code generator
    // uses for the signer address, the nonce, and the slot keys, which begin around forty thousand.
    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    let mut cursor = 8192usize;
    for (i, (scheme, region, index)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#scheme")), *scheme as u64);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#ptr")), off as u64);
        put_word(&mut mem, arg_offset(cc, &format!("approvals#{i}#index")), *index);
    }
    mem
}

// The guardian set state, three guardians seeded across the first twelve slots, plus the counter.
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

// Three module lattice guardians and their addresses.
fn ml_guardians() -> (Vec<(ml_dsa::PublicKey, ml_dsa::SecretKey)>, [[u8; 32]; 3]) {
    let keys: Vec<_> = [1u8, 2, 3].iter().map(|s| ml_dsa::keygen(&[*s; 32])).collect();
    let addrs = [
        signer_address(SCHEME_ML, &keys[0].0),
        signer_address(SCHEME_ML, &keys[1].0),
        signer_address(SCHEME_ML, &keys[2].0),
    ];
    (keys, addrs)
}

#[test]
fn two_distinct_guardians_construct_the_quorum_and_admit_the_entry() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    // Members are guardians zero and one, named by their indices in order.
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0);
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_ML, m1, 1)]);
    let out = run(&cc, board_storage(&addrs), &mem).expect("a met quorum admits the entry");
    assert_eq!(out.get(&slot_key(COUNTER_SLOT)), Some(&11), "the gated body runs");
}

#[test]
fn a_mixed_scheme_quorum_admits_a_module_lattice_and_a_hash_based_guardian() {
    let cc = compile(BOARD);
    let (ml_keys, _) = ml_guardians();
    let (slh_sk, slh_pk) = slh_dsa::keygen(&[7u8; 24], &[7u8; 24], &[7u8; 24]);
    // Guardian zero is a module lattice key, guardian one is a hash based key.
    let g0 = signer_address(SCHEME_ML, &ml_keys[0].0);
    let g1 = signer_address(SCHEME_SLH, &slh_pk);
    let g2 = signer_address(SCHEME_ML, &ml_keys[2].0);
    let guardians = [g0, g1, g2];

    let m0 = ml_region(&cc, &ml_keys[0].0, &ml_keys[0].1, 0);
    let m1 = slh_region(&cc, &slh_pk, &slh_sk, 0);
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_SLH, m1, 1)]);
    let out = run(&cc, board_storage(&guardians), &mem).expect("a mixed scheme quorum admits");
    assert_eq!(out.get(&slot_key(COUNTER_SLOT)), Some(&11));
}

#[test]
fn a_valid_signature_from_a_non_guardian_is_refused() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    // The second member is a stranger who signs a perfectly valid message but is not the guardian at
    // the index it names, so the guardian comparison reverts.
    let (spk, ssk) = ml_dsa::keygen(&[99u8; 32]);
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0);
    let m1 = ml_region(&cc, &spk, &ssk, 0);
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_ML, m1, 1)]);
    assert_eq!(
        run(&cc, board_storage(&addrs), &mem),
        Err(Fault::DivByZero),
        "a valid signature from a non guardian is refused"
    );
}

#[test]
fn a_guardian_counted_twice_is_refused() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    // Both members are guardian zero, naming index zero twice. The indices are not strictly
    // increasing, so the distinctness check reverts.
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0);
    let m0_again = ml_region(&cc, &keys[0].0, &keys[0].1, 1);
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_ML, m0_again, 0)]);
    assert_eq!(
        run(&cc, board_storage(&addrs), &mem),
        Err(Fault::DivByZero),
        "a guardian counted twice is refused"
    );
}

#[test]
fn a_replayed_quorum_is_refused_after_the_nonces_advance() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0);
    let m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0);
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_ML, m1, 1)]);

    let after_first = run(&cc, board_storage(&addrs), &mem).expect("first quorum admits");
    assert_eq!(after_first.get(&slot_key(COUNTER_SLOT)), Some(&11));

    // Replaying the same memory now reverts: each member's nonce has advanced, so the rebuilt messages
    // differ from the ones the captured signatures signed.
    assert_eq!(
        run(&cc, after_first, &mem),
        Err(Fault::DivByZero),
        "a captured quorum cannot be replayed"
    );
}

#[test]
fn an_invalid_member_signature_refuses_the_entry() {
    let cc = compile(BOARD);
    let (keys, addrs) = ml_guardians();
    let m0 = ml_region(&cc, &keys[0].0, &keys[0].1, 0);
    let mut m1 = ml_region(&cc, &keys[1].0, &keys[1].1, 0);
    // Corrupt the first signature byte so the verify fails. The message tail cannot be corrupted here
    // because the compiler rebuilds the message before verifying.
    m1[ml_dsa::PUBLIC_KEY_BYTES] ^= 1;
    let mem = scratch(&cc, &[(SCHEME_ML, m0, 0), (SCHEME_ML, m1, 1)]);
    assert_eq!(
        run(&cc, board_storage(&addrs), &mem),
        Err(Fault::DivByZero),
        "an invalid member signature reverts"
    );
}
