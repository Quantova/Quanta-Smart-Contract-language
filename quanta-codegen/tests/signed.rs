// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{nonce_key, put_addr_slots, signer_address, slot_key};

const COUNTER: &str = "contract Counter {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry bump(order: BumpOrder signed by owner) writes(count) {\n\
    count = checked(count + order.step);\n\
    emit Bumped(count);\n\
  }\n\
  event Bumped(value: u64);\n\
}\n";

const OWNER_SLOT: u64 = 0;
const COUNT_SLOT: u64 = 4;
const CONTRACT_CTX_OFF: usize = 32;
const REGION_OFF: u64 = 8192;
const SCHEME_ML: u8 = 1;
const CONTRACT: [u8; 32] = [0x33; 32];

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn arg_offset(cc: &CompiledContract, key: &str) -> usize {
    cc.entries[0]
        .args
        .iter()
        .find(|slot| slot.key == key)
        .unwrap_or_else(|| panic!("no argument {key}"))
        .offset as usize
}

fn put_word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn canonical_message(
    contract: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(contract);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for f in fields {
        msg.extend_from_slice(&f.to_be_bytes());
    }
    msg
}

fn bump_memory(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    signed_step: u64,
    arg_step: u64,
    nonce: u64,
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let selector = cc.container.entries[0].selector;
    let msg = canonical_message(&CONTRACT, selector, &signer, nonce, &[signed_step]);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), SCHEME_ML as u64);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), REGION_OFF);
    put_word(&mut mem, arg_offset(cc, "order.step"), arg_step);
    mem[REGION_OFF as usize..].copy_from_slice(&region);
    mem
}

fn owned_storage(owner: &[u8; 32], count: u64) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, OWNER_SLOT, owner);
    storage.insert(slot_key(COUNT_SLOT), count);
    storage
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 400_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn the_owner_field_spans_four_slots_and_count_follows_it() {
    let cc = compile(COUNTER);
    assert_eq!(
        cc.container.entries[0].access.writes,
        vec![COUNT_SLOT],
        "count is the fifth slot, past the four word owner address"
    );
}

#[test]
fn the_owner_signature_admits_the_body_and_bumps_the_count() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let mem = bump_memory(&cc, &pk, &sk, 4, 4, 0);
    let out = run(&cc, owned_storage(&owner, 10), &mem).expect("the owner's signature is accepted");
    assert_eq!(
        out.get(&slot_key(COUNT_SLOT)),
        Some(&14),
        "count advances by the step"
    );
    assert_eq!(
        out.get(&nonce_key(&owner)),
        Some(&1),
        "the nonce is consumed"
    );
}

#[test]
fn a_strangers_own_valid_signature_is_refused() {
    let cc = compile(COUNTER);
    let (owner_pk, _owner_sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &owner_pk);
    let (pk, sk) = ml_dsa::keygen(&[9u8; 32]);

    let storage = owned_storage(&owner, 10);
    let mem = bump_memory(&cc, &pk, &sk, 4, 4, 0);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a valid signature by a non owner is refused"
    );
    assert_eq!(
        storage.get(&slot_key(COUNT_SLOT)),
        Some(&10),
        "state is unchanged"
    );
}

#[test]
fn an_address_that_only_collides_in_a_leading_word_is_refused() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[9u8; 32]);
    let signer = signer_address(SCHEME_ML, &pk);
    let mut owner = signer;
    owner[8] ^= 0xFF;

    let mem = bump_memory(&cc, &pk, &sk, 4, 4, 0);
    assert_eq!(
        run(&cc, owned_storage(&owner, 10), &mem),
        Err(Fault::DivByZero),
        "a leading word collision does not forge ownership"
    );
}

#[test]
fn a_tampered_order_field_is_refused() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let mem = bump_memory(&cc, &pk, &sk, 4, 5, 0);
    assert_eq!(
        run(&cc, owned_storage(&owner, 10), &mem),
        Err(Fault::DivByZero),
        "a signature does not carry to a changed field value"
    );
}

#[test]
fn a_replayed_message_is_refused_after_the_nonce_advances() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let mem = bump_memory(&cc, &pk, &sk, 4, 4, 0);
    let after_first = run(&cc, owned_storage(&owner, 10), &mem).expect("first call accepted");
    assert_eq!(after_first.get(&slot_key(COUNT_SLOT)), Some(&14));

    assert_eq!(
        run(&cc, after_first.clone(), &mem),
        Err(Fault::DivByZero),
        "the captured signature cannot be replayed"
    );

    let mem2 = bump_memory(&cc, &pk, &sk, 4, 4, 1);
    let after_second =
        run(&cc, after_first, &mem2).expect("second call with the new nonce accepted");
    assert_eq!(
        after_second.get(&slot_key(COUNT_SLOT)),
        Some(&18),
        "the owner acts again with a fresh nonce"
    );
}

#[test]
fn a_forged_signature_reverts() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);
    let mut mem = bump_memory(&cc, &pk, &sk, 4, 4, 0);
    let sig_start = REGION_OFF as usize + ml_dsa::PUBLIC_KEY_BYTES;
    mem[sig_start] ^= 1;

    let storage = owned_storage(&owner, 10);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a forged signature must revert"
    );
    assert_eq!(
        storage.get(&slot_key(COUNT_SLOT)),
        Some(&10),
        "state is unchanged"
    );
}
