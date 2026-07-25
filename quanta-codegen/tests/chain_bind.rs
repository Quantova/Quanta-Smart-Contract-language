// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The signed authorization preimage binds the chain identity the host presents at the `@chain`

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
// The signed message domain tag before the chain is folded into it, b"QTVSGN01" big endian.
const SIGNED_MSG_TAG: u64 = u64::from_be_bytes(*b"QTVSGN01");

// Two distinct chain identities. Neither is zero, so both differ from the unbound tag.
const CHAIN_A: u64 = 42;
const CHAIN_B: u64 = 99;

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

// The canonical order message the entry rebuilds: the chain bound domain tag, the contract self
// address, the entry selector word, the signer address, the per signer nonce, then the fields. The
// tag carries the chain identity, so signing under a different chain yields a different first word.
fn canonical_message(
    chain: u64,
    contract: &[u8; 32],
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    fields: &[u64],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(SIGNED_MSG_TAG ^ chain).to_be_bytes());
    msg.extend_from_slice(contract);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for f in fields {
        msg.extend_from_slice(&f.to_be_bytes());
    }
    msg
}

// Build a bump call signed over `signed_chain`, while the running memory presents `run_chain` at the
// `@chain` context word. The two differ only when a replay across chains is being tested.
fn bump_memory(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    signed_chain: u64,
    run_chain: u64,
    step: u64,
    nonce: u64,
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let selector = cc.container.entries[0].selector;
    let msg = canonical_message(signed_chain, &CONTRACT, selector, &signer, nonce, &[step]);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "@chain"), run_chain);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), SCHEME_ML as u64);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), REGION_OFF);
    put_word(&mut mem, arg_offset(cc, "order.step"), step);
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
fn a_signature_bound_to_a_chain_is_accepted_on_it() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    // Signed over chain A and presented under chain A: the tag the entry rebuilds matches, so the
    // owner's signature is accepted, the count advances, and the nonce is consumed.
    let mem = bump_memory(&cc, &pk, &sk, CHAIN_A, CHAIN_A, 4, 0);
    let out = run(&cc, owned_storage(&owner, 10), &mem)
        .expect("the owner's signature is accepted on its own chain");
    assert_eq!(out.get(&slot_key(COUNT_SLOT)), Some(&14), "count advances by the step");
    assert_eq!(out.get(&nonce_key(&owner)), Some(&1), "the nonce is consumed");
}

#[test]
fn the_same_signature_does_not_verify_under_a_different_chain() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    // The identical signed order, signed over chain A, presented on chain B. Only the `@chain`
    // context word differs; the signer, the order field, and the nonce are the same. The entry
    // rebuilds the tag with chain B, so the verify runs over a different preimage and reverts.
    let mem = bump_memory(&cc, &pk, &sk, CHAIN_A, CHAIN_B, 4, 0);
    let storage = owned_storage(&owner, 10);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a signature bound to chain A cannot be replayed on chain B"
    );
    assert_eq!(storage.get(&slot_key(COUNT_SLOT)), Some(&10), "state is unchanged");
}
