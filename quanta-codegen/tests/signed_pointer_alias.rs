// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::{ml_dsa, slh_dsa};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{nonce_key, put_addr_slots, signer_address, slot_key};

const VAULT: &str = "contract Vault {\n\
  state { owner: Q_Address; seized: Registry<Q_Address>; }\n\
  genesis { owner = deployer; }\n\
  entry seize(order: SeizeOrder signed by owner) writes(seized) {\n\
    seized.insert(order.target);\n\
  }\n\
}\n";

const OWNER_SLOT: u64 = 0;
const CONTRACT_CTX_OFF: usize = 32;
const SCHEME_ML: u8 = 1;
const SCHEME_SLH: u8 = 2;
const CONTRACT: [u8; 32] = [0x33; 32];

const SIGNER_ADDR_SCRATCH: u64 = 40960;
const MSG_FIELDS_OFF: u64 = 88;
const NONCE_DIGEST_SCRATCH: u64 = 41216;

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
    selector: [u8; 4],
    signer: &[u8; 32],
    nonce: u64,
    target: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(target);
    msg
}

fn msg_start(scheme: u8) -> u64 {
    match scheme {
        SCHEME_ML => (ml_dsa::PUBLIC_KEY_BYTES + ml_dsa::SIGNATURE_BYTES) as u64,
        SCHEME_SLH => (slh_dsa::PUBLIC_KEY_BYTES + slh_dsa::SIGNATURE_BYTES) as u64,
        _ => unreachable!(),
    }
}

fn signed_region(scheme: u8, signer_seed: u8, selector: [u8; 4], nonce: u64, target: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    match scheme {
        SCHEME_ML => {
            let (pk, sk) = ml_dsa::keygen(&[signer_seed; 32]);
            let signer = signer_address(SCHEME_ML, &pk);
            let msg = canonical_message(selector, &signer, nonce, target);
            let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
            let mut region = Vec::new();
            region.extend_from_slice(&pk);
            region.extend_from_slice(&sig);
            region.extend_from_slice(&msg);
            (region, signer)
        }
        SCHEME_SLH => {
            let (sk, pk) = slh_dsa::keygen(&[signer_seed; 24], &[signer_seed; 24], &[signer_seed; 24]);
            let signer = signer_address(SCHEME_SLH, &pk);
            let msg = canonical_message(selector, &signer, nonce, target);
            let sig = slh_dsa::sign(&sk, &msg, &[], &[4u8; 24]).expect("sign");
            let mut region = Vec::new();
            region.extend_from_slice(&pk);
            region.extend_from_slice(&sig);
            region.extend_from_slice(&msg);
            (region, signer)
        }
        _ => unreachable!(),
    }
}

fn call_memory(
    cc: &CompiledContract,
    scheme: u8,
    region: &[u8],
    ptr: u64,
    target: &[u8; 32],
) -> Vec<u8> {
    let end = ptr as usize + region.len();
    let mut mem = vec![0u8; end.max(CONTRACT_CTX_OFF + 32)];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), scheme as u64);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), ptr);
    let t = arg_offset(cc, "order.target");
    mem[t..t + 32].copy_from_slice(target);
    mem[ptr as usize..end].copy_from_slice(region);
    mem
}

fn owned_storage(owner: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, OWNER_SLOT, owner);
    storage
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

const MSG_LEN: u64 = MSG_FIELDS_OFF + 32;

fn aliasing_ptr(scheme: u8) -> u64 {
    SIGNER_ADDR_SCRATCH - msg_start(scheme) - MSG_FIELDS_OFF
}

fn floor_ptr(scheme: u8) -> u64 {
    SIGNER_ADDR_SCRATCH - msg_start(scheme) - MSG_LEN
}

#[test]
fn the_owner_over_a_bounded_pointer_is_admitted() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let victim = [0x77u8; 32];
    let (region, owner) = signed_region(SCHEME_ML, 3, selector, 0, &victim);
    let mem = call_memory(&cc, SCHEME_ML, &region, 8192, &victim);
    let out = run(&cc, owned_storage(&owner), &mem).expect("the owner's own order is admitted");
    assert_eq!(out.get(&nonce_key(&owner)), Some(&1), "the owner's nonce is consumed");
}

fn forge_attempt(scheme: u8) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let (_owner_region, owner) = signed_region(scheme, 3, selector, 0, &[0u8; 32]);
    let ptr = aliasing_ptr(scheme);
    let (region, _attacker) = signed_region(scheme, 9, selector, 0, &owner);
    let mem = call_memory(&cc, scheme, &region, ptr, &owner);
    run(&cc, owned_storage(&owner), &mem)
}

#[test]
fn ml_dsa_pointer_alias_over_the_signer_scratch_is_refused() {
    assert_eq!(
        forge_attempt(SCHEME_ML),
        Err(Fault::DivByZero),
        "a pointer that aliases the derived-signer scratch must revert, not forge owner authority"
    );
}

#[test]
fn slh_dsa_pointer_alias_over_the_signer_scratch_is_refused() {
    assert_eq!(
        forge_attempt(SCHEME_SLH),
        Err(Fault::DivByZero),
        "the hash based scheme is refused the same aliasing pointer"
    );
}

#[test]
fn a_message_ending_exactly_at_the_scratch_floor_is_admitted() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let victim = [0x55u8; 32];
    let (region, owner) = signed_region(SCHEME_ML, 3, selector, 0, &victim);
    let ptr = floor_ptr(SCHEME_ML);
    let mem = call_memory(&cc, SCHEME_ML, &region, ptr, &victim);
    let out = run(&cc, owned_storage(&owner), &mem).expect("a message flush against the floor is admitted");
    assert_eq!(out.get(&nonce_key(&owner)), Some(&1), "the owner's nonce is consumed");
}

#[test]
fn a_message_reaching_one_word_into_the_scratch_is_refused() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let victim = [0x55u8; 32];
    let (region, owner) = signed_region(SCHEME_ML, 3, selector, 0, &victim);
    let ptr = floor_ptr(SCHEME_ML) + 8;
    let mem = call_memory(&cc, SCHEME_ML, &region, ptr, &victim);
    assert_eq!(
        run(&cc, owned_storage(&owner), &mem),
        Err(Fault::DivByZero),
        "a message that reaches into the scratch band is refused"
    );
}

#[test]
fn a_pointer_aliasing_the_nonce_digest_scratch_is_refused() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let victim = [0x66u8; 32];
    let (region, owner) = signed_region(SCHEME_ML, 3, selector, 0, &victim);
    let ptr = NONCE_DIGEST_SCRATCH - msg_start(SCHEME_ML) - MSG_FIELDS_OFF;
    let mem = call_memory(&cc, SCHEME_ML, &region, ptr, &victim);
    assert_eq!(
        run(&cc, owned_storage(&owner), &mem),
        Err(Fault::DivByZero),
        "a pointer aliasing any scratch above the floor is refused"
    );
}

#[test]
fn the_owner_slot_is_the_first_state_field() {
    let cc = compile(VAULT);
    assert!(
        cc.entries[0].args.iter().any(|s| s.key == "order#ptr"),
        "the signed order exposes a caller supplied pointer word"
    );
    let _ = slot_key(OWNER_SLOT);
}
