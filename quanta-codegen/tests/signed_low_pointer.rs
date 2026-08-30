// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{nonce_key, put_addr_slots, signer_address};

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
        .find(|s| s.key == key)
        .unwrap()
        .offset as usize
}

fn max_arg_end(cc: &CompiledContract) -> u64 {
    cc.entries[0]
        .args
        .iter()
        .map(|s| s.offset + 32)
        .max()
        .unwrap_or(0)
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

fn region_for(seed: u8, selector: [u8; 4], target: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let (pk, sk) = ml_dsa::keygen(&[seed; 32]);
    let signer = signer_address(SCHEME_ML, &pk);
    let msg = canonical_message(selector, &signer, 0, target);
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    (region, signer)
}

fn call_memory(cc: &CompiledContract, region: &[u8], ptr: u64, target: &[u8; 32]) -> Vec<u8> {
    let end = ptr as usize + region.len();
    let mut mem = vec![0u8; end.max(CONTRACT_CTX_OFF + 32)];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), SCHEME_ML as u64);
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

fn low_ptr(cc: &CompiledContract) -> u64 {
    (max_arg_end(cc) + 7) / 8 * 8
}

#[test]
fn the_owner_over_a_low_pointer_is_admitted() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let victim = [0x77u8; 32];
    let (region, owner) = region_for(3, selector, &victim);
    let mem = call_memory(&cc, &region, low_ptr(&cc), &victim);
    let out = run(&cc, owned_storage(&owner), &mem)
        .expect("a valid order over a low pointer is admitted");
    assert_eq!(
        out.get(&nonce_key(&owner)),
        Some(&1),
        "the owner's nonce is consumed"
    );
}

#[test]
fn a_low_pointer_cannot_forge_owner_authority() {
    let cc = compile(VAULT);
    let selector = cc.container.entries[0].selector;
    let (_owner_region, owner) = region_for(3, selector, &[0u8; 32]);
    let (region, _attacker) = region_for(9, selector, &owner);
    let mem = call_memory(&cc, &region, low_ptr(&cc), &owner);
    assert_eq!(
        run(&cc, owned_storage(&owner), &mem),
        Err(Fault::DivByZero),
        "the derived signer is not the owner, so a low pointer cannot forge"
    );
}
