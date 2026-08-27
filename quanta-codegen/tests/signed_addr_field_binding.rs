// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{signer_address, slot_key};

const SRC: &str = "contract Rotatable {\n\
  state { admin: Q_Address; owner: Q_Address; }\n\
  genesis { admin = deployer; }\n\
  entry rotate(order: RotateOrder signed by admin) writes(owner) {\n\
    owner = order.newowner;\n\
  }\n\
}\n";

const ADMIN_SLOT: u64 = 0;
const OWNER_SLOT: u64 = 4;
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

fn arg_width(cc: &CompiledContract, key: &str) -> u64 {
    cc.entries[0].args.iter().find(|s| s.key == key).expect("arg").width
}

fn put_word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn words(addr: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for i in 0..4 {
        w[i] = u64::from_be_bytes(addr[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

fn canonical_message(signer: &[u8; 32], selector: [u8; 4], newowner: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&0u64.to_be_bytes());
    for w in words(newowner) {
        msg.extend_from_slice(&w.to_be_bytes());
    }
    msg
}

fn rotate_memory(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    signed_newowner: &[u8; 32],
    arg_newowner: &[u8; 32],
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let selector = cc.container.entries[0].selector;
    let msg = canonical_message(&signer, selector, signed_newowner);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), SCHEME_ML as u64);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), REGION_OFF);
    let no = arg_offset(cc, "order.newowner");
    mem[no..no + 32].copy_from_slice(arg_newowner);
    mem[REGION_OFF as usize..].copy_from_slice(&region);
    mem
}

fn admin_storage(admin: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    for i in 0..4u64 {
        let w = u64::from_be_bytes(admin[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        storage.insert(slot_key(ADMIN_SLOT + i), w);
    }
    storage
}

fn run(cc: &CompiledContract, storage: BTreeMap<[u8; 32], u64>, mem: &[u8]) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 600_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

fn owner_after(storage: &BTreeMap<[u8; 32], u64>) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4u64 {
        let w = storage.get(&slot_key(OWNER_SLOT + i)).copied().unwrap_or(0);
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[test]
fn the_assigned_address_field_is_a_full_thirty_two_byte_argument() {
    let cc = compile(SRC);
    assert_eq!(
        arg_width(&cc, "order.newowner"),
        32,
        "an address only ever assigned into a state address field is still a whole address"
    );
}

#[test]
fn a_signed_rotation_binds_and_stores_the_whole_new_owner() {
    let cc = compile(SRC);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let newowner = [0xABu8; 32];
    let mem = rotate_memory(&cc, &pk, &sk, &newowner, &newowner);
    let after = run(&cc, admin_storage(&admin), &mem).expect("halts");
    assert_eq!(owner_after(&after), newowner, "owner is the full signed address");
}

#[test]
fn tampering_the_unsigned_tail_of_the_new_owner_is_rejected() {
    let cc = compile(SRC);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let signed = [0xABu8; 32];
    let mut tampered = signed;
    for b in tampered.iter_mut().skip(8) {
        *b = 0x77;
    }
    let mem = rotate_memory(&cc, &pk, &sk, &signed, &tampered);
    let out = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(out, Err(Fault::DivByZero)),
        "a new owner whose tail the admin did not sign must be rejected, got {out:?}"
    );
}
