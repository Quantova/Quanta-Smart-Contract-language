// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::{ml_dsa, slh_dsa};
use qtv_vm::interp::{Fault, Interpreter};
use qtv_vm::isa::{decode, OpCode};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{put_addr_slots, signer_address, slot_key};

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
const CONTRACT: [u8; 32] = [0x44; 32];

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

fn canonical_message(selector: [u8; 4], signer: &[u8; 32], nonce: u64, step: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&step.to_be_bytes());
    msg
}

fn opcodes(code: &[u8]) -> Vec<OpCode> {
    let mut ops = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let (instr, len) = decode(code, pc).expect("decode");
        ops.push(instr.opcode());
        pc += len;
    }
    ops
}

fn place(cc: &CompiledContract, scheme: u64, pk: &[u8], sig: &[u8], step: u64) -> Vec<u8> {
    let signer = signer_address(scheme as u8, pk);
    let msg = canonical_message(cc.container.entries[0].selector, &signer, 0, step);
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), scheme);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), REGION_OFF);
    put_word(&mut mem, arg_offset(cc, "order.step"), step);
    mem[REGION_OFF as usize..].copy_from_slice(&region);
    mem
}

fn ml_bump(cc: &CompiledContract, step: u64) -> (Vec<u8>, [u8; 32]) {
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let signer = signer_address(1, &pk);
    let msg = canonical_message(cc.container.entries[0].selector, &signer, 0, step);
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
    (place(cc, 1, &pk, &sig, step), signer)
}

fn slh_bump(cc: &CompiledContract, step: u64) -> (Vec<u8>, [u8; 32]) {
    let (sk, pk) = slh_dsa::keygen(&[1u8; 24], &[2u8; 24], &[3u8; 24]);
    let signer = signer_address(2, &pk);
    let msg = canonical_message(cc.container.entries[0].selector, &signer, 0, step);
    let sig = slh_dsa::sign(&sk, &msg, &[], &[4u8; 24]).expect("sign");
    (place(cc, 2, &pk, &sig, step), signer)
}

fn run(cc: &CompiledContract, owner: Option<[u8; 32]>, mem: &[u8]) -> Result<u64, Fault> {
    let mut storage = BTreeMap::new();
    if let Some(owner) = owner {
        put_addr_slots(&mut storage, OWNER_SLOT, &owner);
    }
    storage.insert(slot_key(COUNT_SLOT), 10);
    Interpreter::new(&cc.container.code, &cc.container.consts, 500_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| *out.storage.get(&slot_key(COUNT_SLOT)).expect("count slot"))
}

#[test]
fn the_lowering_carries_both_verify_opcodes() {
    let cc = compile(COUNTER);
    let ops = opcodes(&cc.container.code);
    assert!(
        ops.contains(&OpCode::VerifyMl),
        "the module lattice verify must be present"
    );
    assert!(
        ops.contains(&OpCode::VerifySlh),
        "the hash based verify must be present"
    );
    assert!(ops.contains(&OpCode::Addr), "the signer address is derived");
}

#[test]
fn scheme_one_verifies_and_binds_with_the_module_lattice_opcode() {
    let cc = compile(COUNTER);
    let (mem, owner) = ml_bump(&cc, 4);
    assert_eq!(run(&cc, Some(owner), &mem), Ok(14), "ML DSA owner verifies");
}

#[test]
fn scheme_two_verifies_and_binds_with_the_hash_based_opcode() {
    let cc = compile(COUNTER);
    let (mem, owner) = slh_bump(&cc, 4);
    assert_eq!(run(&cc, Some(owner), &mem), Ok(14), "SLH DSA owner verifies");
}

#[test]
fn scheme_two_does_not_use_the_module_lattice_opcode() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let signer = signer_address(1, &pk);
    let msg = canonical_message(cc.container.entries[0].selector, &signer, 0, 4);
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mem = place(&cc, 2, &pk, &sig, 4);
    assert!(
        run(&cc, None, &mem).is_err(),
        "scheme two must not accept a module lattice region"
    );
}

#[test]
fn an_unknown_scheme_reverts() {
    let cc = compile(COUNTER);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let signer = signer_address(1, &pk);
    let msg = canonical_message(cc.container.entries[0].selector, &signer, 0, 4);
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mem3 = place(&cc, 3, &pk, &sig, 4);
    assert_eq!(run(&cc, Some(signer), &mem3), Err(Fault::DivByZero));
    let mem99 = place(&cc, 99, &pk, &sig, 4);
    assert_eq!(run(&cc, Some(signer), &mem99), Err(Fault::DivByZero));
}
