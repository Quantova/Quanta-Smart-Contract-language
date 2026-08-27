// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{nonce_key, put_addr_slots, signer_address, slot_key};

const TIMED: &str = "contract Timed {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry act(order: ActOrder signed by owner) writes(count) after order.notbefore {\n\
    count = checked(count + order.step);\n\
    count = checked(count + order.extra);\n\
  }\n\
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

fn canonical_message(signer: &[u8; 32], selector: [u8; 4], nonce: u64, fields: &[u64]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for f in fields {
        msg.extend_from_slice(&f.to_be_bytes());
    }
    msg
}

fn act_memory(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    signed: [u64; 3],
    plain: [u64; 3],
    now: u64,
    nonce: u64,
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let selector = cc.container.entries[0].selector;
    let msg = canonical_message(&signer, selector, nonce, &signed);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    put_word(&mut mem, arg_offset(cc, "order#scheme"), SCHEME_ML as u64);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), REGION_OFF);
    put_word(&mut mem, arg_offset(cc, "@time"), now);
    put_word(&mut mem, arg_offset(cc, "order.notbefore"), plain[0]);
    put_word(&mut mem, arg_offset(cc, "order.step"), plain[1]);
    put_word(&mut mem, arg_offset(cc, "order.extra"), plain[2]);
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
fn a_correct_order_over_the_whole_field_set_verifies_and_runs() {
    let cc = compile(TIMED);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let mem = act_memory(&cc, &pk, &sk, [100, 4, 3], [100, 4, 3], 10_000, 0);
    let out = run(&cc, owned_storage(&owner, 10), &mem).expect("the owner's full order is accepted");
    assert_eq!(out.get(&slot_key(COUNT_SLOT)), Some(&17), "count advances by step then extra");
    assert_eq!(out.get(&nonce_key(&owner)), Some(&1), "the nonce is consumed");
}

#[test]
fn rewriting_the_unsigned_time_gate_target_is_now_refused() {
    let cc = compile(TIMED);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let storage = owned_storage(&owner, 10);
    let mem = act_memory(&cc, &pk, &sk, [500, 4, 3], [0, 4, 3], 400, 0);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::DivByZero),
        "a rewritten time gate target no longer carries the signature"
    );
    assert_eq!(storage.get(&slot_key(COUNT_SLOT)), Some(&10), "state is unchanged");
}

#[test]
fn each_authorizer_field_is_bound_so_any_single_mutation_reverts() {
    let cc = compile(TIMED);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let signed = [100u64, 4, 3];
    let mutations = [
        [0u64, 4, 3],
        [100, 9, 3],
        [100, 4, 9],
    ];
    for plain in mutations {
        let storage = owned_storage(&owner, 10);
        let mem = act_memory(&cc, &pk, &sk, signed, plain, 10_000, 0);
        assert_eq!(
            run(&cc, storage.clone(), &mem),
            Err(Fault::DivByZero),
            "mutating a single authorizer field {plain:?} must revert"
        );
        assert_eq!(storage.get(&slot_key(COUNT_SLOT)), Some(&10), "state is unchanged");
    }
}

#[test]
fn a_correct_order_still_reverts_before_the_gate_opens() {
    let cc = compile(TIMED);
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let owner = signer_address(SCHEME_ML, &pk);

    let mem = act_memory(&cc, &pk, &sk, [500, 4, 3], [500, 4, 3], 400, 0);
    assert_eq!(
        run(&cc, owned_storage(&owner, 10), &mem),
        Err(Fault::DivByZero),
        "the window is still shut at consensus time 400"
    );

    let mem = act_memory(&cc, &pk, &sk, [500, 4, 3], [500, 4, 3], 500, 0);
    let out = run(&cc, owned_storage(&owner, 10), &mem).expect("the window is open at 500");
    assert_eq!(out.get(&slot_key(COUNT_SLOT)), Some(&17));
}
