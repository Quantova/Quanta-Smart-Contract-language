// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::Interpreter;
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{signer_address, slot_key};

const SRC: &str = "contract R {\n\
  state { admin: Q_Address; reserved: Map<Q_Name, u64>; }\n\
  genesis { admin = deployer; }\n\
  entry reserve(label: Q_Name signed by admin) writes(reserved) {\n\
    reserved.set(label, 1);\n\
  }\n\
}\n";

const CONTRACT_CTX_OFF: usize = 32;
const REGION_OFF: u64 = 8192;
const SCHEME_ML: u8 = 1;
const CONTRACT: [u8; 32] = [0x35; 32];

fn compile() -> CompiledContract {
    let program = quanta_parser::parse(SRC).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry_index(cc: &CompiledContract) -> usize {
    cc.entries
        .iter()
        .position(|e| e.name == "reserve")
        .expect("the reserve entry")
}

fn arg_offset(cc: &CompiledContract, key: &str) -> usize {
    cc.entries[entry_index(cc)]
        .args
        .iter()
        .find(|slot| slot.key == key)
        .unwrap_or_else(|| panic!("no argument {key}"))
        .offset as usize
}

fn window(label: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..label.len()].copy_from_slice(label);
    w
}

fn memory(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    signed: &[u8],
    sent: &[u8],
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let selector = cc.entries[entry_index(cc)].selector;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(&signer);
    msg.extend_from_slice(&0u64.to_be_bytes());
    msg.extend_from_slice(&window(signed));
    msg.extend_from_slice(&(signed.len() as u64).to_be_bytes());
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[CONTRACT_CTX_OFF..CONTRACT_CTX_OFF + 32].copy_from_slice(&CONTRACT);
    mem[arg_offset(cc, "label#scheme")..arg_offset(cc, "label#scheme") + 8]
        .copy_from_slice(&(SCHEME_ML as u64).to_be_bytes());
    mem[arg_offset(cc, "label#ptr")..arg_offset(cc, "label#ptr") + 8]
        .copy_from_slice(&REGION_OFF.to_be_bytes());
    let w = arg_offset(cc, "label");
    mem[w..w + 32].copy_from_slice(&window(sent));
    let l = arg_offset(cc, "label#len");
    mem[l..l + 8].copy_from_slice(&(sent.len() as u64).to_be_bytes());
    mem[REGION_OFF as usize..].copy_from_slice(&region);
    mem
}

fn run(cc: &CompiledContract, admin: &[u8; 32], mem: &[u8]) -> bool {
    let mut storage = BTreeMap::new();
    for i in 0..4u64 {
        let w = u64::from_be_bytes(
            admin[i as usize * 8..i as usize * 8 + 8]
                .try_into()
                .unwrap(),
        );
        storage.insert(slot_key(i), w);
    }
    let selector = cc.entries[entry_index(cc)].selector;
    Interpreter::for_entry(&cc.container, selector, 50_000_000)
        .expect("the entry exists")
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .is_ok()
}

#[test]
fn a_signed_name_binds_every_byte_and_its_length() {
    let cc = compile();
    let (pk, sk) = ml_dsa::keygen(&[0x61; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let honest = memory(
        &cc,
        &pk,
        &sk,
        b"quantova-foundation",
        b"quantova-foundation",
    );
    assert!(run(&cc, &admin, &honest), "the signed name is accepted");
    let rewritten = memory(&cc, &pk, &sk, b"quantova-foundation", b"quantova-scam");
    assert!(!run(&cc, &admin, &rewritten), "a rewritten tail is refused");
    let shortened = memory(&cc, &pk, &sk, b"quantova-foundation", b"quantova");
    assert!(!run(&cc, &admin, &shortened), "a shortened name is refused");
}
