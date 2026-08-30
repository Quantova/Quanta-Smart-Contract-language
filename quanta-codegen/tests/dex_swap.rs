// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Effect, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{put_addr_slots, signer_address};

const GAS: u64 = 3_000_000;
const DEX_CONTRACT: [u8; 32] = [0x55; 32];
const DEX_SRC: &str = include_str!("../../examples/Dex.qs");

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn arg_off(cc: &CompiledContract, entry: usize, key: &str) -> Option<usize> {
    cc.entries[entry]
        .args
        .iter()
        .find(|s| s.key == key)
        .map(|s| s.offset as usize)
}

fn signed_swap_memory(
    cc: &CompiledContract,
    entry: usize,
    selector: [u8; 4],
    to: &[u8; 32],
    out: u64,
) -> (Vec<u8>, [u8; 32]) {
    let region_off = 8192usize;
    let (pk, sk) = ml_dsa::keygen(&[9u8; 32]);
    let operator = signer_address(1, &pk);

    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&DEX_CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(&operator);
    msg.extend_from_slice(&0u64.to_be_bytes());
    msg.extend_from_slice(to);
    msg.extend_from_slice(&out.to_be_bytes());
    msg.extend_from_slice(&0u64.to_be_bytes());
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; region_off + region.len()];
    mem[32..64].copy_from_slice(&DEX_CONTRACT);
    if let Some(o) = arg_off(cc, entry, "order#scheme") {
        mem[o..o + 8].copy_from_slice(&1u64.to_be_bytes());
    }
    if let Some(o) = arg_off(cc, entry, "order#ptr") {
        mem[o..o + 8].copy_from_slice(&(region_off as u64).to_be_bytes());
    }
    if let Some(o) = arg_off(cc, entry, "order.to") {
        mem[o..o + 32].copy_from_slice(to);
    }
    if let Some(o) = arg_off(cc, entry, "order.out") {
        mem[o..o + 8].copy_from_slice(&out.to_be_bytes());
    }
    mem[region_off..].copy_from_slice(&region);
    (mem, operator)
}

#[test]
fn swap_a_for_b_verifies_the_operator_order_and_pays_out_token_b() {
    let cc = compile(DEX_SRC);
    let entry = cc
        .entries
        .iter()
        .position(|e| e.name == "swap_a_for_b")
        .expect("swap_a_for_b entry");
    let selector = cc.container.entries[entry].selector;

    let to = [0x11u8; 32];
    let token_b = [0xBBu8; 32];
    let out: u64 = 700;
    let (mem, operator) = signed_swap_memory(&cc, entry, selector, &to, out);

    let mut storage: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    put_addr_slots(&mut storage, 0, &operator);
    put_addr_slots(&mut storage, 8, &token_b);

    let outcome = Interpreter::for_entry(&cc.container, selector, GAS)
        .expect("swap entry")
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .expect("the operator signed swap halts");

    let transfers: Vec<&Effect> = outcome
        .effects
        .iter()
        .filter(|e| matches!(e, Effect::Transfer { .. }))
        .collect();
    assert_eq!(
        transfers.len(),
        1,
        "the swap pays out exactly one asset transfer"
    );
    match transfers[0] {
        Effect::Transfer { to: target, amount } => {
            assert_eq!(
                target.len(),
                64,
                "an asset transfer names the issuer then the holder"
            );
            assert_eq!(&target[0..32], &token_b, "the payout asset is token_b");
            assert_eq!(&target[32..64], &to, "the payout goes to order.to");
            assert_eq!(*amount as u64, out, "the amount is order.out");
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_swap_order_not_signed_by_the_operator_reverts() {
    let cc = compile(DEX_SRC);
    let entry = cc
        .entries
        .iter()
        .position(|e| e.name == "swap_a_for_b")
        .expect("swap_a_for_b entry");
    let selector = cc.container.entries[entry].selector;

    let to = [0x11u8; 32];
    let token_b = [0xBBu8; 32];
    let (mem, _real_operator) = signed_swap_memory(&cc, entry, selector, &to, 700);

    let mut storage: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    put_addr_slots(&mut storage, 0, &[0x22u8; 32]);
    put_addr_slots(&mut storage, 8, &token_b);

    let result = Interpreter::for_entry(&cc.container, selector, GAS)
        .expect("swap entry")
        .with_storage(storage)
        .with_memory(&mem)
        .run();
    assert!(
        result.is_err(),
        "an order whose signer is not the pool operator must revert"
    );
}
