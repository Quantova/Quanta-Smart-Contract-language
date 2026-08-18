// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::slot_key;

const HOLDING_SLOT: u64 = 12;
const PRICE_SLOT: u64 = 13;
const GAS: u64 = 4_000_000;

const FIXED: &str = include_str!("../../examples/Escrow.qs");

const OVERPAY: &str = "contract Escrow {\n\
  state { buyer: Q_Address; seller: Q_Address; arbiter: Q_Address; holding: Q_Asset<QTOV>; price: u128; released: u8 = 0; }\n\
  genesis { price = deploy_params.price; }\n\
  invariant released <= 1;\n\
  entry fund(payment: sealed Q_Asset<QTOV>) conserves QTOV writes(holding) limits payment.amount >= price {\n\
    holding.merge(payment);\n\
  }\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn fund(cc: &CompiledContract, price: u64, holding: u64, payment: u64) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "fund").selector;
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(PRICE_SLOT), price);
    storage.insert(slot_key(HOLDING_SLOT), holding);
    let mut mem = vec![0u8; 4096];
    let off = entry(cc, "fund").args.iter().find(|s| s.key == "payment").expect("payment arg").offset as usize;
    mem[off..off + 8].copy_from_slice(&payment.to_be_bytes());
    let voff = entry(cc, "fund").args.iter().find(|s| s.key == "@value").expect("value arg").offset as usize;
    mem[voff..voff + 8].copy_from_slice(&payment.to_be_bytes());
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn holding(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(HOLDING_SLOT)).copied().unwrap_or(0)
}

#[test]
fn the_old_at_or_above_fund_accepts_overpayment_that_then_strands() {
    let cc = compile(OVERPAY);
    let after = fund(&cc, 1000, 0, 1500).expect("the old fund admits an overpayment");
    assert_eq!(holding(&after), 1500, "the old fund banks the overpayment");
    assert!(holding(&after) > 1000, "the surplus over the price can never leave holding");
}

#[test]
fn exact_payment_funds_the_holding() {
    let cc = compile(FIXED);
    let after = fund(&cc, 1000, 0, 1000).expect("an exact payment funds the escrow");
    assert_eq!(holding(&after), 1000, "holding holds exactly the price with nothing stranded");
}

#[test]
fn overpayment_reverts_and_keeps_state() {
    let cc = compile(FIXED);
    assert_eq!(
        fund(&cc, 1000, 0, 1001),
        Err(Fault::DivByZero),
        "a payment over the price is refused so no surplus can strand"
    );
}

#[test]
fn underpayment_reverts_and_keeps_state() {
    let cc = compile(FIXED);
    assert_eq!(
        fund(&cc, 1000, 0, 999),
        Err(Fault::DivByZero),
        "a payment under the price is refused"
    );
}
