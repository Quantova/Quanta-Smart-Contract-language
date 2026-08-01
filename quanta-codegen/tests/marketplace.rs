// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, read_addr_value, slot_key};

const OWNER_SLOT: u64 = 0;
const ESCROWED_SLOT: u64 = 4;
const LISTINGS_BASE: u64 = 1 << 40;
const ITEM_OWNER_BASE: u64 = (1 << 40) + (1 << 32);
const GAS: u64 = 8_000_000;

const FIXED: &str = include_str!("../../examples/Marketplace.qs");

const UNBOUND: &str = "contract Marketplace {\n\
  state { owner: Q_Address; escrowed: Q_Asset<QTOV>; listings: Map<Q_Id, u64>; fee_bps: u16 = 250; }\n\
  genesis { owner = deployer; }\n\
  invariant fee_bps <= 10_000;\n\
  entry buy(order: BuyOrder, payment: sealed Q_Asset<QTOV>) conserves QTOV writes(escrowed) limits payment.amount >= order.price {\n\
    escrowed.merge(payment);\n\
    send(order.seller, escrowed.split(order.price));\n\
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

fn arg_off(cc: &CompiledContract, name: &str, key: &str) -> usize {
    entry(cc, name).args.iter().find(|s| s.key == key).expect("arg").offset as usize
}

fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn id_key(id: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&id.to_be_bytes());
    k
}

fn put_addr(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, addr: &[u8; 32]) {
    for i in 0..4u64 {
        let w = u64::from_be_bytes(addr[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        storage.insert(slot_key(base + i), w);
    }
}

fn run(
    container: &Container,
    selector: [u8; SELECTOR_BYTES],
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    Interpreter::for_entry(container, selector, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn transfer<'a>(effects: &'a [Effect]) -> Option<&'a Effect> {
    effects.iter().find(|e| matches!(e, Effect::Transfer { .. }))
}

fn listed(owner: &[u8; 32], id: u64, price: u64) -> BTreeMap<[u8; 32], u64> {
    let mut storage = BTreeMap::new();
    put_addr(&mut storage, OWNER_SLOT, owner);
    storage.insert(slot_key(ESCROWED_SLOT), 0);
    storage.insert(map_key(LISTINGS_BASE, &id_key(id)), price);
    for i in 0..4u64 {
        let w = u64::from_be_bytes(owner[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        storage.insert(map_addr_word_key(ITEM_OWNER_BASE, &id_key(id), i), w);
    }
    storage
}

fn buy_mem(cc: &CompiledContract, buyer: &[u8; 32], id: u64, payment: u64) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(buyer);
    let ido = arg_off(cc, "buy", "id");
    mem[ido..ido + 8].copy_from_slice(&id.to_be_bytes());
    let po = arg_off(cc, "buy", "payment");
    mem[po..po + 8].copy_from_slice(&payment.to_be_bytes());
    mem
}

fn buy(cc: &CompiledContract, storage: BTreeMap<[u8; 32], u64>, buyer: &[u8; 32], id: u64, payment: u64) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    run(&cc.container, entry(cc, "buy").selector, storage, &buy_mem(cc, buyer, id, payment))
}

#[test]
fn the_old_unbound_buy_accepts_a_zero_price_purchase() {
    let cc = compile(UNBOUND);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(ESCROWED_SLOT), 0);
    let mem = vec![0u8; 4096];
    let out = run(&cc.container, entry(&cc, "buy").selector, storage, &mem);
    assert!(out.is_ok(), "the old buy accepts a zero price purchase bound to no listing");
}

#[test]
fn a_buy_at_the_listed_price_pays_the_owner_and_hands_the_item_to_the_buyer() {
    let cc = compile(FIXED);
    let owner = addr(0x11);
    let buyer = addr(0xB0);
    let id = 42u64;
    let price = 1000u64;

    let (after, effects) = buy(&cc, listed(&owner, id, price), &buyer, id, price)
        .expect("a buy at the listed price halts");

    assert_eq!(
        transfer(&effects),
        Some(&Effect::Transfer { to: owner.to_vec(), amount: price }),
        "the exact listed price is paid to the listing owner"
    );
    assert_eq!(
        read_addr_value(&after, ITEM_OWNER_BASE, &id_key(id)),
        buyer,
        "the item is handed to the buyer in full"
    );
    assert_eq!(
        after.get(&map_key(LISTINGS_BASE, &id_key(id))).copied().unwrap_or(0),
        0,
        "the listing is cleared so the item cannot be sold twice"
    );
    assert_eq!(after.get(&slot_key(ESCROWED_SLOT)).copied().unwrap_or(0), 0, "nothing strands in escrow");
}

#[test]
fn a_buy_over_the_listed_price_reverts() {
    let cc = compile(FIXED);
    let owner = addr(0x11);
    let buyer = addr(0xB0);
    assert_eq!(
        buy(&cc, listed(&owner, 42, 1000), &buyer, 42, 1001).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "paying over the listed price is refused so nothing strands"
    );
}

#[test]
fn a_buy_under_the_listed_price_reverts() {
    let cc = compile(FIXED);
    let owner = addr(0x11);
    let buyer = addr(0xB0);
    assert_eq!(
        buy(&cc, listed(&owner, 42, 1000), &buyer, 42, 999).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "paying under the listed price is refused"
    );
}

#[test]
fn buying_an_unlisted_id_reverts() {
    let cc = compile(FIXED);
    let owner = addr(0x11);
    let buyer = addr(0xB0);
    let mut storage = BTreeMap::new();
    put_addr(&mut storage, OWNER_SLOT, &owner);
    storage.insert(slot_key(ESCROWED_SLOT), 0);
    assert_eq!(
        buy(&cc, storage, &buyer, 99, 0).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "an id with no live listing cannot be bought, even for zero"
    );
}

#[test]
fn a_sold_item_cannot_be_bought_again() {
    let cc = compile(FIXED);
    let owner = addr(0x11);
    let first = addr(0xB0);
    let second = addr(0xB1);
    let id = 42u64;
    let price = 1000u64;

    let (after, _) = buy(&cc, listed(&owner, id, price), &first, id, price).expect("first buy halts");
    let again = buy(&cc, after, &second, id, price);
    assert!(matches!(again, Err(Fault::DivByZero)), "a cleared listing refuses a second purchase");
}
