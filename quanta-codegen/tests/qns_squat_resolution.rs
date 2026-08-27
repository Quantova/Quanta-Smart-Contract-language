// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::sha3::sha3_256;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_key, slot_key};

const SRC: &str = include_str!("../../examples/QNS.qs");

const BASE3_SLOT: u64 = 28;
const BASE4_SLOT: u64 = 29;
const BASE5_SLOT: u64 = 30;
const GRACE_SLOT: u64 = 31;
const AUCTION_SLOT: u64 = 32;
const START_PREMIUM_SLOT: u64 = 33;
const INTERVAL_SLOT: u64 = 34;
const VAULT_SLOT: u64 = 35;

const EXPIRY_BASE: u64 = 1 << 40;
const OWNER_BASE: u64 = (1 << 40) + (1 << 32);
const RESOLVED_BASE: u64 = (1 << 40) + (2 << 32);

const DAY: u64 = 86_400;
const GAS: u64 = 12_000_000;

fn compiled() -> CompiledContract {
    let program = quanta_parser::parse(SRC).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn arg_off(cc: &CompiledContract, name: &str, key: &str) -> usize {
    entry(cc, name).args.iter().find(|s| s.key == key).expect("arg").offset as usize
}

fn window(label: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = label.len().min(32);
    w[..n].copy_from_slice(&label[..n]);
    w
}

fn name_key(label: &[u8]) -> [u8; 32] {
    sha3_256(label)
}

struct Params {
    base_3: u64,
    base_4: u64,
    base_5_plus: u64,
    grace: u64,
    auction: u64,
    start_premium: u64,
    interval: u64,
    vault: u64,
}

fn base_params() -> Params {
    Params {
        base_3: 500,
        base_4: 300,
        base_5_plus: 100,
        grace: 90 * DAY,
        auction: 100 * DAY,
        start_premium: 1 << 20,
        interval: DAY,
        vault: 0,
    }
}

fn seed(p: &Params) -> BTreeMap<[u8; 32], u64> {
    let mut s = BTreeMap::new();
    s.insert(slot_key(BASE3_SLOT), p.base_3);
    s.insert(slot_key(BASE4_SLOT), p.base_4);
    s.insert(slot_key(BASE5_SLOT), p.base_5_plus);
    s.insert(slot_key(GRACE_SLOT), p.grace);
    s.insert(slot_key(AUCTION_SLOT), p.auction);
    s.insert(slot_key(START_PREMIUM_SLOT), p.start_premium);
    s.insert(slot_key(INTERVAL_SLOT), p.interval);
    s.insert(slot_key(VAULT_SLOT), p.vault);
    s
}

fn addr_word_key(base: u64, label: &[u8], word: u64) -> [u8; 32] {
    let mut input = base.to_be_bytes().to_vec();
    input.extend_from_slice(&name_key(label));
    input.extend_from_slice(&word.to_be_bytes());
    sha3_256(&input)
}

fn seed_addr_value(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, label: &[u8], addr: &[u8; 32]) {
    for word in 0..4u64 {
        let lane = u64::from_be_bytes(addr[(word as usize) * 8..(word as usize) * 8 + 8].try_into().unwrap());
        storage.insert(addr_word_key(base, label, word), lane);
    }
}

fn addr_lane(storage: &BTreeMap<[u8; 32], u64>, base: u64, label: &[u8], word: u64) -> u64 {
    storage.get(&addr_word_key(base, label, word)).copied().unwrap_or(0)
}

fn vault(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(VAULT_SLOT)).copied().unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn run_paid(
    cc: &CompiledContract,
    name: &str,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    time: u64,
    label: &[u8],
    len: u64,
    years: u64,
    payment: u64,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, name).selector;
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let t = arg_off(cc, name, "@time");
    mem[t..t + 8].copy_from_slice(&time.to_be_bytes());
    let no = arg_off(cc, name, "label");
    mem[no..no + 32].copy_from_slice(&window(label));
    let lo = arg_off(cc, name, "label#len");
    mem[lo..lo + 8].copy_from_slice(&len.to_be_bytes());
    let yo = arg_off(cc, name, "years");
    mem[yo..yo + 8].copy_from_slice(&years.to_be_bytes());
    let po = arg_off(cc, name, "payment");
    mem[po..po + 8].copy_from_slice(&payment.to_be_bytes());
    let vo = arg_off(cc, name, "@value");
    mem[vo..vo + 8].copy_from_slice(&payment.to_be_bytes());
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn a_zero_year_register_buys_nothing_and_reverts() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let r = run_paid(&cc, "register", seed(&base_params()), &caller, 0, b"alice", 5, 0, 0);
    assert!(matches!(r, Err(Fault::DivByZero)), "a zero year registration reverts");
}

#[test]
fn a_one_year_register_is_the_shortest_term() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let s = run_paid(&cc, "register", seed(&base_params()), &caller, 0, b"alice", 5, 1, 100)
        .expect("a one year registration halts");
    assert_eq!(vault(&s), 100, "one year of the five plus tier is charged");
}

#[test]
fn a_zero_year_claim_premium_reverts() {
    let cc = compiled();
    let claimant = [0xC1u8; 32];
    let p = base_params();
    let e = 1000 * DAY;
    let mut storage = seed(&p);
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), e);
    let now = e + p.grace + 5 * p.interval;
    let premium = p.start_premium >> 5;
    let r = run_paid(&cc, "claim_premium", storage, &claimant, now, b"alice", 5, 0, premium);
    assert!(matches!(r, Err(Fault::DivByZero)), "a zero year premium claim reverts");
}

#[test]
fn re_registering_a_lapsed_name_drops_the_prior_resolution() {
    let cc = compiled();
    let prior = [0xA1u8; 32];
    let taker = [0xB2u8; 32];
    let p = base_params();
    let e = 1000 * DAY;

    let mut storage = seed(&p);
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"shop")), e);
    seed_addr_value(&mut storage, OWNER_BASE, b"shop", &prior);
    seed_addr_value(&mut storage, RESOLVED_BASE, b"shop", &prior);

    let now = e + p.grace + p.auction;
    let s = run_paid(&cc, "register", storage, &taker, now, b"shop", 4, 1, 300)
        .expect("a fully lapsed name registers to the taker");

    let taker_lane = u64::from_be_bytes(taker[0..8].try_into().unwrap());
    let prior_lane = u64::from_be_bytes(prior[0..8].try_into().unwrap());
    assert_eq!(addr_lane(&s, OWNER_BASE, b"shop", 0), taker_lane, "the taker owns the name");
    assert_eq!(
        addr_lane(&s, RESOLVED_BASE, b"shop", 0),
        taker_lane,
        "re-registration points resolution at the new owner, never the prior holder"
    );
    assert_ne!(
        addr_lane(&s, RESOLVED_BASE, b"shop", 0),
        prior_lane,
        "a payment resolving the name cannot reach the prior holder"
    );
}
