// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::sha3::sha3_256;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, read_addr_value, slot_key};

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

fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
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

fn put_map_addr(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, key: &[u8; 32], value: &[u8; 32]) {
    for i in 0..4u64 {
        let w = u64::from_be_bytes(value[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        storage.insert(map_addr_word_key(base, key, i), w);
    }
}

fn base_params() -> BTreeMap<[u8; 32], u64> {
    let mut s = BTreeMap::new();
    s.insert(slot_key(BASE3_SLOT), 500);
    s.insert(slot_key(BASE4_SLOT), 300);
    s.insert(slot_key(BASE5_SLOT), 100);
    s.insert(slot_key(GRACE_SLOT), 90 * DAY);
    s.insert(slot_key(AUCTION_SLOT), 100 * DAY);
    s.insert(slot_key(START_PREMIUM_SLOT), 1 << 20);
    s.insert(slot_key(INTERVAL_SLOT), DAY);
    s.insert(slot_key(VAULT_SLOT), 0);
    s
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

fn run_transfer(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    label: &[u8],
    to: &[u8; 32],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "transfer").selector;
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let no = arg_off(cc, "transfer", "label");
    mem[no..no + 32].copy_from_slice(&window(label));
    let lo = arg_off(cc, "transfer", "label#len");
    mem[lo..lo + 8].copy_from_slice(&(label.len() as u64).to_be_bytes());
    let to_off = arg_off(cc, "transfer", "to");
    mem[to_off..to_off + 32].copy_from_slice(to);
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn resolved(storage: &BTreeMap<[u8; 32], u64>, label: &[u8]) -> [u8; 32] {
    read_addr_value(storage, RESOLVED_BASE, &name_key(label))
}

#[test]
fn register_refuses_a_zero_year_term() {
    let cc = compiled();
    let caller = addr(0xC0);
    let r = run_paid(&cc, "register", base_params(), &caller, 0, b"alice", 5, 0, 100);
    assert!(matches!(r, Err(Fault::DivByZero)), "a zero year registration reverts and charges nothing");
    let ok = run_paid(&cc, "register", base_params(), &caller, 0, b"alice", 5, 1, 100);
    assert!(ok.is_ok(), "one year is the shortest term that registers");
}

#[test]
fn renew_refuses_a_zero_year_term() {
    let cc = compiled();
    let caller = addr(0xC0);
    let t0 = 1000 * DAY;
    let s = run_paid(&cc, "register", base_params(), &caller, t0, b"jeff", 4, 1, 300).expect("register halts");
    let r = run_paid(&cc, "renew", s, &caller, t0 + DAY, b"jeff", 4, 0, 300);
    assert!(matches!(r, Err(Fault::DivByZero)), "a zero year renewal reverts");
}

#[test]
fn claim_premium_refuses_a_zero_year_term() {
    let cc = compiled();
    let claimant = addr(0xC1);
    let e = 1000 * DAY;
    let mut storage = base_params();
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), e);
    let now = e + 90 * DAY + DAY;
    let r = run_paid(&cc, "claim_premium", storage, &claimant, now, b"alice", 5, 0, 1 << 21);
    assert!(matches!(r, Err(Fault::DivByZero)), "a zero year premium claim reverts");
}

#[test]
fn a_fresh_registration_points_resolution_at_the_registrant() {
    let cc = compiled();
    let caller = addr(0xA1);
    let s = run_paid(&cc, "register", base_params(), &caller, 0, b"alice", 5, 1, 100).expect("register halts");
    assert_eq!(resolved(&s, b"alice"), caller, "a new name resolves to its registrant");
}

#[test]
fn a_transfer_resets_resolution_to_the_new_owner() {
    let cc = compiled();
    let owner = addr(0xA1);
    let to = addr(0xB2);
    let stale = addr(0x99);

    let mut storage = base_params();
    put_map_addr(&mut storage, OWNER_BASE, &name_key(b"alice"), &owner);
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), 1000 * DAY);
    put_map_addr(&mut storage, RESOLVED_BASE, &name_key(b"alice"), &stale);

    let after = run_transfer(&cc, storage, &owner, b"alice", &to).expect("owner transfer halts");
    assert_eq!(resolved(&after, b"alice"), to, "transfer repoints resolution to the recipient");
    assert_ne!(resolved(&after, b"alice"), stale, "the prior resolution target no longer answers for the name");
}

#[test]
fn re_registration_after_a_full_lapse_drops_the_prior_resolution() {
    let cc = compiled();
    let old = addr(0xA1);
    let new = addr(0xB2);
    let stale = addr(0x99);

    let t0 = 1000 * DAY;
    let s = run_paid(&cc, "register", base_params(), &old, t0, b"jeff", 4, 1, 300).expect("register halts");
    let e1 = s.get(&map_key(EXPIRY_BASE, &name_key(b"jeff"))).copied().unwrap();
    assert_eq!(resolved(&s, b"jeff"), old, "the first registrant resolves the name");

    let mut lapsed = s;
    put_map_addr(&mut lapsed, RESOLVED_BASE, &name_key(b"jeff"), &stale);

    let free_at = e1 + 90 * DAY + 100 * DAY;
    let s2 = run_paid(&cc, "register", lapsed, &new, free_at, b"jeff", 4, 1, 300).expect("a fully lapsed name registers");
    assert_eq!(read_addr_value(&s2, OWNER_BASE, &name_key(b"jeff")), new, "the new registrant owns the name");
    assert_eq!(resolved(&s2, b"jeff"), new, "re-registration resets resolution to the new owner");
    assert_ne!(resolved(&s2, b"jeff"), stale, "the prior owner's stale target cannot survive a re-registration");
}
