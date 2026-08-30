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
const RESERVED_BASE: u64 = (1 << 40) + (4 << 32);

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
    entry(cc, name)
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("arg")
        .offset as usize
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

fn seed() -> BTreeMap<[u8; 32], u64> {
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

#[test]
fn a_reserved_name_cannot_be_registered() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let mut storage = seed();
    storage.insert(map_key(RESERVED_BASE, &name_key(b"sol")), 1);
    let refused = run_paid(&cc, "register", storage, &caller, 0, b"sol", 3, 1, 500);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a reserved name is not registrable"
    );
}

#[test]
fn an_unreserved_neighbour_still_registers() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let mut storage = seed();
    storage.insert(map_key(RESERVED_BASE, &name_key(b"sol")), 1);
    let ok = run_paid(&cc, "register", storage, &caller, 0, b"tom", 3, 1, 500);
    assert!(ok.is_ok(), "reserving one name does not reserve another");
}

#[test]
fn a_reserved_name_cannot_be_claimed_in_the_premium_auction() {
    let cc = compiled();
    let claimant = [0xC1u8; 32];
    let e = 1000 * DAY;
    let grace = 90 * DAY;
    let mut storage = seed();
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), e);
    storage.insert(map_key(RESERVED_BASE, &name_key(b"alice")), 1);
    let now = e + grace + 5 * DAY;
    let refused = run_paid(
        &cc,
        "claim_premium",
        storage,
        &claimant,
        now,
        b"alice",
        5,
        1,
        1 << 21,
    );
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a reserved lapsed name cannot be premium claimed"
    );
}

#[test]
fn a_registration_term_that_overflows_the_price_reverts_rather_than_wrapping_cheap() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let years = 1u64 << 60;
    let refused = run_paid(
        &cc,
        "register",
        seed(),
        &caller,
        0,
        b"alice",
        5,
        years,
        u64::MAX,
    );
    assert!(
        matches!(refused, Err(Fault::Overflow)),
        "a wrapping cheap price is not reachable"
    );
}
