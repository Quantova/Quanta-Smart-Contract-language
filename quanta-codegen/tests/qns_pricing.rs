// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The QNS pricing model driven through the register machine with controlled @time and label

use std::collections::BTreeMap;

use qtv_crypto::sha3::sha3_256;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_key, slot_key};

const SRC: &str = include_str!("../../examples/QNS.qs");

// The scalar fields follow the guardian set, which occupies the first twenty eight scalar slots
// (seven members of four words), so the pricing fields begin at slot twenty eight and the vault
// lands at slot thirty five.
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

const YEAR: u64 = 31_536_000;
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

/// Drive register / renew / claim_premium: caller at zero, @time at its context word, the label
fn run(
    cc: &CompiledContract,
    name: &str,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    time: u64,
    label: &[u8],
    len: u64,
    years: u64,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    run_paid(cc, name, storage, caller, time, label, len, years, 0)
}

/// Same drive as `run` with the sealed payment asset amount written at the entry's `payment`
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
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn vault(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(VAULT_SLOT)).copied().unwrap_or(0)
}

fn expiry(storage: &BTreeMap<[u8; 32], u64>, label: &[u8]) -> u64 {
    storage.get(&map_key(EXPIRY_BASE, &name_key(label))).copied().unwrap_or(0)
}

fn owner_word(storage: &BTreeMap<[u8; 32], u64>, label: &[u8], word: u64) -> u64 {
    let mut input = OWNER_BASE.to_be_bytes().to_vec();
    input.extend_from_slice(&name_key(label));
    input.extend_from_slice(&word.to_be_bytes());
    storage.get(&sha3_256(&input)).copied().unwrap_or(0)
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

#[test]
fn tier_selection_charges_base_by_label_length() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    for (label, len, tier) in [
        (b"sol".as_slice(), 3u64, 500u64),
        (b"jeff".as_slice(), 4, 300),
        (b"alice".as_slice(), 5, 100),
        (b"satoshi".as_slice(), 7, 100),
    ] {
        let s = run_paid(&cc, "register", seed(&base_params()), &caller, 0, label, len, 1, tier)
            .expect("register halts");
        assert_eq!(vault(&s), tier, "a {len} character label is charged its tier for one year");
        // Owner and expiry landed under the label-derived key.
        assert_eq!(
            owner_word(&s, label, 0),
            u64::from_be_bytes(caller[0..8].try_into().unwrap()),
            "owner_of[label] is the caller"
        );
        assert_eq!(expiry(&s, label), 0 + YEAR, "a fresh registration expires one year out");
    }
}

#[test]
fn a_multi_year_registration_charges_the_tier_per_year() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let s = run_paid(&cc, "register", seed(&base_params()), &caller, 0, b"jeff", 4, 3, 300 * 3)
        .expect("register halts");
    assert_eq!(vault(&s), 300 * 3, "three years of the four character tier");
}

#[test]
fn the_absolute_expiry_is_now_plus_whole_years() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let t0 = 1000 * DAY;
    // Five character label at the five plus tier for four years.
    let s = run_paid(&cc, "register", seed(&base_params()), &caller, t0, b"alice", 5, 4, 100 * 4)
        .expect("register halts");
    assert_eq!(expiry(&s, b"alice"), t0 + 4 * YEAR, "expiry is now plus four whole years");
    assert_eq!(expiry(&s, b"alice") % DAY, 0, "the expiry lands on a whole day");
}

#[test]
fn a_label_shorter_than_three_reverts() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let r = run(&cc, "register", seed(&base_params()), &caller, 0, b"ab", 2, 1);
    assert!(matches!(r, Err(Fault::DivByZero)), "a two character label reverts and charges nothing");
    let r3 = run_paid(&cc, "register", seed(&base_params()), &caller, 0, b"bob", 3, 1, 500);
    assert!(r3.is_ok(), "a three character label is the shortest that registers");
}

#[test]
fn renew_extends_by_whole_years_within_grace() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let t0 = 1000 * DAY;
    let s = run_paid(&cc, "register", seed(&base_params()), &caller, t0, b"jeff", 4, 1, 300)
        .expect("register halts");
    let e1 = expiry(&s, b"jeff");
    assert_eq!(e1, t0 + YEAR);
    // Renew two years while the name is still active (now well before expiry + grace).
    let s2 = run_paid(&cc, "renew", s, &caller, t0 + 10 * DAY, b"jeff", 4, 2, 300 * 2)
        .expect("renew halts");
    assert_eq!(expiry(&s2, b"jeff"), e1 + 2 * YEAR, "renew adds two whole years to the expiry");
    assert_eq!(vault(&s2), 300 + 300 * 2, "renew charges the tier per renewed year");
}

#[test]
fn renew_past_grace_reverts() {
    let cc = compiled();
    let caller = [0xC0u8; 32];
    let p = base_params();
    let t0 = 1000 * DAY;
    let s = run_paid(&cc, "register", seed(&p), &caller, t0, b"jeff", 4, 1, 300)
        .expect("register halts");
    let e1 = expiry(&s, b"jeff");
    // now beyond expiry + grace: the grace guard reverts.
    let past = e1 + p.grace + DAY;
    let r = run(&cc, "renew", s, &caller, past, b"jeff", 4, 1);
    assert!(matches!(r, Err(Fault::DivByZero)), "a name past its grace cannot be renewed");
}

#[test]
fn the_premium_halves_by_start_premium_shifted_right_k() {
    let cc = compiled();
    let claimant = [0xC1u8; 32];
    let p = base_params();
    let e = 1000 * DAY; // the lapsed name's stored expiry
    let grace_end = e + p.grace;

    for k in [0u64, 1, 2, 3, 10, 20, 21] {
        // Seed a lapsed name whose expiry is e, vault clean.
        let mut storage = seed(&p);
        storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), e);
        let now = grace_end + k * p.interval;
        let premium = p.start_premium >> (k & 63);
        let pay = premium + p.base_5_plus;
        let s = run_paid(&cc, "claim_premium", storage, &claimant, now, b"alice", 5, 1, pay)
            .expect("claim_premium halts inside the auction window");
        assert_eq!(
            vault(&s),
            premium + p.base_5_plus,
            "at step {k} the fee is start_premium >> {k} plus the five plus tier"
        );
        // The claimant becomes the owner and the expiry is reset a whole year out from now.
        assert_eq!(
            owner_word(&s, b"alice", 0),
            u64::from_be_bytes(claimant[0..8].try_into().unwrap()),
            "the premium claimant takes ownership"
        );
        assert_eq!(expiry(&s, b"alice"), now + YEAR, "claim resets the expiry one year out");
    }
}

#[test]
fn claim_premium_before_grace_end_and_after_auction_reverts() {
    let cc = compiled();
    let claimant = [0xC1u8; 32];
    let p = base_params();
    let e = 1000 * DAY;
    let grace_end = e + p.grace;

    let mut storage = seed(&p);
    storage.insert(map_key(EXPIRY_BASE, &name_key(b"alice")), e);

    // Before the grace end: not yet in auction.
    let before = run(&cc, "claim_premium", storage.clone(), &claimant, grace_end - DAY, b"alice", 5, 1);
    assert!(matches!(before, Err(Fault::DivByZero)), "before the auction opens the claim reverts");

    // At or after grace_end + auction_duration: the auction has closed.
    let after = run(&cc, "claim_premium", storage, &claimant, grace_end + p.auction, b"alice", 5, 1);
    assert!(matches!(after, Err(Fault::DivByZero)), "after the auction closes the claim reverts");
}

#[test]
fn a_registered_name_cannot_be_re_registered_before_it_fully_lapses() {
    let cc = compiled();
    let a = [0xA1u8; 32];
    let b = [0xB2u8; 32];
    let p = base_params();
    let t0 = 1000 * DAY;
    let s = run_paid(&cc, "register", seed(&p), &a, t0, b"jeff", 4, 1, 300).expect("register halts");
    let e1 = expiry(&s, b"jeff");

    // A stranger tries to re-register while the name is still held: reverts.
    let held = run(&cc, "register", s.clone(), &b, t0 + DAY, b"jeff", 4, 1);
    assert!(matches!(held, Err(Fault::DivByZero)), "an unexpired name cannot be taken");

    // Once now is past expiry + grace + auction, the name is free again.
    let free_at = e1 + p.grace + p.auction;
    let s2 = run_paid(&cc, "register", s, &b, free_at, b"jeff", 4, 1, 300)
        .expect("a fully lapsed name registers");
    assert_eq!(
        owner_word(&s2, b"jeff", 0),
        u64::from_be_bytes(b[0..8].try_into().unwrap()),
        "the fully lapsed name is taken by the new registrant"
    );
}
