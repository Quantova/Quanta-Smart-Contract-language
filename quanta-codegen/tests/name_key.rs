// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Q_Name parameter type: a thirty two byte plaintext label window plus a label length word. The

use std::collections::BTreeMap;

use qtv_crypto::sha3::sha3_256;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_key, slot_key};

const OWNER_OF_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;

const SRC: &str = "contract Names { \
    state { owner_of: Map<Q_Name, u64>; last_len: u64; last_who: u64; } \
    entry claim(name: Q_Name, who: u64) reads(owner_of) writes(owner_of, last_len, last_who) { \
        owner_of.set(name, who); \
        last_len = name.len; \
        last_who = owner_of.get(name); \
    } \
}";

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

/// A thirty two byte label window; the label bytes at the front, the rest zero.
fn window(label: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = label.len().min(32);
    w[..n].copy_from_slice(&label[..n]);
    w
}

/// The storage key the machine derives for owner_of[name]: SHA3 of the map tag then the name key,
fn expected_key(win: &[u8; 32], len: u64) -> [u8; 32] {
    let name_key = sha3_256(&win[..len as usize]);
    map_key(OWNER_OF_BASE, &name_key)
}

fn run_claim(
    cc: &CompiledContract,
    win: &[u8; 32],
    len: u64,
    who: u64,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "claim").selector;
    let name_off = arg_off(cc, "claim", "name");
    let len_off = arg_off(cc, "claim", "name#len");
    let who_off = arg_off(cc, "claim", "who");

    let mut mem = vec![0u8; 4096];
    mem[name_off..name_off + 32].copy_from_slice(win);
    mem[len_off..len_off + 8].copy_from_slice(&len.to_be_bytes());
    mem[who_off..who_off + 8].copy_from_slice(&who.to_be_bytes());

    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(BTreeMap::new())
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn the_abi_places_the_window_then_the_length_word() {
    let cc = compiled();
    let name_off = arg_off(&cc, "claim", "name");
    let len_off = arg_off(&cc, "claim", "name#len");
    assert_eq!(name_off, 80, "the window follows the caller, contract, time, and chain context");
    assert_eq!(len_off, name_off + 32, "the length word sits directly after the window");
}

#[test]
fn the_same_label_yields_the_same_key_and_the_length_round_trips() {
    let cc = compiled();
    let w = window(b"alice");
    let s1 = run_claim(&cc, &w, 5, 100).expect("claim halts");
    let s2 = run_claim(&cc, &w, 5, 100).expect("claim halts");

    let k = expected_key(&w, 5);
    assert_eq!(s1.get(&k).copied(), Some(100));
    assert_eq!(s2.get(&k).copied(), Some(100), "the same label lands on the same key every call");
    assert_eq!(s1.get(&slot_key(1)).copied(), Some(5), "name.len equals the supplied byte length");
    assert_eq!(s1.get(&slot_key(2)).copied(), Some(100), "a get by the same name round trips the word");
}

#[test]
fn different_labels_hash_to_different_keys() {
    let cc = compiled();
    let a = window(b"alice");
    let b = window(b"bob");
    let sa = run_claim(&cc, &a, 5, 1).expect("claim halts");
    let sb = run_claim(&cc, &b, 3, 2).expect("claim halts");

    let ka = expected_key(&a, 5);
    let kb = expected_key(&b, 3);
    assert_ne!(ka, kb, "distinct labels land on distinct keys");
    assert_eq!(sa.get(&ka).copied(), Some(1));
    assert_eq!(sb.get(&kb).copied(), Some(2));
    assert!(sa.contains_key(&ka) && !sa.contains_key(&kb), "each run writes only its own key");
}

#[test]
fn the_declared_length_is_bound_into_the_key() {
    let cc = compiled();
    // The same window bytes declared at two different lengths must derive two different keys, and the
    // exposed length must move with the declaration. A caller cannot pass long bytes and short length
    // to land on a short name's key while reporting a longer length, or vice versa.
    let w = window(b"alicexyz");
    let s5 = run_claim(&cc, &w, 5, 10).expect("claim halts");
    let s3 = run_claim(&cc, &w, 3, 20).expect("claim halts");

    let k5 = expected_key(&w, 5);
    let k3 = expected_key(&w, 3);
    assert_ne!(k5, k3, "a shorter declared length derives a different key from the same window");
    assert_eq!(s5.get(&k5).copied(), Some(10));
    assert_eq!(s3.get(&k3).copied(), Some(20));
    assert_eq!(s5.get(&slot_key(1)).copied(), Some(5), "the length reported is the length declared");
    assert_eq!(s3.get(&slot_key(1)).copied(), Some(3), "the length reported is the length declared");
    assert!(!s3.contains_key(&k5), "a run that reports length 3 never reaches the length 5 key");
    assert!(!s5.contains_key(&k3), "a run that reports length 5 never reaches the length 3 key");
}

#[test]
fn a_length_past_the_window_reverts() {
    let cc = compiled();
    let w = window(b"alice");
    let r = run_claim(&cc, &w, 33, 1);
    assert!(matches!(r, Err(Fault::DivByZero)), "a length past the 32 byte window reverts");
}
