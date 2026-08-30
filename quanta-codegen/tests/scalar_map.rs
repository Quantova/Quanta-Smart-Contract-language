// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{addr, map_key, slot_key};

const BAL_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;

const SRC: &str = "contract Bank { \
    state { bal: Map<Q_Address, u64>; r1: u64; r2: u64; } \
    entry probe(k1: Q_Address, k2: Q_Address, v1: u64, v2: u64) reads(bal) writes(bal, r1, r2) { \
        bal.set(k1, v1); \
        bal.set(k2, v2); \
        r1 = bal.get(k1); \
        r2 = bal.get(k2); \
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
    entry(cc, name)
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("arg")
        .offset as usize
}

fn run(
    container: &Container,
    selector: [u8; SELECTOR_BYTES],
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::for_entry(container, selector, GAS)?
        .with_storage(BTreeMap::new())
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn set_then_get_returns_the_stored_word_and_keys_stay_independent() {
    let cc = compiled();
    let k1 = addr(0x11);
    let k2 = addr(0x22);
    let v1: u64 = 12_345;
    let v2: u64 = 99;

    let mut mem = vec![0u8; 4096];
    let at = |key: &str| arg_off(&cc, "probe", key);
    mem[at("k1")..at("k1") + 32].copy_from_slice(&k1);
    mem[at("k2")..at("k2") + 32].copy_from_slice(&k2);
    mem[at("v1")..at("v1") + 8].copy_from_slice(&v1.to_be_bytes());
    mem[at("v2")..at("v2") + 8].copy_from_slice(&v2.to_be_bytes());

    let storage = run(&cc.container, entry(&cc, "probe").selector, &mem).expect("probe halts");

    assert_eq!(
        storage.get(&slot_key(1)).copied().unwrap_or(0),
        v1,
        "r1 == bal.get(k1)"
    );
    assert_eq!(
        storage.get(&slot_key(2)).copied().unwrap_or(0),
        v2,
        "r2 == bal.get(k2)"
    );

    assert_eq!(
        storage.get(&map_key(BAL_BASE, &k1)).copied().unwrap_or(0),
        v1
    );
    assert_eq!(
        storage.get(&map_key(BAL_BASE, &k2)).copied().unwrap_or(0),
        v2
    );
    assert_ne!(
        map_key(BAL_BASE, &k1),
        map_key(BAL_BASE, &k2),
        "distinct keys, distinct slots"
    );
}
