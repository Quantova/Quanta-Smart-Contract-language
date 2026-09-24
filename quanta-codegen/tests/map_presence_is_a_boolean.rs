// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::map_key;

const GAS: u64 = 4_000_000;

const SRC: &str = "contract Split { state { a: Map<Q_Address, u64>; b: Map<Q_Address, u64>; hits: u64; } \
    entry act() reads(a, b) writes(hits) { guard a.contains(caller) != b.contains(caller); hits += 1; } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ent<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn run(
    cc: &CompiledContract,
    caller: [u8; 32],
    storage: BTreeMap<[u8; 32], u64>,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let e = ent(cc, "act");
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&caller);
    let sel: [u8; SELECTOR_BYTES] = e.selector;
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_memory(&mem)
        .with_storage(storage)
        .run()
        .map(|out| out.storage)
}

const KEYED_BASE: u64 = 1 << 40;
const KEYED_STRIDE: u64 = 1 << 32;

#[test]
fn a_row_on_both_ledgers_is_on_both_whatever_the_amounts_are() {
    let cc = compile(SRC);
    let caller = [5u8; 32];
    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &caller), 5);
    storage.insert(map_key(KEYED_BASE + KEYED_STRIDE, &caller), 1);
    assert!(
        run(&cc, caller, storage).is_err(),
        "present on both ledgers is not present on exactly one, whatever each row holds"
    );
}

#[test]
fn a_row_on_one_ledger_only_still_fires() {
    let cc = compile(SRC);
    let caller = [5u8; 32];
    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &caller), 5);
    let out = run(&cc, caller, storage).expect("present on one ledger only");
    let counted = (0..8u64).any(|slot| out.get(&qtv_vm::abi::scalar_key(slot)) == Some(&1));
    assert!(counted, "the entry ran and recorded the hit, got {out:?}");
}
