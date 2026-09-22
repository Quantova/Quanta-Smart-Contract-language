// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;

mod common;
use common::slot_key;

const GAS: u64 = 2_000_000;

const SRC: &str = "contract N { state { level: u8; flags: Map<u64, u8>; big: u64; open: bool; } \
    entry put(v: u64) writes(level) { level = v; } \
    entry take(v: u8) writes(big) { big = v; } \
    entry flag(k: u64, v: u64) writes(flags) { flags.set(k, v); } \
    entry mark(v: u64) writes(open) { open = v; } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("the source parses");
    quanta_typeck::check(&program).expect("the source type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("the contract compiles")
}

fn call(
    cc: &CompiledContract,
    name: &str,
    args: &[(&str, u64)],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let e: &EntryArtifact = cc
        .entries
        .iter()
        .find(|e| e.name == name)
        .expect("the entry");
    let mut mem = vec![0u8; 4096];
    for (key, value) in args {
        let slot = e.args.iter().find(|s| s.key == *key).expect("the argument");
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    Interpreter::for_entry(&cc.container, e.selector, GAS)?
        .with_storage(BTreeMap::new())
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn a_narrow_field_refuses_a_value_past_its_width() {
    let cc = compile(SRC);
    let out = call(&cc, "put", &[("v", 255)]).expect("the widest u8 is stored");
    assert_eq!(out.get(&slot_key(0)), Some(&255));
    assert!(
        call(&cc, "put", &[("v", 256)]).is_err(),
        "a u8 cannot hold 256"
    );
    assert!(
        call(&cc, "mark", &[("v", 2)]).is_err(),
        "a bool holds only zero or one"
    );
    assert!(call(&cc, "mark", &[("v", 1)]).is_ok());
}

#[test]
fn a_narrow_parameter_refuses_a_value_past_its_width() {
    let cc = compile(SRC);
    let out = call(&cc, "take", &[("v", 200)]).expect("an in range u8 is read");
    assert_eq!(out.get(&slot_key(2)), Some(&200));
    assert!(
        call(&cc, "take", &[("v", 300)]).is_err(),
        "a u8 argument cannot carry 300"
    );
}

#[test]
fn a_narrow_map_value_refuses_a_value_past_its_width() {
    let cc = compile(SRC);
    assert!(call(&cc, "flag", &[("k", 1), ("v", 255)]).is_ok());
    assert!(
        call(&cc, "flag", &[("k", 1), ("v", 256)]).is_err(),
        "a u8 map value cannot hold 256"
    );
}
