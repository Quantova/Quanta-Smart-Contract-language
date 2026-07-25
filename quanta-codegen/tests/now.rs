// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `now` expression reads the injected `@time` context word, the same way `caller` reads

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::slot_key;

const GAS: u64 = 8_000_000;

const SRC: &str = "contract Clock { \
    state { last: u64; } \
    entry stamp() writes(last) { last = now; } \
    entry after_deadline(deadline: u64) writes(last) { guard now > deadline; last = now; } \
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

fn word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn now_lowers_to_the_injected_time_word() {
    let cc = compiled();
    let time_off = arg_off(&cc, "stamp", "@time");
    assert_eq!(time_off, 64, "the context reserves caller, then contract, then time");

    let mut mem = vec![0u8; 4096];
    let t: u64 = 1_726_000_000;
    word(&mut mem, time_off, t);

    let storage = run(&cc.container, entry(&cc, "stamp").selector, &mem).expect("stamp halts");
    assert_eq!(
        storage.get(&slot_key(0)).copied().unwrap_or(0),
        t,
        "last holds the injected @time"
    );
}

#[test]
fn now_in_a_guard_reads_the_injected_time() {
    let cc = compiled();
    let sel = entry(&cc, "after_deadline").selector;
    let time_off = arg_off(&cc, "after_deadline", "@time");
    let dl_off = arg_off(&cc, "after_deadline", "deadline");

    // now after the deadline: the guard passes and records now.
    let mut mem = vec![0u8; 4096];
    word(&mut mem, time_off, 100);
    word(&mut mem, dl_off, 50);
    let storage = run(&cc.container, sel, &mem).expect("a later now passes the guard");
    assert_eq!(storage.get(&slot_key(0)).copied().unwrap_or(0), 100);

    // now before the deadline: the guard reverts.
    let mut mem = vec![0u8; 4096];
    word(&mut mem, time_off, 50);
    word(&mut mem, dl_off, 100);
    let result = run(&cc.container, sel, &mem);
    assert!(
        matches!(result, Err(Fault::DivByZero)),
        "an earlier now reverts the guard"
    );
}
