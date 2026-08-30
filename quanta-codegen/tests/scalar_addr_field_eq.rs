// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

const GAS: u64 = 4_000_000;

const SRC: &str = "contract C { state { seen: Map<Q_Address, u64>; hits: u64; } \
    entry act(order: Pair) writes(seen, hits) { \
      guard order.a == order.b; \
      seen.insert(order.a); \
      seen.insert(order.b); \
      hits += 1; \
    } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ent<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn mem_with(cc: &CompiledContract, name: &str, vals: &[(&str, [u8; 32])]) -> Vec<u8> {
    let mut mem = vec![0u8; 8192];
    for s in &ent(cc, name).args {
        if let Some((_, v)) = vals.iter().find(|(k, _)| *k == s.key) {
            let at = s.offset as usize;
            let w = s.width as usize;
            mem[at..at + w].copy_from_slice(&v[..w]);
        }
    }
    mem
}

fn run(cc: &CompiledContract, name: &str, mem: &[u8]) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = ent(cc, name).selector;
    Interpreter::for_entry(&cc.container, sel, GAS)
        .expect("entry")
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn both_fields_take_a_full_address_slot() {
    let cc = compile(SRC);
    let e = ent(&cc, "act");
    for key in ["order.a", "order.b"] {
        let w = e.args.iter().find(|s| s.key == key).expect("arg").width;
        assert_eq!(w, 32, "{key} must be a full address argument");
    }
}

#[test]
fn two_addresses_sharing_only_the_first_word_do_not_pass() {
    let cc = compile(SRC);
    let a = [0x11u8; 32];
    let mut b = [0x11u8; 32];
    b[16] = 0xEE;
    let mem = mem_with(&cc, "act", &[("order.a", a), ("order.b", b)]);
    assert!(
        run(&cc, "act", &mem).is_err(),
        "distinct addresses sharing a first word must fail the equality guard"
    );
}

#[test]
fn identical_addresses_pass() {
    let cc = compile(SRC);
    let a = [0x11u8; 32];
    let mem = mem_with(&cc, "act", &[("order.a", a), ("order.b", a)]);
    let out = run(&cc, "act", &mem).expect("equal addresses pass the guard");
    assert_eq!(
        out.get(&qtv_vm::abi::scalar_key(1)),
        Some(&1),
        "the body ran"
    );
}

#[test]
fn an_address_field_compared_to_a_non_address_is_rejected() {
    let program = quanta_parser::parse(
        "contract C { state { seen: Map<Q_Address, u64>; hits: u64; } \
         entry act(order: Pair) writes(seen, hits) { \
           guard order.a == 5; seen.insert(order.a); hits += 1; } }",
    )
    .expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    assert!(
        compile_contract(&program.contracts[0]).is_err(),
        "an address field compared to a bare integer must be refused"
    );
}
