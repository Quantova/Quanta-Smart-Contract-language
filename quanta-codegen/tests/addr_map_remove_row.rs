// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

const GAS: u64 = 8_000_000;

const SRC: &str = "contract Nft { state { owner_of: Map<Q_Id, Q_Address>; } \
    entry claim(id: Q_Id) writes(owner_of) { \
      guard owner_of.get(id) == 0; \
      owner_of.set(id, caller); \
    } \
    entry burn(id: Q_Id) writes(owner_of) { \
      guard owner_of.get(id) == caller; \
      owner_of.remove(id); \
    } }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ent<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn call(
    cc: &CompiledContract,
    name: &str,
    caller: u8,
    storage: BTreeMap<[u8; 32], u64>,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let e = ent(cc, name);
    let mut mem = vec![0u8; 8192];
    mem[0..32].copy_from_slice(&[caller; 32]);
    let at = e
        .args
        .iter()
        .find(|s| s.key == "id")
        .expect("id arg")
        .offset as usize;
    let mut id = [0u8; 32];
    id[7] = 7;
    mem[at..at + 32].copy_from_slice(&id);
    let sel: [u8; SELECTOR_BYTES] = e.selector;
    Interpreter::for_entry(&cc.container, sel, GAS)
        .expect("entry")
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn removing_an_address_row_clears_the_word_the_reader_checks() {
    let cc = compile(SRC);
    let owned = call(&cc, "claim", 0xAA, BTreeMap::new()).expect("first claim");
    let burned = call(&cc, "burn", 0xAA, owned).expect("the holder burns it");
    assert!(
        call(&cc, "claim", 0xBB, burned).is_ok(),
        "the row still read as occupied after remove, so it is bricked forever"
    );
}
