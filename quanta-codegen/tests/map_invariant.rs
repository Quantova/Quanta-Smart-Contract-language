// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

mod common;
use common::{addr, put_addr_slots};

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

const MAP_CAPPED: &str = "contract MapCapped {\n\
  state { anchor: Q_Address; bal: Map<Q_Address, u64>; }\n\
  entry put(v: u64) writes(bal) {\n\
    bal.set(anchor, v);\n\
  }\n\
  invariant bal.get(anchor) <= 100;\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn run(cc: &CompiledContract, v: u64) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let anchor = addr(1);
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, 0, &anchor);
    let mut mem = vec![0u8; 65536];
    for slot in &cc.entries[0].args {
        if slot.key == "v" {
            let at = slot.offset as usize;
            mem[at..at + 8].copy_from_slice(&v.to_be_bytes());
        }
    }
    Interpreter::new(&cc.container.code, &cc.container.consts, 300_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn a_map_write_within_the_invariant_commits() {
    let cc = compile(MAP_CAPPED);
    assert!(
        run(&cc, 50).is_ok(),
        "the map invariant holds so the keyed-only write commits"
    );
}

#[test]
fn a_map_write_that_breaks_the_invariant_reverts() {
    let cc = compile(MAP_CAPPED);
    assert_eq!(
        run(&cc, 150),
        Err(Fault::DivByZero),
        "a contract invariant must be enforced on a keyed-only writer and revert"
    );
}
