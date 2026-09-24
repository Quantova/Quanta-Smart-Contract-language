// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

const GAS: u64 = 2_000_000;

const SRC: &str = "contract E { \
    entry log(x: u64) { emit Tick(x); } \
    event Tick(level: u8); }";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn run(cc: &CompiledContract, x: u64) -> Result<Vec<qtv_vm::interp::Effect>, Fault> {
    let e = cc.entries.iter().find(|e| e.name == "log").expect("entry");
    let at = e.args.iter().find(|s| s.key == "x").expect("arg").offset as usize;
    let mut mem = vec![0u8; 4096];
    mem[at..at + 8].copy_from_slice(&x.to_be_bytes());
    let sel: [u8; SELECTOR_BYTES] = e.selector;
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_memory(&mem)
        .run()
        .map(|out| out.effects)
}

#[test]
fn an_event_field_cannot_carry_more_than_its_declared_width() {
    let cc = compile(SRC);
    assert!(run(&cc, 255).is_ok(), "the widest u8 is logged");
    assert!(
        run(&cc, 256).is_err(),
        "a value past the declared width must trap, not be logged as a number \
         the event's own signature says cannot exist"
    );
    assert!(run(&cc, 70_000).is_err());
}
