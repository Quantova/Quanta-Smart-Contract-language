//! The milestone. Compile the simplest contract, load its container into the interpreter, run the

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

// Place one argument word in scratch memory at the offset the entry expects.
fn memory_with(cc: &CompiledContract, entry: usize, values: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    for slot in &cc.entries[entry].args {
        let value = values
            .iter()
            .find(|(k, _)| *k == slot.key)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    mem
}

#[test]
fn meter_advance_runs_metered_and_writes_state() {
    let cc = compile(&fixture("Meter.qs"));

    // The reading state field is slot zero. Seed it to five and advance it by seven.
    let mut storage = BTreeMap::new();
    storage.insert(0u64, 5u64);
    let mem = memory_with(&cc, 0, &[("step", 7)]);

    let out = Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .expect("clean halt");

    assert_eq!(out.storage.get(&0), Some(&12), "reading must become twelve");
    assert_eq!(out.gas_used, 717, "metered gas cost of the advance entry");
}

#[test]
fn a_failing_guard_reverts_and_keeps_state() {
    let cc = compile(&fixture("Meter.qs"));

    // A step of zero fails the guard, so the entry must fault and roll back.
    let mut persistent = BTreeMap::new();
    persistent.insert(0u64, 5u64);
    let mem = memory_with(&cc, 0, &[("step", 0)]);

    let result = Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(persistent.clone())
        .with_memory(&mem)
        .run();

    assert_eq!(result, Err(Fault::DivByZero), "the guard trap must fault");
    assert_eq!(
        persistent.get(&0),
        Some(&5),
        "state is unchanged after a revert"
    );
}
