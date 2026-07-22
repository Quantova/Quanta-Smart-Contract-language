use std::collections::BTreeMap;

use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{addr, put_addr_slots, slot_key};

const GUARDED: &str = "contract Guarded {\n\
  state { owner: Q_Address; count: u64; }\n\
  entry bump() writes(count) {\n\
    guard caller == owner;\n\
    count = checked(count + 1);\n\
  }\n\
}\n";

const OWNER_SLOT: u64 = 0;
const COUNT_SLOT: u64 = 4;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn run_bump(
    cc: &CompiledContract,
    owner: &[u8; 32],
    caller: &[u8; 32],
    count: u64,
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, OWNER_SLOT, owner);
    storage.insert(slot_key(COUNT_SLOT), count);

    let mut mem = vec![0u8; 128];
    mem[0..32].copy_from_slice(caller);

    Interpreter::new(&cc.container.code, &cc.container.consts, 100_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn the_owner_field_spans_four_slots_and_count_follows_it() {
    let cc = compile(GUARDED);
    assert_eq!(cc.container.entries[0].access.writes, vec![COUNT_SLOT]);
}

#[test]
fn the_owner_is_admitted_and_advances_the_count() {
    let cc = compile(GUARDED);
    let owner = addr(0xAB);
    let out = run_bump(&cc, &owner, &owner, 10).expect("the owner is admitted");
    assert_eq!(out.get(&slot_key(COUNT_SLOT)), Some(&11));
}

#[test]
fn a_caller_matching_only_the_leading_word_is_refused() {
    let cc = compile(GUARDED);
    let owner = addr(0xAB);
    let mut caller = owner;
    caller[8] ^= 0xFF;
    assert_eq!(run_bump(&cc, &owner, &caller, 10), Err(Fault::DivByZero));
}

#[test]
fn a_caller_differing_only_in_the_trailing_word_is_refused() {
    let cc = compile(GUARDED);
    let owner = addr(0xAB);
    let mut caller = owner;
    caller[31] ^= 0x01;
    assert_eq!(run_bump(&cc, &owner, &caller, 10), Err(Fault::DivByZero));
}
