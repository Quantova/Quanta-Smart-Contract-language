//! An emit records a typed event effect the host appends to the block event trie. The event selector

use qtv_vm::container::selector as vm_selector;
use qtv_vm::interp::{Effect, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};
use std::collections::BTreeMap;


const GAS: u64 = 2_000_000;
/// Matches the code generator's high word offset for a two word scalar field.
const HI: u64 = 1 << 56;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("the source parses");
    quanta_typeck::check(&program).expect("the source type checks");
    let contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("the contract compiles")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("the entry")
}

fn put_arg(mem: &mut [u8], e: &EntryArtifact, key: &str, value: u64) {
    let slot = e.args.iter().find(|s| s.key == key).expect("the argument");
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn effects(
    cc: &CompiledContract,
    e: &EntryArtifact,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Vec<Effect> {
    Interpreter::for_entry(&cc.container, e.selector, GAS)
        .expect("the selector resolves")
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .expect("the entry halts")
        .effects
}

const SCALARS: &str = "contract M { state { reading: u64; } genesis { reading = 0; } \
     entry advance(step: u64) writes(reading) \
     { reading = checked(reading + step); emit Advanced(reading, step); } \
     event Advanced(value: u64, step: u64); }";

#[test]
fn an_emit_records_a_typed_event_with_scalar_operands() {
    let cc = compile(SCALARS);
    let e = entry(&cc, "advance");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "step", 5);

    let got = effects(&cc, e, BTreeMap::new(), &mem);

    let mut payload = Vec::new();
    payload.extend_from_slice(&5u64.to_be_bytes()); // reading, zero plus five
    payload.extend_from_slice(&5u64.to_be_bytes()); // step
    assert_eq!(
        got,
        vec![Effect::Event {
            selector: vm_selector("Advanced(u64,u64)"),
            data: payload,
        }]
    );
}

const WIDE: &str = "contract W { state { total: u128; } genesis { total = 0; } \
     entry record() writes(total) \
     { total = 20_000_000_000_000_000_000; emit Recorded(total); } \
     event Recorded(value: u128); }";

#[test]
fn an_emit_records_a_wide_operand_as_low_then_high_word() {
    let cc = compile(WIDE);
    let e = entry(&cc, "record");
    let mem = vec![0u8; 4096];

    let got = effects(&cc, e, BTreeMap::new(), &mem);

    // Twenty quintillion splits into a low word and a high word of one, and the payload carries them
    // low word first.
    let mut payload = Vec::new();
    payload.extend_from_slice(&1_553_255_926_290_448_384u64.to_be_bytes());
    payload.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(
        got,
        vec![Effect::Event {
            selector: vm_selector("Recorded(u128)"),
            data: payload,
        }]
    );
    let _ = HI;
}

#[test]
fn a_clean_entry_without_emit_records_no_event() {
    // The record entry above emits; an entry with no emit records nothing, proving the effect comes
    // from the emit and not the machinery around it.
    const PLAIN: &str = "contract P { state { x: u64; } genesis { x = 0; } \
         entry set(v: u64) writes(x) { x = v; } }";
    let cc = compile(PLAIN);
    let e = entry(&cc, "set");
    let mut mem = vec![0u8; 4096];
    put_arg(&mut mem, e, "v", 9);
    assert!(effects(&cc, e, BTreeMap::new(), &mem).is_empty());
}
