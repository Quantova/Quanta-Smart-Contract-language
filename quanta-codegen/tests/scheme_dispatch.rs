//! Conformance vectors for the multi scheme signature dispatch. The one signed by lowering carries

use std::collections::BTreeMap;

use qtv_crypto::{ml_dsa, slh_dsa};
use qtv_vm::interp::{Fault, Interpreter};
use qtv_vm::isa::{decode, OpCode};
use quanta_codegen::{compile_contract, CompiledContract};

const COUNTER: &str = "contract Counter {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry bump(order: BumpOrder signed by owner) writes(count) {\n\
    count = checked(count + order.step);\n\
    emit Bumped(count);\n\
  }\n\
  event Bumped(value: u64);\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn arg_offset(cc: &CompiledContract, key: &str) -> usize {
    cc.entries[0]
        .args
        .iter()
        .find(|slot| slot.key == key)
        .unwrap_or_else(|| panic!("no argument {key}"))
        .offset as usize
}

fn opcodes(code: &[u8]) -> Vec<OpCode> {
    let mut ops = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let (instr, len) = decode(code, pc).expect("decode");
        ops.push(instr.opcode());
        pc += len;
    }
    ops
}

fn ml_region() -> Vec<u8> {
    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let payload = b"order canonical bytes";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);
    region
}

fn slh_region() -> Vec<u8> {
    let (sk, pk) = slh_dsa::keygen(&[1u8; 24], &[2u8; 24], &[3u8; 24]);
    let payload = b"order canonical bytes";
    let sig = slh_dsa::sign(&sk, payload, &[], &[4u8; 24]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);
    region
}

fn scratch(cc: &CompiledContract, scheme: u64, region: &[u8], step: u64) -> Vec<u8> {
    let region_off = 8192usize;
    let mut mem = vec![0u8; region_off + region.len()];
    let mut put = |key: &str, value: u64| {
        let at = arg_offset(cc, key);
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    };
    put("order#scheme", scheme);
    put("order#ptr", region_off as u64);
    put("order#len", region.len() as u64);
    put("order.step", step);
    mem[region_off..].copy_from_slice(region);
    mem
}

// Run bump with a scheme and region and return the outcome and the storage seen on a clean halt.
fn run(cc: &CompiledContract, scheme: u64, region: &[u8]) -> Result<u64, Fault> {
    let mem = scratch(cc, scheme, region, 4);
    let mut storage = BTreeMap::new();
    storage.insert(1u64, 10u64);
    Interpreter::new(&cc.container.code, &cc.container.consts, 300_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| *out.storage.get(&1).expect("count slot"))
}

#[test]
fn the_lowering_carries_both_verify_opcodes() {
    let cc = compile(COUNTER);
    let ops = opcodes(&cc.container.code);
    assert!(
        ops.contains(&OpCode::VerifyMl),
        "the module lattice verify must be present"
    );
    assert!(
        ops.contains(&OpCode::VerifySlh),
        "the hash based verify must be present"
    );
}

#[test]
fn scheme_one_verifies_with_the_module_lattice_opcode() {
    let cc = compile(COUNTER);
    assert_eq!(run(&cc, 1, &ml_region()), Ok(14), "ML DSA scheme verifies");
}

#[test]
fn scheme_two_verifies_with_the_hash_based_opcode() {
    let cc = compile(COUNTER);
    assert_eq!(
        run(&cc, 2, &slh_region()),
        Ok(14),
        "SLH DSA scheme verifies"
    );
}

#[test]
fn scheme_two_does_not_use_the_module_lattice_opcode() {
    let cc = compile(COUNTER);
    // A valid module lattice region is offered under scheme two. If scheme two wrongly ran the
    // module lattice verify it would accept and commit. Instead it runs the hash based verify, which
    // reverts on the region, proving the dispatch routes scheme two to the hash based opcode.
    assert!(
        run(&cc, 2, &ml_region()).is_err(),
        "scheme two must not accept a module lattice region"
    );
}

#[test]
fn an_unknown_scheme_reverts() {
    let cc = compile(COUNTER);
    // Scheme three is FN DSA, which has no opcode in the tagged machine and reverts, and any other
    // value reverts as well.
    assert_eq!(run(&cc, 3, &ml_region()), Err(Fault::DivByZero));
    assert_eq!(run(&cc, 99, &ml_region()), Err(Fault::DivByZero));
}
