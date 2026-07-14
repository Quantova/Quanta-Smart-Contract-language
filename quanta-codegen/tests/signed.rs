//! A `signed by` parameter lowers to a module lattice signature verify before the body runs. A

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
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

fn put_word(mem: &mut [u8], off: usize, value: u64) {
    mem[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

// Build the scratch memory: the scheme identifier, the verify region for the order, and the plain
// argument words. Scheme one is ML DSA.
fn scratch(cc: &CompiledContract, region: &[u8], step: u64) -> Vec<u8> {
    let region_off = 8192usize;
    let mut mem = vec![0u8; region_off + region.len()];
    put_word(&mut mem, arg_offset(cc, "order#scheme"), 1);
    put_word(&mut mem, arg_offset(cc, "order#ptr"), region_off as u64);
    put_word(&mut mem, arg_offset(cc, "order#len"), region.len() as u64);
    put_word(&mut mem, arg_offset(cc, "order.step"), step);
    mem[region_off..].copy_from_slice(region);
    mem
}

fn verify_region(sig: &[u8], pk: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(sig);
    region.extend_from_slice(payload);
    region
}

#[test]
fn a_valid_signature_admits_the_body() {
    let cc = compile(COUNTER);
    // The count field is state slot one, owner is slot zero.
    assert_eq!(cc.container.entries[0].access.writes, vec![1]);

    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let payload = b"bump order canonical bytes";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let region = verify_region(&sig, &pk, payload);
    let mem = scratch(&cc, &region, 4);

    let mut storage = BTreeMap::new();
    storage.insert(1u64, 10u64);

    let out = Interpreter::new(&cc.container.code, &cc.container.consts, 200_000)
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .expect("clean halt");

    assert_eq!(out.storage.get(&1), Some(&14), "count advances by the step");
}

#[test]
fn a_forged_signature_reverts() {
    let cc = compile(COUNTER);

    let (pk, sk) = ml_dsa::keygen(&[3u8; 32]);
    let payload = b"bump order canonical bytes";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let mut region = verify_region(&sig, &pk, payload);
    // Flip one byte of the signature so the verify fails.
    let sig_start = ml_dsa::PUBLIC_KEY_BYTES;
    region[sig_start] ^= 1;
    let mem = scratch(&cc, &region, 4);

    let mut persistent = BTreeMap::new();
    persistent.insert(1u64, 10u64);

    let result = Interpreter::new(&cc.container.code, &cc.container.consts, 200_000)
        .with_storage(persistent.clone())
        .with_memory(&mem)
        .run();

    assert_eq!(
        result,
        Err(Fault::DivByZero),
        "a forged signature must revert"
    );
    assert_eq!(persistent.get(&1), Some(&10), "state is unchanged");
}
