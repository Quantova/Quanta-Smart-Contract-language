//! Quorum lowering. A `Quorum<M of N, set>` is constructed only from M valid guardian signatures, so

use std::collections::BTreeMap;

use qtv_crypto::{ml_dsa, slh_dsa};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

const BOARD: &str = "contract Board {\n\
  state { board: GuardianSet<3>; counter: u64; }\n\
  entry act(approvals: Quorum<2 of 3, board>) writes(counter) {\n\
    counter = checked(counter + 1);\n\
  }\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn ml_region(seed: u8) -> Vec<u8> {
    let (pk, sk) = ml_dsa::keygen(&[seed; 32]);
    let payload = b"guardian approval";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);
    region
}

fn slh_region(seed: u8) -> Vec<u8> {
    let (sk, pk) = slh_dsa::keygen(&[seed; 24], &[seed; 24], &[seed; 24]);
    let payload = b"guardian approval";
    let sig = slh_dsa::sign(&sk, payload, &[], &[seed; 24]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);
    region
}

// Place each member's signature region and its scheme, pointer, and length words. A member is a
// scheme identifier and its signature region.
fn scratch(cc: &CompiledContract, members: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    let put = |mem: &mut [u8], key: String, value: u64| {
        if let Some(slot) = cc.entries[0].args.iter().find(|s| s.key == key) {
            let at = slot.offset as usize;
            mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
    };
    let mut cursor = 16384usize;
    for (i, (scheme, region)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put(&mut mem, format!("approvals#{i}#scheme"), *scheme);
        put(&mut mem, format!("approvals#{i}#ptr"), off as u64);
        put(&mut mem, format!("approvals#{i}#len"), region.len() as u64);
    }
    mem
}

fn run(cc: &CompiledContract, mem: &[u8]) -> Result<u64, Fault> {
    let mut storage = BTreeMap::new();
    storage.insert(1u64, 10u64); // the counter slot
    Interpreter::new(&cc.container.code, &cc.container.consts, 3_000_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| *out.storage.get(&1).expect("counter slot"))
}

#[test]
fn two_valid_signatures_construct_the_quorum_and_admit_the_entry() {
    let cc = compile(BOARD);
    let mem = scratch(&cc, &[(1, ml_region(3)), (1, ml_region(9))]);
    assert_eq!(
        run(&cc, &mem),
        Ok(11),
        "the gated body runs on a met quorum"
    );
}

#[test]
fn a_mixed_scheme_quorum_admits_a_module_lattice_and_a_hash_based_member() {
    let cc = compile(BOARD);
    let mem = scratch(&cc, &[(1, ml_region(3)), (2, slh_region(7))]);
    assert_eq!(
        run(&cc, &mem),
        Ok(11),
        "each member signs with its own scheme"
    );
}

#[test]
fn an_invalid_member_signature_refuses_the_entry() {
    let cc = compile(BOARD);
    // The second member offers a correctly sized module lattice region with a corrupted signature, so
    // its verify returns false and the entry reverts at the guard trap: the quorum is not met.
    let mut bad = ml_region(9);
    let last = bad.len() - 1;
    bad[last] ^= 255;
    let mem = scratch(&cc, &[(1, ml_region(3)), (1, bad)]);
    assert_eq!(
        run(&cc, &mem),
        Err(Fault::DivByZero),
        "an unmet quorum reverts at the trap"
    );
}

#[test]
fn an_unknown_member_scheme_refuses_the_entry() {
    let cc = compile(BOARD);
    // A member offered under a scheme with no verify opcode, such as reserved FN DSA, reverts.
    let mem = scratch(&cc, &[(1, ml_region(3)), (3, ml_region(9))]);
    assert!(run(&cc, &mem).is_err(), "an unknown scheme is refused");
}
