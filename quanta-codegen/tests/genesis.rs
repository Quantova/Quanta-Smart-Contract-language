//! The genesis constructor. A contract's genesis block lowers to a reserved entry the chain runs at

use qtv_vm::container::{selector, GENESIS_SIGNATURE};
use qtv_vm::interp::Interpreter;
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::slot_key;

const COUNTER: &str = "contract Counter {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry bump(order: BumpOrder signed by owner) writes(count) {\n\
    count = checked(count + order.step);\n\
  }\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

#[test]
fn the_container_carries_a_genesis_entry() {
    let cc = compile(COUNTER);
    let gsel = selector(GENESIS_SIGNATURE);
    assert!(
        cc.container.entry_offset(&gsel).is_some(),
        "a contract with a genesis block emits the genesis constructor"
    );
    // The genesis constructor is not surfaced as a callable interface entry.
    assert!(
        cc.entries.iter().all(|e| e.name != "@genesis"),
        "genesis is not a public entry"
    );
}

#[test]
fn genesis_stores_the_whole_deployer_address_as_the_owner() {
    let cc = compile(COUNTER);
    let gsel = selector(GENESIS_SIGNATURE);

    // The deployer address in the caller context at offset zero, a full thirty two byte value.
    let deployer = [0xD1u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&deployer);

    let out = Interpreter::for_entry(&cc.container, gsel, 200_000)
        .expect("the genesis selector resolves")
        .with_memory(&mem)
        .run()
        .expect("genesis halts");

    // The owner occupies the first four slots, each holding a word of the deployer address.
    for i in 0..4u64 {
        let word = u64::from_be_bytes(
            deployer[i as usize * 8..i as usize * 8 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            out.storage.get(&slot_key(i)),
            Some(&word),
            "owner word {i} is the deployer address word"
        );
    }
    // Count is the fifth slot and is initialized to zero.
    assert_eq!(out.storage.get(&slot_key(4)), Some(&0), "count starts at zero");
}

#[test]
fn a_bump_after_genesis_is_gated_by_the_stored_owner() {
    // The owner the genesis stored is exactly the address a later `signed by owner` bump checks the
    // signer against, so genesis and the binding agree on the owner slots.
    let cc = compile(COUNTER);
    let gsel = selector(GENESIS_SIGNATURE);
    let deployer = [0x7Eu8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&deployer);
    let out = Interpreter::for_entry(&cc.container, gsel, 200_000)
        .expect("genesis resolves")
        .with_memory(&mem)
        .run()
        .expect("genesis halts");
    // The four owner words the bump binding reads all come from the deployer address.
    let owner: Vec<u64> = (0..4).map(|i| *out.storage.get(&slot_key(i)).unwrap()).collect();
    let expected: Vec<u64> = (0..4)
        .map(|i: usize| u64::from_be_bytes(deployer[i * 8..i * 8 + 8].try_into().unwrap()))
        .collect();
    assert_eq!(owner, expected, "the stored owner is the whole deployer address");
}
