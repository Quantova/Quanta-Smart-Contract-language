//! Deploy time parameters read by a genesis block, and the sentinel that guards a short deploy.

use qtv_vm::container::{selector, GENESIS_SIGNATURE};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::slot_key;

const SENTINEL: [u8; 8] = *b"QGENSNTL";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn run_genesis(cc: &CompiledContract, mem: &[u8]) -> Result<std::collections::BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::for_entry(&cc.container, selector(GENESIS_SIGNATURE), 400_000)
        .expect("the genesis selector resolves")
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

fn params_memory(param_bytes: &[u8]) -> Vec<u8> {
    let context = 72usize;
    let mut mem = vec![0u8; context + param_bytes.len() + 8];
    mem[context..context + param_bytes.len()].copy_from_slice(param_bytes);
    mem[context + param_bytes.len()..].copy_from_slice(&SENTINEL);
    mem
}

const OWNER_SUPPLY: &str = "contract T {\n\
  state { owner: Q_Address; total_supply: u128; }\n\
  genesis { owner = deploy_params.owner; total_supply = deploy_params.initial_supply; }\n\
}\n";

#[test]
fn genesis_stores_an_address_param_in_full_and_a_wide_param_across_two_slots() {
    let cc = compile(OWNER_SUPPLY);
    assert_eq!(
        cc.deploy_params
            .iter()
            .map(|p| (p.key.as_str(), p.offset, p.width))
            .collect::<Vec<_>>(),
        vec![
            ("deploy_params.owner", 72, 32),
            ("deploy_params.initial_supply", 104, 16),
        ]
    );

    let owner = [0xA7u8; 32];
    let supply: u128 = 0xDEAD_BEEF_0000_0001u128 + (1u128 << 64) * 7;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&(supply as u64).to_be_bytes());
    bytes.extend_from_slice(&((supply >> 64) as u64).to_be_bytes());

    let storage = run_genesis(&cc, &params_memory(&bytes)).expect("genesis halts on a full deploy");

    for i in 0..4u64 {
        let word = u64::from_be_bytes(owner[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        assert_eq!(storage.get(&slot_key(i)), Some(&word), "owner word {i}");
    }
    let supply_lo = supply as u64;
    let supply_hi = (supply >> 64) as u64;
    assert_eq!(storage.get(&slot_key(4)), Some(&supply_lo), "supply low word");
    let hi_slot = 4u64 | (1u64 << 56);
    assert_eq!(storage.get(&slot_key(hi_slot)), Some(&supply_hi), "supply high word");
}

#[test]
fn a_deploy_that_omits_the_sentinel_reverts_and_stores_nothing() {
    let cc = compile(OWNER_SUPPLY);
    let owner = [0x11u8; 32];
    let supply: u128 = 500;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&(supply as u64).to_be_bytes());
    bytes.extend_from_slice(&((supply >> 64) as u64).to_be_bytes());
    let context = 72usize;
    let mut mem = vec![0u8; context + bytes.len()];
    mem[context..].copy_from_slice(&bytes);
    assert_eq!(
        run_genesis(&cc, &mem),
        Err(Fault::DivByZero),
        "a missing sentinel reverts the constructor"
    );
}

#[test]
fn a_deploy_that_omits_a_required_param_reverts() {
    let cc = compile(OWNER_SUPPLY);
    let owner = [0x22u8; 32];
    let context = 72usize;
    let mut mem = vec![0u8; context + 32];
    mem[context..].copy_from_slice(&owner);
    assert_eq!(
        run_genesis(&cc, &mem),
        Err(Fault::DivByZero),
        "an omitted parameter reverts the constructor"
    );
}

#[test]
fn a_deploy_with_a_wrong_sentinel_reverts() {
    let cc = compile(OWNER_SUPPLY);
    let owner = [0x33u8; 32];
    let supply: u128 = 1;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&(supply as u64).to_be_bytes());
    bytes.extend_from_slice(&((supply >> 64) as u64).to_be_bytes());
    let mut mem = params_memory(&bytes);
    let last = mem.len() - 1;
    mem[last] ^= 0xFF;
    assert_eq!(
        run_genesis(&cc, &mem),
        Err(Fault::DivByZero),
        "a wrong sentinel reverts the constructor"
    );
}

const U64_PARAM: &str = "contract N {\n\
  state { limit: u64; }\n\
  genesis { limit = deploy_params.limit; }\n\
}\n";

#[test]
fn a_u64_deploy_param_is_read_as_one_word() {
    let cc = compile(U64_PARAM);
    assert_eq!(
        cc.deploy_params
            .iter()
            .map(|p| (p.key.as_str(), p.offset, p.width))
            .collect::<Vec<_>>(),
        vec![("deploy_params.limit", 72, 8)]
    );
    let value: u64 = 9_000_000_000_000;
    let storage = run_genesis(&cc, &params_memory(&value.to_be_bytes())).expect("genesis halts");
    assert_eq!(storage.get(&slot_key(0)), Some(&value), "the u64 param is stored");
}

const GUARDIAN_PARAM: &str = "contract G {\n\
  state { guardians: GuardianSet<3>; }\n\
  genesis { guardians = deploy_params.guardians; }\n\
}\n";

#[test]
fn a_guardian_set_deploy_param_seeds_the_whole_set() {
    let cc = compile(GUARDIAN_PARAM);
    assert_eq!(
        cc.deploy_params
            .iter()
            .map(|p| (p.key.as_str(), p.offset, p.width))
            .collect::<Vec<_>>(),
        vec![("deploy_params.guardians", 72, 96)]
    );
    let g: [[u8; 32]; 3] = [[0xA1; 32], [0xB2; 32], [0xC3; 32]];
    let mut bytes = Vec::new();
    for a in &g {
        bytes.extend_from_slice(a);
    }
    let storage = run_genesis(&cc, &params_memory(&bytes)).expect("genesis halts");
    for (j, a) in g.iter().enumerate() {
        for w in 0..4u64 {
            let word = u64::from_be_bytes(a[w as usize * 8..w as usize * 8 + 8].try_into().unwrap());
            assert_eq!(
                storage.get(&slot_key(j as u64 * 4 + w)),
                Some(&word),
                "guardian {j} word {w}"
            );
        }
    }
}

#[test]
fn a_deploy_param_read_outside_genesis_is_refused() {
    let src = "contract Bad {\n\
      state { owner: Q_Address; }\n\
      genesis { owner = deploy_params.owner; }\n\
      entry grab(step: u64) writes(owner) { owner = deploy_params.owner; }\n\
    }\n";
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let err = compile_contract(&program.contracts[0]).expect_err("a deploy param read in an entry is refused");
    let msg = err.to_string();
    assert!(msg.contains("address"), "the refusal names the unsupported read: {msg}");
}
