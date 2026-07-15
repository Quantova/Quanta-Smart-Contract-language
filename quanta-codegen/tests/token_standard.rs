//! The issuer control token standard, end to end. The reference contract type checks, compiles to a

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, compile_entry, CompiledContract};

// State slots follow declaration order: guardians, total_supply, max_supply, paused, then the keyed
// balances and frozen fields.
const SLOT_SUPPLY: u64 = 1;
const SLOT_MAX: u64 = 2;
// Keyed bases, matching the code generator's layout of the first two keyed fields.
const BAL_BASE: u64 = 1 << 40;
// Two demonstration accounts, reduced to their representative address words.
const ACCOUNT_A: u64 = 1;
const ACCOUNT_B: u64 = 2;
const CEILING: u64 = 1_000_000_000;
const GAS: u64 = 6_000_000;

fn token_standard() -> Contract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("examples/IssuerToken.qs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read example: {e}"));
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("the token standard type checks clean");
    program.contracts.into_iter().next().expect("one contract")
}

fn ml_region(seed: u8) -> Vec<u8> {
    let (pk, sk) = ml_dsa::keygen(&[seed; 32]);
    let payload = b"issuer guardian approval";
    let sig = ml_dsa::sign(&sk, payload, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(payload);
    region
}

fn put_arg(mem: &mut [u8], cc: &CompiledContract, key: &str, value: u64) {
    if let Some(slot) = cc.entries[0].args.iter().find(|s| s.key == key) {
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
}

// Place each quorum member's signature region and its scheme, pointer, and length words.
fn put_quorum(mem: &mut [u8], cc: &CompiledContract, name: &str, members: &[(u64, Vec<u8>)]) {
    let mut cursor = 20000usize;
    for (i, (scheme, region)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_arg(mem, cc, &format!("{name}#{i}#scheme"), *scheme);
        put_arg(mem, cc, &format!("{name}#{i}#ptr"), off as u64);
        put_arg(mem, cc, &format!("{name}#{i}#len"), region.len() as u64);
    }
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<u64, u64>,
    mem: &[u8],
) -> Result<BTreeMap<u64, u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, GAS)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn the_whole_token_standard_compiles_to_a_container() {
    let contract = token_standard();
    let cc = compile_contract(&contract).expect("the token standard compiles");
    assert_eq!(cc.container.entries.len(), 8, "every issuer power lowers");
    assert!(!cc.container.code.is_empty());
}

#[test]
fn a_quorum_gated_mint_creates_supply_and_credits_the_recipient() {
    let contract = token_standard();
    let cc = compile_entry(&contract, "mint").expect("mint compiles");

    let members = vec![(1, ml_region(1)), (1, ml_region(2)), (1, ml_region(3))];
    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, &cc, "order.amount", 500);
    put_arg(&mut mem, &cc, "order.to", ACCOUNT_A);
    put_quorum(&mut mem, &cc, "approvals", &members);

    let mut storage = BTreeMap::new();
    storage.insert(SLOT_MAX, CEILING);

    let out = run(&cc, storage, &mem).expect("the mint halts under a met quorum");
    assert_eq!(
        out.get(&SLOT_SUPPLY),
        Some(&500),
        "supply grows under the quorum"
    );
    assert_eq!(
        out.get(&(BAL_BASE + ACCOUNT_A)),
        Some(&500),
        "the recipient balance is credited"
    );
}

#[test]
fn a_transfer_moves_ledger_balance_between_accounts() {
    let contract = token_standard();
    let cc = compile_entry(&contract, "transfer").expect("transfer compiles");

    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, &cc, "funds", 200);
    put_arg(&mut mem, &cc, "to", ACCOUNT_B);
    put_arg(&mut mem, &cc, "@caller", ACCOUNT_A);

    let mut storage = BTreeMap::new();
    storage.insert(BAL_BASE + ACCOUNT_A, 500);
    storage.insert(SLOT_SUPPLY, 500);
    storage.insert(SLOT_MAX, CEILING);

    let out = run(&cc, storage, &mem).expect("the transfer halts");
    assert_eq!(
        out.get(&(BAL_BASE + ACCOUNT_A)),
        Some(&300),
        "the sender balance falls"
    );
    assert_eq!(
        out.get(&(BAL_BASE + ACCOUNT_B)),
        Some(&200),
        "the recipient balance rises by the same amount"
    );
}

#[test]
fn a_mint_with_an_unmet_quorum_is_refused() {
    let contract = token_standard();
    let cc = compile_entry(&contract, "mint").expect("mint compiles");

    // The third guardian region is correctly sized but its signature is corrupted, so its verify
    // returns false and the quorum is not met.
    let mut bad = ml_region(3);
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    let members = vec![(1, ml_region(1)), (1, ml_region(2)), (1, bad)];

    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, &cc, "order.amount", 500);
    put_arg(&mut mem, &cc, "order.to", ACCOUNT_A);
    put_quorum(&mut mem, &cc, "approvals", &members);

    let mut storage = BTreeMap::new();
    storage.insert(SLOT_MAX, CEILING);

    assert_eq!(
        run(&cc, storage, &mem),
        Err(Fault::DivByZero),
        "an unauthorized mint reverts at the quorum trap"
    );
}
