//! The issuer control token standard, end to end. The reference contract type checks, compiles to a

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, SELECTOR_BYTES};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{addr, map_key, slot_key};

// State slots follow declaration order: guardians, total_supply, max_supply, paused, then the keyed
// balances and frozen fields.
const SLOT_SUPPLY: u64 = 1;
const SLOT_MAX: u64 = 2;
// The keyed base of the balances map, the first keyed field, matching the code generator's layout.
const BAL_BASE: u64 = 1 << 40;
const CEILING: u64 = 1_000_000_000;
const GAS: u64 = 6_000_000;

// Two demonstration accounts as whole thirty two byte addresses.
fn account_a() -> [u8; 32] {
    addr(0xA1)
}
fn account_b() -> [u8; 32] {
    addr(0xB2)
}

fn token_standard() -> Contract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("examples/IssuerToken.qs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read example: {e}"));
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("the token standard type checks clean");
    program.contracts.into_iter().next().expect("one contract")
}

fn find_entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("the container carries the {name} entry"))
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

fn put_arg(mem: &mut [u8], entry: &EntryArtifact, key: &str, value: u64) {
    if let Some(slot) = entry.args.iter().find(|s| s.key == key) {
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
}

fn put_addr(mem: &mut [u8], entry: &EntryArtifact, key: &str, address: &[u8; 32]) {
    if let Some(slot) = entry.args.iter().find(|s| s.key == key) {
        let at = slot.offset as usize;
        mem[at..at + 32].copy_from_slice(address);
    }
}

// Place each quorum member's signature region and its scheme, pointer, and length words.
fn put_quorum(mem: &mut [u8], entry: &EntryArtifact, name: &str, members: &[(u64, Vec<u8>)]) {
    let mut cursor = 20000usize;
    for (i, (scheme, region)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_arg(mem, entry, &format!("{name}#{i}#scheme"), *scheme);
        put_arg(mem, entry, &format!("{name}#{i}#ptr"), off as u64);
        put_arg(mem, entry, &format!("{name}#{i}#len"), region.len() as u64);
    }
}

fn run(
    cc: &CompiledContract,
    entry: [u8; SELECTOR_BYTES],
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::for_entry(&cc.container, entry, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn the_whole_token_standard_compiles_to_a_container() {
    let cc = compile_contract(&token_standard()).expect("the token standard compiles");
    assert_eq!(cc.container.entries.len(), 8, "every issuer power lowers");
    assert!(!cc.container.code.is_empty());
}

#[test]
fn a_quorum_gated_mint_creates_supply_and_credits_the_recipient() {
    let cc = compile_contract(&token_standard()).expect("the token standard compiles");
    let mint = find_entry(&cc, "mint");

    let members = vec![(1, ml_region(1)), (1, ml_region(2)), (1, ml_region(3))];
    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, mint, "order.amount", 500);
    put_addr(&mut mem, mint, "order.to", &account_a());
    put_quorum(&mut mem, mint, "approvals", &members);

    let mut storage = BTreeMap::new();
    storage.insert(slot_key(SLOT_MAX), CEILING);

    let out = run(&cc, mint.selector, storage, &mem).expect("the mint halts under a met quorum");
    assert_eq!(
        out.get(&slot_key(SLOT_SUPPLY)),
        Some(&500),
        "supply grows under the quorum"
    );
    assert_eq!(
        out.get(&map_key(BAL_BASE, &account_a())),
        Some(&500),
        "the recipient balance is credited"
    );
}

#[test]
fn a_transfer_moves_ledger_balance_between_accounts() {
    let cc = compile_contract(&token_standard()).expect("the token standard compiles");
    let transfer = find_entry(&cc, "transfer");

    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, transfer, "funds", 200);
    put_addr(&mut mem, transfer, "to", &account_b());
    put_addr(&mut mem, transfer, "@caller", &account_a());

    let mut storage = BTreeMap::new();
    storage.insert(map_key(BAL_BASE, &account_a()), 500);
    storage.insert(slot_key(SLOT_SUPPLY), 500);
    storage.insert(slot_key(SLOT_MAX), CEILING);

    let out = run(&cc, transfer.selector, storage, &mem).expect("the transfer halts");
    assert_eq!(
        out.get(&map_key(BAL_BASE, &account_a())),
        Some(&300),
        "the sender balance falls"
    );
    assert_eq!(
        out.get(&map_key(BAL_BASE, &account_b())),
        Some(&200),
        "the recipient balance rises by the same amount"
    );
}

#[test]
fn a_mint_with_an_unmet_quorum_is_refused() {
    let cc = compile_contract(&token_standard()).expect("the token standard compiles");
    let mint = find_entry(&cc, "mint");

    // The third guardian region is correctly sized but its signature is corrupted, so its verify
    // returns false and the quorum is not met.
    let mut bad = ml_region(3);
    let last = bad.len() - 1;
    bad[last] ^= 255;
    let members = vec![(1, ml_region(1)), (1, ml_region(2)), (1, bad)];

    let mut mem = vec![0u8; 65536];
    put_arg(&mut mem, mint, "order.amount", 500);
    put_addr(&mut mem, mint, "order.to", &account_a());
    put_quorum(&mut mem, mint, "approvals", &members);

    let mut storage = BTreeMap::new();
    storage.insert(slot_key(SLOT_MAX), CEILING);

    assert_eq!(
        run(&cc, mint.selector, storage, &mem),
        Err(Fault::DivByZero),
        "an unauthorized mint reverts at the quorum trap"
    );
}

#[test]
fn a_call_to_an_unknown_selector_reverts() {
    let cc = compile_contract(&token_standard()).expect("the token standard compiles");
    let res = Interpreter::for_entry(&cc.container, selector("nonexistent()"), GAS);
    assert!(matches!(res, Err(Fault::UnknownSelector)));
}
