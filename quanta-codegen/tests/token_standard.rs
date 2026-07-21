//! The issuer control token standard, end to end. The reference contract type checks, compiles to a

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, SELECTOR_BYTES};
use qtv_vm::interp::{Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{addr, map_key, put_addr_slots, signer_address, slot_key};

// State slots follow declaration order: the five guardian set holds the first twenty slots, then
// total_supply, max_supply, and paused, then the keyed balances and frozen fields.
const SLOT_SUPPLY: u64 = 20;
const SLOT_MAX: u64 = 21;
// The keyed base of the balances map, the first keyed field, matching the code generator's layout.
const BAL_BASE: u64 = 1 << 40;
const CEILING: u64 = 1_000_000_000;
const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SCHEME_ML: u8 = 1;

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

fn compiled() -> CompiledContract {
    compile_contract(&token_standard()).expect("the token standard compiles")
}

fn find_entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("the container carries the {name} entry"))
}

fn selector_of(cc: &CompiledContract, name: &str) -> [u8; 4] {
    find_entry(cc, name).selector
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

// Five module lattice guardians and their addresses, seeded into the guardian set at the front slots.
fn guardians() -> (Vec<(ml_dsa::PublicKey, ml_dsa::SecretKey)>, Vec<[u8; 32]>) {
    let keys: Vec<_> = (1u8..=5).map(|s| ml_dsa::keygen(&[s; 32])).collect();
    let addrs = keys
        .iter()
        .map(|(pk, _)| signer_address(SCHEME_ML, pk))
        .collect();
    (keys, addrs)
}

fn seed_guardians(storage: &mut BTreeMap<[u8; 32], u64>, addrs: &[[u8; 32]]) {
    for (j, g) in addrs.iter().enumerate() {
        put_addr_slots(storage, j as u64 * 4, g);
    }
}

// The canonical quorum message a mint member signs: the tag, the contract, the mint selector, the
// member address, the member nonce, then the order fields the code generator commits to, order.amount
// as a word and order.to as a whole address.
fn mint_message(
    cc: &CompiledContract,
    member: &[u8; 32],
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector_of(cc, "mint")) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(to);
    msg
}

fn ml_member(
    cc: &CompiledContract,
    key: &(ml_dsa::PublicKey, ml_dsa::SecretKey),
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    let member = signer_address(SCHEME_ML, &key.0);
    let msg = mint_message(cc, &member, nonce, amount, to);
    let sig = ml_dsa::sign(&key.1, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&key.0);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    region
}

// Assemble the mint memory: the order, the contract context, and the member regions with their scheme,
// pointer, and guardian index. Members sit low in scratch, below the code generator's fixed regions.
fn mint_memory(
    mint: &EntryArtifact,
    amount: u64,
    to: &[u8; 32],
    members: &[(Vec<u8>, u64)],
) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    put_arg(&mut mem, mint, "order.amount", amount);
    put_addr(&mut mem, mint, "order.to", to);
    let mut cursor = 8192usize;
    for (i, (region, index)) in members.iter().enumerate() {
        let off = cursor;
        cursor += region.len();
        mem[off..off + region.len()].copy_from_slice(region);
        put_arg(&mut mem, mint, &format!("approvals#{i}#scheme"), SCHEME_ML as u64);
        put_arg(&mut mem, mint, &format!("approvals#{i}#ptr"), off as u64);
        put_arg(&mut mem, mint, &format!("approvals#{i}#index"), *index);
    }
    mem
}

#[test]
fn the_whole_token_standard_compiles_to_a_container() {
    let cc = compiled();
    // Eight callable entries plus the genesis constructor.
    assert!(cc.entries.len() >= 8, "every issuer power lowers");
    assert!(!cc.container.code.is_empty());
}

#[test]
fn a_quorum_gated_mint_binds_three_distinct_guardians_and_credits_the_recipient() {
    let cc = compiled();
    let mint = find_entry(&cc, "mint");
    let (keys, addrs) = guardians();

    let to = account_a();
    let members = vec![
        (ml_member(&cc, &keys[0], 0, 500, &to), 0),
        (ml_member(&cc, &keys[1], 0, 500, &to), 1),
        (ml_member(&cc, &keys[2], 0, 500, &to), 2),
    ];
    let mem = mint_memory(mint, 500, &to, &members);

    let mut storage = BTreeMap::new();
    seed_guardians(&mut storage, &addrs);
    storage.insert(slot_key(SLOT_MAX), CEILING);

    let out = run(&cc, mint.selector, storage, &mem).expect("a met quorum admits the mint");
    assert_eq!(out.get(&slot_key(SLOT_SUPPLY)), Some(&500), "supply grows under the quorum");
    assert_eq!(
        out.get(&map_key(BAL_BASE, &to)),
        Some(&500),
        "the recipient balance is credited"
    );
}

#[test]
fn a_mint_with_a_non_guardian_member_is_refused() {
    let cc = compiled();
    let mint = find_entry(&cc, "mint");
    let (keys, addrs) = guardians();

    // The third member is a stranger who signs a valid message but is not the guardian at its index.
    let (spk, ssk) = ml_dsa::keygen(&[200u8; 32]);
    let stranger = (spk, ssk);
    let to = account_a();
    let members = vec![
        (ml_member(&cc, &keys[0], 0, 500, &to), 0),
        (ml_member(&cc, &keys[1], 0, 500, &to), 1),
        (ml_member(&cc, &stranger, 0, 500, &to), 2),
    ];
    let mem = mint_memory(mint, 500, &to, &members);

    let mut storage = BTreeMap::new();
    seed_guardians(&mut storage, &addrs);
    storage.insert(slot_key(SLOT_MAX), CEILING);

    assert_eq!(
        run(&cc, mint.selector, storage, &mem),
        Err(Fault::DivByZero),
        "a mint with a non guardian member is refused"
    );
}

#[test]
fn a_transfer_moves_ledger_balance_between_accounts() {
    let cc = compiled();
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
fn a_call_to_an_unknown_selector_reverts() {
    let cc = compiled();
    let res = Interpreter::for_entry(&cc.container, selector("nonexistent()"), GAS);
    assert!(matches!(res, Err(Fault::UnknownSelector)));
}
