// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, GENESIS_SIGNATURE, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, signer_address, slot_key};

const SLOT_SUPPLY: u64 = 4;
const HI: u64 = 1 << 56;
const BAL_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SCHEME_ML: u8 = 1;
const SENTINEL: [u8; 8] = *b"QGENSNTL";

const TWO_TO_64: u128 = 1u128 << 64;

fn qasset() -> Contract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("examples/QAsset.qs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read example: {e}"));
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("the QAsset standard type checks clean");
    program.contracts.into_iter().next().expect("one contract")
}

fn compiled() -> CompiledContract {
    compile_contract(&qasset()).expect("the QAsset standard compiles")
}

fn find_entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn selector_of(cc: &CompiledContract, name: &str) -> [u8; 4] {
    find_entry(cc, name).selector
}

fn put_wide(mem: &mut [u8], entry: &EntryArtifact, key: &str, value: u128) {
    let slot = entry
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("wide argument");
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&(value as u64).to_be_bytes());
    mem[at + 8..at + 16].copy_from_slice(&((value >> 64) as u64).to_be_bytes());
}

fn put_addr(mem: &mut [u8], entry: &EntryArtifact, key: &str, address: &[u8; 32]) {
    let slot = entry
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("address argument");
    let at = slot.offset as usize;
    mem[at..at + 32].copy_from_slice(address);
}

fn run(
    cc: &CompiledContract,
    entry: [u8; SELECTOR_BYTES],
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    Interpreter::for_entry(&cc.container, entry, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn balance(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u128 {
    let lo = storage.get(&map_key(BAL_BASE, who)).copied().unwrap_or(0) as u128;
    let hi = storage
        .get(&map_addr_word_key(BAL_BASE, who, 1))
        .copied()
        .unwrap_or(0) as u128;
    (hi << 64) | lo
}

fn seed_balance(storage: &mut BTreeMap<[u8; 32], u64>, who: &[u8; 32], value: u128) {
    storage.insert(map_key(BAL_BASE, who), value as u64);
    storage.insert(map_addr_word_key(BAL_BASE, who, 1), (value >> 64) as u64);
}

fn supply(storage: &BTreeMap<[u8; 32], u64>) -> u128 {
    let lo = storage.get(&slot_key(SLOT_SUPPLY)).copied().unwrap_or(0) as u128;
    let hi = storage
        .get(&slot_key(SLOT_SUPPLY | HI))
        .copied()
        .unwrap_or(0) as u128;
    (hi << 64) | lo
}

fn owner_key() -> (ml_dsa::PublicKey, ml_dsa::SecretKey) {
    ml_dsa::keygen(&[7u8; 32])
}

fn holder_a() -> [u8; 32] {
    [0xA1; 32]
}
fn holder_b() -> [u8; 32] {
    [0xB2; 32]
}

fn deploy(
    cc: &CompiledContract,
    owner: &[u8; 32],
    initial_supply: u128,
) -> BTreeMap<[u8; 32], u64> {
    let mut mem = vec![0u8; 88 + 32 + 16 + 8];
    mem[88..120].copy_from_slice(owner);
    mem[120..128].copy_from_slice(&(initial_supply as u64).to_be_bytes());
    mem[128..136].copy_from_slice(&((initial_supply >> 64) as u64).to_be_bytes());
    mem[136..144].copy_from_slice(&SENTINEL);
    run(cc, selector(GENESIS_SIGNATURE), BTreeMap::new(), &mem)
        .expect("genesis initializes from the deploy parameters")
        .0
}

fn transfer_memory(
    cc: &CompiledContract,
    caller: &[u8; 32],
    to: &[u8; 32],
    amount: u128,
) -> Vec<u8> {
    let transfer = find_entry(cc, "transfer");
    let mut mem = vec![0u8; 65536];
    mem[0..32].copy_from_slice(caller);
    mem[32..64].copy_from_slice(&CONTRACT);
    put_addr(&mut mem, transfer, "to", to);
    put_wide(&mut mem, transfer, "amount", amount);
    mem
}

fn mint_message(
    cc: &CompiledContract,
    owner: &[u8; 32],
    nonce: u64,
    amount: u128,
    to: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector_of(cc, "mint")) as u64).to_be_bytes());
    msg.extend_from_slice(owner);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&(amount as u64).to_be_bytes());
    msg.extend_from_slice(&((amount >> 64) as u64).to_be_bytes());
    msg.extend_from_slice(to);
    msg
}

fn mint_memory(
    cc: &CompiledContract,
    key: &(ml_dsa::PublicKey, ml_dsa::SecretKey),
    nonce: u64,
    amount: u128,
    to: &[u8; 32],
) -> Vec<u8> {
    let mint = find_entry(cc, "mint");
    let signer = signer_address(SCHEME_ML, &key.0);
    let msg = mint_message(cc, &signer, nonce, amount, to);
    let sig = ml_dsa::sign(&key.1, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&key.0);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    put_addr(&mut mem, mint, "order.to", to);
    put_wide(&mut mem, mint, "order.amount", amount);
    let region_off = 8192usize;
    mem[region_off..region_off + region.len()].copy_from_slice(&region);
    let scheme = mint
        .args
        .iter()
        .find(|s| s.key == "order#scheme")
        .expect("scheme")
        .offset as usize;
    mem[scheme..scheme + 8].copy_from_slice(&(SCHEME_ML as u64).to_be_bytes());
    let ptr = mint
        .args
        .iter()
        .find(|s| s.key == "order#ptr")
        .expect("ptr")
        .offset as usize;
    mem[ptr..ptr + 8].copy_from_slice(&(region_off as u64).to_be_bytes());
    mem
}

fn transferred_amount(effects: &[Effect]) -> u128 {
    let data = effects
        .iter()
        .find_map(|e| match e {
            Effect::Event { selector: s, data }
                if *s == selector("Transferred(Q_Address,Q_Address,u128)") =>
            {
                Some(data)
            }
            _ => None,
        })
        .expect("a Transferred event is recorded");
    assert_eq!(
        data.len(),
        32 + 32 + 16,
        "the event carries two addresses and a two word amount"
    );
    let lo = u64::from_be_bytes(data[64..72].try_into().unwrap()) as u128;
    let hi = u64::from_be_bytes(data[72..80].try_into().unwrap()) as u128;
    (hi << 64) | lo
}

#[test]
fn a_transfer_above_the_word_boundary_moves_the_whole_two_word_amount() {
    let cc = compiled();
    let amount = TWO_TO_64 + 5;

    let mut storage = deploy(&cc, &[0u8; 32], 0);
    seed_balance(&mut storage, &holder_a(), amount);

    let mem = transfer_memory(&cc, &holder_a(), &holder_b(), amount);
    let (after, effects) =
        run(&cc, selector_of(&cc, "transfer"), storage, &mem).expect("the wide transfer halts");

    assert_eq!(
        balance(&after, &holder_b()),
        amount,
        "the recipient receives the whole two word amount, not the low word"
    );
    assert_eq!(
        balance(&after, &holder_a()),
        0,
        "the sender is fully debited"
    );
    assert_eq!(
        transferred_amount(&effects),
        amount,
        "the event carries the whole sixteen byte amount"
    );
}

#[test]
fn a_transfer_of_exactly_two_to_the_sixty_fourth_passes_the_guard_and_moves_in_full() {
    let cc = compiled();
    let amount = TWO_TO_64;

    let mut storage = deploy(&cc, &[0u8; 32], 0);
    seed_balance(&mut storage, &holder_a(), amount);

    let mem = transfer_memory(&cc, &holder_a(), &holder_b(), amount);
    let (after, effects) = run(&cc, selector_of(&cc, "transfer"), storage, &mem)
        .expect("the amount greater than zero guard admits a value whose low word is zero");

    assert_eq!(
        balance(&after, &holder_b()),
        amount,
        "the recipient receives exactly two to the sixty fourth"
    );
    assert_eq!(
        balance(&after, &holder_a()),
        0,
        "the sender is fully debited"
    );
    assert_eq!(
        transferred_amount(&effects),
        amount,
        "the event carries the two word amount in full"
    );
}

#[test]
fn a_mint_of_a_wide_order_amount_keeps_supply_equal_to_the_credited_balances() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, 0);

    let first = TWO_TO_64 + 100;
    let second = TWO_TO_64 + 200;

    let (storage, _) = run(
        &cc,
        selector_of(&cc, "mint"),
        storage,
        &mint_memory(&cc, &key, 0, first, &holder_a()),
    )
    .expect("the first wide mint halts");
    let (storage, _) = run(
        &cc,
        selector_of(&cc, "mint"),
        storage,
        &mint_memory(&cc, &key, 1, second, &holder_b()),
    )
    .expect("the second wide mint halts");

    assert_eq!(
        balance(&storage, &holder_a()),
        first,
        "holder a holds the whole first wide amount"
    );
    assert_eq!(
        balance(&storage, &holder_b()),
        second,
        "holder b holds the whole second wide amount"
    );
    let credited = balance(&storage, &holder_a()) + balance(&storage, &holder_b());
    assert_eq!(
        supply(&storage),
        credited,
        "the two word supply equals the sum of the two word balances"
    );
    assert_eq!(
        supply(&storage),
        first + second,
        "the supply is the sum of the wide mints"
    );
}

#[test]
fn a_wide_overflow_in_a_u128_field_reverts_rather_than_wrapping() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, u128::MAX);

    let mem = mint_memory(&cc, &key, 0, 1, &holder_a());
    assert_eq!(
        run(&cc, selector_of(&cc, "mint"), storage, &mem).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a mint that overflows the two word supply reverts"
    );
}
