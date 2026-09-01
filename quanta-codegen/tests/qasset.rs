// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::type_complexity)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, GENESIS_SIGNATURE, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_key, signer_address, slot_key};

const SLOT_SUPPLY: u64 = 4;
const BAL_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SCHEME_ML: u8 = 1;
const SENTINEL: [u8; 8] = *b"QGENSNTL";

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

fn put_arg(mem: &mut [u8], entry: &EntryArtifact, key: &str, value: u64) {
    let slot = entry.args.iter().find(|s| s.key == key).expect("arg word");
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_addr(mem: &mut [u8], entry: &EntryArtifact, key: &str, address: &[u8; 32]) {
    let slot = entry
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("arg address");
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

fn deploy(cc: &CompiledContract, owner: &[u8; 32], supply: u64) -> BTreeMap<[u8; 32], u64> {
    let mut mem = vec![0u8; 120 + 32 + 16 + 8];
    mem[120..152].copy_from_slice(owner);
    mem[152..160].copy_from_slice(&supply.to_be_bytes());
    mem[160..168].copy_from_slice(&0u64.to_be_bytes());
    mem[168..176].copy_from_slice(&SENTINEL);
    let (storage, _) = run(cc, selector(GENESIS_SIGNATURE), BTreeMap::new(), &mem)
        .expect("genesis initializes from the deploy parameters");
    for i in 0..4u64 {
        let word = u64::from_be_bytes(
            owner[i as usize * 8..i as usize * 8 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            storage.get(&slot_key(i)),
            Some(&word),
            "owner word {i} at genesis"
        );
    }
    assert_eq!(
        storage.get(&slot_key(SLOT_SUPPLY)),
        Some(&supply),
        "supply at genesis"
    );
    storage
}

fn mint_message(
    cc: &CompiledContract,
    owner: &[u8; 32],
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector_of(cc, "mint")) as u64).to_be_bytes());
    msg.extend_from_slice(owner);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&0u64.to_be_bytes());
    msg.extend_from_slice(to);
    msg
}

fn mint_memory(
    cc: &CompiledContract,
    key: &(ml_dsa::PublicKey, ml_dsa::SecretKey),
    nonce: u64,
    amount: u64,
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
    put_arg(&mut mem, mint, "order.amount", amount);
    let region_off = 8192usize;
    mem[region_off..region_off + region.len()].copy_from_slice(&region);
    put_arg(&mut mem, mint, "order#scheme", SCHEME_ML as u64);
    put_arg(&mut mem, mint, "order#ptr", region_off as u64);
    mem
}

fn transfer_memory(
    cc: &CompiledContract,
    caller: &[u8; 32],
    to: &[u8; 32],
    amount: u64,
) -> Vec<u8> {
    let transfer = find_entry(cc, "transfer");
    let mut mem = vec![0u8; 65536];
    mem[0..32].copy_from_slice(caller);
    mem[32..64].copy_from_slice(&CONTRACT);
    put_addr(&mut mem, transfer, "to", to);
    put_arg(&mut mem, transfer, "amount", amount);
    mem
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

fn balance(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u64 {
    storage.get(&map_key(BAL_BASE, who)).copied().unwrap_or(0)
}

#[test]
fn the_whole_qasset_standard_compiles_to_a_container_with_a_genesis() {
    let cc = compiled();
    assert!(cc.entries.iter().any(|e| e.name == "mint"));
    assert!(cc.entries.iter().any(|e| e.name == "transfer"));
    assert!(cc
        .container
        .entry_offset(&selector(GENESIS_SIGNATURE))
        .is_some());
    assert_eq!(
        cc.deploy_params
            .iter()
            .map(|p| p.key.as_str())
            .collect::<Vec<_>>(),
        vec!["deploy_params.owner", "deploy_params.initial_supply"]
    );
}

#[test]
fn an_owner_signed_mint_raises_supply_and_credits_the_holder_and_emits() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, 0);
    let to = holder_a();

    let mem = mint_memory(&cc, &key, 0, 500, &to);
    let (after, effects) =
        run(&cc, selector_of(&cc, "mint"), storage, &mem).expect("the owner mint halts");

    assert_eq!(
        after.get(&slot_key(SLOT_SUPPLY)),
        Some(&500),
        "supply rises to the minted amount"
    );
    assert_eq!(balance(&after, &to), 500, "the holder balance is credited");
    assert_eq!(
        balance(&after, &to),
        *after.get(&slot_key(SLOT_SUPPLY)).unwrap()
    );

    let minted = effects
        .iter()
        .find_map(|e| match e {
            Effect::Event { selector: s, data } if *s == selector("Minted(Q_Address,u128)") => {
                Some(data)
            }
            _ => None,
        })
        .expect("a Minted event is recorded");
    assert_eq!(
        &minted[0..32],
        &to,
        "the Minted event carries the whole recipient address"
    );
    let amount = u64::from_be_bytes(minted[32..40].try_into().unwrap());
    assert_eq!(
        amount, 500,
        "the Minted event carries the amount after the full address"
    );
}

#[test]
fn a_transfer_moves_balance_between_two_holders_and_conserves_supply() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);

    let storage = deploy(&cc, &owner, 0);
    let (storage, _) = run(
        &cc,
        selector_of(&cc, "mint"),
        storage,
        &mint_memory(&cc, &key, 0, 500, &holder_a()),
    )
    .expect("mint halts");

    let mem = transfer_memory(&cc, &holder_a(), &holder_b(), 200);
    let (after, effects) =
        run(&cc, selector_of(&cc, "transfer"), storage, &mem).expect("the transfer halts");

    assert_eq!(
        balance(&after, &holder_a()),
        300,
        "the sender balance falls by the amount"
    );
    assert_eq!(
        balance(&after, &holder_b()),
        200,
        "the recipient balance rises by the amount"
    );
    let supply = *after.get(&slot_key(SLOT_SUPPLY)).unwrap();
    assert_eq!(
        balance(&after, &holder_a()) + balance(&after, &holder_b()),
        supply
    );

    let transferred = effects
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
        &transferred[0..32],
        &holder_a(),
        "the Transferred event carries the whole sender address"
    );
    assert_eq!(
        &transferred[32..64],
        &holder_b(),
        "the Transferred event carries the whole recipient address"
    );
    let amount = u64::from_be_bytes(transferred[64..72].try_into().unwrap());
    assert_eq!(
        amount, 200,
        "the Transferred event carries the amount after the two full addresses"
    );
}

#[test]
fn a_mint_signed_by_a_non_owner_is_refused_with_no_supply_change() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, 0);

    let stranger = ml_dsa::keygen(&[200u8; 32]);
    let mem = mint_memory(&cc, &stranger, 0, 500, &holder_a());
    assert_eq!(
        run(&cc, selector_of(&cc, "mint"), storage, &mem).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a mint by a non owner is refused"
    );
}

#[test]
fn a_replayed_mint_is_refused_once_the_owner_nonce_advances() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, 0);

    let order = mint_memory(&cc, &key, 0, 500, &holder_a());
    let (after, _) =
        run(&cc, selector_of(&cc, "mint"), storage, &order).expect("the first mint halts");
    assert_eq!(after.get(&slot_key(SLOT_SUPPLY)), Some(&500));

    assert_eq!(
        run(&cc, selector_of(&cc, "mint"), after, &order).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a replayed mint is refused"
    );
}

#[test]
fn a_transfer_of_more_than_the_balance_reverts() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner, 0);
    let (storage, _) = run(
        &cc,
        selector_of(&cc, "mint"),
        storage,
        &mint_memory(&cc, &key, 0, 100, &holder_a()),
    )
    .expect("mint halts");

    let mem = transfer_memory(&cc, &holder_a(), &holder_b(), 500);
    assert_eq!(
        run(&cc, selector_of(&cc, "transfer"), storage, &mem).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "an overdrawn transfer reverts"
    );
}

#[test]
fn a_signed_mint_is_bound_to_its_chain_and_does_not_replay_on_another() {
    let cc = compiled();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let to = holder_a();
    let chain_a: u64 = 3;
    let chain_b: u64 = 9;
    let mint = find_entry(&cc, "mint");
    let mint_sel = selector_of(&cc, "mint");

    let mut msg = mint_message(&cc, &owner, 0, 100, &to);
    let tag = (u64::from_be_bytes(*b"QTVSGN01") ^ chain_a).to_be_bytes();
    msg[0..8].copy_from_slice(&tag);
    let sig = ml_dsa::sign(&key.1, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&key.0);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mem_on = |chain: u64| {
        let mut mem = vec![0u8; 65536];
        mem[32..64].copy_from_slice(&CONTRACT);
        mem[72..80].copy_from_slice(&chain.to_be_bytes());
        put_addr(&mut mem, mint, "order.to", &to);
        put_arg(&mut mem, mint, "order.amount", 100);
        let region_off = 8192usize;
        mem[region_off..region_off + region.len()].copy_from_slice(&region);
        put_arg(&mut mem, mint, "order#scheme", SCHEME_ML as u64);
        put_arg(&mut mem, mint, "order#ptr", region_off as u64);
        mem
    };

    let on_a = run(&cc, mint_sel, deploy(&cc, &owner, 0), &mem_on(chain_a));
    assert!(
        on_a.is_ok(),
        "the order authorised for chain A mints on chain A"
    );

    let on_b = run(&cc, mint_sel, deploy(&cc, &owner, 0), &mem_on(chain_b));
    assert!(
        on_b.is_err(),
        "the same captured order does not verify on chain B, so a cross chain replay is refused"
    );
}
