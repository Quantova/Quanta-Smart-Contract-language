// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The regulated entity token, end to end through the register machine. The example carries the

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, GENESIS_SIGNATURE, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_key, nonce_key, signer_address, slot_key};

const SLOT_SUPPLY: u64 = 4; // owner spans slots 0..4, then total_supply low word at slot 4.
const HI: u64 = 1 << 56; // the code generator's high word offset for a two word field.
const BAL_BASE: u64 = 1 << 40; // the balances map, the first keyed field.
const FROZEN_BASE: u64 = (1 << 40) + (1 << 32); // the frozen registry, the second keyed field.
const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SCHEME_ML: u8 = 1;
const SENTINEL: [u8; 8] = *b"QGENSNTL";

type Key = (ml_dsa::PublicKey, ml_dsa::SecretKey);

fn token() -> CompiledContract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("examples/RegulatedToken.qs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read example: {e}"));
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("the regulated token type checks");
    compile_contract(&program.contracts[0]).expect("the regulated token compiles")
}

fn find_entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn selector_of(cc: &CompiledContract, name: &str) -> [u8; 4] {
    find_entry(cc, name).selector
}

fn put_arg(mem: &mut [u8], entry: &EntryArtifact, key: &str, value: u64) {
    let slot = entry.args.iter().find(|s| s.key == key).unwrap_or_else(|| panic!("word arg {key}"));
    let at = slot.offset as usize;
    mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_addr(mem: &mut [u8], entry: &EntryArtifact, key: &str, address: &[u8; 32]) {
    let slot = entry.args.iter().find(|s| s.key == key).unwrap_or_else(|| panic!("addr arg {key}"));
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

fn owner_key() -> Key {
    ml_dsa::keygen(&[7u8; 32])
}

fn holder(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn balance(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u64 {
    storage.get(&map_key(BAL_BASE, who)).copied().unwrap_or(0)
}

fn supply_lo(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(SLOT_SUPPLY)).copied().unwrap_or(0)
}

fn supply_hi(storage: &BTreeMap<[u8; 32], u64>) -> u64 {
    storage.get(&slot_key(SLOT_SUPPLY | HI)).copied().unwrap_or(0)
}

fn supply_u128(storage: &BTreeMap<[u8; 32], u64>) -> u128 {
    (supply_hi(storage) as u128) << 64 | supply_lo(storage) as u128
}

fn deploy(cc: &CompiledContract, owner: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let slot = cc
        .deploy_params
        .iter()
        .find(|p| p.key == "deploy_params.owner")
        .expect("the owner deploy parameter");
    let owner_off = slot.offset as usize;
    let sentinel_off = (slot.offset + slot.width) as usize;
    let mut mem = vec![0u8; sentinel_off + 8];
    mem[owner_off..owner_off + 32].copy_from_slice(owner);
    mem[sentinel_off..sentinel_off + 8].copy_from_slice(&SENTINEL);
    let (storage, _) = run(cc, selector(GENESIS_SIGNATURE), BTreeMap::new(), &mem)
        .expect("genesis initializes from the deploy parameters");
    storage
}

/// A committed order field: either a single machine word or a whole thirty two byte address. The order
enum Field<'a> {
    Wide(&'a str, u64),
    Addr(&'a str, &'a [u8; 32]),
}

/// Build the memory for an owner signed entry: the order fields at their argument slots, the context
fn signed_memory(
    cc: &CompiledContract,
    entry_name: &str,
    key: &Key,
    signer: &[u8; 32],
    nonce: u64,
    fields: &[Field],
) -> Vec<u8> {
    let entry = find_entry(cc, entry_name);
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector_of(cc, entry_name)) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    for f in fields {
        match f {
            Field::Wide(_, v) => {
                msg.extend_from_slice(&v.to_be_bytes());
                msg.extend_from_slice(&0u64.to_be_bytes());
            }
            Field::Addr(_, a) => msg.extend_from_slice(*a),
        }
    }
    let sig = ml_dsa::sign(&key.1, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(&key.0);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; 65536];
    mem[32..64].copy_from_slice(&CONTRACT);
    for f in fields {
        match f {
            Field::Wide(k, v) => put_arg(&mut mem, entry, k, *v),
            Field::Addr(k, a) => put_addr(&mut mem, entry, k, a),
        }
    }
    let region_off = 8192usize;
    mem[region_off..region_off + region.len()].copy_from_slice(&region);
    put_arg(&mut mem, entry, "order#scheme", SCHEME_ML as u64);
    put_arg(&mut mem, entry, "order#ptr", region_off as u64);
    mem
}

fn mint(
    cc: &CompiledContract,
    key: &Key,
    signer: &[u8; 32],
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    signed_memory(
        cc,
        "mint",
        key,
        signer,
        nonce,
        &[Field::Wide("order.amount", amount), Field::Addr("order.to", to)],
    )
}

fn burn(
    cc: &CompiledContract,
    key: &Key,
    signer: &[u8; 32],
    nonce: u64,
    holder: &[u8; 32],
    amount: u64,
) -> Vec<u8> {
    signed_memory(
        cc,
        "burn",
        key,
        signer,
        nonce,
        &[Field::Addr("order.holder", holder), Field::Wide("order.amount", amount)],
    )
}

fn freeze(cc: &CompiledContract, key: &Key, signer: &[u8; 32], nonce: u64, who: &[u8; 32]) -> Vec<u8> {
    signed_memory(cc, "freeze", key, signer, nonce, &[Field::Addr("order.who", who)])
}

fn unfreeze(cc: &CompiledContract, key: &Key, signer: &[u8; 32], nonce: u64, who: &[u8; 32]) -> Vec<u8> {
    signed_memory(cc, "unfreeze", key, signer, nonce, &[Field::Addr("order.who", who)])
}

fn transfer_memory(cc: &CompiledContract, caller: &[u8; 32], to: &[u8; 32], amount: u64) -> Vec<u8> {
    let entry = find_entry(cc, "transfer");
    let mut mem = vec![0u8; 65536];
    mem[0..32].copy_from_slice(caller);
    mem[32..64].copy_from_slice(&CONTRACT);
    put_addr(&mut mem, entry, "to", to);
    put_arg(&mut mem, entry, "amount", amount);
    mem
}

#[test]
fn the_token_carries_mint_transfer_burn_freeze_and_unfreeze() {
    let cc = token();
    for e in ["mint", "transfer", "burn", "freeze", "unfreeze"] {
        assert!(cc.entries.iter().any(|x| x.name == e), "the token carries {e}");
    }
    assert!(cc.container.entry_offset(&selector(GENESIS_SIGNATURE)).is_some());
}

#[test]
fn the_owner_mints_and_supply_and_the_holder_balance_rise_together() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner);
    let alice = holder(0xA1);

    let mem = mint(&cc, &key, &owner, 0, 500, &alice);
    let (after, effects) = run(&cc, selector_of(&cc, "mint"), storage, &mem).expect("the owner mint halts");

    assert_eq!(supply_u128(&after), 500, "supply rises to the minted amount");
    assert_eq!(balance(&after, &alice), 500, "the holder is credited");
    assert_eq!(after.get(&nonce_key(&owner)), Some(&1), "the owner nonce advanced");
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Event { selector: s, .. } if *s == selector("Minted(Q_Address,u128)"))),
        "a Minted event is recorded"
    );
}

#[test]
fn a_mint_signed_by_a_stranger_is_refused() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let storage = deploy(&cc, &owner);

    let stranger = ml_dsa::keygen(&[200u8; 32]);
    let stranger_addr = signer_address(SCHEME_ML, &stranger.0);
    let mem = mint(&cc, &stranger, &stranger_addr, 0, 500, &holder(0xA1));
    assert_eq!(
        run(&cc, selector_of(&cc, "mint"), storage, &mem).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a mint that is not the owner's signature is refused"
    );
}

#[test]
fn a_holder_transfers_and_supply_is_conserved() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);
    let bob = holder(0xB2);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, 500, &alice)).expect("mint");

    let (after, _) = run(&cc, selector_of(&cc, "transfer"), storage, &transfer_memory(&cc, &alice, &bob, 200)).expect("the transfer halts");
    assert_eq!(balance(&after, &alice), 300, "the sender balance falls");
    assert_eq!(balance(&after, &bob), 200, "the recipient balance rises");
    assert_eq!(supply_u128(&after), 500, "the transfer conserves supply");
}

#[test]
fn a_frozen_account_cannot_receive_and_unfreezing_restores_it() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);
    let bob = holder(0xB2);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, 500, &alice)).expect("mint");

    // The owner freezes bob (nonce one, after the mint at nonce zero).
    let (storage, _) = run(&cc, selector_of(&cc, "freeze"), storage, &freeze(&cc, &key, &owner, 1, &bob)).expect("freeze halts");
    assert_eq!(storage.get(&map_key(FROZEN_BASE, &bob)), Some(&1), "bob is frozen");

    // A transfer to the frozen recipient reverts and leaves balances untouched.
    let frozen_storage = storage.clone();
    assert_eq!(
        run(&cc, selector_of(&cc, "transfer"), frozen_storage, &transfer_memory(&cc, &alice, &bob, 200)).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a transfer to a frozen account reverts"
    );

    // Unfreezing bob (nonce two) restores the transfer.
    let (storage, _) = run(&cc, selector_of(&cc, "unfreeze"), storage, &unfreeze(&cc, &key, &owner, 2, &bob)).expect("unfreeze halts");
    let (after, _) = run(&cc, selector_of(&cc, "transfer"), storage, &transfer_memory(&cc, &alice, &bob, 200)).expect("the transfer halts after unfreeze");
    assert_eq!(balance(&after, &bob), 200, "the unfrozen recipient can be paid");
}

#[test]
fn a_frozen_account_cannot_send() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);
    let carol = holder(0xC3);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, 500, &alice)).expect("mint");
    let (storage, _) = run(&cc, selector_of(&cc, "freeze"), storage, &freeze(&cc, &key, &owner, 1, &alice)).expect("freeze halts");

    assert_eq!(
        run(&cc, selector_of(&cc, "transfer"), storage, &transfer_memory(&cc, &alice, &carol, 100)).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a frozen sender cannot transfer"
    );
}

#[test]
fn a_mint_to_a_frozen_account_is_denied() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let mallory = holder(0xDD);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "freeze"), storage, &freeze(&cc, &key, &owner, 0, &mallory)).expect("freeze halts");

    // The mint carries a denies clause over the frozen set, so minting to a frozen holder reverts.
    let mem = mint(&cc, &key, &owner, 1, 500, &mallory);
    assert_eq!(
        run(&cc, selector_of(&cc, "mint"), storage, &mem).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "a mint to a frozen account is denied"
    );
}

#[test]
fn a_burn_lowers_a_holder_balance_and_the_supply_together() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, 500, &alice)).expect("mint");

    let (after, effects) = run(&cc, selector_of(&cc, "burn"), storage, &burn(&cc, &key, &owner, 1, &alice, 200)).expect("the burn halts");
    assert_eq!(balance(&after, &alice), 300, "the burn debits the holder");
    assert_eq!(supply_u128(&after), 300, "the burn lowers supply by the same amount");
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Event { selector: s, .. } if *s == selector("Burned(Q_Address,u128)"))),
        "a Burned event is recorded"
    );
}

#[test]
fn a_burn_of_more_than_the_holder_holds_reverts() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);

    let storage = deploy(&cc, &owner);
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, 100, &alice)).expect("mint");
    assert_eq!(
        run(&cc, selector_of(&cc, "burn"), storage, &burn(&cc, &key, &owner, 1, &alice, 500)).map(|(s, _)| s),
        Err(Fault::DivByZero),
        "an over burn reverts on the checked debit"
    );
}

#[test]
fn supply_and_balances_stay_consistent_across_the_word_boundary_at_large_amounts() {
    let cc = token();
    let key = owner_key();
    let owner = signer_address(SCHEME_ML, &key.0);
    let alice = holder(0xA1);
    let bob = holder(0xB2);

    let storage = deploy(&cc, &owner);

    // Mint the largest one word amount to alice, then again to bob. The two word supply crosses the
    // machine word boundary while each one word balance stays under it.
    let big = u64::MAX;
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 0, big, &alice)).expect("first large mint");
    assert_eq!(supply_u128(&storage), big as u128, "supply holds the first large mint");
    let (storage, _) = run(&cc, selector_of(&cc, "mint"), storage, &mint(&cc, &key, &owner, 1, big, &bob)).expect("second large mint");

    // The supply now needs its high word.
    assert_eq!(supply_hi(&storage), 1, "supply carried into the high word");
    assert_eq!(balance(&storage, &alice), big, "alice holds a full word");
    assert_eq!(balance(&storage, &bob), big, "bob holds a full word");

    // The invariant the token maintains: the two word supply equals the sum of the one word balances.
    let sum = balance(&storage, &alice) as u128 + balance(&storage, &bob) as u128;
    assert_eq!(supply_u128(&storage), sum, "the two word supply equals the sum of the one word balances");
    assert_eq!(supply_u128(&storage), (big as u128) * 2, "supply is twice the largest word");
}
