// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::needless_lifetimes)]
#![allow(clippy::type_complexity)]

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, read_addr_value, slot_key};

const SUPPLY_SLOT: u64 = 0;
const OWNER_OF_BASE: u64 = 1 << 40;
const HOLDINGS_BASE: u64 = (1 << 40) + (1 << 32);
const CONTENT_BASE: u64 = (1 << 40) + (2 << 32);
const GAS: u64 = 8_000_000;

const SRC: &str = "contract C { \
    state { \
        supply: u64; \
        owner_of: Map<Q_Id, Q_Address>; \
        holdings: Map<Q_Address, u64>; \
        content_of: Map<Q_Id, Q_Address>; \
        admin: Q_Address; \
    } \
    genesis { admin = deployer; } \
    entry mint(id: Q_Id, to: Q_Address, content: Q_Address) \
        reads(admin, owner_of) writes(owner_of, content_of, supply, holdings) { \
        guard caller == admin; \
        guard !owner_of.contains(id); \
        owner_of.set(id, to); \
        content_of.set(id, content); \
        supply = checked(supply + 1); \
        holdings.credit(to, 1); \
        emit Minted(id, to, content); \
    } \
    entry move_to(id: Q_Id, to: Q_Address) reads(owner_of) writes(owner_of, holdings) { \
        guard owner_of.get(id) == caller; \
        owner_of.set(id, to); \
        holdings.debit(caller, 1); \
        holdings.credit(to, 1); \
        emit Moved(id, caller, to); \
    } \
    event Minted(id: Q_Id, to: Q_Address, content: Q_Address); \
    event Moved(id: Q_Id, prior: Q_Address, to: Q_Address); \
}";

fn compiled() -> CompiledContract {
    let program = quanta_parser::parse(SRC).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn arg_off(cc: &CompiledContract, name: &str, key: &str) -> usize {
    entry(cc, name)
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("arg")
        .offset as usize
}

fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn id_key(id: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&id.to_be_bytes());
    k
}

fn put_owner(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, id: u64, owner: &[u8; 32]) {
    let key = id_key(id);
    for i in 0..4u64 {
        let w = u64::from_be_bytes(
            owner[i as usize * 8..i as usize * 8 + 8]
                .try_into()
                .unwrap(),
        );
        storage.insert(map_addr_word_key(base, &key, i), w);
    }
}

fn holding(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u64 {
    storage
        .get(&map_key(HOLDINGS_BASE, who))
        .copied()
        .unwrap_or(0)
}

fn mem_mint(
    cc: &CompiledContract,
    _caller: &[u8; 32],
    id: u64,
    to: &[u8; 32],
    content: &[u8; 32],
) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    let ido = arg_off(cc, "mint", "id");
    mem[ido..ido + 8].copy_from_slice(&id.to_be_bytes());
    let too = arg_off(cc, "mint", "to");
    mem[too..too + 32].copy_from_slice(to);
    let co = arg_off(cc, "mint", "content");
    mem[co..co + 32].copy_from_slice(content);
    mem
}

fn mem_move(cc: &CompiledContract, caller: &[u8; 32], id: u64, to: &[u8; 32]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let ido = arg_off(cc, "move_to", "id");
    mem[ido..ido + 8].copy_from_slice(&id.to_be_bytes());
    let too = arg_off(cc, "move_to", "to");
    mem[too..too + 32].copy_from_slice(to);
    mem
}

fn run(
    container: &Container,
    selector: [u8; SELECTOR_BYTES],
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    Interpreter::for_entry(container, selector, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn event<'a>(effects: &'a [Effect], selector: [u8; 4]) -> Option<&'a Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::Event { selector: s, data } if *s == selector => Some(data),
        _ => None,
    })
}

fn selector_of(cc: &CompiledContract, name: &str) -> [u8; 4] {
    cc.events
        .iter()
        .find(|e| e.name == name)
        .expect("event")
        .selector
}

#[test]
fn mint_sets_the_full_owner_and_bumps_the_supply_and_holding_counts() {
    let cc = compiled();
    let a = addr(0xA1);
    let content = addr(0xC0);
    let id = 7u64;

    let mem = mem_mint(&cc, &a, id, &a, &content);
    let (storage, effects) = run(
        &cc.container,
        entry(&cc, "mint").selector,
        BTreeMap::new(),
        &mem,
    )
    .expect("mint halts");

    assert_eq!(
        read_addr_value(&storage, OWNER_OF_BASE, &id_key(id)),
        a,
        "owner_of[id] is the full recipient"
    );
    assert_eq!(
        read_addr_value(&storage, CONTENT_BASE, &id_key(id)),
        content,
        "content_of[id] is the full content"
    );
    assert_eq!(
        storage.get(&slot_key(SUPPLY_SLOT)).copied().unwrap_or(0),
        1,
        "supply is one"
    );
    assert_eq!(holding(&storage, &a), 1, "the recipient holds one");

    let data = event(&effects, selector_of(&cc, "Minted")).expect("a Minted event");
    assert_eq!(
        &data[0..8],
        &id.to_be_bytes(),
        "the event leads with the token id word"
    );
    assert_eq!(&data[8..40], &a, "the event carries the whole recipient");
    assert_eq!(
        &data[40..72],
        &content,
        "the event carries the whole content"
    );
}

#[test]
fn a_minted_id_cannot_be_minted_again() {
    let cc = compiled();
    let a = addr(0xA1);
    let content = addr(0xC0);
    let id = 7u64;

    let (storage, _) = run(
        &cc.container,
        entry(&cc, "mint").selector,
        BTreeMap::new(),
        &mem_mint(&cc, &a, id, &a, &content),
    )
    .expect("mint halts");

    let again = run(
        &cc.container,
        entry(&cc, "mint").selector,
        storage,
        &mem_mint(&cc, &a, id, &a, &content),
    );
    assert!(
        matches!(again, Err(Fault::DivByZero)),
        "a second mint of a live id reverts"
    );
}

#[test]
fn move_moves_the_whole_owner_and_adjusts_the_holding_counts() {
    let cc = compiled();
    let a = addr(0xA1);
    let b = addr(0xB2);
    let id = 7u64;

    let mut storage = BTreeMap::new();
    put_owner(&mut storage, OWNER_OF_BASE, id, &a);
    storage.insert(map_key(HOLDINGS_BASE, &a), 1);

    let (after, effects) = run(
        &cc.container,
        entry(&cc, "move_to").selector,
        storage,
        &mem_move(&cc, &a, id, &b),
    )
    .expect("the owner move halts");

    assert_eq!(
        read_addr_value(&after, OWNER_OF_BASE, &id_key(id)),
        b,
        "ownership moved to b in full"
    );
    assert_eq!(
        holding(&after, &a),
        0,
        "the prior owner's holding fell to zero"
    );
    assert_eq!(
        holding(&after, &b),
        1,
        "the new owner's holding rose to one"
    );

    let data = event(&effects, selector_of(&cc, "Moved")).expect("a Moved event");
    assert_eq!(&data[0..8], &id.to_be_bytes());
    assert_eq!(&data[8..40], &a, "the prior owner");
    assert_eq!(&data[40..72], &b, "the new owner");
}

#[test]
fn a_move_binds_all_thirty_two_bytes_of_the_caller_not_a_leading_word() {
    let cc = compiled();
    let a = addr(0xA1);
    let id = 7u64;

    let mut storage = BTreeMap::new();
    put_owner(&mut storage, OWNER_OF_BASE, id, &a);
    storage.insert(map_key(HOLDINGS_BASE, &a), 1);

    let mut impostor = a;
    impostor[8] ^= 0xFF;
    let refused = run(
        &cc.container,
        entry(&cc, "move_to").selector,
        storage.clone(),
        &mem_move(&cc, &impostor, id, &impostor),
    );
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "the prefix collision impostor is refused"
    );

    let stranger = addr(0xCC);
    let refused = run(
        &cc.container,
        entry(&cc, "move_to").selector,
        storage,
        &mem_move(&cc, &stranger, id, &stranger),
    );
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a stranger is refused"
    );
}

#[test]
fn a_token_id_keyed_owner_is_independent_across_ids() {
    let cc = compiled();
    let a = addr(0xA1);
    let b = addr(0xB2);

    let (mut storage, _) = run(
        &cc.container,
        entry(&cc, "mint").selector,
        BTreeMap::new(),
        &mem_mint(&cc, &a, 1, &a, &addr(0xC1)),
    )
    .expect("mint one halts");
    let (storage2, _) = run(
        &cc.container,
        entry(&cc, "mint").selector,
        storage.clone(),
        &mem_mint(&cc, &b, 2, &b, &addr(0xC2)),
    )
    .expect("mint two halts");
    storage = storage2;

    assert_eq!(
        read_addr_value(&storage, OWNER_OF_BASE, &id_key(1)),
        a,
        "id one is owned by a"
    );
    assert_eq!(
        read_addr_value(&storage, OWNER_OF_BASE, &id_key(2)),
        b,
        "id two is owned by b"
    );
    assert_ne!(
        map_addr_word_key(OWNER_OF_BASE, &id_key(1), 0),
        map_addr_word_key(OWNER_OF_BASE, &id_key(2), 0),
        "distinct ids land on distinct slots"
    );

    let (after, _) = run(
        &cc.container,
        entry(&cc, "move_to").selector,
        storage,
        &mem_move(&cc, &a, 1, &b),
    )
    .expect("move id one halts");
    assert_eq!(
        read_addr_value(&after, OWNER_OF_BASE, &id_key(1)),
        b,
        "id one moved to b"
    );
    assert_eq!(
        read_addr_value(&after, OWNER_OF_BASE, &id_key(2)),
        b,
        "id two is untouched by the move of id one"
    );
}

#[test]
fn the_shipped_qcollectible_contract_compiles_with_its_signed_mint_and_guarded_transfer() {
    let src = include_str!("../../examples/QCollectible.qs");
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    assert_eq!(cc.name, "QCollectible");
    assert!(entry(&cc, "mint").signature.starts_with("mint("));
    assert_eq!(entry(&cc, "transfer").signature, "transfer(Q_Id,Q_Address)");
    assert!(cc.events.iter().any(|e| e.name == "Minted"));
    assert!(cc.events.iter().any(|e| e.name == "Transferred"));
}
