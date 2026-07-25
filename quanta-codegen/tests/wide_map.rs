// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A `Map<Q_Address, Q_Address>` driven through the register machine: a set stores the whole thirty

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::read_addr_value;

const OWNER_OF_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;

const SRC: &str = "contract W { \
    state { owner_of: Map<Q_Address, Q_Address>; } \
    entry claim(name: Q_Address) writes(owner_of) { \
        owner_of.set(name, caller); \
        emit Claimed(name, caller); \
    } \
    entry rebind(name: Q_Address, to: Q_Address) reads(owner_of) writes(owner_of) { \
        guard owner_of.get(name) == caller; \
        owner_of.set(name, to); \
        emit Rebound(name, caller, to); \
    } \
    entry attest(name: Q_Address) reads(owner_of) { \
        guard owner_of.contains(name); \
    } \
    event Claimed(name: Q_Address, owner: Q_Address); \
    event Rebound(name: Q_Address, prior: Q_Address, to: Q_Address); \
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
    entry(cc, name).args.iter().find(|s| s.key == key).expect("arg").offset as usize
}

fn memory(cc: &CompiledContract, name: &str, caller: &[u8; 32], addrs: &[(&str, [u8; 32])]) -> Vec<u8> {
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    for (key, value) in addrs {
        let at = arg_off(cc, name, key);
        mem[at..at + 32].copy_from_slice(value);
    }
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

fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[test]
fn a_set_stores_the_whole_address_value_and_the_event_carries_it_in_full() {
    let cc = compiled();
    let caller = addr(0xA1);
    let name = addr(0x11);

    let mem = memory(&cc, "claim", &caller, &[("name", name)]);
    let (storage, effects) = run(&cc.container, entry(&cc, "claim").selector, BTreeMap::new(), &mem)
        .expect("claim halts");

    // All four words of the stored value reassemble to the whole caller address.
    assert_eq!(read_addr_value(&storage, OWNER_OF_BASE, &name), caller, "owner_of[name] is the full caller");

    // The Claimed event carries the name then the owner, each its whole thirty two bytes.
    let data = event(&effects, claimed_selector(&cc)).expect("a Claimed event");
    assert_eq!(&data[0..32], &name, "the event carries the whole name");
    assert_eq!(&data[32..64], &caller, "the event carries the whole owner");
    assert_eq!(data.len(), 64, "two full addresses, no truncation");
}

fn claimed_selector(cc: &CompiledContract) -> [u8; 4] {
    cc.events.iter().find(|e| e.name == "Claimed").expect("Claimed").selector
}

fn rebound_selector(cc: &CompiledContract) -> [u8; 4] {
    cc.events.iter().find(|e| e.name == "Rebound").expect("Rebound").selector
}

#[test]
fn a_get_equality_that_matches_the_whole_owner_rebinds() {
    let cc = compiled();
    let a = addr(0xA1);
    let b = addr(0xB2);
    let name = addr(0x11);

    let (storage, _) = run(
        &cc.container,
        entry(&cc, "claim").selector,
        BTreeMap::new(),
        &memory(&cc, "claim", &a, &[("name", name)]),
    )
    .expect("claim halts");

    let mem = memory(&cc, "rebind", &a, &[("name", name), ("to", b)]);
    let (after, effects) = run(&cc.container, entry(&cc, "rebind").selector, storage, &mem)
        .expect("the owner rebind halts");
    assert_eq!(read_addr_value(&after, OWNER_OF_BASE, &name), b, "ownership moved to b in full");
    let data = event(&effects, rebound_selector(&cc)).expect("a Rebound event");
    assert_eq!(&data[0..32], &name);
    assert_eq!(&data[32..64], &a, "the prior owner");
    assert_eq!(&data[64..96], &b, "the new owner");
}

#[test]
fn contains_on_an_address_valued_map_tracks_presence() {
    let cc = compiled();
    let a = addr(0xA1);
    let name = addr(0x11);
    let other = addr(0x22);

    let (storage, _) = run(
        &cc.container,
        entry(&cc, "claim").selector,
        BTreeMap::new(),
        &memory(&cc, "claim", &a, &[("name", name)]),
    )
    .expect("claim halts");

    // A set name is present, so the guard passes and the entry halts clean.
    run(
        &cc.container,
        entry(&cc, "attest").selector,
        storage.clone(),
        &memory(&cc, "attest", &a, &[("name", name)]),
    )
    .expect("attest of a present name halts");

    // An unset name is absent, so the guard reverts.
    let result = run(
        &cc.container,
        entry(&cc, "attest").selector,
        storage,
        &memory(&cc, "attest", &a, &[("name", other)]),
    );
    assert!(matches!(result, Err(Fault::DivByZero)), "attest of an absent name reverts");
}

#[test]
fn a_get_equality_binds_all_thirty_two_bytes_not_a_leading_word() {
    let cc = compiled();
    let a = addr(0xA1);
    let name = addr(0x11);

    let (storage, _) = run(
        &cc.container,
        entry(&cc, "claim").selector,
        BTreeMap::new(),
        &memory(&cc, "claim", &a, &[("name", name)]),
    )
    .expect("claim halts");

    // An impostor whose leading eight bytes equal the owner's but whose tail differs. A truncated single
    // word compare would accept it; the full thirty two byte compare must reject it.
    let mut impostor = a;
    impostor[8] ^= 0xFF;
    let mem = memory(&cc, "rebind", &impostor, &[("name", name), ("to", impostor)]);
    let result = run(&cc.container, entry(&cc, "rebind").selector, storage.clone(), &mem);
    assert!(matches!(result, Err(Fault::DivByZero)), "the prefix collision impostor is reverted");

    // A wholly different caller is likewise refused.
    let stranger = addr(0xCC);
    let mem = memory(&cc, "rebind", &stranger, &[("name", name), ("to", stranger)]);
    let result = run(&cc.container, entry(&cc, "rebind").selector, storage, &mem);
    assert!(matches!(result, Err(Fault::DivByZero)), "a stranger is reverted");
}
