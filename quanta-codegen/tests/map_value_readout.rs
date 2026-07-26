// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Reading a full thirty two byte address back out of a keyed map value and reusing it. An emitted

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{addr, map_key, read_addr_value};

const OWNER_BASE: u64 = 1 << 40;
const MIRROR_BASE: u64 = (1 << 40) + (1 << 32);
const TICK_BASE: u64 = (1 << 40) + 2 * (1 << 32);
const GAS: u64 = 8_000_000;

const SRC: &str = "contract Resolver { \
    state { \
        owner_of: Map<Q_Address, Q_Address>; \
        mirror_of: Map<Q_Address, Q_Address>; \
        tick_of: Map<Q_Address, u64>; \
    } \
    entry claim(name: Q_Address) writes(owner_of) { \
        owner_of.set(name, caller); \
    } \
    entry resolve(name: Q_Address) reads(owner_of) { \
        emit Resolved(name, owner_of.get(name)); \
    } \
    entry mirror(name: Q_Address) reads(owner_of) writes(mirror_of) { \
        mirror_of.set(name, owner_of.get(name)); \
    } \
    entry tick(name: Q_Address, v: u64) writes(tick_of) { \
        tick_of.set(name, v); \
    } \
    event Resolved(name: Q_Address, owner: Q_Address); \
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

fn addr_memory(cc: &CompiledContract, name: &str, caller: &[u8; 32], addrs: &[(&str, [u8; 32])]) -> Vec<u8> {
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

fn resolved_selector(cc: &CompiledContract) -> [u8; 4] {
    cc.events.iter().find(|e| e.name == "Resolved").expect("Resolved").selector
}

fn claim(cc: &CompiledContract, owner: &[u8; 32], name: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mem = addr_memory(cc, "claim", owner, &[("name", *name)]);
    run(&cc.container, entry(cc, "claim").selector, BTreeMap::new(), &mem)
        .expect("claim halts")
        .0
}

#[test]
fn an_emitted_field_carries_the_stored_owner_read_out_of_the_map_not_the_caller() {
    let cc = compiled();
    let owner = addr(0xA1);
    let name = addr(0x11);
    let stored = claim(&cc, &owner, &name);

    // A stranger resolves the name. The event owner field must be the stored owner read out of the
    // map, never the resolving caller.
    let stranger = addr(0xCC);
    let mem = addr_memory(&cc, "resolve", &stranger, &[("name", name)]);
    let (_, effects) = run(&cc.container, entry(&cc, "resolve").selector, stored, &mem)
        .expect("resolve halts");

    let data = event(&effects, resolved_selector(&cc)).expect("a Resolved event");
    assert_eq!(data.len(), 64, "two full addresses, no truncation");
    assert_eq!(&data[0..32], &name, "the event carries the whole name");
    assert_eq!(&data[32..64], &owner, "the event carries the whole stored owner, read from the map");
    assert_ne!(&data[32..64], &stranger[..], "the resolving caller never leaks into the owner field");
}

#[test]
fn a_stored_owner_reads_out_and_stores_into_a_second_map_byte_identical() {
    let cc = compiled();
    let owner = addr(0xA1);
    let name = addr(0x11);
    let stored = claim(&cc, &owner, &name);

    let mem = addr_memory(&cc, "mirror", &addr(0xCC), &[("name", name)]);
    let (after, _) = run(&cc.container, entry(&cc, "mirror").selector, stored, &mem)
        .expect("mirror halts");

    // The mirror map holds the whole thirty two byte owner across its own four hashed word slots.
    assert_eq!(
        read_addr_value(&after, MIRROR_BASE, &name),
        owner,
        "the mirror map value reassembles to the whole owner"
    );
    // The source map is unchanged by the read.
    assert_eq!(read_addr_value(&after, OWNER_BASE, &name), owner, "the source owner is intact");
}

#[test]
fn a_read_out_of_an_absent_name_yields_the_zero_address() {
    let cc = compiled();
    let name = addr(0x11);

    // No claim ran, so every word slot is absent and reads as zero.
    let mem = addr_memory(&cc, "mirror", &addr(0xCC), &[("name", name)]);
    let (after, _) = run(&cc.container, entry(&cc, "mirror").selector, BTreeMap::new(), &mem)
        .expect("mirror halts");
    assert_eq!(read_addr_value(&after, MIRROR_BASE, &name), [0u8; 32], "an absent owner reads as zero");
}

#[test]
fn a_single_word_map_value_keeps_its_one_slot_layout() {
    let cc = compiled();
    let name = addr(0x11);
    let v: u64 = 0xDEAD_BEEF;

    let mut mem = vec![0u8; 4096];
    let at = arg_off(&cc, "tick", "name");
    mem[at..at + 32].copy_from_slice(&name);
    let vat = arg_off(&cc, "tick", "v");
    mem[vat..vat + 8].copy_from_slice(&v.to_be_bytes());

    let (storage, _) = run(&cc.container, entry(&cc, "tick").selector, BTreeMap::new(), &mem)
        .expect("tick halts");

    // A one word value lands in the single hashed map slot, not the four word address layout.
    assert_eq!(storage.len(), 1, "a scalar map value writes exactly one slot");
    assert_eq!(storage.get(&map_key(TICK_BASE, &name)).copied(), Some(v), "the one word is at the plain map key");
}
