// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::sha3::sha3_256;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, read_addr_value};

const SRC: &str = include_str!("../../examples/QNS.qs");

const EXPIRY_BASE: u64 = 1 << 40;
const OWNER_BASE: u64 = (1 << 40) + (1 << 32);
const RESOLVED_BASE: u64 = (1 << 40) + (2 << 32);

const DAY: u64 = 86_400;
const GAS: u64 = 12_000_000;

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

fn window(label: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = label.len().min(32);
    w[..n].copy_from_slice(&label[..n]);
    w
}

fn name_key(label: &[u8]) -> [u8; 32] {
    sha3_256(label)
}

fn put_map_addr(
    storage: &mut BTreeMap<[u8; 32], u64>,
    base: u64,
    key: &[u8; 32],
    value: &[u8; 32],
) {
    for i in 0..4u64 {
        let w = u64::from_be_bytes(
            value[i as usize * 8..i as usize * 8 + 8]
                .try_into()
                .unwrap(),
        );
        storage.insert(map_addr_word_key(base, key, i), w);
    }
}

fn seed_owner(label: &[u8], owner: &[u8; 32], expiry: u64) -> BTreeMap<[u8; 32], u64> {
    let mut s = BTreeMap::new();
    put_map_addr(&mut s, OWNER_BASE, &name_key(label), owner);
    s.insert(map_key(EXPIRY_BASE, &name_key(label)), expiry);
    s
}

fn run_transfer(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    label: &[u8],
    to: &[u8; 32],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "transfer").selector;
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let no = arg_off(cc, "transfer", "label");
    mem[no..no + 32].copy_from_slice(&window(label));
    let lo = arg_off(cc, "transfer", "label#len");
    mem[lo..lo + 8].copy_from_slice(&(label.len() as u64).to_be_bytes());
    let to_off = arg_off(cc, "transfer", "to");
    mem[to_off..to_off + 32].copy_from_slice(to);
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn run_set_resolved(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    time: u64,
    label: &[u8],
    target: &[u8; 32],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "set_resolved").selector;
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let t = arg_off(cc, "set_resolved", "@time");
    mem[t..t + 8].copy_from_slice(&time.to_be_bytes());
    let no = arg_off(cc, "set_resolved", "label");
    mem[no..no + 32].copy_from_slice(&window(label));
    let lo = arg_off(cc, "set_resolved", "label#len");
    mem[lo..lo + 8].copy_from_slice(&(label.len() as u64).to_be_bytes());
    let tg = arg_off(cc, "set_resolved", "target");
    mem[tg..tg + 32].copy_from_slice(target);
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

fn run_set_primary(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    time: u64,
    label: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    let sel: [u8; SELECTOR_BYTES] = entry(cc, "set_primary").selector;
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(caller);
    let t = arg_off(cc, "set_primary", "@time");
    mem[t..t + 8].copy_from_slice(&time.to_be_bytes());
    let no = arg_off(cc, "set_primary", "label");
    mem[no..no + 32].copy_from_slice(&window(label));
    let lo = arg_off(cc, "set_primary", "label#len");
    mem[lo..lo + 8].copy_from_slice(&(label.len() as u64).to_be_bytes());
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(&mem)
        .run()
        .map(|out| out.storage)
}

#[test]
fn transfer_by_the_owner_moves_the_whole_name() {
    let cc = compiled();
    let owner = addr(0xA1);
    let to = addr(0xB2);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let after = run_transfer(&cc, storage, &owner, b"alice", &to).expect("owner transfer halts");
    assert_eq!(
        read_addr_value(&after, OWNER_BASE, &name_key(b"alice")),
        to,
        "ownership moved to the recipient in full"
    );
}

#[test]
fn transfer_by_a_non_owner_reverts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let stranger = addr(0xCC);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let refused = run_transfer(&cc, storage, &stranger, b"alice", &stranger);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a stranger cannot transfer a name it does not own"
    );
}

#[test]
fn transfer_refuses_a_prefix_collision_impostor() {
    let cc = compiled();
    let owner = addr(0xA1);
    let mut impostor = owner;
    impostor[8] ^= 0xFF;
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let refused = run_transfer(&cc, storage, &impostor, b"alice", &impostor);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "an owner check that compares all thirty two bytes rejects a leading word collision"
    );
}

#[test]
fn set_resolved_by_the_owner_points_resolution() {
    let cc = compiled();
    let owner = addr(0xA1);
    let target = addr(0x77);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let after = run_set_resolved(&cc, storage, &owner, 10 * DAY, b"alice", &target)
        .expect("owner set_resolved halts");
    assert_eq!(
        read_addr_value(&after, RESOLVED_BASE, &name_key(b"alice")),
        target,
        "the owner points resolution at the target in full"
    );
}

#[test]
fn set_resolved_by_a_non_owner_reverts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let stranger = addr(0xCC);
    let target = addr(0x77);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let refused = run_set_resolved(&cc, storage, &stranger, 10 * DAY, b"alice", &target);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a non owner cannot repoint a name's resolution"
    );
}

#[test]
fn set_resolved_on_an_expired_name_reverts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let target = addr(0x77);
    let storage = seed_owner(b"alice", &owner, 100 * DAY);
    let refused = run_set_resolved(&cc, storage, &owner, 100 * DAY, b"alice", &target);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "resolution cannot be set once the name has expired"
    );
}

#[test]
fn set_primary_by_a_non_owner_reverts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let stranger = addr(0xCC);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let refused = run_set_primary(&cc, storage, &stranger, 10 * DAY, b"alice");
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a non owner cannot claim a name as its primary"
    );
}

#[test]
fn set_primary_on_an_expired_name_reverts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let storage = seed_owner(b"alice", &owner, 100 * DAY);
    let refused = run_set_primary(&cc, storage, &owner, 100 * DAY, b"alice");
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "an expired name cannot be set as a primary"
    );
}

#[test]
fn set_primary_by_the_owner_within_the_term_halts() {
    let cc = compiled();
    let owner = addr(0xA1);
    let storage = seed_owner(b"alice", &owner, 1000 * DAY);
    let after = run_set_primary(&cc, storage, &owner, 10 * DAY, b"alice");
    assert!(
        after.is_ok(),
        "the owner may set a live name as its primary"
    );
}
