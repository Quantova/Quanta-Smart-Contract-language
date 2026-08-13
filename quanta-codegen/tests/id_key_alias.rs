// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_vm::container::{Container, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, read_addr_value};

const OWNER_OF_BASE: u64 = 1 << 40;
const LINK_BASE: u64 = 1 << 40;
const GAS: u64 = 8_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("type check");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

fn arg_off(cc: &CompiledContract, name: &str, key: &str) -> usize {
    entry(cc, name).args.iter().find(|s| s.key == key).expect("arg").offset as usize
}

fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn id_key(id: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&id.to_be_bytes());
    k
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

// A set whose value reads another id-keyed slot must write the set's own key, not the read's key.
#[test]
fn a_set_whose_value_reads_another_id_slot_writes_its_own_key() {
    let src = "contract C { state { owner_of: Map<Q_Id, Q_Address>; } \
               entry reassign(a: Q_Id, b: Q_Id) reads(owner_of) writes(owner_of) { \
                   owner_of.set(b, caller); \
                   owner_of.set(a, owner_of.get(b)); \
               } }";
    let cc = compile(src);
    let caller = addr(0x33);
    let (a_id, b_id) = (2u64, 1u64);
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&caller);
    let ao = arg_off(&cc, "reassign", "a");
    mem[ao..ao + 8].copy_from_slice(&a_id.to_be_bytes());
    let bo = arg_off(&cc, "reassign", "b");
    mem[bo..bo + 8].copy_from_slice(&b_id.to_be_bytes());

    let (storage, _) = run(&cc.container, entry(&cc, "reassign").selector, BTreeMap::new(), &mem).expect("halts");
    assert_eq!(read_addr_value(&storage, OWNER_OF_BASE, &id_key(b_id)), caller, "owner_of[b] is the caller");
    assert_eq!(
        read_addr_value(&storage, OWNER_OF_BASE, &id_key(a_id)),
        caller,
        "owner_of[a] took b's value written to a's own slot, not b's slot"
    );
}

fn put_addr(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, key: &[u8; 32], val: &[u8; 32]) {
    for i in 0..4u64 {
        let w = u64::from_be_bytes(val[i as usize * 8..i as usize * 8 + 8].try_into().unwrap());
        storage.insert(map_addr_word_key(base, key, i), w);
    }
}

// A set whose key and value both read the SAME map must use the intended key, not a clobbered one.
#[test]
fn a_map_set_whose_key_and_value_read_the_same_map_uses_the_intended_key() {
    let src = "contract C { state { link: Map<Q_Address, Q_Address>; } \
               entry rekey(x: Q_Address, y: Q_Address) reads(link) writes(link) \
               { link.set(link.get(x), link.get(y)); } }";
    let cc = compile(src);
    let (x, y) = (addr(0x01), addr(0x02));
    let (ax, ay) = (addr(0xAA), addr(0xBB));
    let mut storage = BTreeMap::new();
    put_addr(&mut storage, LINK_BASE, &x, &ax);
    put_addr(&mut storage, LINK_BASE, &y, &ay);
    let mut mem = vec![0u8; 4096];
    let xo = arg_off(&cc, "rekey", "x");
    mem[xo..xo + 32].copy_from_slice(&x);
    let yo = arg_off(&cc, "rekey", "y");
    mem[yo..yo + 32].copy_from_slice(&y);

    let (after, _) = run(&cc.container, entry(&cc, "rekey").selector, storage, &mem).expect("halts");
    assert_eq!(
        read_addr_value(&after, LINK_BASE, &ax),
        ay,
        "link[link[x]] = link[y]: the write must land on link[x]'s target, not link[y]'s"
    );
}

// A guard comparing two id-keyed reads must compare the two intended keys, not one clobbered key.
#[test]
fn a_guard_comparing_two_id_reads_uses_both_keys() {
    let src = "contract C { state { owner_of: Map<Q_Id, Q_Address>; note_of: Map<Q_Id, Q_Address>; flag: u64; } \
               entry demo(id: Q_Id, other: Q_Id, x: Q_Address) writes(owner_of, note_of, flag) { \
                   owner_of.set(id, x); \
                   owner_of.set(other, caller); \
                   note_of.set(other, caller); \
                   guard owner_of.get(id) == note_of.get(other); \
                   flag = 1; \
               } }";
    let cc = compile(src);
    let caller = addr(0x33);
    let x = addr(0x44);
    let (id, other) = (5u64, 9u64);
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&caller);
    let ido = arg_off(&cc, "demo", "id");
    mem[ido..ido + 8].copy_from_slice(&id.to_be_bytes());
    let oo = arg_off(&cc, "demo", "other");
    mem[oo..oo + 8].copy_from_slice(&other.to_be_bytes());
    let xo = arg_off(&cc, "demo", "x");
    mem[xo..xo + 32].copy_from_slice(&x);

    // owner_of[id] = x (0x44) differs from note_of[other] = caller (0x33), so the guard must revert;
    // if the id key is clobbered to `other`, the run wrongly compares equal words and passes.
    let out = run(&cc.container, entry(&cc, "demo").selector, BTreeMap::new(), &mem);
    assert!(
        matches!(out, Err(Fault::DivByZero)),
        "the guard compares owner_of[id] against note_of[other] and must revert, not pass on a clobbered key"
    );
}
