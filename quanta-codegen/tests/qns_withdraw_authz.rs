// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{nonce_key, put_addr_slots, signer_address, slot_key};

const SRC: &str = include_str!("../../examples/QNS.qs");

const VAULT_SLOT: u64 = 35;
const CONTRACT: [u8; 32] = [0x44; 32];
const SCHEME_ML: u8 = 1;
const GAS: u64 = 200_000_000;
const SIGNED_TAG: &[u8; 8] = b"QTVSGN01";

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

fn put_word(mem: &mut [u8], off: usize, v: u64) {
    mem[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

fn member_message(
    sel: [u8; SELECTOR_BYTES],
    member: &[u8; 32],
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    let tag = u64::from_be_bytes(*SIGNED_TAG);
    let mut msg = Vec::new();
    msg.extend_from_slice(&tag.to_be_bytes());
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(sel) as u64).to_be_bytes());
    msg.extend_from_slice(member);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&0u64.to_be_bytes());
    msg.extend_from_slice(to);
    msg
}

fn region(
    sel: [u8; SELECTOR_BYTES],
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    nonce: u64,
    amount: u64,
    to: &[u8; 32],
) -> Vec<u8> {
    let addr = signer_address(SCHEME_ML, pk);
    let msg = member_message(sel, &addr, nonce, amount, to);
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut r = Vec::new();
    r.extend_from_slice(pk);
    r.extend_from_slice(&sig);
    r.extend_from_slice(&msg);
    r
}

fn guardians() -> (Vec<(ml_dsa::PublicKey, ml_dsa::SecretKey)>, Vec<[u8; 32]>) {
    let keys: Vec<_> = (0u8..7).map(|s| ml_dsa::keygen(&[s + 1; 32])).collect();
    let addrs = keys
        .iter()
        .map(|(pk, _)| signer_address(SCHEME_ML, pk))
        .collect();
    (keys, addrs)
}

fn base_storage(addrs: &[[u8; 32]], vault: u64) -> BTreeMap<[u8; 32], u64> {
    let mut s = BTreeMap::new();
    for (j, g) in addrs.iter().enumerate() {
        put_addr_slots(&mut s, j as u64 * 4, g);
    }
    s.insert(slot_key(VAULT_SLOT), vault);
    s
}

#[allow(clippy::too_many_arguments)]
fn withdraw_mem(
    cc: &CompiledContract,
    keys: &[(ml_dsa::PublicKey, ml_dsa::SecretKey)],
    members: &[(u64, usize, u64)],
    signed_amount: u64,
    signed_to: &[u8; 32],
    plain_amount: u64,
    plain_to: &[u8; 32],
) -> Vec<u8> {
    let sel = entry(cc, "withdraw").selector;
    let mut mem = vec![0u8; 262_144];
    mem[32..64].copy_from_slice(&CONTRACT);
    put_word(
        &mut mem,
        arg_off(cc, "withdraw", "order.amount"),
        plain_amount,
    );
    mem[arg_off(cc, "withdraw", "order.to")..arg_off(cc, "withdraw", "order.to") + 32]
        .copy_from_slice(plain_to);
    let mut cursor = 8_192usize;
    for (slot, (gindex, keyidx, nonce)) in members.iter().enumerate() {
        let (pk, sk) = &keys[*keyidx];
        let r = region(sel, pk, sk, *nonce, signed_amount, signed_to);
        let off = cursor;
        cursor += r.len();
        mem[off..off + r.len()].copy_from_slice(&r);
        put_word(
            &mut mem,
            arg_off(cc, "withdraw", &format!("approvals#{slot}#scheme")),
            SCHEME_ML as u64,
        );
        put_word(
            &mut mem,
            arg_off(cc, "withdraw", &format!("approvals#{slot}#ptr")),
            off as u64,
        );
        put_word(
            &mut mem,
            arg_off(cc, "withdraw", &format!("approvals#{slot}#index")),
            *gindex,
        );
    }
    mem
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    let sel = entry(cc, "withdraw").selector;
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn five(keys: &[(ml_dsa::PublicKey, ml_dsa::SecretKey)]) -> Vec<(u64, usize, u64)> {
    let _ = keys;
    (0..5).map(|i| (i as u64, i, 0u64)).collect()
}

#[test]
fn a_met_quorum_sweeps_the_exact_amount_to_the_signed_recipient() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let mem = withdraw_mem(&cc, &keys, &five(&keys), 400, &to, 400, &to);
    let (storage, effects) =
        run(&cc, base_storage(&addrs, 1000), &mem).expect("a five of seven quorum sweeps");

    assert_eq!(
        storage.get(&slot_key(VAULT_SLOT)).copied().unwrap_or(0),
        600,
        "the vault falls by the swept amount"
    );
    let transfer = effects.iter().find_map(|e| match e {
        Effect::Transfer { to, amount } => Some((to.clone(), *amount)),
        _ => None,
    });
    assert_eq!(
        transfer,
        Some((to.to_vec(), 400)),
        "the sweep sends the exact amount to the signed recipient"
    );
    for i in 0..5usize {
        assert_eq!(
            storage.get(&nonce_key(&addrs[i])).copied().unwrap_or(0),
            1,
            "each signer nonce is consumed"
        );
    }
}

#[test]
fn redirecting_the_recipient_past_its_leading_word_reverts() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let mut redirected = to;
    redirected[8] ^= 0xFF;
    let mem = withdraw_mem(&cc, &keys, &five(&keys), 400, &to, 400, &redirected);
    let refused = run(&cc, base_storage(&addrs, 1000), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a redirected sweep recipient is refused"
    );
}

#[test]
fn inflating_the_amount_past_the_signed_value_reverts() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let mem = withdraw_mem(&cc, &keys, &five(&keys), 400, &to, 900, &to);
    let refused = run(&cc, base_storage(&addrs, 1000), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a sweep amount the guardians did not sign is refused"
    );
}

#[test]
fn four_guardians_do_not_meet_the_five_of_seven_threshold() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let members: Vec<(u64, usize, u64)> = (0..4).map(|i| (i as u64, i, 0u64)).collect();
    let mem = withdraw_mem(&cc, &keys, &members, 400, &to, 400, &to);
    let refused = run(&cc, base_storage(&addrs, 1000), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "fewer than five approvals cannot sweep"
    );
}

#[test]
fn a_non_guardian_in_the_fifth_slot_is_refused() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let (spk, ssk) = ml_dsa::keygen(&[200u8; 32]);
    let mut keys2 = keys;
    keys2.push((spk, ssk));
    let stranger_idx = keys2.len() - 1;
    let members: Vec<(u64, usize, u64)> = vec![
        (0, 0, 0),
        (1, 1, 0),
        (2, 2, 0),
        (3, 3, 0),
        (4, stranger_idx, 0),
    ];
    let mem = withdraw_mem(&cc, &keys2, &members, 400, &to, 400, &to);
    let refused = run(&cc, base_storage(&addrs, 1000), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a non guardian cannot fill a quorum slot"
    );
}

#[test]
fn a_guardian_counted_twice_is_refused() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let members: Vec<(u64, usize, u64)> =
        vec![(0, 0, 0), (1, 1, 0), (2, 2, 0), (3, 3, 0), (3, 3, 1)];
    let mem = withdraw_mem(&cc, &keys, &members, 400, &to, 400, &to);
    let refused = run(&cc, base_storage(&addrs, 1000), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a repeated guardian index is refused"
    );
}

#[test]
fn a_sweep_larger_than_the_vault_reverts() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let mem = withdraw_mem(&cc, &keys, &five(&keys), 400, &to, 400, &to);
    let refused = run(&cc, base_storage(&addrs, 100), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a sweep cannot exceed the vault balance"
    );
}

#[test]
fn a_replayed_quorum_is_refused_after_the_nonces_advance() {
    let cc = compiled();
    let (keys, addrs) = guardians();
    let to = [0x77u8; 32];
    let mem = withdraw_mem(&cc, &keys, &five(&keys), 400, &to, 400, &to);
    let (after, _) = run(&cc, base_storage(&addrs, 1000), &mem).expect("first sweep halts");
    let refused = run(&cc, after, &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a captured quorum cannot be replayed after nonces advance"
    );
}
