// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::type_complexity)]

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::container::SELECTOR_BYTES;
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{
    map_addr_word_key, map_key, nonce_key, put_addr_slots, read_addr_value, signer_address,
    slot_key,
};

const SRC: &str = include_str!("../../examples/QCollectible.qs");

const ADMIN_SLOT: u64 = 0;
const SUPPLY_SLOT: u64 = 4;
const OWNER_OF_BASE: u64 = 1 << 40;
const HOLDINGS_BASE: u64 = (1 << 40) + (1 << 32);
const CONTENT_BASE: u64 = (1 << 40) + (2 << 32);

const CONTRACT: [u8; 32] = [0x33; 32];
const SCHEME_ML: u8 = 1;
const REGION_OFF: u64 = 8192;
const GAS: u64 = 60_000_000;
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

fn id_key(id: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&id.to_be_bytes());
    k
}

fn message(
    chain: u64,
    selector: [u8; SELECTOR_BYTES],
    signer: &[u8; 32],
    nonce: u64,
    id: u64,
    to: &[u8; 32],
    content: &[u8; 32],
) -> Vec<u8> {
    let tag = u64::from_be_bytes(*SIGNED_TAG) ^ chain;
    let mut msg = Vec::new();
    msg.extend_from_slice(&tag.to_be_bytes());
    msg.extend_from_slice(&CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(signer);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(to);
    msg.extend_from_slice(content);
    msg
}

struct Order {
    id: u64,
    to: [u8; 32],
    content: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn mint_mem(
    cc: &CompiledContract,
    pk: &[u8],
    sk: &ml_dsa::SecretKey,
    chain: u64,
    signed: &Order,
    plain: &Order,
    nonce: u64,
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, pk);
    let sel = entry(cc, "mint").selector;
    let msg = message(
        chain,
        sel,
        &signer,
        nonce,
        signed.id,
        &signed.to,
        &signed.content,
    );
    let sig = ml_dsa::sign(sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[32..64].copy_from_slice(&CONTRACT);
    mem[72..80].copy_from_slice(&chain.to_be_bytes());
    let too = arg_off(cc, "mint", "order.to");
    mem[too..too + 32].copy_from_slice(&plain.to);
    let co = arg_off(cc, "mint", "order.content");
    mem[co..co + 32].copy_from_slice(&plain.content);
    let so = arg_off(cc, "mint", "order#scheme");
    mem[so..so + 8].copy_from_slice(&(SCHEME_ML as u64).to_be_bytes());
    let po = arg_off(cc, "mint", "order#ptr");
    mem[po..po + 8].copy_from_slice(&REGION_OFF.to_be_bytes());
    let io = arg_off(cc, "mint", "order.id");
    mem[io..io + 8].copy_from_slice(&plain.id.to_be_bytes());
    mem[REGION_OFF as usize..].copy_from_slice(&region);
    mem
}

fn admin_storage(admin: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mut s = BTreeMap::new();
    put_addr_slots(&mut s, ADMIN_SLOT, admin);
    s
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    let sel = entry(cc, "mint").selector;
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn holding(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u64 {
    storage
        .get(&map_key(HOLDINGS_BASE, who))
        .copied()
        .unwrap_or(0)
}

#[test]
fn the_admin_signature_mints_the_exact_order() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let order = Order { id: 7, to, content };

    let mem = mint_mem(&cc, &pk, &sk, 0, &order, &order, 0);
    let (storage, effects) = run(&cc, admin_storage(&admin), &mem).expect("the admin order mints");

    assert_eq!(
        read_addr_value(&storage, OWNER_OF_BASE, &id_key(7)),
        to,
        "owner_of[id] is the full recipient"
    );
    assert_eq!(
        read_addr_value(&storage, CONTENT_BASE, &id_key(7)),
        content,
        "content_of[id] is the full content"
    );
    assert_eq!(
        storage.get(&slot_key(SUPPLY_SLOT)).copied().unwrap_or(0),
        1,
        "supply advanced to one"
    );
    assert_eq!(holding(&storage, &to), 1, "the recipient holds one");
    assert_eq!(
        storage.get(&nonce_key(&admin)).copied().unwrap_or(0),
        1,
        "the admin nonce is consumed"
    );
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Event { .. })),
        "a Minted event is emitted"
    );
}

#[test]
fn redirecting_the_recipient_past_its_leading_word_reverts() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let signed = Order { id: 7, to, content };

    let mut redirected = to;
    redirected[8] ^= 0xFF;
    let plain = Order {
        id: 7,
        to: redirected,
        content,
    };

    let mem = mint_mem(&cc, &pk, &sk, 0, &signed, &plain, 0);
    let refused = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a recipient rewritten past its leading word is refused"
    );
}

#[test]
fn retargeting_the_token_id_reverts() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let signed = Order { id: 7, to, content };
    let plain = Order { id: 8, to, content };

    let mem = mint_mem(&cc, &pk, &sk, 0, &signed, &plain, 0);
    let refused = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a rewritten token id is refused"
    );
}

#[test]
fn rewriting_the_content_reverts() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let signed = Order { id: 7, to, content };
    let mut other = content;
    other[8] ^= 0xFF;
    let plain = Order {
        id: 7,
        to,
        content: other,
    };

    let mem = mint_mem(&cc, &pk, &sk, 0, &signed, &plain, 0);
    let refused = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "rewritten content is refused"
    );
}

#[test]
fn a_non_admin_signer_sharing_the_admin_leading_word_is_refused() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[9u8; 32]);
    let mut admin = signer_address(SCHEME_ML, &pk);
    admin[8] ^= 0xFF;

    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let order = Order { id: 7, to, content };

    let mem = mint_mem(&cc, &pk, &sk, 0, &order, &order, 0);
    let refused = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a leading word collision does not forge the admin"
    );
}

#[test]
fn a_replayed_admin_order_is_refused_after_the_nonce_advances() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let order = Order { id: 7, to, content };

    let mem = mint_mem(&cc, &pk, &sk, 0, &order, &order, 0);
    let (after, _) = run(&cc, admin_storage(&admin), &mem).expect("first mint accepted");
    let order2 = Order { id: 8, to, content };
    let mem2 = mint_mem(&cc, &pk, &sk, 0, &order2, &order2, 0);
    let refused = run(&cc, after, &mem2);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "the captured nonce zero order cannot be replayed"
    );
}

#[test]
fn an_order_captured_on_another_chain_does_not_verify_here() {
    let cc = compiled();
    let (pk, sk) = ml_dsa::keygen(&[5u8; 32]);
    let admin = signer_address(SCHEME_ML, &pk);
    let to = [0xB2u8; 32];
    let content = [0xC0u8; 32];
    let order = Order { id: 7, to, content };

    let signer = signer_address(SCHEME_ML, &pk);
    let sel = entry(&cc, "mint").selector;
    let msg = message(1, sel, &signer, 0, order.id, &order.to, &order.content);
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");
    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);
    let mut mem = vec![0u8; REGION_OFF as usize + region.len()];
    mem[32..64].copy_from_slice(&CONTRACT);
    mem[72..80].copy_from_slice(&2u64.to_be_bytes());
    let too = arg_off(&cc, "mint", "order.to");
    mem[too..too + 32].copy_from_slice(&order.to);
    let co = arg_off(&cc, "mint", "order.content");
    mem[co..co + 32].copy_from_slice(&order.content);
    let so = arg_off(&cc, "mint", "order#scheme");
    mem[so..so + 8].copy_from_slice(&(SCHEME_ML as u64).to_be_bytes());
    let po = arg_off(&cc, "mint", "order#ptr");
    mem[po..po + 8].copy_from_slice(&REGION_OFF.to_be_bytes());
    let io = arg_off(&cc, "mint", "order.id");
    mem[io..io + 8].copy_from_slice(&order.id.to_be_bytes());
    mem[REGION_OFF as usize..].copy_from_slice(&region);

    let refused = run(&cc, admin_storage(&admin), &mem);
    assert!(
        matches!(refused, Err(Fault::DivByZero)),
        "a cross chain order does not verify"
    );
    let _ = map_addr_word_key(OWNER_OF_BASE, &id_key(7), 0);
}
