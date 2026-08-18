// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The emitted argument offsets are the wire contract the client encoder, the host, and the entry share.

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_crypto::ml_dsa;
use qtv_vm::container::{selector, GENESIS_SIGNATURE, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_ast::Contract;
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;
use common::{map_addr_word_key, map_key, signer_address, slot_key};

// The client and host canonical layout, frozen.
const SDK_CONTEXT_BYTES: u64 = 88;
const SDK_WORD: u64 = 8;
const SDK_ADDR: u64 = 32;
const SDK_U128: u64 = 16;
const CTX_CALLER_OFF: u64 = 0;
const CTX_CONTRACT_OFF: u64 = 32;
const CTX_TIME_OFF: u64 = 64;
const CTX_CHAIN_OFF: u64 = 72;
const CTX_VALUE_OFF: u64 = 80;

const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SCHEME_ML: u8 = 1;
const SENTINEL: [u8; 8] = *b"QGENSNTL";
const REGION_OFF: usize = 8192;
const SLOT_SUPPLY: u64 = 4;
const HI: u64 = 1 << 56;
const BAL_BASE: u64 = 1 << 40;
const TWO_TO_64: u128 = 1u128 << 64;

fn compile_example(name: &str) -> CompiledContract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push(format!("examples/{name}"));
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read example {name}: {e}"));
    let program = quanta_parser::parse(&src).expect("the example parses");
    quanta_typeck::check(&program).expect("the example type checks");
    let contract: Contract = program.contracts.into_iter().next().expect("one contract");
    compile_contract(&contract).expect("the example compiles")
}

fn compile_src(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry present")
}

fn offset(cc: &CompiledContract, name: &str, key: &str) -> u64 {
    entry(cc, name)
        .args
        .iter()
        .find(|slot| slot.key == key)
        .unwrap_or_else(|| panic!("entry {name} has no argument {key}"))
        .offset
}

// The four host context words, at their fixed positions across the eighty byte prefix.
fn assert_host_context(cc: &CompiledContract, name: &str) {
    assert_eq!(offset(cc, name, "@caller"), CTX_CALLER_OFF, "@caller leads the context");
    assert_eq!(offset(cc, name, "@contract"), CTX_CONTRACT_OFF, "@contract is one address in");
    assert_eq!(offset(cc, name, "@time"), CTX_TIME_OFF, "@time follows the two addresses");
    assert_eq!(offset(cc, name, "@chain"), CTX_CHAIN_OFF, "@chain is the last context word");
    // The context is exactly the eighty byte prefix; no caller argument may land inside it.
    assert_eq!(offset(cc, name, "@value"), CTX_VALUE_OFF, "@value is the last context word");
    assert_eq!(CTX_VALUE_OFF + SDK_WORD, SDK_CONTEXT_BYTES, "the five context words span eighty eight bytes");
    for slot in &entry(cc, name).args {
        if slot.key.starts_with('@') {
            continue;
        }
        assert!(
            slot.offset >= SDK_CONTEXT_BYTES,
            "argument {} at offset {} overlaps the host context prefix",
            slot.key,
            slot.offset
        );
    }
}

#[test]
fn the_qasset_mint_offsets_equal_the_sdk_canonical_layout() {
    // QAsset mint: a Q_Address destination then a u128 amount, at the frozen positions asserted below.
    let cc = compile_example("QAsset.qs");
    assert_host_context(&cc, "mint");
    let to = offset(&cc, "mint", "order.to");
    let scheme = offset(&cc, "mint", "order#scheme");
    let ptr = offset(&cc, "mint", "order#ptr");
    let amount = offset(&cc, "mint", "order.amount");
    assert_eq!(to, SDK_CONTEXT_BYTES, "the destination address opens the argument region");
    assert_eq!(scheme, to + SDK_ADDR, "the scheme word sits one whole address past the destination");
    assert_eq!(ptr, scheme + SDK_WORD, "the region pointer follows the scheme word");
    assert_eq!(amount, ptr + SDK_WORD, "the amount follows the pointer word");
    // The absolute numbers, frozen, so a silent context shift fails here.
    assert_eq!((to, scheme, ptr, amount), (88, 120, 128, 136), "the frozen QAsset mint layout");
}

#[test]
fn the_qasset_transfer_offsets_equal_the_sdk_canonical_layout() {
    // transfer(to: Q_Address, amount: u128): the address opens the region, the u128 follows one address later.
    let cc = compile_example("QAsset.qs");
    assert_host_context(&cc, "transfer");
    let to = offset(&cc, "transfer", "to");
    let amount = offset(&cc, "transfer", "amount");
    assert_eq!(to, SDK_CONTEXT_BYTES, "the destination address opens the argument region");
    assert_eq!(amount, to + SDK_ADDR, "the amount sits one whole address past the destination");
    assert_eq!((to, amount), (88, 120), "the frozen QAsset transfer layout");
}

#[test]
fn scalar_argument_widths_equal_the_sdk_field_widths() {
    // A width probe: each scalar's width shows as the gap to the next, pinning u128 = 16 and u64 = 8.
    const WIDTHS: &str = "contract W {\n\
      state { owner: Q_Address; total: u128; c: u64; }\n\
      genesis { owner = deployer; total = 0; c = 0; }\n\
      entry w(a: u128, b: u64, d: u128) writes(total, c) {\n\
        total = checked(total + a);\n\
        c = checked(c + b);\n\
        total = checked(total + d);\n\
      }\n\
    }\n";
    let cc = compile_src(WIDTHS);
    assert_host_context(&cc, "w");
    let a = offset(&cc, "w", "a");
    let b = offset(&cc, "w", "b");
    let d = offset(&cc, "w", "d");
    assert_eq!(a, SDK_CONTEXT_BYTES, "the first scalar opens the region");
    assert_eq!(b - a, SDK_U128, "a u128 argument is sixteen bytes wide");
    assert_eq!(d - b, SDK_WORD, "a u64 argument is eight bytes wide");
    assert_eq!((a, b, d), (88, 104, 112), "the frozen width probe layout");
}

// An end to end proof: an order at the emitted offsets verifies, and the stale shifted offsets are rejected.

fn selector_of(cc: &CompiledContract, name: &str) -> [u8; 4] {
    entry(cc, name).selector
}

fn run(
    cc: &CompiledContract,
    sel: [u8; SELECTOR_BYTES],
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    Interpreter::for_entry(&cc.container, sel, GAS)?
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| (out.storage, out.effects))
}

fn deploy(cc: &CompiledContract, owner: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    // The genesis deploy region: owner address, then the u128 initial supply, then the sentinel.
    let mut mem = vec![0u8; 88 + 32 + 16 + 8];
    mem[88..120].copy_from_slice(owner);
    mem[136..144].copy_from_slice(&SENTINEL);
    run(cc, selector(GENESIS_SIGNATURE), BTreeMap::new(), &mem)
        .expect("genesis initializes from the deploy parameters")
        .0
}

// The signed order preimage, byte identical to QCore.rs `canonical_order_message_typed`.
fn canonical_order_message(
    chain_id: u64,
    signer: &[u8; 32],
    sel: [u8; 4],
    nonce: u64,
    amount: u128,
    to: &[u8; 32],
) -> Vec<u8> {
    let tag = u64::from_be_bytes(*b"QTVSGN01") ^ chain_id;
    let mut msg = Vec::new();
    msg.extend_from_slice(&tag.to_be_bytes()); // MSG_TAG_OFF 0
    msg.extend_from_slice(&CONTRACT); // MSG_CONTRACT_OFF 8
    msg.extend_from_slice(&(u32::from_be_bytes(sel) as u64).to_be_bytes()); // MSG_SELECTOR_OFF 40
    msg.extend_from_slice(signer); // MSG_SIGNER_OFF 48
    msg.extend_from_slice(&nonce.to_be_bytes()); // MSG_NONCE_OFF 80
    msg.extend_from_slice(&(amount as u64).to_be_bytes()); // MSG_FIELDS_OFF 88, amount low
    msg.extend_from_slice(&((amount >> 64) as u64).to_be_bytes()); // amount high
    msg.extend_from_slice(to); // then the whole destination address
    msg
}

// Lay out the mint call for a given assumed context size; client words hang off `client_context`.
fn mint_memory(
    cc: &CompiledContract,
    key: &(ml_dsa::PublicKey, ml_dsa::SecretKey),
    chain_id: u64,
    nonce: u64,
    amount: u128,
    to: &[u8; 32],
    client_context: u64,
) -> Vec<u8> {
    let signer = signer_address(SCHEME_ML, &key.0);
    let msg = canonical_order_message(chain_id, &signer, selector_of(cc, "mint"), nonce, amount, to);
    let sig = ml_dsa::sign(&key.1, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(&key.0);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; 65536];
    // Host injected context words, at their fixed positions.
    mem[CTX_CONTRACT_OFF as usize..CTX_CONTRACT_OFF as usize + 32].copy_from_slice(&CONTRACT);
    mem[CTX_CHAIN_OFF as usize..CTX_CHAIN_OFF as usize + 8].copy_from_slice(&chain_id.to_be_bytes());

    // Client controlled argument words, hung off whatever context size the client assumes.
    let to_off = client_context as usize;
    let scheme_off = (client_context + SDK_ADDR) as usize;
    let ptr_off = (client_context + SDK_ADDR + SDK_WORD) as usize;
    let amount_off = (client_context + SDK_ADDR + 2 * SDK_WORD) as usize;
    mem[to_off..to_off + 32].copy_from_slice(to);
    mem[scheme_off..scheme_off + 8].copy_from_slice(&(SCHEME_ML as u64).to_be_bytes());
    mem[ptr_off..ptr_off + 8].copy_from_slice(&(REGION_OFF as u64).to_be_bytes());
    mem[amount_off..amount_off + 8].copy_from_slice(&(amount as u64).to_be_bytes());
    mem[amount_off + 8..amount_off + 16].copy_from_slice(&((amount >> 64) as u64).to_be_bytes());

    mem[REGION_OFF..REGION_OFF + region.len()].copy_from_slice(&region);
    mem
}

fn balance(storage: &BTreeMap<[u8; 32], u64>, who: &[u8; 32]) -> u128 {
    let lo = storage.get(&map_key(BAL_BASE, who)).copied().unwrap_or(0) as u128;
    let hi = storage.get(&map_addr_word_key(BAL_BASE, who, 1)).copied().unwrap_or(0) as u128;
    (hi << 64) | lo
}

fn supply(storage: &BTreeMap<[u8; 32], u64>) -> u128 {
    let lo = storage.get(&slot_key(SLOT_SUPPLY)).copied().unwrap_or(0) as u128;
    let hi = storage.get(&slot_key(SLOT_SUPPLY | HI)).copied().unwrap_or(0) as u128;
    (hi << 64) | lo
}

#[test]
fn a_signed_order_at_the_emitted_offsets_verifies_and_the_stale_shift_is_rejected() {
    let cc = compile_example("QAsset.qs");
    let key = ml_dsa::keygen(&[7u8; 32]);
    let owner = signer_address(SCHEME_ML, &key.0);
    let chain_id: u64 = 0x0123_4567_89AB_CDEF;
    let holder = [0xA1u8; 32];
    let amount = TWO_TO_64 + 100;

    // The emitted eighty byte context: arguments land where mint reads them and the order runs.
    let storage = deploy(&cc, &owner);
    let mem = mint_memory(&cc, &key, chain_id, 0, amount, &holder, SDK_CONTEXT_BYTES);
    let (after, _) = run(&cc, selector_of(&cc, "mint"), storage, &mem)
        .expect("an order placed at the emitted offsets verifies and mints");
    assert_eq!(balance(&after, &holder), amount, "the whole two word amount is credited");
    assert_eq!(supply(&after), amount, "supply tracks the wide mint");

    // The stale seventy two byte context: every client word lands eight bytes low, so verify fails.
    let storage = deploy(&cc, &owner);
    let stale = mint_memory(&cc, &key, chain_id, 0, amount, &holder, SDK_CONTEXT_BYTES - SDK_WORD);
    assert!(
        run(&cc, selector_of(&cc, "mint"), storage, &stale).is_err(),
        "an order laid out for the stale seventy two byte context must be rejected, never silently \
         read from the wrong offsets"
    );
}
