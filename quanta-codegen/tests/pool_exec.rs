// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::path::PathBuf;

use qtv_vm::container::{selector, GENESIS_SIGNATURE, SELECTOR_BYTES};
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

mod common;

const GAS: u64 = 8_000_000;
const CONTRACT: [u8; 32] = [0x99; 32];
const SENTINEL: [u8; 8] = *b"QGENSNTL";
const CTX: usize = 120;

fn pool() -> CompiledContract {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("examples/Pool.qs");
    let src = std::fs::read_to_string(&path).expect("read the pool example");
    let program = quanta_parser::parse(&src).expect("parse");
    quanta_typeck::check(&program).expect("the pool type checks");
    compile_contract(&program.contracts.into_iter().next().expect("one contract"))
        .expect("the pool compiles")
}

fn entry_of<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
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

fn context(caller: &[u8; 32], value: u64, in_asset: &[u8; 32]) -> Vec<u8> {
    let mut mem = vec![0u8; 8192];
    mem[0..32].copy_from_slice(caller);
    mem[32..64].copy_from_slice(&CONTRACT);
    mem[80..88].copy_from_slice(&value.to_be_bytes());
    mem[88..120].copy_from_slice(in_asset);
    mem
}

fn genesis(cc: &CompiledContract, a: &[u8; 32], b: &[u8; 32]) -> BTreeMap<[u8; 32], u64> {
    let mut mem = vec![0u8; CTX + 128 + 8];
    let mut at = CTX;
    for p in &cc.deploy_params {
        let w = p.width as usize;
        if p.key.ends_with("token_a") {
            mem[p.offset as usize..p.offset as usize + w].copy_from_slice(a);
        } else if p.key.ends_with("token_b") {
            mem[p.offset as usize..p.offset as usize + w].copy_from_slice(b);
        }
        at = at.max(p.offset as usize + w);
    }
    mem[at..at + 8].copy_from_slice(&SENTINEL);
    run(cc, selector(GENESIS_SIGNATURE), BTreeMap::new(), &mem)
        .expect("genesis runs")
        .0
}

fn call(
    cc: &CompiledContract,
    name: &str,
    storage: BTreeMap<[u8; 32], u64>,
    caller: &[u8; 32],
    value: u64,
    in_asset: &[u8; 32],
    words: &[(&str, u64)],
) -> Result<(BTreeMap<[u8; 32], u64>, Vec<Effect>), Fault> {
    let e = entry_of(cc, name);
    let mut mem = context(caller, value, in_asset);
    let mut put = |mem: &mut [u8], key: &str, v: u64| {
        let slot = e
            .args
            .iter()
            .find(|s| s.key == key)
            .unwrap_or_else(|| panic!("{name} has no arg {key}"));
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&v.to_be_bytes());
    };
    if e.args.iter().any(|s| s.key == "funds") {
        put(&mut mem, "funds", value);
    }
    for (key, v) in words {
        put(&mut mem, key, *v);
    }
    run(cc, e.selector, storage, &mem)
}

#[test]
fn a_swap_pays_out_the_constant_product_price() {
    let cc = pool();
    let token_a = [0xAAu8; 32];
    let token_b = [0xBBu8; 32];
    let lp = [0x11u8; 32];
    let trader = [0x22u8; 32];

    let st = genesis(&cc, &token_a, &token_b);
    let (st, _) = call(&cc, "deposit_a", st, &lp, 1_000, &token_a, &[]).expect("deposit a");
    let (st, _) = call(&cc, "seed_liquidity", st, &lp, 2_000, &token_b, &[]).expect("seed");

    let (_, effects) = call(
        &cc,
        "swap_a_for_b",
        st,
        &trader,
        100,
        &token_a,
        &[("min_out", 1)],
    )
    .expect("the swap runs");

    let expected = (100u128 * 997 * 2_000) / (1_000u128 * 1_000 + 100 * 997);
    let paid: Vec<u64> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Transfer { amount, .. } => Some(*amount),
            _ => None,
        })
        .collect();
    assert_eq!(
        paid,
        vec![expected as u64],
        "the pool must pay the constant product price of {expected}"
    );
}

#[test]
fn a_swap_that_misses_its_floor_reverts_and_pays_nothing() {
    let cc = pool();
    let token_a = [0xAAu8; 32];
    let token_b = [0xBBu8; 32];
    let lp = [0x11u8; 32];
    let trader = [0x22u8; 32];

    let st = genesis(&cc, &token_a, &token_b);
    let (st, _) = call(&cc, "deposit_a", st, &lp, 1_000, &token_a, &[]).expect("deposit a");
    let (st, _) = call(&cc, "seed_liquidity", st, &lp, 2_000, &token_b, &[]).expect("seed");

    assert!(
        call(
            &cc,
            "swap_a_for_b",
            st,
            &trader,
            100,
            &token_a,
            &[("min_out", 100_000)],
        )
        .is_err(),
        "a floor the price cannot meet must revert rather than pay less"
    );
}

#[test]
fn a_swap_paid_in_the_wrong_asset_reverts() {
    let cc = pool();
    let token_a = [0xAAu8; 32];
    let token_b = [0xBBu8; 32];
    let lp = [0x11u8; 32];
    let trader = [0x22u8; 32];

    let st = genesis(&cc, &token_a, &token_b);
    let (st, _) = call(&cc, "deposit_a", st, &lp, 1_000, &token_a, &[]).expect("deposit a");
    let (st, _) = call(&cc, "seed_liquidity", st, &lp, 2_000, &token_b, &[]).expect("seed");

    assert!(
        call(
            &cc,
            "swap_a_for_b",
            st,
            &trader,
            100,
            &token_b,
            &[("min_out", 1)],
        )
        .is_err(),
        "paying token b into the a for b side must revert, this is what in_asset is for"
    );
}
