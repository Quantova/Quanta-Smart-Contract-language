// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::interp::{Effect, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract, EntryArtifact};

const GAS: u64 = 2_000_000;

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn entry<'a>(cc: &'a CompiledContract, name: &str) -> &'a EntryArtifact {
    cc.entries.iter().find(|e| e.name == name).expect("entry")
}

const SELF_PAY: &str = "contract SelfPay { entry claim() { send_asset(caller, caller, 40); } }";

const MINTER: &str = "contract Minter { asset MTK; state { total_supply: u128; } \
     genesis { total_supply = 100; mint_asset(deployer, 100); } }";

#[test]
fn mint_asset_emits_a_mint_control_event_with_the_holder_and_amount() {
    let cc = compile(MINTER);
    let caller = [7u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&caller);

    let genesis = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
    let out = Interpreter::for_entry(&cc.container, genesis, GAS)
        .expect("genesis entry")
        .with_memory(&mem)
        .run()
        .expect("the genesis halts");

    let mint = out
        .effects
        .iter()
        .find_map(|e| match e {
            Effect::Event { selector, data } if selector == b"MINT" => Some(data),
            _ => None,
        })
        .expect("a MINT control event");
    assert_eq!(mint.len(), 40, "the mint data is a holder then an amount");
    assert_eq!(&mint[0..32], &caller, "the deployer holder leads the mint data");
    assert_eq!(
        u64::from_be_bytes(mint[32..40].try_into().unwrap()),
        100,
        "the amount follows as a big endian word"
    );
}

#[test]
fn send_asset_emits_a_sixty_four_byte_issuer_and_holder_transfer() {
    let cc = compile(SELF_PAY);
    let claim = entry(&cc, "claim");

    let caller = [7u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&caller);

    let out = Interpreter::for_entry(&cc.container, claim.selector, GAS)
        .expect("entry")
        .with_memory(&mem)
        .run()
        .expect("the entry halts");

    let transfers: Vec<&Effect> = out
        .effects
        .iter()
        .filter(|e| matches!(e, Effect::Transfer { .. }))
        .collect();
    assert_eq!(transfers.len(), 1, "claim sends exactly one asset transfer");
    match transfers[0] {
        Effect::Transfer { to, amount } => {
            assert_eq!(to.len(), 64, "an asset transfer names the issuer then the holder");
            assert_eq!(&to[0..32], &caller, "the issuer address leads the target");
            assert_eq!(&to[32..64], &caller, "the holder address follows the issuer");
            assert_eq!(*amount, 40, "the amount is the third argument");
        }
        _ => unreachable!(),
    }
}
