// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A send_asset call lowers to a single transfer effect whose target is the issuer address followed
//! by the holder address, sixty four bytes, the shape the ledger reads to move a non native asset.

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
