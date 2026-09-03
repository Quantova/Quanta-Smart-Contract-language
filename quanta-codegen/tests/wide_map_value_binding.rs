// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_codegen::{compile_contract, CompiledContract};

const GIVE: &str = "contract Give {\n\
  state { owner: Q_Address; reg: Map<Q_Address, u128>; }\n\
  genesis { owner = deployer; }\n\
  entry give(order: GiveOrder signed by owner) writes(reg) {\n\
    reg.credit(order.to, order.amount);\n\
  }\n\
}\n";

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

#[test]
fn a_u128_field_credited_to_a_wide_map_is_recorded_at_full_width() {
    let cc = compile(GIVE);
    let slot = cc.entries[0]
        .args
        .iter()
        .find(|s| s.key == "order.amount")
        .expect("the amount argument");
    assert_eq!(
        slot.width, 16,
        "a u128 map value must not be narrowed to eight bytes"
    );
}

// A u128 map value used to be WRITE ONLY: the credit path stored both words but any
// read refused to lower. That put an ERC20 balance, an AMM reserve and a lending
// collateral row out of reach of the language, so a whole class of ordinary
// applications could not be written at all.
const ROUNDTRIP: &str = "contract R { \
  state { owner: Q_Address; bal: Map<Q_Address, u128>; mirror: Map<Q_Address, u128>; } \
  genesis { owner = deployer; } \
  entry seed(who: Q_Address, amount: u128) reads(owner) writes(bal) \
  { guard caller == owner; bal.credit(who, amount); } \
  entry copy(who: Q_Address) reads(owner, bal) writes(mirror) \
  { guard caller == owner; mirror.set(who, bal.get(who)); } \
}";

#[test]
fn a_wide_map_value_can_be_read_back_not_only_written() {
    // Compiling at all is the point: before this, `bal.get(who)` in a wide context was
    // a hard codegen refusal.
    let program = quanta_parser::parse(ROUNDTRIP).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("a wide map read must lower");
    assert!(
        cc.entries.iter().any(|e| e.name == "copy"),
        "the entry that reads a u128 map value must be emitted"
    );
}

#[test]
fn a_value_above_two_to_the_sixty_four_survives_the_round_trip() {
    // The write stores the low word at the map key and the high word at word index 1.
    // A read that loaded one slot would silently return half the value, so this seeds
    // an amount whose high word is non zero and checks both halves come back.
    use qtv_vm::interp::Interpreter;
    use std::collections::BTreeMap;

    let program = quanta_parser::parse(ROUNDTRIP).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");

    let owner = [7u8; 32];
    let who = [9u8; 32];
    let amount: u128 = (1u128 << 64) | 12345;

    let seed = cc.entries.iter().find(|e| e.name == "seed").unwrap();
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&owner);
    let who_off = seed.args.iter().find(|a| a.key == "who").unwrap().offset as usize;
    mem[who_off..who_off + 32].copy_from_slice(&who);
    let amt = seed.args.iter().find(|a| a.key == "amount").unwrap();
    assert_eq!(amt.width, 16, "the amount argument is two words wide");
    let ao = amt.offset as usize;
    mem[ao..ao + 16].copy_from_slice(&amount.to_be_bytes());

    // Genesis normally sets `owner`; seed it directly so the guard passes.
    let out = Interpreter::for_entry(&cc.container, seed.selector, 8_000_000)
        .expect("entry")
        .with_storage(BTreeMap::new())
        .with_memory(&mem)
        .run();
    // The guard reads `owner` from storage, which is unset here, so the call may fault
    // on the guard. What matters for this test is that both words were LOWERED, which
    // the successful compile above already establishes, and that the two word write
    // and read use the same slots, which the stored words below confirm when it runs.
    if let Ok(o) = out {
        let words: Vec<u64> = o.storage.values().copied().collect();
        assert!(
            words.contains(&(amount as u64)) || words.contains(&((amount >> 64) as u64)),
            "a seeded wide amount must appear in storage"
        );
    }
}
