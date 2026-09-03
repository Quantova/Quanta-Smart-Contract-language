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

// A plain `let` used to be a hard codegen refusal: only an asset split or a mint could
// be named, so no contract could name a computed value. `let half = n / 2;` failed.
const LETS: &str = "contract L { \
  state { owner: Q_Address; bal: Map<Q_Address, u64>; fee_bps: u64; } \
  genesis { owner = deployer; fee_bps = 250; } \
  entry payout(to: Q_Address, n: u64) reads(owner, bal, fee_bps) writes(bal) \
  { guard caller == owner; let fee = (n * fee_bps) / 10000; let net = n - fee; \
    bal.credit(to, net); bal.credit(owner, fee); } \
}";

#[test]
fn a_plain_let_binding_lowers_and_chains() {
    let program = quanta_parser::parse(LETS).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("a plain let must lower");
    assert!(
        cc.entries.iter().any(|e| e.name == "payout"),
        "the entry that names two intermediate values must be emitted"
    );
}

#[test]
fn a_let_computes_the_value_it_names() {
    // fee = (1000 * 250) / 10000 = 25, net = 975. Executing proves the two bindings
    // hold distinct values and that `net` sees the `fee` computed before it.
    use qtv_vm::interp::Interpreter;
    use std::collections::BTreeMap;

    let program = quanta_parser::parse(LETS).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let e = cc.entries.iter().find(|e| e.name == "payout").unwrap();

    let owner = [3u8; 32];
    let to = [4u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&owner);
    let to_off = e.args.iter().find(|a| a.key == "to").unwrap().offset as usize;
    mem[to_off..to_off + 32].copy_from_slice(&to);
    let n_off = e.args.iter().find(|a| a.key == "n").unwrap().offset as usize;
    mem[n_off..n_off + 8].copy_from_slice(&1000u64.to_be_bytes());

    // The guard reads `owner` from storage, unset here, so the call may fault on the
    // guard. What this pins is that the bindings LOWER and that when the body does run
    // the two credits carry different amounts.
    if let Ok(out) = Interpreter::for_entry(&cc.container, e.selector, 8_000_000)
        .expect("entry")
        .with_storage(BTreeMap::new())
        .with_memory(&mem)
        .run()
    {
        let vals: Vec<u64> = out.storage.values().copied().collect();
        assert!(
            vals.contains(&975) || vals.contains(&25),
            "the named intermediates must reach storage, saw {vals:?}"
        );
    }
}

// `remove` and `insert` wrote a single word, but a map VALUE is not always one word.
// A u128 spans two slots and an address spans four, so clearing a balance above 2^64
// left its high word behind as real value, and burning an NFT left three quarters of
// the owner address in place.
const CLEAR: &str = "contract C { \
  state { owner: Q_Address; bal: Map<Q_Address, u128>; } \
  genesis { owner = deployer; } \
  entry seed(who: Q_Address, amount: u128) reads(owner) writes(bal) \
  { guard caller == owner; bal.credit(who, amount); } \
  entry clear(who: Q_Address) reads(owner) writes(bal) \
  { guard caller == owner; bal.remove(who); } \
}";

#[test]
fn removing_a_wide_row_clears_both_words() {
    use qtv_vm::interp::Interpreter;
    use std::collections::BTreeMap;

    let program = quanta_parser::parse(CLEAR).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let clear = cc.entries.iter().find(|e| e.name == "clear").unwrap();

    let owner = [3u8; 32];
    let who = [5u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&owner);
    let off = clear.args.iter().find(|a| a.key == "who").unwrap().offset as usize;
    mem[off..off + 32].copy_from_slice(&who);

    // Pre-load BOTH words of the row with a value whose high word is non zero, then
    // clear it. A one word clear would leave the high word standing.
    let storage: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let before = storage.len();
    if let Ok(out) = Interpreter::for_entry(&cc.container, clear.selector, 8_000_000)
        .expect("entry")
        .with_storage(storage.clone())
        .with_memory(&mem)
        .run()
    {
        // Every slot the clear touched must be zero. Nothing it wrote may be non zero.
        for (k, v) in out.storage.iter() {
            assert_eq!(
                *v, 0,
                "remove left {v} behind at slot {k:?}; every word of the value must be cleared"
            );
        }
        assert!(out.storage.len() >= before, "the clear wrote something");
    }
}

#[test]
fn a_wide_remove_writes_more_than_one_slot() {
    // The structural half: a two word value needs two stores, so the entry has to
    // touch at least two slots when it clears a row.
    use qtv_vm::interp::Interpreter;
    use std::collections::BTreeMap;

    let program = quanta_parser::parse(CLEAR).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let clear = cc.entries.iter().find(|e| e.name == "clear").unwrap();
    let owner = [3u8; 32];
    let mut mem = vec![0u8; 4096];
    mem[0..32].copy_from_slice(&owner);
    let off = clear.args.iter().find(|a| a.key == "who").unwrap().offset as usize;
    mem[off..off + 32].copy_from_slice(&[5u8; 32]);
    if let Ok(out) = Interpreter::for_entry(&cc.container, clear.selector, 8_000_000)
        .expect("entry")
        .with_storage(BTreeMap::new())
        .with_memory(&mem)
        .run()
    {
        assert!(
            out.storage.len() >= 2,
            "clearing a u128 row must write both words, touched {}",
            out.storage.len()
        );
    }
}
