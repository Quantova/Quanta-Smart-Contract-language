//! Asset operation lowering. An asset amount is a stored balance, so split, merge, mint, and burn

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa;
use qtv_vm::interp::{Effect, Fault, Interpreter};
use quanta_codegen::{compile_contract, CompiledContract};

mod common;
use common::{addr, map_key, put_addr_slots, signer_address, slot_key};

fn compile(src: &str) -> CompiledContract {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    compile_contract(&program.contracts[0]).expect("compile")
}

fn memory_with(cc: &CompiledContract, entry: usize, values: &[(&str, u64)]) -> Vec<u8> {
    let mut mem = vec![0u8; 65536];
    for slot in &cc.entries[entry].args {
        let value = values
            .iter()
            .find(|(k, _)| *k == slot.key)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        let at = slot.offset as usize;
        mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    mem
}

/// Write a full thirty two byte address into an argument region by its key.
fn set_addr_arg(mem: &mut [u8], cc: &CompiledContract, entry: usize, key: &str, address: &[u8; 32]) {
    let slot = cc.entries[entry]
        .args
        .iter()
        .find(|s| s.key == key)
        .expect("the address argument");
    let at = slot.offset as usize;
    mem[at..at + 32].copy_from_slice(address);
}

fn run(
    cc: &CompiledContract,
    storage: BTreeMap<[u8; 32], u64>,
    mem: &[u8],
) -> Result<BTreeMap<[u8; 32], u64>, Fault> {
    Interpreter::new(&cc.container.code, &cc.container.consts, 300_000)
        .with_storage(storage)
        .with_memory(mem)
        .run()
        .map(|out| out.storage)
}

const MERGE: &str = "contract Merge {\n\
  state { pool: Q_Asset<QTOV>; }\n\
  entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) { pool.merge(funds); }\n\
}\n";

#[test]
fn merge_adds_the_incoming_amount_to_the_pooled_balance() {
    let cc = compile(MERGE);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 100u64); // the pool balance slot
    let mem = memory_with(&cc, 0, &[("funds", 5)]);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(out.get(&slot_key(0)), Some(&105), "the pool must absorb the merge");
}

#[test]
fn merge_overflow_reverts_and_keeps_state() {
    let cc = compile(MERGE);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), u64::MAX);
    let mem = memory_with(&cc, 0, &[("funds", 1)]);
    assert_eq!(
        run(&cc, storage, &mem),
        Err(Fault::Overflow),
        "a merge that overflows the balance must fault"
    );
}

const SPLIT: &str = "contract Split {\n\
  state { reserve: Q_Asset<QTOV>; pool: Q_Asset<QTOV>; }\n\
  entry moveover(req: MoveReq) writes(reserve, pool) conserves QTOV {\n\
    let part = reserve.split(req.amount);\n\
    pool.merge(part);\n\
  }\n\
}\n";

#[test]
fn split_moves_a_balance_between_two_asset_fields_conserving_total() {
    let cc = compile(SPLIT);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 100u64); // reserve
    storage.insert(slot_key(1), 10u64); // pool
    let mem = memory_with(&cc, 0, &[("req.amount", 30)]);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(out.get(&slot_key(0)), Some(&70), "reserve loses the split amount");
    assert_eq!(out.get(&slot_key(1)), Some(&40), "pool gains the split amount");
}

#[test]
fn splitting_more_than_is_held_reverts() {
    let cc = compile(SPLIT);
    let mut storage = BTreeMap::new();
    storage.insert(slot_key(0), 20u64);
    storage.insert(slot_key(1), 10u64);
    let mem = memory_with(&cc, 0, &[("req.amount", 30)]);
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::Overflow),
        "a split larger than the balance must fault"
    );
}

const MINT: &str = "contract Minter {\n\
  asset TKN;\n\
  state { owner: Q_Address; vault: Q_Asset<TKN>; supply: u128; }\n\
  entry issue(order: MintOrder signed by owner)\n\
    mints TKN writes(vault, supply)\n\
    limits supply + order.amount <= 1000000000\n\
  {\n\
    supply += order.amount;\n\
    vault.merge(mint(order.amount));\n\
  }\n\
}\n";

// The owner spans the first four slots; the vault and the supply low word follow it.
const MINT_VAULT_SLOT: u64 = 4;
const MINT_SUPPLY_SLOT: u64 = 5;
const MINT_CONTRACT: [u8; 32] = [0x55; 32];

// Seed the argument words and a bound owner signature region for the `issue` entry, signing the
// canonical order message the compiler rebuilds. Returns the memory and the owner address.
fn signed_mint_memory(cc: &CompiledContract, amount: u64) -> (Vec<u8>, [u8; 32]) {
    let region_off = 8192usize;
    let (pk, sk) = ml_dsa::keygen(&[7u8; 32]);
    let signer = signer_address(1, &pk);

    let selector = cc.container.entries[0].selector;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"QTVSGN01");
    msg.extend_from_slice(&MINT_CONTRACT);
    msg.extend_from_slice(&(u32::from_be_bytes(selector) as u64).to_be_bytes());
    msg.extend_from_slice(&signer);
    msg.extend_from_slice(&0u64.to_be_bytes()); // nonce zero
    msg.extend_from_slice(&amount.to_be_bytes());
    let sig = ml_dsa::sign(&sk, &msg, &[], &[0u8; 32]).expect("sign");

    let mut region = Vec::new();
    region.extend_from_slice(&pk);
    region.extend_from_slice(&sig);
    region.extend_from_slice(&msg);

    let mut mem = vec![0u8; region_off + region.len()];
    mem[32..64].copy_from_slice(&MINT_CONTRACT);
    let mut put = |key: &str, value: u64| {
        if let Some(slot) = cc.entries[0].args.iter().find(|s| s.key == key) {
            let at = slot.offset as usize;
            mem[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
    };
    put("order#scheme", 1);
    put("order#ptr", region_off as u64);
    put("order.amount", amount);
    mem[region_off..].copy_from_slice(&region);
    (mem, signer)
}

#[test]
fn a_signed_mint_creates_supply_and_credits_the_vault() {
    let cc = compile(MINT);
    let (mem, owner) = signed_mint_memory(&cc, 500);
    let mut storage = BTreeMap::new();
    put_addr_slots(&mut storage, 0, &owner);
    storage.insert(slot_key(MINT_VAULT_SLOT), 0);
    storage.insert(slot_key(MINT_SUPPLY_SLOT), 0);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(
        out.get(&slot_key(MINT_SUPPLY_SLOT)),
        Some(&500),
        "supply grows by the minted amount"
    );
    assert_eq!(
        out.get(&slot_key(MINT_VAULT_SLOT)),
        Some(&500),
        "the vault receives the minted asset"
    );
}

/// The keyed base of the first `Map` or `Registry` field, matching the code generator's layout.
const KEYED_BASE: u64 = 1 << 40;

const LEDGER: &str = "contract CallerLedger {\n\
  state { balances: Map<Q_Address, u128>; }\n\
  entry withdraw(to: Q_Address, amt: u64) writes(balances) {\n\
    balances.debit(caller, amt);\n\
    balances.credit(to, amt);\n\
  }\n\
}\n";

#[test]
fn a_transfer_debits_the_caller_and_credits_the_recipient_balance() {
    let cc = compile(LEDGER);
    let caller = addr(1);
    let to = addr(2);
    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &caller), 100u64); // caller balance
    let mut mem = memory_with(&cc, 0, &[("amt", 40)]);
    set_addr_arg(&mut mem, &cc, 0, "@caller", &caller);
    set_addr_arg(&mut mem, &cc, 0, "to", &to);
    let out = run(&cc, storage, &mem).expect("clean halt");
    assert_eq!(
        out.get(&map_key(KEYED_BASE, &caller)),
        Some(&60),
        "caller balance falls"
    );
    assert_eq!(
        out.get(&map_key(KEYED_BASE, &to)),
        Some(&40),
        "recipient balance rises by the same amount"
    );
}

#[test]
fn two_addresses_colliding_in_a_leading_word_have_distinct_balances() {
    // A caller and a victim that share their leading eight bytes but differ past them. Under the old
    // sixty four bit slot the caller would key the victim's balance; the full address hashed into the
    // slot keeps them distinct, so the caller cannot spend the victim's balance.
    let cc = compile(LEDGER);
    let mut caller = [9u8; 32];
    caller[16] = 1;
    let mut victim = [9u8; 32];
    victim[16] = 2;
    let to = addr(3);

    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &victim), 100u64); // the victim's balance
    // The caller holds nothing.
    let mut mem = memory_with(&cc, 0, &[("amt", 40)]);
    set_addr_arg(&mut mem, &cc, 0, "@caller", &caller);
    set_addr_arg(&mut mem, &cc, 0, "to", &to);

    // The debit hits the caller's own empty slot, not the victim's, so it underflows and reverts.
    assert_eq!(
        run(&cc, storage.clone(), &mem),
        Err(Fault::Overflow),
        "the caller cannot draw on a balance that only shares a leading word"
    );
    assert_eq!(
        storage.get(&map_key(KEYED_BASE, &victim)),
        Some(&100),
        "the victim's balance is untouched"
    );
    // The caller and the victim key distinct slots.
    assert_ne!(
        map_key(KEYED_BASE, &caller),
        map_key(KEYED_BASE, &victim),
        "a leading word collision does not collide the balance slots"
    );
}

#[test]
fn debiting_more_than_the_caller_holds_reverts() {
    let cc = compile(LEDGER);
    let caller = addr(1);
    let to = addr(2);
    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &caller), 10u64);
    let mut mem = memory_with(&cc, 0, &[("amt", 40)]);
    set_addr_arg(&mut mem, &cc, 0, "@caller", &caller);
    set_addr_arg(&mut mem, &cc, 0, "to", &to);
    assert_eq!(
        run(&cc, storage, &mem),
        Err(Fault::Overflow),
        "an overdrawn debit must fault"
    );
}

const FREEZER: &str = "contract Freezer {\n\
  state { frozen: Registry<Q_Address>; flag: u64; }\n\
  entry freeze(who: Q_Address) writes(frozen, flag) {\n\
    frozen.insert(who);\n\
    guard frozen.contains(who);\n\
    flag = 1;\n\
  }\n\
}\n";

#[test]
fn an_insert_sets_a_flag_that_contains_reads_back() {
    let cc = compile(FREEZER);
    let who = addr(5);
    let mut mem = memory_with(&cc, 0, &[]);
    set_addr_arg(&mut mem, &cc, 0, "who", &who);
    let out = run(&cc, BTreeMap::new(), &mem).expect("clean halt");
    assert_eq!(
        out.get(&map_key(KEYED_BASE, &who)),
        Some(&1),
        "the registry entry is set"
    );
    assert_eq!(out.get(&slot_key(1)), Some(&1), "the guard over contains passed");
}

const GATE: &str = "contract Gate {\n\
  state { allow: Registry<Q_Address>; flag: u64; }\n\
  entry act(who: Q_Address) reads(allow) writes(flag) {\n\
    guard allow.contains(who);\n\
    flag = 1;\n\
  }\n\
}\n";

#[test]
fn a_membership_guard_admits_a_listed_key_and_reverts_an_absent_one() {
    let cc = compile(GATE);
    let who = addr(3);
    let mut listed = memory_with(&cc, 0, &[]);
    set_addr_arg(&mut listed, &cc, 0, "who", &who);
    let mut storage = BTreeMap::new();
    storage.insert(map_key(KEYED_BASE, &who), 1u64);
    assert_eq!(
        run(&cc, storage, &listed).expect("clean halt").get(&slot_key(1)),
        Some(&1),
        "a listed key passes the guard"
    );

    let mut absent = memory_with(&cc, 0, &[]);
    set_addr_arg(&mut absent, &cc, 0, "who", &who);
    assert_eq!(
        run(&cc, BTreeMap::new(), &absent),
        Err(Fault::DivByZero),
        "an absent key reverts at the guard trap"
    );
}

// A send moves an asset to an account and lowers to the native transfer the SEND opcode records. The
// machine returns the move as a transfer effect for the host to apply against the native ledger keyed
// by the whole thirty two byte address, and the contract's own state is untouched.
const SENDER: &str = "contract Sender {\n\
  state { pool: Q_Asset<QTOV>; }\n\
  entry payout(to: Q_Address, funds: Q_Asset<QTOV>) conserves QTOV { send(to, funds); }\n\
}\n";

#[test]
fn a_send_lowers_and_the_machine_records_the_transfer_effect() {
    let cc = compile(SENDER);
    let to = addr(0x7B);
    let mut mem = memory_with(&cc, 0, &[("funds", 750)]);
    set_addr_arg(&mut mem, &cc, 0, "to", &to);
    let out = Interpreter::for_entry(&cc.container, cc.entries[0].selector, 300_000)
        .expect("the payout selector resolves")
        .with_memory(&mem)
        .run()
        .expect("the send halts");
    assert_eq!(
        out.effects,
        vec![Effect::Transfer {
            to: to.to_vec(),
            amount: 750,
        }],
        "the machine records the transfer to the whole address the send names"
    );
}
