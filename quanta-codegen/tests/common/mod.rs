// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Shared helpers for the code generator tests under the thirty two byte storage key model. A scalar

#![allow(dead_code)]

use qtv_crypto::sha3::sha3_256;
use std::collections::BTreeMap;

/// The thirty two byte key of a scalar field slot, the machine's scalar_key of the slot number.
pub fn slot_key(slot: u64) -> [u8; 32] {
    qtv_vm::abi::scalar_key(slot)
}

/// Seed a four slot `Q_Address` state field starting at `base` with the four words of an address, so a
pub fn put_addr_slots(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, addr: &[u8; 32]) {
    for i in 0..4usize {
        let w = u64::from_be_bytes(addr[i * 8..i * 8 + 8].try_into().unwrap());
        storage.insert(slot_key(base + i as u64), w);
    }
}

/// The thirty two byte storage key of a keyed map entry: SHA3 of the map's domain tag then the whole
pub fn map_key(map_base: u64, addr: &[u8; 32]) -> [u8; 32] {
    let mut input = map_base.to_be_bytes().to_vec();
    input.extend_from_slice(addr);
    sha3_256(&input)
}

/// The thirty two byte storage key of word `word` of an address valued map entry: SHA3 of the map's
pub fn map_addr_word_key(map_base: u64, addr: &[u8; 32], word: u64) -> [u8; 32] {
    let mut input = map_base.to_be_bytes().to_vec();
    input.extend_from_slice(addr);
    input.extend_from_slice(&word.to_be_bytes());
    sha3_256(&input)
}

/// Reassemble the thirty two byte address value stored across the four hashed word slots of an address
pub fn read_addr_value(storage: &BTreeMap<[u8; 32], u64>, map_base: u64, addr: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4u64 {
        let w = storage
            .get(&map_addr_word_key(map_base, addr, i))
            .copied()
            .unwrap_or(0);
        out[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// The signer address the ADDR opcode and the chain both derive: SHA3 of the scheme byte then the key.
pub fn signer_address(scheme: u8, pk: &[u8]) -> [u8; 32] {
    let mut input = vec![scheme];
    input.extend_from_slice(pk);
    sha3_256(&input)
}

/// The per signer nonce storage key: SHA3 of the nonce domain tag then the signer address.
pub fn nonce_key(signer: &[u8; 32]) -> [u8; 32] {
    let mut input = b"QTVNONCE".to_vec();
    input.extend_from_slice(signer);
    sha3_256(&input)
}

/// A thirty two byte address whose low `n` bytes carry `tag`, for building distinct test addresses.
pub fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}
