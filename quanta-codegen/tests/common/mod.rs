// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(dead_code)]

use qtv_crypto::sha3::sha3_256;
use std::collections::BTreeMap;

pub fn slot_key(slot: u64) -> [u8; 32] {
    qtv_vm::abi::scalar_key(slot)
}

pub fn put_addr_slots(storage: &mut BTreeMap<[u8; 32], u64>, base: u64, addr: &[u8; 32]) {
    for i in 0..4usize {
        let w = u64::from_be_bytes(addr[i * 8..i * 8 + 8].try_into().unwrap());
        storage.insert(slot_key(base + i as u64), w);
    }
}

pub fn map_key(map_base: u64, addr: &[u8; 32]) -> [u8; 32] {
    let mut input = map_base.to_be_bytes().to_vec();
    input.extend_from_slice(addr);
    sha3_256(&input)
}

pub fn map_addr_word_key(map_base: u64, addr: &[u8; 32], word: u64) -> [u8; 32] {
    let mut input = map_base.to_be_bytes().to_vec();
    input.extend_from_slice(addr);
    input.extend_from_slice(&word.to_be_bytes());
    sha3_256(&input)
}

pub fn read_addr_value(
    storage: &BTreeMap<[u8; 32], u64>,
    map_base: u64,
    addr: &[u8; 32],
) -> [u8; 32] {
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

pub fn signer_address(scheme: u8, pk: &[u8]) -> [u8; 32] {
    let mut input = vec![scheme];
    input.extend_from_slice(pk);
    sha3_256(&input)
}

pub fn nonce_key(signer: &[u8; 32]) -> [u8; 32] {
    let mut input = b"QTVNONCE".to_vec();
    input.extend_from_slice(signer);
    sha3_256(&input)
}

pub fn addr(tag: u8) -> [u8; 32] {
    [tag; 32]
}
