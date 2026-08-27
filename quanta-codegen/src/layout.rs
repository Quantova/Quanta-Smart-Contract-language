// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::container::StateAccess;
use quanta_ast::{Clause, Contract, EntryDecl, Item};
use std::collections::{HashMap, HashSet};

const KEYED_TYPES: &[&str] = &["Map", "Registry"];
const KEYED_BASE: u64 = 1 << 40;
const KEYED_STRIDE: u64 = 1 << 32;
const WIDE_TYPE: &str = "u128";
const ADDR_TYPE: &str = "Q_Address";
const ID_TYPE: &str = "Q_Id";
pub const ADDR_WORDS: u64 = 4;
const GUARDIAN_SET_TYPE: &str = "GuardianSet";
pub const MAX_GUARDIAN_SET: u64 = 1024;
const HI_OFFSET: u64 = 1 << 56;

pub struct Layout {
    slots: HashMap<String, u64>,
    map_bases: HashMap<String, u64>,
    wide: HashSet<String>,
    addr: HashSet<String>,
    map_key_addr: HashSet<String>,
    map_key_id: HashSet<String>,
    map_value_addr: HashSet<String>,
    map_value_wide: HashSet<String>,
    guardian_sets: HashMap<String, u64>,
}

impl Layout {
    pub fn build(contract: &Contract) -> Layout {
        let mut slots = HashMap::new();
        let mut map_bases = HashMap::new();
        let mut wide = HashSet::new();
        let mut addr = HashSet::new();
        let mut map_key_addr = HashSet::new();
        let mut map_key_id = HashSet::new();
        let mut map_value_addr = HashSet::new();
        let mut map_value_wide = HashSet::new();
        let mut guardian_sets = HashMap::new();
        let mut next = 0u64;
        let mut keyed = 0u64;
        for item in &contract.items {
            if let Item::State(block) = item {
                for field in &block.fields {
                    if slots.contains_key(&field.name.text) {
                        continue;
                    }
                    let ty = field.ty.name.text.as_str();
                    slots.insert(field.name.text.clone(), next);
                    if KEYED_TYPES.contains(&ty) {
                        map_bases
                            .insert(field.name.text.clone(), KEYED_BASE + keyed * KEYED_STRIDE);
                        keyed += 1;
                        if matches!(
                            field.ty.args.first(),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == ADDR_TYPE
                        ) {
                            map_key_addr.insert(field.name.text.clone());
                        }
                        if matches!(
                            field.ty.args.first(),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == ID_TYPE
                        ) {
                            map_key_id.insert(field.name.text.clone());
                        }
                        if matches!(
                            field.ty.args.get(1),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == ADDR_TYPE
                        ) {
                            map_value_addr.insert(field.name.text.clone());
                        }
                        if matches!(
                            field.ty.args.get(1),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == WIDE_TYPE
                        ) {
                            map_value_wide.insert(field.name.text.clone());
                        }
                        next += 1;
                    } else if ty == WIDE_TYPE {
                        wide.insert(field.name.text.clone());
                        next += 1;
                    } else if ty == ADDR_TYPE {
                        addr.insert(field.name.text.clone());
                        next += ADDR_WORDS;
                    } else if ty == GUARDIAN_SET_TYPE {
                        let n = match field.ty.args.first() {
                            Some(quanta_ast::GenericArg::Int(i)) => {
                                i.text.replace('_', "").parse::<u64>().unwrap_or(0)
                            }
                            _ => 0,
                        };
                        let n = n.min(MAX_GUARDIAN_SET);
                        guardian_sets.insert(field.name.text.clone(), n);
                        next += n.saturating_mul(ADDR_WORDS);
                    } else {
                        next += 1;
                    }
                }
            }
        }
        Layout {
            slots,
            map_bases,
            wide,
            addr,
            map_key_addr,
            map_key_id,
            map_value_addr,
            map_value_wide,
            guardian_sets,
        }
    }

    pub fn guardian_set(&self, name: &str) -> Option<(u64, u64)> {
        let count = self.guardian_sets.get(name).copied()?;
        let base = self.slot(name)?;
        Some((base, count))
    }

    pub fn map_key_is_addr(&self, name: &str) -> bool {
        self.map_key_addr.contains(name)
    }

    pub fn map_key_is_id(&self, name: &str) -> bool {
        self.map_key_id.contains(name)
    }

    pub fn map_value_is_addr(&self, name: &str) -> bool {
        self.map_value_addr.contains(name)
    }

    pub fn map_value_is_wide(&self, name: &str) -> bool {
        self.map_value_wide.contains(name)
    }

    pub fn slot(&self, name: &str) -> Option<u64> {
        self.slots.get(name).copied()
    }

    pub fn map_base(&self, name: &str) -> Option<u64> {
        self.map_bases.get(name).copied()
    }

    pub fn all_state_slots(&self) -> Vec<u64> {
        let mut ordered: Vec<(&str, u64)> =
            self.slots.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        ordered.sort_by_key(|(_, slot)| *slot);
        let mut out = Vec::new();
        for (name, _) in ordered {
            self.field_slots(name, &mut out);
        }
        out
    }

    pub fn all_map_bases(&self) -> Vec<u64> {
        let mut bases: Vec<u64> = self.map_bases.values().copied().collect();
        bases.sort_unstable();
        bases
    }

    pub fn is_wide(&self, name: &str) -> bool {
        self.wide.contains(name)
    }

    pub fn is_addr(&self, name: &str) -> bool {
        self.addr.contains(name)
    }

    pub fn addr_slot(&self, name: &str, word: u64) -> Option<u64> {
        if self.is_addr(name) && word < ADDR_WORDS {
            self.slot(name).map(|slot| slot + word)
        } else {
            None
        }
    }

    pub fn hi_slot(&self, name: &str) -> Option<u64> {
        if self.is_wide(name) {
            self.slot(name).map(|slot| slot | HI_OFFSET)
        } else {
            None
        }
    }

    fn field_slots(&self, name: &str, out: &mut Vec<u64>) {
        let slot = match self.slot(name) {
            Some(slot) => slot,
            None => return,
        };
        if let Some((base, count)) = self.guardian_set(name) {
            for word in 0..count * ADDR_WORDS {
                out.push(base + word);
            }
        } else if self.is_addr(name) {
            for word in 0..ADDR_WORDS {
                out.push(slot + word);
            }
        } else {
            out.push(slot);
            if let Some(hi) = self.hi_slot(name) {
                out.push(hi);
            }
        }
    }

    pub fn access(&self, entry: &EntryDecl) -> StateAccess {
        let reads = self.all_state_slots();
        let keyed_reads = self.all_map_bases();
        let mut writes = Vec::new();
        let mut keyed_writes = Vec::new();
        for clause in &entry.clauses {
            if let Clause::Writes { names, .. } = clause {
                for name in names {
                    if let Some(base) = self.map_base(&name.text) {
                        keyed_writes.push(base);
                    } else {
                        self.field_slots(&name.text, &mut writes);
                    }
                }
            }
        }
        let touches_nonce = entry
            .params
            .iter()
            .any(|p| p.signed_by.is_some() || p.ty.name.text == "Quorum");
        if touches_nonce {
            keyed_writes.push(crate::lower::NONCE_TAG);
        }
        StateAccess {
            reads,
            writes,
            keyed_reads,
            keyed_writes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quanta_ast::Item;

    fn contract(src: &str) -> quanta_ast::Contract {
        quanta_parser::parse(src).expect("source parses").contracts[0].clone()
    }

    fn first_entry(c: &quanta_ast::Contract) -> &EntryDecl {
        c.items
            .iter()
            .find_map(|item| match item {
                Item::Entry(e) => Some(e),
                _ => None,
            })
            .expect("an entry")
    }

    #[test]
    fn slots_follow_declaration_order() {
        let c = contract("contract C { state { a: u64; b: u64; c: u128; } }");
        let layout = Layout::build(&c);
        assert_eq!(layout.slot("a"), Some(0));
        assert_eq!(layout.slot("b"), Some(1));
        assert_eq!(layout.slot("c"), Some(2));
        assert_eq!(layout.slot("missing"), None);
    }

    #[test]
    fn two_word_fields_are_marked_and_carry_a_distinct_high_word_slot() {
        let c = contract("contract C { state { a: u64; total: u128; owner: Q_Address; } }");
        let layout = Layout::build(&c);
        assert!(!layout.is_wide("a"));
        assert!(layout.is_wide("total"));
        assert!(!layout.is_wide("owner"));
        assert_eq!(layout.hi_slot("a"), None);
        let total_lo = layout.slot("total").unwrap();
        let total_hi = layout.hi_slot("total").unwrap();
        assert!(total_hi > super::KEYED_BASE);
        assert_ne!(total_hi, total_lo);
        let d = contract("contract D { state { x: u128; y: u128; } }");
        let dl = Layout::build(&d);
        assert_ne!(dl.hi_slot("x"), dl.hi_slot("y"));
    }

    #[test]
    fn keyed_fields_get_distinct_bases_above_the_scalar_slots() {
        let c = contract(
            "contract C { state { total: u128; balances: Map<Q_Address, u128>; \
             frozen: Registry<Q_Address>; } }",
        );
        let layout = Layout::build(&c);
        assert_eq!(layout.map_base("total"), None, "a scalar field has no base");
        let balances = layout.map_base("balances").expect("a keyed base");
        let frozen = layout.map_base("frozen").expect("a keyed base");
        assert!(balances >= super::KEYED_BASE);
        assert_ne!(balances, frozen, "distinct keyed fields never share a base");
    }

    #[test]
    fn a_map_value_of_address_is_marked() {
        let c = contract(
            "contract C { state { expiry_of: Map<Q_Address, u64>; \
             owner_of: Map<Q_Address, Q_Address>; } }",
        );
        let layout = Layout::build(&c);
        assert!(!layout.map_value_is_addr("expiry_of"));
        assert!(layout.map_value_is_addr("owner_of"));
        assert!(layout.map_key_is_addr("owner_of"));
    }

    #[test]
    fn a_map_value_of_the_wide_type_is_marked() {
        let c = contract(
            "contract C { state { holdings: Map<Q_Address, u64>; \
             balances: Map<Q_Address, u128>; } }",
        );
        let layout = Layout::build(&c);
        assert!(!layout.map_value_is_wide("holdings"));
        assert!(layout.map_value_is_wide("balances"));
        assert!(!layout.map_value_is_addr("balances"));
    }

    #[test]
    fn a_token_id_key_is_marked_and_carries_a_full_address_value() {
        let c = contract(
            "contract C { state { owner_of: Map<Q_Id, Q_Address>; holdings: Map<Q_Address, u64>; } }",
        );
        let layout = Layout::build(&c);
        assert!(layout.map_key_is_id("owner_of"));
        assert!(!layout.map_key_is_addr("owner_of"));
        assert!(layout.map_value_is_addr("owner_of"));
        assert!(!layout.map_key_is_id("holdings"));
        assert!(layout.map_key_is_addr("holdings"));
    }

    #[test]
    fn access_reads_broadly_and_writes_tightly() {
        let c = contract(
            "contract C { state { a: u64; b: u64; } entry e(x: u64) reads(a) writes(b) { } }",
        );
        let layout = Layout::build(&c);
        let access = layout.access(first_entry(&c));
        assert_eq!(access.reads, vec![0, 1]);
        assert_eq!(access.writes, vec![1]);
    }
}
