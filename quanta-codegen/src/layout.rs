//! State layout. Each state field of a contract gets a storage slot, assigned in declaration order,

use qtv_vm::container::StateAccess;
use quanta_ast::{Clause, Contract, EntryDecl, Item};
use std::collections::HashMap;

/// Keyed field types. A `Map` or `Registry` holds one value per key, addressed at a base far above
const KEYED_TYPES: &[&str] = &["Map", "Registry"];
/// Base storage key of the first keyed field. It sits far above the scalar slots.
const KEYED_BASE: u64 = 1 << 40;
/// Gap between one keyed field's region and the next, wide enough that distinct fields never share a
const KEYED_STRIDE: u64 = 1 << 32;

/// The storage slot assigned to each state field, keyed by field name. A keyed field also records the
pub struct Layout {
    slots: HashMap<String, u64>,
    map_bases: HashMap<String, u64>,
}

impl Layout {
    /// Assigns a slot to every state field, in declaration order across all state blocks, and a keyed
    pub fn build(contract: &Contract) -> Layout {
        let mut slots = HashMap::new();
        let mut map_bases = HashMap::new();
        let mut next = 0u64;
        let mut keyed = 0u64;
        for item in &contract.items {
            if let Item::State(block) = item {
                for field in &block.fields {
                    if !slots.contains_key(&field.name.text) {
                        slots.insert(field.name.text.clone(), next);
                        next += 1;
                        if KEYED_TYPES.contains(&field.ty.name.text.as_str()) {
                            map_bases
                                .insert(field.name.text.clone(), KEYED_BASE + keyed * KEYED_STRIDE);
                            keyed += 1;
                        }
                    }
                }
            }
        }
        Layout { slots, map_bases }
    }

    /// The slot of a state field, if the name is one.
    pub fn slot(&self, name: &str) -> Option<u64> {
        self.slots.get(name).copied()
    }

    /// The base storage key of a keyed field, if the name is a `Map` or `Registry`.
    pub fn map_base(&self, name: &str) -> Option<u64> {
        self.map_bases.get(name).copied()
    }

    /// The state access manifest of an entry, built from its reads and writes clauses. The checker
    pub fn access(&self, entry: &EntryDecl) -> StateAccess {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for clause in &entry.clauses {
            match clause {
                Clause::Reads { names, .. } => {
                    for name in names {
                        if let Some(slot) = self.slot(&name.text) {
                            reads.push(slot);
                        }
                    }
                }
                Clause::Writes { names, .. } => {
                    for name in names {
                        if let Some(slot) = self.slot(&name.text) {
                            writes.push(slot);
                        }
                    }
                }
                _ => {}
            }
        }
        StateAccess { reads, writes }
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
    fn access_maps_reads_and_writes_to_slots() {
        let c = contract(
            "contract C { state { a: u64; b: u64; } entry e(x: u64) reads(a) writes(b) { } }",
        );
        let layout = Layout::build(&c);
        let access = layout.access(first_entry(&c));
        assert_eq!(access.reads, vec![0]);
        assert_eq!(access.writes, vec![1]);
    }
}
