//! State layout. Each state field of a contract gets a storage slot, assigned in declaration order,

use qtv_vm::container::StateAccess;
use quanta_ast::{Clause, Contract, EntryDecl, Item};
use std::collections::{HashMap, HashSet};

/// Keyed field types. A `Map` or `Registry` holds one value per key, addressed at a base far above
const KEYED_TYPES: &[&str] = &["Map", "Registry"];
/// Base storage key of the first keyed field. It sits far above the scalar slots.
const KEYED_BASE: u64 = 1 << 40;
/// Gap between one keyed field's region and the next, wide enough that distinct fields never share a
const KEYED_STRIDE: u64 = 1 << 32;
/// The wide type that needs two machine words to hold. Its low word lives in the field's slot and its
const WIDE_TYPE: &str = "u128";
/// The address type, the full thirty two byte account address. It occupies four consecutive slots, so
const ADDR_TYPE: &str = "Q_Address";
/// The number of machine words a `Q_Address` field spans.
pub const ADDR_WORDS: u64 = 4;
/// A guardian set field, holding a fixed number of guardian addresses inline. Each guardian is a full
const GUARDIAN_SET_TYPE: &str = "GuardianSet";
/// The offset that separates the high word of a two word scalar field from its low word. It sits far
const HI_OFFSET: u64 = 1 << 56;

/// The storage slot assigned to each state field, keyed by field name. A keyed field also records the
pub struct Layout {
    slots: HashMap<String, u64>,
    map_bases: HashMap<String, u64>,
    wide: HashSet<String>,
    addr: HashSet<String>,
    /// Keyed fields whose key type is `Q_Address`, so a key expression handed to one is read as a full
    map_key_addr: HashSet<String>,
    /// Keyed fields whose value type is `Q_Address`, so an entry holds a full thirty two byte address
    map_value_addr: HashSet<String>,
    /// Guardian set fields, each mapped to the number of guardians it holds. A `GuardianSet<N>` field
    guardian_sets: HashMap<String, u64>,
}

impl Layout {
    /// Assigns a slot to every state field, in declaration order across all state blocks, and a keyed
    pub fn build(contract: &Contract) -> Layout {
        let mut slots = HashMap::new();
        let mut map_bases = HashMap::new();
        let mut wide = HashSet::new();
        let mut addr = HashSet::new();
        let mut map_key_addr = HashSet::new();
        let mut map_value_addr = HashSet::new();
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
                        // A keyed field whose first type argument is `Q_Address` keys on a full address.
                        if matches!(
                            field.ty.args.first(),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == ADDR_TYPE
                        ) {
                            map_key_addr.insert(field.name.text.clone());
                        }
                        if matches!(
                            field.ty.args.get(1),
                            Some(quanta_ast::GenericArg::Type(t)) if t.name.text == ADDR_TYPE
                        ) {
                            map_value_addr.insert(field.name.text.clone());
                        }
                        next += 1;
                    } else if ty == WIDE_TYPE {
                        wide.insert(field.name.text.clone());
                        next += 1;
                    } else if ty == ADDR_TYPE {
                        // A full address occupies four consecutive slots, so the field after it starts
                        // past its four words and never overlaps them.
                        addr.insert(field.name.text.clone());
                        next += ADDR_WORDS;
                    } else if ty == GUARDIAN_SET_TYPE {
                        // A guardian set holds a fixed number of guardian addresses inline, so it
                        // occupies that many address spans and the field after it starts past them all.
                        let n = match field.ty.args.first() {
                            Some(quanta_ast::GenericArg::Int(i)) => {
                                i.text.replace('_', "").parse::<u64>().unwrap_or(0)
                            }
                            _ => 0,
                        };
                        guardian_sets.insert(field.name.text.clone(), n);
                        next += n * ADDR_WORDS;
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
            map_value_addr,
            guardian_sets,
        }
    }

    /// The base slot and the guardian count of a guardian set field, if the name is one. Guardian `j`
    pub fn guardian_set(&self, name: &str) -> Option<(u64, u64)> {
        let count = self.guardian_sets.get(name).copied()?;
        let base = self.slot(name)?;
        Some((base, count))
    }

    /// Whether a keyed field keys on a full `Q_Address`, so a key expression handed to it is a whole
    pub fn map_key_is_addr(&self, name: &str) -> bool {
        self.map_key_addr.contains(name)
    }

    /// Whether a keyed field holds a full `Q_Address` value, stored across four one word slots derived
    pub fn map_value_is_addr(&self, name: &str) -> bool {
        self.map_value_addr.contains(name)
    }

    /// The slot of a state field, if the name is one.
    pub fn slot(&self, name: &str) -> Option<u64> {
        self.slots.get(name).copied()
    }

    /// The base storage key of a keyed field, if the name is a `Map` or `Registry`.
    pub fn map_base(&self, name: &str) -> Option<u64> {
        self.map_bases.get(name).copied()
    }

    /// Whether a scalar state field is a two word field, held across a low and a high machine word.
    pub fn is_wide(&self, name: &str) -> bool {
        self.wide.contains(name)
    }

    /// Whether a state field is a full address field, held across four consecutive machine words.
    pub fn is_addr(&self, name: &str) -> bool {
        self.addr.contains(name)
    }

    /// The slot holding word `word` of a `Q_Address` field, if the name is one. Word zero is the
    pub fn addr_slot(&self, name: &str, word: u64) -> Option<u64> {
        if self.is_addr(name) && word < ADDR_WORDS {
            self.slot(name).map(|slot| slot + word)
        } else {
            None
        }
    }

    /// The storage slot of the high word of a two word field, if the name is a two word field. The low
    pub fn hi_slot(&self, name: &str) -> Option<u64> {
        if self.is_wide(name) {
            self.slot(name).map(|slot| slot | HI_OFFSET)
        } else {
            None
        }
    }

    /// Appends every storage slot a named field occupies to `out`: a plain field its one slot, a two
    fn field_slots(&self, name: &str, out: &mut Vec<u64>) {
        let slot = match self.slot(name) {
            Some(slot) => slot,
            None => return,
        };
        if self.is_addr(name) {
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

    /// The state access manifest of an entry, built from its reads and writes clauses. The checker
    pub fn access(&self, entry: &EntryDecl) -> StateAccess {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for clause in &entry.clauses {
            match clause {
                Clause::Reads { names, .. } => {
                    for name in names {
                        self.field_slots(&name.text, &mut reads);
                    }
                }
                Clause::Writes { names, .. } => {
                    for name in names {
                        self.field_slots(&name.text, &mut writes);
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
    fn two_word_fields_are_marked_and_carry_a_distinct_high_word_slot() {
        let c = contract("contract C { state { a: u64; total: u128; owner: Q_Address; } }");
        let layout = Layout::build(&c);
        assert!(!layout.is_wide("a"));
        assert!(layout.is_wide("total"));
        assert!(!layout.is_wide("owner"));
        // The low word stays at the plain slot; the high word sits far above every slot.
        assert_eq!(layout.hi_slot("a"), None);
        let total_lo = layout.slot("total").unwrap();
        let total_hi = layout.hi_slot("total").unwrap();
        assert!(total_hi > super::KEYED_BASE);
        assert_ne!(total_hi, total_lo);
        // Distinct two word fields never share a high word slot.
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
