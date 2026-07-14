//! Contract compilation. Lowers every entry of a contract into one code image, embeds the entry

use crate::emit::Builder;
use crate::error::CodegenError;
use crate::layout::Layout;
use crate::lower::lower_entry;
use crate::selector::{entry_selector, entry_signature, event_selector, event_signature};
use qtv_vm::container::{Container, Entry, SELECTOR_BYTES};
use qtv_vm::isa::Instr;
use quanta_ast::{Contract, Item, Program};

/// A compiled contract: the loadable container plus the interface facts a caller needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledContract {
    pub name: String,
    pub container: Container,
    pub entries: Vec<EntryArtifact>,
    pub events: Vec<EventArtifact>,
}

/// One entry of the interface, with the scratch memory layout of its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryArtifact {
    pub name: String,
    pub signature: String,
    pub selector: [u8; SELECTOR_BYTES],
    pub args: Vec<ArgSlot>,
}

/// An argument value and the scratch memory offset it is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSlot {
    pub key: String,
    pub offset: u64,
}

/// One event of the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventArtifact {
    pub name: String,
    pub signature: String,
    pub selector: [u8; SELECTOR_BYTES],
}

/// Compiles every contract in a program.
pub fn compile(program: &Program) -> Result<Vec<CompiledContract>, CodegenError> {
    program.contracts.iter().map(compile_contract).collect()
}

/// Compiles one contract to its container and interface.
pub fn compile_contract(contract: &Contract) -> Result<CompiledContract, CodegenError> {
    let layout = Layout::build(contract);
    let mut b = Builder::new();
    let trap = b.label();

    let mut entries = Vec::new();
    let mut container_entries = Vec::new();
    for item in &contract.items {
        if let Item::Entry(entry) = item {
            let args = lower_entry(&layout, entry, &mut b, trap)?;
            let selector = entry_selector(entry);
            container_entries.push(Entry {
                selector,
                access: layout.access(entry),
            });
            entries.push(EntryArtifact {
                name: entry.name.text.clone(),
                signature: entry_signature(entry),
                selector,
                args: args
                    .layout()
                    .into_iter()
                    .map(|(key, offset)| ArgSlot { key, offset })
                    .collect(),
            });
        }
    }

    // Shared revert trap. A guard or invariant that fails jumps here and the divide by zero faults,
    // which rolls back every state change of the call.
    b.mark(trap);
    b.op(Instr::Ldi { d: 0, imm: 0 });
    b.op(Instr::Div { d: 0, a: 0, b: 0 });

    let code = b.link().map_err(CodegenError::Link)?;

    let events = contract
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Event(ev) => Some(EventArtifact {
                name: ev.name.text.clone(),
                signature: event_signature(ev),
                selector: event_selector(ev),
            }),
            _ => None,
        })
        .collect();

    Ok(CompiledContract {
        name: contract.name.text.clone(),
        container: Container::new(code, Vec::new(), container_entries),
        entries,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_vm::container::selector as vm_selector;

    const METER: &str = "contract Meter { state { reading: u64; } \
        entry advance(step: u64) writes(reading) { \
        guard step > 0; reading = checked(reading + step); emit Advanced(reading); } \
        event Advanced(value: u64); }";

    fn compile_one(src: &str) -> CompiledContract {
        let program = quanta_parser::parse(src).expect("parse");
        quanta_typeck::check(&program).expect("typecheck");
        let mut out = compile(&program).expect("compile");
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    #[test]
    fn meter_compiles_to_a_container() {
        let cc = compile_one(METER);
        assert_eq!(cc.name, "Meter");
        assert!(!cc.container.code.is_empty());
    }

    #[test]
    fn the_entry_carries_its_selector_and_writes() {
        let cc = compile_one(METER);
        assert_eq!(cc.container.entries.len(), 1);
        assert_eq!(
            cc.container.entries[0].selector,
            vm_selector("advance(u64)")
        );
        assert_eq!(cc.container.entries[0].access.writes, vec![0]);
        assert!(cc.container.entries[0].access.reads.is_empty());
    }

    #[test]
    fn the_argument_layout_places_the_step_at_the_base() {
        let cc = compile_one(METER);
        assert_eq!(
            cc.entries[0].args,
            vec![ArgSlot {
                key: "step".to_string(),
                offset: 0,
            }]
        );
    }

    #[test]
    fn the_event_selector_is_recorded() {
        let cc = compile_one(METER);
        assert_eq!(cc.events.len(), 1);
        assert_eq!(cc.events[0].signature, "Advanced(u64)");
        assert_eq!(cc.events[0].selector, vm_selector("Advanced(u64)"));
    }

    #[test]
    fn the_container_identifier_is_stable() {
        assert_eq!(
            compile_one(METER).container.identifier(),
            compile_one(METER).container.identifier()
        );
    }
}
