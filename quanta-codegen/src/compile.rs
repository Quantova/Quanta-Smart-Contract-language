// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::emit::{Builder, LinkError};
use crate::error::CodegenError;
use crate::layout::{Layout, ADDR_WORDS};
use crate::lower::{lower_entry, EventSig};
use crate::selector::{entry_selector, entry_signature, event_selector, event_signature};
use qtv_vm::container::{Container, Entry, SELECTOR_BYTES};
use qtv_vm::isa::Instr;
use quanta_ast::{
    AssignOp, Contract, EntryDecl, EventDecl, Expr, Ident, Item, Program, Stmt, Type,
};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledContract {
    pub name: String,
    pub container: Container,
    pub entries: Vec<EntryArtifact>,
    pub events: Vec<EventArtifact>,
    pub deploy_params: Vec<DeployParamArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployParamArtifact {
    pub key: String,
    pub offset: u64,
    pub width: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryArtifact {
    pub name: String,
    pub signature: String,
    pub selector: [u8; SELECTOR_BYTES],
    pub args: Vec<ArgSlot>,
    /// Names of the parameters declared `sealed`. Their bytes travel under key encapsulation and are
    pub sealed_params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSlot {
    pub key: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventArtifact {
    pub name: String,
    pub signature: String,
    pub selector: [u8; SELECTOR_BYTES],
}

pub fn compile(program: &Program) -> Result<Vec<CompiledContract>, CodegenError> {
    program.contracts.iter().map(compile_contract).collect()
}

fn event_field_words(ev: &EventDecl) -> Vec<u64> {
    ev.params.iter().map(|p| type_words(&p.ty)).collect()
}

fn type_words(ty: &Type) -> u64 {
    match ty.name.text.as_str() {
        "Q_Address" => ADDR_WORDS,
        "u128" | "i128" => 2,
        _ => 1,
    }
}

pub fn compile_contract(contract: &Contract) -> Result<CompiledContract, CodegenError> {
    let entries: Vec<&EntryDecl> = contract
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Entry(entry) => Some(entry),
            _ => None,
        })
        .collect();
    compile_entries(contract, &entries)
}

fn compile_entries(
    contract: &Contract,
    entries: &[&EntryDecl],
) -> Result<CompiledContract, CodegenError> {
    let layout = Layout::build(contract);
    crate::lower::check_anchor_state_writes(contract, &layout)?;
    let invariants: Vec<&quanta_ast::Expr> = contract
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Invariant(inv) => Some(&inv.expr),
            _ => None,
        })
        .collect();

    let events_map: HashMap<String, EventSig> = contract
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Event(ev) => Some((
                ev.name.text.clone(),
                EventSig {
                    selector: u32::from_be_bytes(event_selector(ev)),
                    field_words: event_field_words(ev),
                },
            )),
            _ => None,
        })
        .collect();

    let mut b = Builder::new();
    let trap = b.label();

    let mut artifacts = Vec::new();
    let mut placed = Vec::new();
    let mut deploy_params = Vec::new();
    for entry in entries {
        let start = b.label();
        b.mark(start);
        let args = lower_entry(&layout, entry, &invariants, &events_map, &mut b, trap, false)?;
        let selector = entry_selector(entry);
        placed.push((selector, layout.access(entry), start));
        artifacts.push(EntryArtifact {
            name: entry.name.text.clone(),
            signature: entry_signature(entry),
            selector,
            args: args
                .layout()
                .into_iter()
                .map(|(key, offset)| ArgSlot { key, offset })
                .collect(),
            sealed_params: entry
                .params
                .iter()
                .filter(|p| p.sealed)
                .map(|p| p.name.text.clone())
                .collect(),
        });
    }

    let state_block = contract.items.iter().find_map(|item| match item {
        Item::State(sb) => Some(sb),
        _ => None,
    });
    let default_assigns: Vec<Stmt> = state_block
        .map(|sb| {
            sb.fields
                .iter()
                .filter_map(|f| {
                    f.default.as_ref().map(|value| Stmt::Assign {
                        target: Expr::Ident(f.name.clone()),
                        op: AssignOp::Set,
                        value: value.clone(),
                        span: f.span,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let genesis_block = contract.items.iter().find_map(|item| match item {
        Item::Genesis(g) => Some(g),
        _ => None,
    });
    if genesis_block.is_some() || !default_assigns.is_empty() {
        let gspan = genesis_block
            .map(|g| g.span)
            .or_else(|| state_block.map(|sb| sb.span))
            .unwrap_or_default();
        let mut body = default_assigns;
        if let Some(g) = genesis_block {
            body.extend(g.body.clone());
        }
        let synthetic = EntryDecl {
            name: Ident {
                text: "@genesis".to_string(),
                span: gspan,
            },
            params: Vec::new(),
            clauses: Vec::new(),
            body,
            span: gspan,
        };
        let start = b.label();
        b.mark(start);
        let genesis_args = lower_entry(&layout, &synthetic, &[], &events_map, &mut b, trap, true)?;
        deploy_params = genesis_args
            .deploy_params()
            .iter()
            .map(|slot| DeployParamArtifact {
                key: slot.key.clone(),
                offset: slot.offset,
                width: slot.width,
            })
            .collect();
        let selector = qtv_vm::container::selector(qtv_vm::container::GENESIS_SIGNATURE);
        // Genesis is the constructor, it initialises the whole state and may seed any map, so it
        // declares every scalar slot and its init guard as writes, and every map base as a keyed domain.
        // This is a real manifest, it lists exactly the contract's own storage, not a bypass.
        let mut genesis_writes = layout.all_state_slots();
        genesis_writes.push(crate::lower::GENESIS_INIT_GUARD_SLOT);
        let genesis_access = qtv_vm::container::StateAccess {
            reads: vec![crate::lower::GENESIS_INIT_GUARD_SLOT],
            writes: genesis_writes,
            keyed_reads: layout.all_map_bases(),
            keyed_writes: layout.all_map_bases(),
        };
        placed.push((selector, genesis_access, start));
    }

    b.mark(trap);
    b.op(Instr::Ldi { d: 0, imm: 0 });
    b.op(Instr::Div { d: 0, a: 0, b: 0 });

    let (code, offsets) = b.link_with_offsets().map_err(CodegenError::Link)?;

    let mut container_entries = Vec::new();
    for (selector, access, start) in placed {
        let offset = offsets
            .get(start as usize)
            .copied()
            .flatten()
            .ok_or(CodegenError::Link(LinkError::UnplacedLabel(start)))?;
        container_entries.push(Entry {
            selector,
            offset,
            access,
        });
    }

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
        entries: artifacts,
        events,
        deploy_params,
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
        // Reads are broad, the contract's one scalar field.
        assert_eq!(cc.container.entries[0].access.reads, vec![0]);
    }

    #[test]
    fn the_argument_layout_reserves_the_context_words_then_the_parameters() {
        let cc = compile_one(METER);
        assert_eq!(
            cc.entries[0].args,
            vec![
                ArgSlot {
                    key: "@caller".to_string(),
                    offset: 0,
                },
                ArgSlot {
                    key: "@contract".to_string(),
                    offset: 32,
                },
                ArgSlot {
                    key: "@time".to_string(),
                    offset: 64,
                },
                ArgSlot {
                    key: "@chain".to_string(),
                    offset: 72,
                },
                ArgSlot {
                    key: "step".to_string(),
                    offset: 80,
                },
            ]
        );
    }

    #[test]
    fn the_event_selector_is_recorded() {
        let cc = compile_one(METER);
        assert_eq!(cc.events.len(), 1);
        assert_eq!(cc.events[0].signature, "Advanced(u64)");
        assert_eq!(cc.events[0].selector, vm_selector("Advanced(u64)"));
    }

    const TWO: &str = "contract Two { state { a: u64; b: u64; } \
        entry one(x: u64) writes(a) { a = x; } \
        entry two(y: u64) writes(b) { b = y; } }";

    #[test]
    fn the_first_entry_begins_at_offset_zero() {
        let cc = compile_one(TWO);
        assert_eq!(cc.container.entries[0].offset, 0);
    }

    #[test]
    fn a_later_entry_begins_where_its_code_starts() {
        let cc = compile_one(TWO);
        let second = cc.container.entries[1].offset;
        assert_ne!(second, 0, "the second entry does not begin at zero");
        assert_eq!(
            cc.container.entry_offset(&vm_selector("two(u64)")),
            Some(second)
        );
    }

    #[test]
    fn an_unknown_selector_has_no_entry_offset() {
        let cc = compile_one(TWO);
        assert_eq!(cc.container.entry_offset(&vm_selector("three(u64)")), None);
    }

    #[test]
    fn the_container_identifier_is_stable() {
        assert_eq!(
            compile_one(METER).container.identifier(),
            compile_one(METER).container.identifier()
        );
    }
}
