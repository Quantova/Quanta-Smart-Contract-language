// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::container::{selector as vm_selector, SELECTOR_BYTES};
use quanta_ast::{EntryDecl, EventDecl, GenericArg, Type};

pub fn entry_signature(entry: &EntryDecl) -> String {
    signature(&entry.name.text, entry.params.iter().map(|p| &p.ty))
}

pub fn event_signature(event: &EventDecl) -> String {
    signature(&event.name.text, event.params.iter().map(|p| &p.ty))
}

fn signature<'a>(name: &str, types: impl Iterator<Item = &'a Type>) -> String {
    let joined = types.map(type_string).collect::<Vec<_>>().join(",");
    format!("{name}({joined})")
}

pub fn type_string(ty: &Type) -> String {
    if ty.args.is_empty() {
        return ty.name.text.clone();
    }
    let args = ty.args.iter().map(arg_string).collect::<Vec<_>>().join(",");
    format!("{}<{}>", ty.name.text, args)
}

fn arg_string(arg: &GenericArg) -> String {
    match arg {
        GenericArg::Type(t) => type_string(t),
        GenericArg::Int(i) => i.text.clone(),
        GenericArg::MofN { m, n, .. } => format!("{} of {}", m.text, n.text),
    }
}

pub fn entry_selector(entry: &EntryDecl) -> [u8; SELECTOR_BYTES] {
    vm_selector(&entry_signature(entry))
}

pub fn event_selector(event: &EventDecl) -> [u8; SELECTOR_BYTES] {
    vm_selector(&event_signature(event))
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
    fn scalar_entry_signature_names_the_type() {
        let c = contract("contract C { entry advance(step: u64) writes(x) { } state { x: u64; } }");
        assert_eq!(entry_signature(first_entry(&c)), "advance(u64)");
    }

    #[test]
    fn generic_type_renders_its_arguments() {
        let c = contract("contract C { entry transfer(funds: Q_Asset<TKN>, to: Q_Address) { } }");
        assert_eq!(
            entry_signature(first_entry(&c)),
            "transfer(Q_Asset<TKN>,Q_Address)"
        );
    }

    #[test]
    fn selector_is_deterministic_and_distinguishes_names() {
        let c = contract("contract C { entry advance(step: u64) writes(x) { } state { x: u64; } }");
        let e = first_entry(&c);
        assert_eq!(entry_selector(e), entry_selector(e));
        assert_ne!(vm_selector("advance(u64)"), vm_selector("retreat(u64)"));
    }
}
