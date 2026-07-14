//! Shared view of one contract, indexed for the passes. Built once per contract

use quanta_ast::{Contract, EntryDecl, FieldDecl, GenericArg, Item, Type};
use std::collections::{HashMap, HashSet};

/// Native assets that exist without a local `asset` declaration.
const NATIVE_ASSETS: &[&str] = &["QTOV"];

pub struct Model<'a> {
    pub contract: &'a Contract,
    pub state: HashMap<&'a str, &'a FieldDecl>,
    pub entries: Vec<&'a EntryDecl>,
    declared_assets: HashSet<&'a str>,
    asset_universe: HashSet<String>,
}

impl<'a> Model<'a> {
    pub fn build(contract: &'a Contract) -> Model<'a> {
        let mut state = HashMap::new();
        let mut entries = Vec::new();
        let mut declared_assets = HashSet::new();
        let mut asset_universe: HashSet<String> =
            NATIVE_ASSETS.iter().map(|s| s.to_string()).collect();

        for item in &contract.items {
            match item {
                Item::Asset(a) => {
                    declared_assets.insert(a.name.text.as_str());
                    asset_universe.insert(a.name.text.clone());
                }
                Item::State(block) => {
                    for field in &block.fields {
                        state.insert(field.name.text.as_str(), field);
                        collect_asset_names(&field.ty, &mut asset_universe);
                    }
                }
                Item::Entry(e) => {
                    entries.push(e);
                    for param in &e.params {
                        collect_asset_names(&param.ty, &mut asset_universe);
                    }
                }
                Item::Event(_) | Item::Genesis(_) | Item::Invariant(_) => {}
            }
        }

        Model {
            contract,
            state,
            entries,
            declared_assets,
            asset_universe,
        }
    }

    pub fn is_state(&self, name: &str) -> bool {
        self.state.contains_key(name)
    }

    /// An asset name a `mints` or `burns` clause may name: it must be declared
    pub fn is_declared_asset(&self, name: &str) -> bool {
        self.declared_assets.contains(name)
    }

    /// An asset name a `conserves` clause may name: a declared asset, a native
    pub fn is_known_asset(&self, name: &str) -> bool {
        self.asset_universe.contains(name)
    }
}

fn collect_asset_names(ty: &Type, out: &mut HashSet<String>) {
    if ty.name.text == "Q_Asset" {
        if let Some(GenericArg::Type(inner)) = ty.args.first() {
            out.insert(inner.name.text.clone());
        }
    }
    for arg in &ty.args {
        if let GenericArg::Type(inner) = arg {
            collect_asset_names(inner, out);
        }
    }
}
