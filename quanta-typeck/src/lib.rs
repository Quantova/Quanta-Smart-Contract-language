// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::collapsible_match)]
#![allow(clippy::single_match)]
#![allow(clippy::unnecessary_map_or)]

mod access;
mod anchor;
mod asset_identity;
mod binding;
mod conserve;
pub mod error;
mod linear;
mod model;
mod resolve;
mod sealed;
mod signature;
mod types;

pub use error::TypeError;

use model::Model;
use quanta_ast::Program;

pub fn check(program: &Program) -> Result<(), TypeError> {
    for contract in &program.contracts {
        let model = Model::build(contract);
        resolve::check(&model)?;
        types::check(&model)?;
        linear::check(&model)?;
        signature::check(&model)?;
        anchor::check(&model)?;
        conserve::check(&model)?;
        asset_identity::check(&model)?;
        access::check(&model)?;
        binding::check(&model)?;
        sealed::check(&model)?;
    }
    Ok(())
}
