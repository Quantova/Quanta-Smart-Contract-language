//! Static checker for the Quanta language. It runs a fixed sequence of passes

mod conserve;
pub mod error;
mod linear;
mod model;
mod resolve;
mod signature;
mod types;

pub use error::TypeError;

use model::Model;
use quanta_ast::Program;

/// Checks a whole program. Returns the first error, or `Ok` when every contract
pub fn check(program: &Program) -> Result<(), TypeError> {
    for contract in &program.contracts {
        let model = Model::build(contract);
        resolve::check(&model)?;
        types::check(&model)?;
        linear::check(&model)?;
        signature::check(&model)?;
        conserve::check(&model)?;
    }
    Ok(())
}
