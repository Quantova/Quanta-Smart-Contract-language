//! Static checker for the Quanta language. It runs a fixed sequence of passes

pub mod error;

pub use error::TypeError;

use quanta_ast::Program;

/// Checks a whole program. Returns the first error, or `Ok` when every contract
pub fn check(program: &Program) -> Result<(), TypeError> {
    for _contract in &program.contracts {
        // Passes are wired in as they are added.
    }
    Ok(())
}
