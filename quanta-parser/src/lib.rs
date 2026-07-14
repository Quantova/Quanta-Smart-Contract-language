//! Hand written recursive descent parser for the Quanta language.

mod decl;
pub mod error;
mod expr;
mod parser;
mod program;
mod stmt;
mod ty;

pub use decl::parse_item;
pub use error::ParseError;
pub use expr::parse_expr;
pub use program::parse;
pub use stmt::parse_stmt;
pub use ty::parse_type;
