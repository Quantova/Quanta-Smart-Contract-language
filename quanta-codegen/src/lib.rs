//! Code generation. Lowers a type checked Quanta contract to the register machine bytecode

pub mod emit;
pub mod error;
pub mod layout;
pub mod lower;
pub mod selector;

pub use error::CodegenError;
