// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Abstract syntax tree for the Quanta language.

pub mod ast;
pub mod print;

pub use ast::*;
pub use print::pretty;
