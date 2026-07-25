// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The browser binding for the Quanta compiler.

use wasm_bindgen::prelude::*;

/// Compile Quanta source and return the compiler's JSON document. On success it carries every contract
#[wasm_bindgen]
pub fn compile(source: &str) -> String {
    quanta_emit::compile_json(source).json
}
