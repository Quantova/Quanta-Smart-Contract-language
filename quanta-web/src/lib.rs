// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn compile(source: &str) -> String {
    quanta_emit::compile_json(source).json
}
