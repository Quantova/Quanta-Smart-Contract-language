// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs;
use std::path::{Path, PathBuf};

fn examples_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.push("examples");
    dir
}

fn qs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "qs").unwrap_or(false))
        .collect();
    files.sort();
    files
}

#[test]
fn every_example_lowers_to_a_container() {
    let files = qs_files(&examples_dir());
    assert_eq!(
        files.len(),
        22,
        "the example corpus has twenty two contracts"
    );
    for file in files {
        let src = fs::read_to_string(&file).unwrap();
        let program = quanta_parser::parse(&src)
            .unwrap_or_else(|e| panic!("{}: parse error: {}", file.display(), e.message));
        quanta_typeck::check(&program)
            .unwrap_or_else(|e| panic!("{}: the checker rejected it: {}", file.display(), e));
        let contracts = quanta_codegen::compile(&program)
            .unwrap_or_else(|e| panic!("{}: code generation failed: {}", file.display(), e));
        for cc in &contracts {
            assert!(
                !cc.container.code.is_empty(),
                "{}: {} produced an empty container",
                file.display(),
                cc.name
            );
        }
    }
}
