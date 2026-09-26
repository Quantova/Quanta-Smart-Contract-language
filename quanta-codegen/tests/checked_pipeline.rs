// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs;
use std::path::PathBuf;

use quanta_codegen::{compile, compile_contract};

fn exploits() -> Vec<(PathBuf, String)> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.push("tests");
    dir.push("exploits");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "qs").unwrap_or(false))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let src = fs::read_to_string(&p).unwrap();
            (p, src)
        })
        .collect()
}

#[test]
fn codegen_refuses_every_exploit_even_when_the_checker_is_skipped() {
    let all = exploits();
    assert!(!all.is_empty());
    for (path, src) in all {
        let program = quanta_parser::parse(&src).unwrap();
        assert!(compile(&program).is_err(), "{}", path.display());
        for contract in &program.contracts {
            assert!(compile_contract(contract).is_err(), "{}", path.display());
        }
    }
}

#[test]
fn two_incoming_asset_parameters_are_refused() {
    let src = "contract Double {\n\
  state { vault: Q_Asset<QTOV>; }\n\
  entry fund(a: Q_Asset<QTOV>, b: Q_Asset<QTOV>) conserves QTOV writes(vault) { guard in_asset == native; vault.merge(a); vault.merge(b); }\n\
}\n";
    let program = quanta_parser::parse(src).unwrap();
    let error = quanta_typeck::check(&program).unwrap_err();
    assert!(
        error
            .message
            .contains("more than one incoming asset parameter"),
        "{}",
        error.message
    );
    assert!(compile(&program).is_err());
}

#[test]
fn a_bare_structured_parameter_is_refused() {
    let src = "contract Bare {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry bump(order: BumpOrder signed by owner) writes(count) { count = order; }\n\
}\n";
    let program = quanta_parser::parse(src).unwrap();
    assert!(compile(&program).is_err());
}
