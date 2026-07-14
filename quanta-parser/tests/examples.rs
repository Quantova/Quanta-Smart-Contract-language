//! End to end checks over the example corpus.

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
fn there_are_seventeen_examples() {
    assert_eq!(qs_files(&examples_dir()).len(), 17);
}

#[test]
fn every_example_lexes_and_parses() {
    for file in qs_files(&examples_dir()) {
        let src = fs::read_to_string(&file).unwrap();
        quanta_lexer::tokenize(&src)
            .unwrap_or_else(|e| panic!("{}: lex error: {}", file.display(), e.message));
        quanta_parser::parse(&src)
            .unwrap_or_else(|e| panic!("{}: parse error: {}", file.display(), e.message));
    }
}

#[test]
fn parse_print_parse_yields_the_same_tree() {
    // The canonical printer depends only on tree structure, never on spans, so
    // equal printed forms witness structurally identical trees.
    for file in qs_files(&examples_dir()) {
        let src = fs::read_to_string(&file).unwrap();
        let first = quanta_parser::parse(&src).unwrap();
        let printed = quanta_ast::pretty(&first);
        let second = quanta_parser::parse(&printed)
            .unwrap_or_else(|e| panic!("{}: reparse error: {}", file.display(), e.message));
        assert_eq!(
            printed,
            quanta_ast::pretty(&second),
            "{}: tree changed across a print and reparse",
            file.display()
        );
    }
}

#[test]
fn each_forbidden_token_is_rejected() {
    for word in quanta_lexer::FORBIDDEN {
        let src = format!("contract C {{ entry f(x: {word}) {{ }} }}");
        assert!(
            quanta_parser::parse(&src).is_err(),
            "forbidden token `{word}` must not parse"
        );
    }
}

#[test]
fn a_malformed_contract_reports_a_span() {
    let err = quanta_parser::parse("contract C { entry f( { } }").unwrap_err();
    assert!(err.span.end >= err.span.start);
    assert!(!err.message.is_empty());
}
