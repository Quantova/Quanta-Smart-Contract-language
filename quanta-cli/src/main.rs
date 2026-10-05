// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod tree;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: quanta-cli <parse|fmt|tokens|check|build|emit> <file>");
        exit(2);
    }
    let command = args[1].as_str();
    let path = args[2].as_str();

    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            exit(2);
        }
    };

    match command {
        "parse" => match quanta_parser::parse(&src) {
            Ok(program) => print!("{}", tree::render(&program)),
            Err(e) => {
                report(path, &src, &e.message, e.span.start);
                exit(1);
            }
        },
        "fmt" => match quanta_parser::parse(&src) {
            Ok(program) => print!("{}", quanta_ast::pretty(&program)),
            Err(e) => {
                report(path, &src, &e.message, e.span.start);
                exit(1);
            }
        },
        "check" => match quanta_parser::parse(&src) {
            Ok(program) => match quanta_typeck::check(&program) {
                Ok(()) => println!("ok"),
                Err(e) => {
                    report(path, &src, &e.message, e.span.start);
                    exit(1);
                }
            },
            Err(e) => {
                report(path, &src, &e.message, e.span.start);
                exit(1);
            }
        },
        "build" => match quanta_parser::parse(&src) {
            Ok(program) => {
                if let Err(e) = quanta_typeck::check(&program) {
                    report(path, &src, &e.message, e.span.start);
                    exit(1);
                }
                match quanta_codegen::compile(&program) {
                    Ok(contracts) => build(path, &contracts),
                    Err(e) => {
                        report(path, &src, &e.to_string(), e.span().start);
                        exit(1);
                    }
                }
            }
            Err(e) => {
                report(path, &src, &e.message, e.span.start);
                exit(1);
            }
        },
        "emit" => {
            let mut seed = match provenance_seed() {
                Ok(seed) => seed,
                Err(e) => {
                    eprintln!("error: {e}");
                    exit(2);
                }
            };
            let emit = match &seed {
                Some(seed) => quanta_emit::compile_json_with(&src, |cc| attest(seed, cc)),
                None => quanta_emit::compile_json(&src),
            };
            if let Some(s) = seed.as_mut() {
                use zeroize::Zeroize;
                s.zeroize();
            }
            println!("{}", emit.json);
            if !emit.ok {
                exit(1);
            }
        }
        "tokens" => match quanta_lexer::tokenize(&src) {
            Ok(tokens) => {
                for t in tokens {
                    println!("{:>4}..{:<4} {:?}", t.span.start, t.span.end, t.kind);
                }
            }
            Err(e) => {
                report(path, &src, &e.message, e.span.start);
                exit(1);
            }
        },
        other => {
            eprintln!("error: unknown command `{other}`");
            eprintln!("usage: quanta-cli <parse|fmt|tokens|check|build|emit> <file>");
            exit(2);
        }
    }
}

fn build(path: &str, contracts: &[quanta_codegen::CompiledContract]) {
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut seed = match provenance_seed() {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("error: {e}");
            exit(2);
        }
    };
    for cc in contracts {
        let out = dir.join(format!("{}.qbc", cc.name));
        let bytes = match &seed {
            Some(seed) => match attest(seed, cc) {
                Some(bytes) => bytes,
                None => {
                    eprintln!("error: cannot attest {}", out.display());
                    exit(2);
                }
            },
            None => cc.container.canonical_bytes(),
        };
        if let Err(e) = std::fs::write(&out, &bytes) {
            eprintln!("error: cannot write {}: {e}", out.display());
            exit(2);
        }
        println!("wrote {} ({} bytes)", out.display(), bytes.len());
        for entry in &cc.entries {
            println!("  entry {}", entry.signature);
        }
        for event in &cc.events {
            println!("  event {}", event.signature);
        }
    }
    if let Some(s) = seed.as_mut() {
        use zeroize::Zeroize;
        s.zeroize();
    }
}

fn attest(seed: &[u8; 32], cc: &quanta_codegen::CompiledContract) -> Option<Vec<u8>> {
    use zeroize::Zeroize;
    let (_, mut sk) = qtv_crypto::ml_dsa::keygen(seed);
    let signature = qtv_crypto::ml_dsa::sign_os(
        &sk,
        &cc.container.identifier(),
        b"QUANTOVA/QVM/PROVENANCE/v1",
    );
    sk.zeroize();
    let mut bytes = cc.container.canonical_bytes();
    bytes.extend_from_slice(b"QPRV");
    bytes.extend_from_slice(&signature?);
    Some(bytes)
}

fn provenance_seed() -> Result<Option<[u8; 32]>, String> {
    let hex = match std::env::var("QUANTA_PROVENANCE_SEED") {
        Ok(hex) => hex,
        Err(_) => return Ok(None),
    };
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("QUANTA_PROVENANCE_SEED must be 64 hex characters".to_string());
    }
    let bytes = hex.as_bytes();
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]).unwrap_or("");
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| "QUANTA_PROVENANCE_SEED is not valid hex".to_string())?;
    }
    Ok(Some(seed))
}

fn report(path: &str, src: &str, message: &str, offset: usize) {
    let (line, col) = line_col(src, offset);
    eprintln!("error: {message}");
    eprintln!("  --> {path}:{line}:{col}");
}

fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in src.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}
