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
                    Ok(contracts) => build(path, src.as_bytes(), &contracts),
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
            let seed = match provenance_key() {
                Ok(seed) => seed,
                Err(e) => {
                    eprintln!("error: {e}");
                    exit(2);
                }
            };
            let emit = match &seed {
                Some(seed) => {
                    quanta_emit::compile_json_with(&src, |cc| attest(seed, src.as_bytes(), cc))
                }
                None => quanta_emit::compile_json(&src),
            };
            drop(seed);
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

fn build(path: &str, source: &[u8], contracts: &[quanta_codegen::CompiledContract]) {
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let seed = match provenance_key() {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("error: {e}");
            exit(2);
        }
    };
    for cc in contracts {
        let out = dir.join(format!("{}.qbc", cc.name));
        let bytes = match &seed {
            Some(seed) => match attest(seed, source, cc) {
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
}

const PROVENANCE_CONTEXT: &[u8] = b"QUANTOVA/QVM/PROVENANCE/v2";
const PROVENANCE_MAGIC: &[u8; 4] = b"QPV2";
const PROVENANCE_KEY_FILE: &str = "QUANTA_PROVENANCE_KEY_FILE";

fn compiler_id() -> [u8; 32] {
    let commit = option_env!("QUANTA_BUILD_COMMIT").unwrap_or("unknown");
    let mut input = Vec::new();
    input.extend_from_slice(b"quanta ");
    input.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
    input.extend_from_slice(b" ");
    input.extend_from_slice(commit.as_bytes());
    qtv_crypto::sha3::sha3_256(&input)
}

fn provenance_statement(
    cc: &quanta_codegen::CompiledContract,
    source: &[u8],
) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let compiler = compiler_id();
    let source_hash = qtv_crypto::sha3::sha3_256(source);
    let mut message = Vec::with_capacity(96);
    message.extend_from_slice(&cc.container.identifier());
    message.extend_from_slice(&compiler);
    message.extend_from_slice(&source_hash);
    (compiler, source_hash, message)
}

fn attest(
    seed: &zeroize::Zeroizing<[u8; 32]>,
    source: &[u8],
    cc: &quanta_codegen::CompiledContract,
) -> Option<Vec<u8>> {
    use zeroize::Zeroize;
    let (compiler, source_hash, message) = provenance_statement(cc, source);
    let (_, mut sk) = qtv_crypto::ml_dsa::keygen(seed);
    let signature = qtv_crypto::ml_dsa::sign_os(&sk, &message, PROVENANCE_CONTEXT);
    sk.zeroize();
    let mut bytes = cc.container.canonical_bytes();
    bytes.extend_from_slice(PROVENANCE_MAGIC);
    bytes.extend_from_slice(&compiler);
    bytes.extend_from_slice(&source_hash);
    bytes.extend_from_slice(&signature?);
    Some(bytes)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_key_text(text: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    if body.len() != 64 {
        return Err(format!(
            "{PROVENANCE_KEY_FILE} must hold exactly 64 hex characters"
        ));
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    for (i, slot) in seed.iter_mut().enumerate() {
        let (Some(hi), Some(lo)) = (hex_nibble(body[2 * i]), hex_nibble(body[2 * i + 1])) else {
            return Err(format!("{PROVENANCE_KEY_FILE} is not valid hex"));
        };
        *slot = (hi << 4) | lo;
    }
    Ok(seed)
}

#[cfg(unix)]
fn check_key_permissions(meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{PROVENANCE_KEY_FILE} must be readable by its owner only (mode 0600 or stricter)"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_meta: &std::fs::Metadata) -> Result<(), String> {
    Err(format!(
        "{PROVENANCE_KEY_FILE} needs a platform with owner only file permissions"
    ))
}

fn provenance_key() -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, String> {
    let path = match std::env::var_os(PROVENANCE_KEY_FILE) {
        Some(path) => path,
        None => return Ok(None),
    };
    let meta =
        std::fs::metadata(&path).map_err(|e| format!("cannot read {PROVENANCE_KEY_FILE}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{PROVENANCE_KEY_FILE} must name a regular file"));
    }
    check_key_permissions(&meta)?;
    let text = zeroize::Zeroizing::new(
        std::fs::read(&path).map_err(|e| format!("cannot read {PROVENANCE_KEY_FILE}: {e}"))?,
    );
    parse_key_text(&text).map(Some)
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
