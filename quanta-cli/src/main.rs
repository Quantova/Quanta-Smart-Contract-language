//! Command line front end. Parses a Quanta source file and prints its tree,

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
        "emit" => match quanta_parser::parse(&src) {
            Ok(program) => {
                if let Err(e) = quanta_typeck::check(&program) {
                    emit_error(&src, &e.message, e.span.start);
                    exit(1);
                }
                match quanta_codegen::compile(&program) {
                    Ok(contracts) => emit_contracts(&contracts),
                    Err(e) => {
                        emit_error(&src, &e.to_string(), e.span().start);
                        exit(1);
                    }
                }
            }
            Err(e) => {
                emit_error(&src, &e.message, e.span.start);
                exit(1);
            }
        },
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

/// Prints every compiled contract as one JSON document on stdout: the container bytes as
fn emit_contracts(contracts: &[quanta_codegen::CompiledContract]) {
    let mut out = String::from("{\"ok\":true,\"contracts\":[");
    for (i, cc) in contracts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_str(&mut out, &cc.name);
        out.push_str(",\"container\":");
        json_hex(&mut out, &cc.container.canonical_bytes());
        out.push_str(",\"entries\":[");
        for (j, entry) in cc.entries.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json_str(&mut out, &entry.name);
            out.push_str(",\"signature\":");
            json_str(&mut out, &entry.signature);
            out.push_str(",\"selector\":");
            json_hex(&mut out, &entry.selector);
            out.push_str(",\"args\":[");
            for (k, arg) in entry.args.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push_str("{\"key\":");
                json_str(&mut out, &arg.key);
                out.push_str(&format!(",\"offset\":{}}}", arg.offset));
            }
            out.push_str("]}");
        }
        out.push_str("],\"events\":[");
        for (j, event) in cc.events.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json_str(&mut out, &event.name);
            out.push_str(",\"signature\":");
            json_str(&mut out, &event.signature);
            out.push_str(",\"selector\":");
            json_hex(&mut out, &event.selector);
            out.push('}');
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    println!("{out}");
}

/// Prints a compile failure as the same JSON shape emit uses, so a driving tool reads one
fn emit_error(src: &str, message: &str, offset: usize) {
    let (line, col) = line_col(src, offset);
    let mut out = String::from("{\"ok\":false,\"errors\":[{\"message\":");
    json_str(&mut out, message);
    out.push_str(&format!(",\"line\":{line},\"col\":{col},\"offset\":{offset}}}]}}"));
    println!("{out}");
}

/// Appends a JSON string literal, escaping the characters JSON requires.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends bytes as a JSON string of lower case hex, the form the wire carries a container
fn json_hex(out: &mut String, bytes: &[u8]) {
    out.push('"');
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out.push('"');
}

/// Writes each compiled contract to a container file beside the source and prints its interface.
fn build(path: &str, contracts: &[quanta_codegen::CompiledContract]) {
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    for cc in contracts {
        let out = dir.join(format!("{}.qbc", cc.name));
        let bytes = cc.container.canonical_bytes();
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
