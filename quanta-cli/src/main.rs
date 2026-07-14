//! Command line front end. Parses a Quanta source file and prints its tree,

mod tree;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: quanta-cli <parse|fmt|tokens> <file>");
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
            eprintln!("usage: quanta-cli <parse|fmt|tokens> <file>");
            exit(2);
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
