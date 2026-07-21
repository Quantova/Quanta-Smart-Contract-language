//! The compiler's machine readable output, in one place. One function turns Quanta source into a JSON

use quanta_codegen::CompiledContract;

/// The result of a compile: the JSON document and whether it succeeded, so a caller can print the
pub struct Emit {
    pub json: String,
    pub ok: bool,
}

/// Compile Quanta source to a JSON document. On success the document carries every contract, its
pub fn compile_json(src: &str) -> Emit {
    let program = match quanta_parser::parse(src) {
        Ok(program) => program,
        Err(e) => return Emit { json: error_json(src, &e.message, e.span.start), ok: false },
    };
    if let Err(e) = quanta_typeck::check(&program) {
        return Emit { json: error_json(src, &e.message, e.span.start), ok: false };
    }
    match quanta_codegen::compile(&program) {
        Ok(contracts) => Emit { json: contracts_json(&contracts), ok: true },
        Err(e) => Emit { json: error_json(src, &e.to_string(), e.span().start), ok: false },
    }
}

/// The success document: every compiled contract with its container bytes as hex and the interface a
fn contracts_json(contracts: &[CompiledContract]) -> String {
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
    out
}

/// The failure document: the error message and its position in the source. The offset is the byte
fn error_json(src: &str, message: &str, offset: usize) -> String {
    let (line, col) = line_col(src, offset);
    let mut out = String::from("{\"ok\":false,\"errors\":[{\"message\":");
    json_str(&mut out, message);
    out.push_str(&format!(",\"line\":{line},\"col\":{col},\"offset\":{offset}}}]}}"));
    out
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

/// Appends bytes as a JSON string of lower case hex, the form the wire carries a container and a
fn json_hex(out: &mut String, bytes: &[u8]) {
    out.push('"');
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out.push('"');
}

/// The line and column, both one based, of a byte offset in the source.
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
