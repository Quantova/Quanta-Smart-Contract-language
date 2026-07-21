use quanta_codegen::CompiledContract;

pub struct Emit {
    pub json: String,
    pub ok: bool,
}

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
        out.push_str("],\"deploy_params\":[");
        for (j, param) in cc.deploy_params.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str("{\"key\":");
            json_str(&mut out, &param.key);
            out.push_str(&format!(
                ",\"offset\":{},\"width\":{}}}",
                param.offset, param.width
            ));
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

fn error_json(src: &str, message: &str, offset: usize) -> String {
    let (line, col) = line_col(src, offset);
    let mut out = String::from("{\"ok\":false,\"errors\":[{\"message\":");
    json_str(&mut out, message);
    out.push_str(&format!(",\"line\":{line},\"col\":{col},\"offset\":{offset}}}]}}"));
    out
}

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

fn json_hex(out: &mut String, bytes: &[u8]) {
    out.push('"');
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out.push('"');
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
