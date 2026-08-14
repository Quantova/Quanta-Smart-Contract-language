// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
                out.push_str(&format!(",\"offset\":{},\"width\":{}}}", arg.offset, arg.width));
            }
            out.push_str("],\"signed_orders\":[");
            for (s, order) in entry.signed_orders.iter().enumerate() {
                if s > 0 {
                    out.push(',');
                }
                out.push_str("{\"param\":");
                json_str(&mut out, &order.param);
                out.push_str(",\"fields\":[");
                for (fi, field) in order.fields.iter().enumerate() {
                    if fi > 0 {
                        out.push(',');
                    }
                    json_str(&mut out, field);
                }
                out.push_str("]}");
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

#[cfg(test)]
mod tests {
    use super::*;

    // The width recorded directly after the first occurrence of a given arg key.
    fn width_of(json: &str, key: &str) -> u64 {
        let at = json
            .find(&format!("\"key\":\"{key}\""))
            .expect("the arg key is present");
        let tail = &json[at..];
        let w = tail.find("\"width\":").expect("a width follows the key") + "\"width\":".len();
        let rest = &tail[w..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().expect("the width is a number")
    }

    #[test]
    fn the_descriptor_records_each_signed_field_width() {
        // A signer-ordered message the SDK must reproduce byte for byte: a wide amount and a whole
        // address. Without the width a client packs both as eight byte words and the signature fails.
        let src = "contract A { state { owner: Q_Address; total: u128; reg: Map<Q_Address, u128>; } \
                   entry give(order: GiveOrder signed by owner) writes(total, reg) \
                   { total = checked(total + order.amount); reg.credit(order.to, order.amount); } }";
        let emit = compile_json(src);
        assert!(emit.ok, "the contract compiles: {}", emit.json);
        assert_eq!(width_of(&emit.json, "order.amount"), 16, "a u128 signed field is sixteen bytes");
        assert_eq!(width_of(&emit.json, "order.to"), 32, "an address signed field is a full word set");
        assert_eq!(width_of(&emit.json, "@caller"), 32, "the caller context is a full address");
        // The message order the owner signs is amount then to (amount is read first in the body); the
        // argument offsets put `to` first, so only this explicit list conveys the true preimage order.
        assert!(
            emit.json.contains("\"signed_orders\":[{\"param\":\"order\",\"fields\":[\"order.amount\",\"order.to\"]}]"),
            "the descriptor exposes the signed fields in message order: {}",
            emit.json
        );
    }

    #[test]
    fn a_bare_signed_address_parameter_is_bound_at_full_width() {
        let src = "import { Q_Asset } from \"quantova/primitives\"; \
                   contract C { state { admin: Q_Address; vault: Q_Asset<QTOV>; } \
                   genesis { admin = deployer; } \
                   entry pay(who: Q_Address signed by admin) conserves QTOV writes(vault) \
                   { send(who, vault.split(1000)); } }";
        let emit = compile_json(src);
        assert!(emit.ok, "the contract compiles: {}", emit.json);
        assert_eq!(width_of(&emit.json, "who"), 32, "the recipient is a full address");
        assert!(
            emit.json.contains("\"signed_orders\":[{\"param\":\"who\",\"fields\":[\"who\"]}]"),
            "the signer binds the bare address parameter it authorizes: {}",
            emit.json
        );
    }

    #[test]
    fn a_signed_address_in_a_scalar_guard_is_bound_at_full_width() {
        let src = "contract C { state { admin: Q_Address; owner: Q_Address; flag: u64; } \
                   entry act(who: Q_Address signed by admin) writes(flag) \
                   { guard who == owner; flag = 1; } }";
        let emit = compile_json(src);
        assert!(emit.ok, "the contract compiles: {}", emit.json);
        assert_eq!(width_of(&emit.json, "who"), 32, "a scalar address compare binds the full address");
    }
}
