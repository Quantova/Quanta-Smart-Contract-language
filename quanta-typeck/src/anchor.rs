// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_asset_type, is_quorum_param, Model};
use quanta_ast::{AfterTarget, BinOp, Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::HashSet;

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_after_anchors(entry)?;
        check_anchor_liveness(model, entry)?;
    }
    Ok(())
}

fn check_anchor_liveness(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    for clause in &entry.clauses {
        let Clause::After { target, from, span } = clause else {
            continue;
        };
        let mut reads: Vec<&Expr> = Vec::new();
        if let AfterTarget::Expr(expr) = target {
            collect_anchor_reads(model, &params, expr, &mut reads);
        }
        if let Some(expr) = from {
            collect_anchor_reads(model, &params, expr, &mut reads);
        }
        for read in reads {
            let Some(field) = anchor_field(read) else {
                continue;
            };
            if field_is_asset(model, field) {
                continue;
            }
            if read_starts_nonzero(model, read, field) {
                continue;
            }
            if !entry_requires_nonzero(entry, read) {
                return Err(liveness_rejection(field, *span));
            }
        }
    }
    Ok(())
}

fn collect_anchor_reads<'a>(
    model: &Model,
    params: &HashSet<&str>,
    expr: &'a Expr,
    out: &mut Vec<&'a Expr>,
) {
    match expr {
        Expr::Ident(id) => {
            let name = id.text.as_str();
            if !params.contains(name) && model.state.contains_key(name) {
                out.push(expr);
            }
        }
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" {
                    if let Expr::Ident(map_id) = base.as_ref() {
                        if !params.contains(map_id.text.as_str())
                            && model.state.contains_key(map_id.text.as_str())
                        {
                            out.push(expr);
                        }
                    }
                }
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            collect_anchor_reads(model, params, expr, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_anchor_reads(model, params, left, out);
            collect_anchor_reads(model, params, right, out);
        }
        _ => {}
    }
}

fn anchor_field(read: &Expr) -> Option<&str> {
    match read {
        Expr::Ident(id) => Some(id.text.as_str()),
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, .. } = callee.as_ref() {
                if let Expr::Ident(map_id) = base.as_ref() {
                    return Some(map_id.text.as_str());
                }
            }
            None
        }
        _ => None,
    }
}

fn field_is_asset(model: &Model, field: &str) -> bool {
    model.state.get(field).is_some_and(|f| is_asset_type(&f.ty))
}

fn genesis_arms_nonzero(model: &Model, field: &str) -> bool {
    for item in &model.contract.items {
        let quanta_ast::Item::Genesis(genesis) = item else {
            continue;
        };
        for stmt in &genesis.body {
            if let Stmt::Assign { target, value, .. } = stmt {
                if matches!(target, Expr::Ident(id) if id.text == field) {
                    match value {
                        Expr::Now { .. } | Expr::Date { .. } => return true,
                        Expr::Int(lit) => {
                            if lit.text.replace('_', "").parse::<u128>() != Ok(0) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    false
}

fn read_starts_nonzero(model: &Model, read: &Expr, field: &str) -> bool {
    if !matches!(read, Expr::Ident(_)) {
        return false;
    }
    let has_nonzero_default = match model.state.get(field).and_then(|f| f.default.as_ref()) {
        None => false,
        Some(Expr::Int(lit)) => lit.text.replace('_', "").parse::<u128>() != Ok(0),
        Some(_) => true,
    };
    if !has_nonzero_default && !genesis_arms_nonzero(model, field) {
        return false;
    }
    for e in &model.entries {
        for stmt in &e.body {
            if let Stmt::Assign { target, value, .. } = stmt {
                if matches!(target, Expr::Ident(id) if id.text == field)
                    && !matches!(value, Expr::Now { .. })
                {
                    return false;
                }
            }
        }
    }
    true
}

fn entry_requires_nonzero(entry: &EntryDecl, read: &Expr) -> bool {
    for clause in &entry.clauses {
        if let Clause::Denies { expr, .. } = clause {
            if denies_read_zero(expr, read) {
                return true;
            }
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if guard_read_nonzero(expr, read) {
                return true;
            }
        }
    }
    false
}

fn denies_read_zero(expr: &Expr, read: &Expr) -> bool {
    if let Expr::Binary {
        op: BinOp::Eq,
        left,
        right,
        ..
    } = expr
    {
        return (read_eq(left, read) && is_zero(right)) || (read_eq(right, read) && is_zero(left));
    }
    false
}

fn guard_read_nonzero(expr: &Expr, read: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::Ne,
            left,
            right,
            ..
        } => (read_eq(left, read) && is_zero(right)) || (read_eq(right, read) && is_zero(left)),
        Expr::Binary {
            op: BinOp::Gt,
            left,
            right,
            ..
        } => read_eq(left, read) && is_zero(right),
        Expr::Binary {
            op: BinOp::Ge,
            left,
            right,
            ..
        } => read_eq(left, read) && is_positive_int(right),
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => guard_read_nonzero(left, read) || guard_read_nonzero(right, read),
        _ => false,
    }
}

fn read_eq(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Ident(x), Expr::Ident(y)) => x.text == y.text,
        (Expr::Caller { .. }, Expr::Caller { .. }) => true,
        (Expr::Now { .. }, Expr::Now { .. }) => true,
        (Expr::Int(x), Expr::Int(y)) => x.text == y.text,
        (
            Expr::Field {
                base: ba, name: na, ..
            },
            Expr::Field {
                base: bb, name: nb, ..
            },
        ) => na.text == nb.text && read_eq(ba, bb),
        (
            Expr::Call {
                callee: ca,
                args: aa,
                ..
            },
            Expr::Call {
                callee: cb,
                args: ab,
                ..
            },
        ) => {
            read_eq(ca, cb) && aa.len() == ab.len() && aa.iter().zip(ab).all(|(x, y)| read_eq(x, y))
        }
        _ => false,
    }
}

fn is_positive_int(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(lit) if lit.text.replace('_', "").parse::<u128>().map_or(false, |v| v >= 1))
}

fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(lit) if lit.text.replace('_', "").parse::<u128>() == Ok(0))
}

fn liveness_rejection(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "a time gate anchored on `{field}`, which starts at zero, lets the delay pass before \
             the anchor is set; give `{field}` a nonzero default or deny `{field} == 0` in this \
             entry so the cooling off cannot be skipped on the first call"
        ),
        span,
    )
}

fn check_after_anchors(entry: &EntryDecl) -> Result<(), TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let quorum_params: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| is_quorum_param(p))
        .map(|p| p.name.text.as_str())
        .collect();

    let mut authenticated: HashSet<String> = HashSet::new();
    for param in &entry.params {
        if param.signed_by.is_some() {
            for key in collect_signed_fields(entry, &param.name.text) {
                authenticated.insert(key);
            }
        }
    }
    if !quorum_params.is_empty() {
        for param in &entry.params {
            if is_quorum_param(param) || param.ty.name.text == "Q_Asset" {
                continue;
            }
            for key in collect_signed_fields(entry, &param.name.text) {
                authenticated.insert(key);
            }
        }
    }

    for clause in &entry.clauses {
        let Clause::After { target, from, span } = clause else {
            continue;
        };
        if let AfterTarget::Expr(expr) = target {
            check_anchor_expr(expr, &params, &quorum_params, &authenticated, *span)?;
        }
        if let Some(expr) = from {
            check_anchor_expr(expr, &params, &quorum_params, &authenticated, *span)?;
        }
    }
    Ok(())
}

fn check_anchor_expr(
    expr: &Expr,
    params: &HashSet<&str>,
    quorum_params: &HashSet<&str>,
    authenticated: &HashSet<String>,
    span: Span,
) -> Result<(), TypeError> {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if params.contains(id.text.as_str()) {
                    let key = format!("{}.{}", id.text, name.text);
                    if !authenticated.contains(&key) {
                        return Err(anchor_rejection(
                            key,
                            quorum_params.contains(id.text.as_str()),
                            span,
                        ));
                    }
                    return Ok(());
                }
            }
            check_anchor_expr(base, params, quorum_params, authenticated, span)
        }
        Expr::Ident(id) => {
            if params.contains(id.text.as_str()) {
                return Err(anchor_rejection(
                    id.text.clone(),
                    quorum_params.contains(id.text.as_str()),
                    span,
                ));
            }
            Ok(())
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            check_anchor_expr(expr, params, quorum_params, authenticated, span)
        }
        Expr::Binary { left, right, .. } => {
            check_anchor_expr(left, params, quorum_params, authenticated, span)?;
            check_anchor_expr(right, params, quorum_params, authenticated, span)
        }
        Expr::Call { callee, args, .. } => {
            check_anchor_expr(callee, params, quorum_params, authenticated, span)?;
            for arg in args {
                check_anchor_expr(arg, params, quorum_params, authenticated, span)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn anchor_rejection(display: String, is_quorum: bool, span: Span) -> TypeError {
    let source = if is_quorum {
        format!("a time gate anchored on `{display}`, a quorum field that no guardian signs")
    } else {
        format!(
            "a time gate anchored on `{display}`, a caller supplied value that no signature covers"
        )
    };
    TypeError::new(
        format!("{source}; anchor the delay on state that an authorized entry records with `now`"),
        span,
    )
}

fn collect_signed_fields(entry: &EntryDecl, param: &str) -> Vec<String> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                collect_fields_expr(expr, param, &mut out)
            }
            Clause::After { target, from, .. } => {
                if let AfterTarget::Expr(expr) = target {
                    collect_fields_expr(expr, param, &mut out);
                }
                if let Some(expr) = from {
                    collect_fields_expr(expr, param, &mut out);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        collect_fields_stmt(stmt, param, &mut out);
    }
    out
}

fn collect_fields_stmt(stmt: &Stmt, param: &str, out: &mut Vec<String>) {
    match stmt {
        Stmt::Guard { expr, .. } => collect_fields_expr(expr, param, out),
        Stmt::Let { value, .. } => collect_fields_expr(value, param, out),
        Stmt::Emit { args, .. } => {
            for arg in args {
                collect_fields_expr(arg, param, out);
            }
        }
        Stmt::Assign { target, value, .. } => {
            collect_fields_expr(target, param, out);
            collect_fields_expr(value, param, out);
        }
        Stmt::Expr { expr, .. } => collect_fields_expr(expr, param, out),
    }
}

fn collect_fields_expr(expr: &Expr, param: &str, out: &mut Vec<String>) {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if id.text == param {
                    let key = format!("{param}.{}", name.text);
                    if !out.contains(&key) {
                        out.push(key);
                    }
                    return;
                }
            }
            collect_fields_expr(base, param, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            collect_fields_expr(expr, param, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_fields_expr(left, param, out);
            collect_fields_expr(right, param, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_fields_expr(callee, param, out);
            for arg in args {
                collect_fields_expr(arg, param, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Model;

    fn error_for(src: &str) -> String {
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        super::check(&model)
            .expect_err("checker should reject")
            .message
    }

    fn ok(src: &str) {
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        super::check(&model).expect("checker should accept");
    }

    #[test]
    fn a_caller_supplied_anchor_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from order.deadline { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("caller supplied value"));
    }

    #[test]
    fn a_signed_anchor_is_authenticated() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; }
                entry release(order: Rel signed by owner) conserves QTOV writes(vault)
                  after 24 hours from order.deadline { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn an_anchor_on_recorded_state_is_authenticated() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: u64; vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at
                  denies armed_at == 0 { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn an_arm_then_act_anchor_without_a_liveness_guard_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_zero_init_self_recording_anchor_is_refused_and_a_denied_zero_is_accepted() {
        let unsafe_src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { period_reset: u64; vault: Q_Asset<QTOV>; }
                entry roll(order: Rel) conserves QTOV writes(vault, period_reset)
                  after 30 days from period_reset
                  { period_reset = now; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(unsafe_src).contains("lets the delay pass"));

        let safe_src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { period_reset: u64; vault: Q_Asset<QTOV>; }
                entry roll(order: Rel) conserves QTOV writes(vault, period_reset)
                  after 30 days from period_reset denies period_reset == 0
                  { period_reset = now; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(safe_src);
    }

    #[test]
    fn an_anchor_with_a_non_zero_default_needs_no_liveness_guard() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { start: u64 = 100; vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 365 days from start { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_zero_start_anchor_wrapped_in_arithmetic_is_still_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; grace: u64 = 3600; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed + grace { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_ge_one_liveness_guard_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed
                  { guard armed >= 1; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_keyed_map_anchor_without_a_liveness_guard_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed_at) { armed_at.set(caller, now); }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at.get(caller) { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_keyed_map_anchor_with_a_keyed_guard_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed_at) { armed_at.set(caller, now); }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at.get(caller)
                  denies armed_at.get(caller) == 0 { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_nonzero_default_anchor_re_zeroed_by_an_entry_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { start: u64 = 2000000000; vault: Q_Asset<QTOV>; }
                entry reset() writes(start) { start = 0; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 365 days from start { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn an_entry_without_a_time_gate_is_unaffected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }
}
