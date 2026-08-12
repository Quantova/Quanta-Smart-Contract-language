// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_quorum_param, Model};
use quanta_ast::{AfterTarget, Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::HashSet;

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_after_anchors(entry)?;
    }
    Ok(())
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
        format!("a time gate anchored on `{display}`, a caller supplied value that no signature covers")
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
                  after 24 hours from armed_at { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
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
