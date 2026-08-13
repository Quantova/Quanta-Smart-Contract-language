// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::Model;
use crate::signature::has_protected_signed_authority;
use quanta_ast::{Clause, EntryDecl, Expr, Stmt};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let mints = entry.clauses.iter().find_map(|c| match c {
        Clause::Mints { span, .. } => Some(*span),
        _ => None,
    });

    if let Some(span) = mints {
        if !has_protected_signed_authority(model, entry) {
            return Err(TypeError::new(
                format!(
                    "conservation: entry `{}` mints supply without protected authority; a mint must be \
                     gated by a signed party or quorum whose key is set only from an authorized entry or genesis",
                    entry.name.text
                ),
                span,
            ));
        }
    } else if let Some(span) = mint_call(&entry.body) {
        return Err(TypeError::new(
            "conservation: this creates supply but the entry does not declare `mints`",
            span,
        ));
    }
    Ok(())
}

fn mint_call(body: &[Stmt]) -> Option<quanta_lexer::Span> {
    let mut found = None;
    for stmt in body {
        for_each_expr(stmt, &mut |e| {
            if found.is_none() {
                if let Expr::Call { callee, span, .. } = e {
                    if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "mint") {
                        found = Some(*span);
                    }
                }
            }
        });
    }
    found
}

fn for_each_expr(stmt: &Stmt, f: &mut impl FnMut(&Expr)) {
    match stmt {
        Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => walk(expr, f),
        Stmt::Let { value, .. } => walk(value, f),
        Stmt::Assign { target, value, .. } => {
            walk(target, f);
            walk(value, f);
        }
        Stmt::Emit { args, .. } => {
            for a in args {
                walk(a, f);
            }
        }
    }
}

fn walk(expr: &Expr, f: &mut impl FnMut(&Expr)) {
    f(expr);
    match expr {
        Expr::Unary { expr, .. } => walk(expr, f),
        Expr::Binary { left, right, .. } => {
            walk(left, f);
            walk(right, f);
        }
        Expr::Field { base, .. } => walk(base, f),
        Expr::Call { callee, args, .. } => {
            walk(callee, f);
            for a in args {
                walk(a, f);
            }
        }
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => walk(expr, f),
        Expr::Int(_) | Expr::Date { .. } | Expr::Str(_) | Expr::Ident(_) | Expr::Caller { .. } | Expr::Now { .. } => {}
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
    fn an_ungated_mint_is_rejected() {
        let src = "contract C { asset BAD; state { supply: u128; } \
                   entry inflate(order: MintOrder) mints BAD writes(supply) \
                   { supply += order.amount; } }";
        assert!(error_for(src).contains("without protected authority"));
    }

    #[test]
    fn a_mint_signed_by_a_settable_owner_is_rejected() {
        let src = "contract C { asset TKN; state { owner: Q_Address; s: u128; } \
                   entry claim(a: Q_Address) writes(owner) { owner = a; } \
                   entry mint_to(order: MintOrder signed by owner) mints TKN writes(s) \
                   { s += order.amount; } }";
        assert!(error_for(src).contains("without protected authority"));
    }

    #[test]
    fn a_signed_mint_is_allowed() {
        let src = "contract C { asset TKN; state { owner: Q_Address; s: u128; } \
                   entry mint_to(order: MintOrder signed by owner) mints TKN writes(s) \
                   { s += order.amount; } }";
        ok(src);
    }

    #[test]
    fn a_quorum_mint_is_allowed() {
        let src = "contract C { asset QSGD; state { board: GuardianSet<5>; s: u128; } \
                   entry issue(order: Order, approvals: Quorum<3 of 5, board>) mints QSGD writes(s) \
                   { s += order.amount; } }";
        ok(src);
    }
}
