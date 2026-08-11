// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_asset_param, is_asset_type, is_quorum_param, Model};
use quanta_ast::{Clause, EntryDecl, Expr, Stmt};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let pooled = match pooled_field(model, entry) {
        Some(p) => p,
        None => return Ok(()),
    };
    if pooled_field_sent(entry, &pooled) {
        return Ok(());
    }
    for param in &entry.params {
        if is_asset_param(param) || param.signed_by.is_some() || is_quorum_param(param) {
            continue;
        }
        if param.sealed {
            continue;
        }
        if order_field_gates(entry, &param.name.text) {
            return Err(TypeError::new(
                format!(
                    "front running: order parameter `{}` competes for a pooled asset yet is \
                     visible in the mempool; declare it `sealed`",
                    param.name.text
                ),
                param.span,
            ));
        }
    }
    Ok(())
}

fn pooled_field(model: &Model, entry: &EntryDecl) -> Option<String> {
    let mut pooled = None;
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "merge" {
                        if let Some(root) = root_ident(base) {
                            if model.state.get(root).is_some_and(|f| is_asset_type(&f.ty)) {
                                pooled = Some(root.to_string());
                            }
                        }
                    }
                }
            }
        });
    }
    pooled
}

fn pooled_field_sent(entry: &EntryDecl, pooled: &str) -> bool {
    let mut sent = false;
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") {
                    for a in args {
                        walk(a, &mut |x| {
                            if matches!(x, Expr::Ident(id) if id.text == pooled) {
                                sent = true;
                            }
                        });
                    }
                }
            }
        });
    }
    sent
}

fn order_field_gates(entry: &EntryDecl, param: &str) -> bool {
    let mut gates = false;
    let mut scan = |expr: &Expr| {
        walk(expr, &mut |e| {
            if let Expr::Field { base, .. } = e {
                if matches!(base.as_ref(), Expr::Ident(id) if id.text == param) {
                    gates = true;
                }
            }
        });
    };
    for clause in &entry.clauses {
        if let Clause::Limits { expr, .. } | Clause::Denies { expr, .. } = clause {
            scan(expr);
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            scan(expr);
        }
    }
    gates
}

fn root_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(id) => Some(&id.text),
        Expr::Field { base, .. } => root_ident(base),
        _ => None,
    }
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
    fn an_unsealed_pooled_bid_is_front_runnable() {
        let src = "contract C { state { pot: Q_Asset<QTOV>; } \
                   entry bid(offer: Bid, funds: Q_Asset<QTOV>) conserves QTOV writes(pot) \
                   { guard funds.amount >= offer.amount; pot.merge(funds); } }";
        assert!(error_for(src).contains("front running"));
    }

    #[test]
    fn a_sealed_order_is_accepted() {
        let src = "contract C { state { pot: Q_Asset<QTOV>; } \
                   entry bid(offer: sealed Bid, funds: Q_Asset<QTOV>) conserves QTOV writes(pot) \
                   { guard funds.amount >= offer.amount; pot.merge(funds); } }";
        ok(src);
    }

    #[test]
    fn paying_out_in_the_same_call_is_not_pooled() {
        let src = "contract C { state { escrowed: Q_Asset<QTOV>; } \
                   entry buy(order: BuyOrder, payment: Q_Asset<QTOV>) conserves QTOV writes(escrowed) \
                   { guard payment.amount >= order.price; escrowed.merge(payment); \
                     send(order.seller, escrowed.split(order.price)); } }";
        ok(src);
    }
}
