// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{asset_inner, Model};
use quanta_ast::{Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let mut declared: HashSet<&str> = HashSet::new();
    let mut mint_kind: Option<&str> = None;
    for clause in &entry.clauses {
        match clause {
            Clause::Conserves { asset, .. } | Clause::Burns { asset, .. } => {
                declared.insert(asset.text.as_str());
            }
            Clause::Mints { asset, .. } => {
                declared.insert(asset.text.as_str());
                mint_kind = Some(asset.text.as_str());
            }
            _ => {}
        }
    }

    let mut kinds: HashMap<String, String> = HashMap::new();
    for param in &entry.params {
        if let Some(sym) = asset_inner(&param.ty) {
            if !declared.contains(sym) {
                return Err(TypeError::new(
                    format!(
                        "asset `{}` of kind `{}` moves through this entry, but the entry declares \
                         no `conserves {}`, `mints {}`, or `burns {}`, so its accounting is unstated",
                        param.name.text, sym, sym, sym, sym
                    ),
                    param.name.span,
                ));
            }
            kinds.insert(param.name.text.clone(), sym.to_string());
        }
    }

    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            if let Some(sym) = expr_asset_kind(model, &kinds, mint_kind, value) {
                kinds.insert(name.text.clone(), sym);
            }
        }
        if let Stmt::Assign { target, value, span, .. } = stmt {
            if let Some(into) = expr_asset_kind(model, &kinds, mint_kind, target) {
                if let Some(err) = asset_flow_error(model, &kinds, mint_kind, &into, value, *span) {
                    return Err(err);
                }
            }
        }
        let mut err = None;
        for_each_expr(stmt, &mut |e| {
            if err.is_some() {
                return;
            }
            err = merge_mismatch(model, &kinds, mint_kind, e);
        });
        if let Some(e) = err {
            return Err(e);
        }
    }
    Ok(())
}

fn merge_mismatch(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    expr: &Expr,
) -> Option<TypeError> {
    if let Expr::Call { callee, args, span } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "merge" && args.len() == 1 {
                if let Some(into) = expr_asset_kind(model, kinds, mint_kind, base) {
                    return asset_flow_error(model, kinds, mint_kind, &into, &args[0], *span);
                }
            }
        }
    }
    None
}

fn asset_flow_error(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    into: &str,
    value: &Expr,
    span: Span,
) -> Option<TypeError> {
    match expr_asset_kind(model, kinds, mint_kind, value) {
        None => Some(TypeError::new(
            "a value that is not an asset cannot be moved into an asset slot; move, merge, or \
             split an asset of this kind instead"
                .to_string(),
            span,
        )),
        Some(from) if from != into => Some(TypeError::new(
            format!("asset kinds do not mix: `{from}` and `{into}`"),
            span,
        )),
        Some(_) if !is_movable_asset(kinds, value) => Some(TypeError::new(
            "an asset pool cannot be copied; move or split it".to_string(),
            span,
        )),
        Some(_) => None,
    }
}

fn expr_asset_kind(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    expr: &Expr,
) -> Option<String> {
    match expr {
        Expr::Ident(id) => kinds.get(id.text.as_str()).cloned().or_else(|| {
            model
                .state
                .get(id.text.as_str())
                .and_then(|f| asset_inner(&f.ty))
                .map(|s| s.to_string())
        }),
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "split" {
                    return expr_asset_kind(model, kinds, mint_kind, base);
                }
            }
            if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "mint") {
                return mint_kind.map(|s| s.to_string());
            }
            None
        }
        _ => None,
    }
}

fn is_movable_asset(kinds: &HashMap<String, String>, value: &Expr) -> bool {
    match value {
        Expr::Ident(id) => kinds.contains_key(id.text.as_str()),
        Expr::Call { callee, .. } => match callee.as_ref() {
            Expr::Field { name, .. } => name.text == "split",
            Expr::Ident(id) => id.text == "mint",
            _ => false,
        },
        _ => false,
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
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            walk(expr, f)
        }
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
    fn merging_two_different_asset_kinds_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { vault: Q_Asset<GOLD>; } \
                   entry deposit(funds: Q_Asset<DUST>) conserves DUST writes(vault) \
                   { vault.merge(funds); } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn conserving_the_wrong_asset_is_rejected() {
        let src = "contract C { asset TKN; state { poolt: Q_Asset<TKN>; } \
                   entry deposit(funds: Q_Asset<TKN>) conserves QTOV writes(poolt) \
                   { poolt.merge(funds); } }";
        assert!(error_for(src).contains("accounting is unstated"));
    }

    #[test]
    fn moving_an_asset_with_no_accounting_clause_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry deposit(funds: Q_Asset<QTOV>) writes(pool) \
                   { pool.merge(funds); } }";
        assert!(error_for(src).contains("accounting is unstated"));
    }

    #[test]
    fn minting_into_a_pool_of_a_different_kind_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { owner: Q_Address; dustp: Q_Asset<DUST>; } \
                   entry issue(order: Order signed by owner) mints GOLD writes(dustp) \
                   { dustp.merge(mint(order.amount)); } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn storing_an_asset_into_a_pool_of_a_different_kind_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { vault: Q_Asset<GOLD>; } \
                   entry swap(funds: Q_Asset<DUST>) conserves DUST writes(vault) \
                   { vault = funds; } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn storing_an_asset_amount_scalar_into_an_asset_slot_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) \
                   { pool = funds.amount; } }";
        assert!(error_for(src).contains("not an asset"));
    }

    #[test]
    fn copying_one_asset_pool_into_another_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; pool2: Q_Asset<QTOV>; } \
                   entry dup(order: Order) conserves QTOV writes(pool) { pool = pool2; } }";
        assert!(error_for(src).contains("cannot be copied"));
    }

    #[test]
    fn merging_a_non_asset_scalar_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) \
                   { pool.merge(funds.amount); } }";
        assert!(error_for(src).contains("not an asset"));
    }

    #[test]
    fn moving_an_asset_into_a_slot_is_accepted() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) { pool = funds; } }";
        ok(src);
    }

    #[test]
    fn merging_the_same_asset_kind_is_accepted() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; } \
                   entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(vault) \
                   { vault.merge(funds); } }";
        ok(src);
    }

    #[test]
    fn splitting_a_pool_and_merging_it_back_matches() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; pending: Q_Asset<QTOV>; } \
                   entry shuffle(order: Order) conserves QTOV writes(vault, pending) \
                   { let out = vault.split(order.amount); pending.merge(out); } }";
        ok(src);
    }
}
