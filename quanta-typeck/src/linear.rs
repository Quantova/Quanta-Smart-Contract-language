//! Linearity. An asset value must be used exactly once. A linear value is an

use crate::error::TypeError;
use crate::model::{asset_inner, is_asset_param, Model};
use quanta_ast::{Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::HashMap;

struct Linear {
    name: String,
    span: Span,
    consumed: usize,
}

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(entry)?;
    }
    Ok(())
}

fn check_entry(entry: &EntryDecl) -> Result<(), TypeError> {
    let mut linears: Vec<Linear> = Vec::new();

    for param in &entry.params {
        if is_asset_param(param) {
            linears.push(Linear {
                name: param.name.text.clone(),
                span: param.name.span,
                consumed: 0,
            });
        }
    }
    for stmt in &entry.body {
        if let Stmt::Let { name, value, span } = stmt {
            if produces_asset(value) {
                linears.push(Linear {
                    name: name.text.clone(),
                    span: *span,
                    consumed: 0,
                });
            }
        }
    }

    // A burn consumes the incoming asset of the burned kind.
    let burned: Vec<&str> = entry
        .clauses
        .iter()
        .filter_map(|c| match c {
            Clause::Burns { asset, .. } => Some(asset.text.as_str()),
            _ => None,
        })
        .collect();
    for param in &entry.params {
        if let Some(inner) = asset_inner(&param.ty) {
            if burned.contains(&inner) {
                bump(&mut linears, &param.name.text);
            }
        }
    }

    let names: HashMap<&str, usize> = linears
        .iter()
        .enumerate()
        .map(|(i, l)| (l.name.as_str(), i))
        .collect();
    let mut counts = vec![0usize; linears.len()];
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| count_consumes(e, &names, &mut counts));
    }
    for (i, l) in linears.iter_mut().enumerate() {
        l.consumed += counts[i];
    }

    for l in &linears {
        if l.consumed == 0 {
            return Err(TypeError::new(
                format!(
                    "asset `{}` is never consumed; a linear asset must be used exactly once",
                    l.name
                ),
                l.span,
            ));
        }
        if l.consumed > 1 {
            return Err(TypeError::new(
                format!(
                    "asset `{}` is used more than once; a linear asset must be used exactly once",
                    l.name
                ),
                l.span,
            ));
        }
    }
    Ok(())
}

fn bump(linears: &mut [Linear], name: &str) {
    if let Some(l) = linears.iter_mut().find(|l| l.name == name) {
        l.consumed += 1;
    }
}

/// An expression that yields a fresh linear asset value.
fn produces_asset(value: &Expr) -> bool {
    match value {
        Expr::Call { callee, .. } => match callee.as_ref() {
            Expr::Field { name, .. } => name.text == "split",
            Expr::Ident(id) => id.text == "mint",
            _ => false,
        },
        _ => false,
    }
}

/// Counts a consumption when a linear name is passed as a bare argument to a
fn count_consumes(expr: &Expr, names: &HashMap<&str, usize>, counts: &mut [usize]) {
    if let Expr::Call { args, .. } = expr {
        for arg in args {
            if let Expr::Ident(id) = arg {
                if let Some(&i) = names.get(id.text.as_str()) {
                    counts[i] += 1;
                }
            }
        }
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
        Expr::Int(_) | Expr::Date { .. } | Expr::Str(_) | Expr::Ident(_) | Expr::Caller { .. } => {}
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
    fn an_unconsumed_asset_is_dropped() {
        let src = "contract C { state { a: u64; } \
                   entry deposit(funds: Q_Asset<QTOV>) conserves QTOV \
                   { guard funds.amount > 0; } }";
        assert!(error_for(src).contains("never consumed"));
    }

    #[test]
    fn sending_the_asset_consumes_it() {
        let src = "contract C { state { a: u64; } \
                   entry transfer(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV \
                   { send(to, funds); } }";
        ok(src);
    }

    #[test]
    fn consuming_twice_is_a_copy() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry twice(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) \
                   { pool.merge(funds); send(caller, funds); } }";
        assert!(error_for(src).contains("more than once"));
    }

    #[test]
    fn burning_consumes_the_incoming_asset() {
        let src = "contract C { asset TKN; state { s: u128; } \
                   entry burn(funds: Q_Asset<TKN>) burns TKN writes(s) \
                   { s -= funds.amount; } }";
        ok(src);
    }
}
