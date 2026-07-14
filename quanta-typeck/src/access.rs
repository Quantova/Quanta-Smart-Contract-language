//! Invariant and access checks. A contract invariant ranges only over declared

use crate::error::TypeError;
use crate::model::Model;
use quanta_ast::{Clause, EntryDecl, Expr, Item, Stmt};
use std::collections::HashSet;

const MUTATORS: &[&str] = &["merge", "split", "credit", "insert", "remove"];

pub fn check(model: &Model) -> Result<(), TypeError> {
    for item in &model.contract.items {
        if let Item::Invariant(inv) = item {
            check_invariant(model, &inv.expr)?;
        }
    }
    for entry in &model.entries {
        check_writes(model, entry)?;
    }
    Ok(())
}

fn check_invariant(model: &Model, expr: &Expr) -> Result<(), TypeError> {
    let mut error = None;
    walk(expr, &mut |e| {
        if error.is_none() {
            if let Expr::Ident(id) = e {
                if !model.is_state(&id.text) {
                    error = Some(TypeError::new(
                        format!(
                            "invariant references `{}`, which is not a state field",
                            id.text
                        ),
                        id.span,
                    ));
                }
            }
        }
    });
    match error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn check_writes(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let declared: HashSet<&str> = entry
        .clauses
        .iter()
        .filter_map(|c| match c {
            Clause::Writes { names, .. } => Some(names),
            _ => None,
        })
        .flatten()
        .map(|n| n.text.as_str())
        .collect();

    for stmt in &entry.body {
        if let Some(err) = undeclared_write(model, &declared, stmt) {
            return Err(err);
        }
    }
    Ok(())
}

fn undeclared_write(model: &Model, declared: &HashSet<&str>, stmt: &Stmt) -> Option<TypeError> {
    let mut error = None;
    let mut visit = |field: &str, span| {
        if error.is_none() && model.is_state(field) && !declared.contains(field) {
            error = Some(TypeError::new(
                format!("entry writes `{field}` without declaring it in a writes clause"),
                span,
            ));
        }
    };

    if let Stmt::Assign { target, span, .. } = stmt {
        if let Some(name) = root_ident(target) {
            visit(name, *span);
        }
    }
    for_each_expr(stmt, &mut |e| {
        if let Expr::Call { callee, span, .. } = e {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if MUTATORS.contains(&name.text.as_str()) {
                    if let Some(root) = root_ident(base) {
                        visit(root, *span);
                    }
                }
            }
        }
    });
    error
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
    fn assigning_an_undeclared_field_is_rejected() {
        let src = "contract C { state { a: u64; b: u64; } \
                   entry f() writes(a) { b = 1; } }";
        assert!(error_for(src).contains("without declaring it"));
    }

    #[test]
    fn a_mutating_method_needs_the_field_declared() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry f(funds: Q_Asset<QTOV>) conserves QTOV { pool.merge(funds); } }";
        assert!(error_for(src).contains("without declaring it"));
    }

    #[test]
    fn declared_writes_are_accepted() {
        let src = "contract C { state { a: u64; } entry f() writes(a) { a = 1; } }";
        ok(src);
    }

    #[test]
    fn an_invariant_over_state_is_accepted() {
        let src = "contract C { state { a: u64; b: u64; } invariant a <= b; }";
        ok(src);
    }
}
