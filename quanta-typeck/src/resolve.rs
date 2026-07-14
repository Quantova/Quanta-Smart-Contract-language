//! Name resolution. The structured references a contract makes, the fields it

use crate::error::TypeError;
use crate::model::Model;
use quanta_ast::{Clause, EntryDecl, Expr, Item, Stmt};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for item in &model.contract.items {
        if let Item::Genesis(g) = item {
            for stmt in &g.body {
                check_genesis_stmt(model, stmt)?;
            }
        }
    }
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_genesis_stmt(model: &Model, stmt: &Stmt) -> Result<(), TypeError> {
    if let Stmt::Assign { target, span, .. } = stmt {
        if let Some(name) = root_ident(target) {
            if !model.is_state(name) {
                return Err(TypeError::new(
                    format!("genesis assigns `{name}`, which is not a state field"),
                    *span,
                ));
            }
        }
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    for param in &entry.params {
        if let Some(party) = &param.signed_by {
            if !model.is_state(&party.text) {
                return Err(TypeError::new(
                    format!(
                        "parameter `{}` is signed by `{}`, which is not a state field",
                        param.name.text, party.text
                    ),
                    party.span,
                ));
            }
        }
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Writes { names, .. } | Clause::Reads { names, .. } => {
                for name in names {
                    if !model.is_state(&name.text) {
                        return Err(TypeError::new(
                            format!("clause names `{}`, which is not a state field", name.text),
                            name.span,
                        ));
                    }
                }
            }
            Clause::Conserves { asset, .. } => {
                if !model.is_known_asset(&asset.text) {
                    return Err(TypeError::new(
                        format!("conserves an unknown asset `{}`", asset.text),
                        asset.span,
                    ));
                }
            }
            Clause::Mints { asset, .. } => {
                if !model.is_declared_asset(&asset.text) {
                    return Err(TypeError::new(
                        format!("mints `{}`, which is not a declared asset", asset.text),
                        asset.span,
                    ));
                }
            }
            Clause::Burns { asset, .. } => {
                if !model.is_declared_asset(&asset.text) {
                    return Err(TypeError::new(
                        format!("burns `{}`, which is not a declared asset", asset.text),
                        asset.span,
                    ));
                }
            }
            Clause::Limits { .. } | Clause::Denies { .. } | Clause::After { .. } => {}
        }
    }
    Ok(())
}

/// The leftmost identifier of an lvalue, if any.
fn root_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(id) => Some(&id.text),
        Expr::Field { base, .. } => root_ident(base),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Model;

    fn error_for(src: &str) -> String {
        let program = quanta_parser::parse(src).expect("source parses");
        let contract = &program.contracts[0];
        let model = Model::build(contract);
        super::check(&model)
            .expect_err("checker should reject")
            .message
    }

    #[test]
    fn writes_must_name_a_state_field() {
        let src = "contract C { state { a: u64; } entry f() writes(b) { } }";
        assert!(error_for(src).contains("not a state field"));
    }

    #[test]
    fn mints_must_name_a_declared_asset() {
        let src = "contract C { state { a: u64; } entry f() mints GHOST { } }";
        assert!(error_for(src).contains("not a declared asset"));
    }

    #[test]
    fn signed_by_must_name_a_state_field() {
        let src = "contract C { state { a: u64; } entry f(o: Order signed by ghost) { } }";
        assert!(error_for(src).contains("not a state field"));
    }
}
