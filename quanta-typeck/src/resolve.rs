use crate::error::TypeError;
use crate::model::Model;
use quanta_ast::{Clause, EntryDecl, Expr, Item, Stmt};
use std::collections::HashSet;

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
    check_no_external_call(model, entry)?;
    Ok(())
}

fn check_no_external_call(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let addresses = address_names(model, entry);
    let mut offending = None;
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| {
            if offending.is_none() {
                if let Expr::Call { callee, span, .. } = e {
                    if is_external_address(callee, &addresses) {
                        offending = Some(*span);
                    }
                }
            }
        });
    }
    if let Some(span) = offending {
        return Err(TypeError::new(
            "no synchronous external call: control cannot leave and reenter an entry; \
             the only outward transfer is `send`, which returns nothing",
            span,
        ));
    }
    Ok(())
}

fn address_names<'a>(model: &'a Model, entry: &'a EntryDecl) -> HashSet<&'a str> {
    let mut set = HashSet::new();
    for (name, field) in &model.state {
        if field.ty.name.text == "Q_Address" {
            set.insert(*name);
        }
    }
    for param in &entry.params {
        if param.ty.name.text == "Q_Address" {
            set.insert(param.name.text.as_str());
        }
    }
    set
}

fn is_external_address(expr: &Expr, addresses: &HashSet<&str>) -> bool {
    match expr {
        Expr::Caller { .. } => true,
        Expr::Ident(id) => addresses.contains(id.text.as_str()),
        Expr::Field { base, .. } => is_external_address(base, addresses),
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

    #[test]
    fn a_synchronous_external_call_to_the_caller_is_rejected() {
        let src = "contract C { state { owner: Q_Address; vault: Q_Asset<QTOV>; } \
                   entry withdraw(order: WithdrawOrder signed by owner) conserves QTOV writes(vault) \
                   { let out = vault.split(order.amount); let ack = caller.receive(out); } }";
        assert!(error_for(src).contains("external call"));
    }
}
