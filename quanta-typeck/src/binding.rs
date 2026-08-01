// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_asset_param, is_quorum_param, Model};
use quanta_ast::{AfterTarget, Clause, EntryDecl, Expr, Ident, Param, Stmt};
use std::collections::HashSet;

const GUARDIAN_SET: &str = "GuardianSet";

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(entry)?;
    }
    Ok(())
}

struct Authorized<'a> {
    params: HashSet<&'a str>,
    signed: HashSet<&'a str>,
    quorum: HashSet<&'a str>,
    asset: HashSet<&'a str>,
    guardian: HashSet<&'a str>,
    has_quorum: bool,
}

impl<'a> Authorized<'a> {
    fn read_field(&self, base: &str, field: &str, span: quanta_lexer::Span) -> Option<TypeError> {
        if self.asset.contains(base) || self.quorum.contains(base) || self.signed.contains(base) {
            return None;
        }
        if self.guardian.contains(base) {
            return self.guardian_ok(base, span);
        }
        if self.has_quorum {
            return None;
        }
        Some(TypeError::new(
            format!(
                "authorized entry reads `{base}.{field}`, but the `signed by` order does not bind \
                 `{base}`; every field an authorized entry reads must be carried by the signed order"
            ),
            span,
        ))
    }

    fn read_bare(&self, name: &str, span: quanta_lexer::Span) -> Option<TypeError> {
        if self.asset.contains(name) || self.quorum.contains(name) || self.signed.contains(name) {
            return None;
        }
        if self.guardian.contains(name) {
            return self.guardian_ok(name, span);
        }
        Some(TypeError::new(
            format!(
                "authorized entry reads parameter `{name}`, whose value no signature binds; carry it \
                 inside a `signed by` order so the authorizer signs the value it approves"
            ),
            span,
        ))
    }

    fn guardian_ok(&self, name: &str, span: quanta_lexer::Span) -> Option<TypeError> {
        if self.has_quorum {
            None
        } else {
            Some(TypeError::new(
                format!("authorized entry reads guardian set `{name}` with no quorum to bind it"),
                span,
            ))
        }
    }
}

fn kind_sets<'a>(entry: &'a EntryDecl) -> Authorized<'a> {
    let mut params = HashSet::new();
    let mut signed = HashSet::new();
    let mut quorum = HashSet::new();
    let mut asset = HashSet::new();
    let mut guardian = HashSet::new();
    for p in &entry.params {
        let name = p.name.text.as_str();
        params.insert(name);
        if p.signed_by.is_some() {
            signed.insert(name);
        }
        if is_quorum_param(p) {
            quorum.insert(name);
        }
        if is_asset_param(p) {
            asset.insert(name);
        }
        if p.ty.name.text == GUARDIAN_SET {
            guardian.insert(name);
        }
    }
    let has_quorum = !quorum.is_empty();
    Authorized {
        params,
        signed,
        quorum,
        asset,
        guardian,
        has_quorum,
    }
}

fn is_authorized(entry: &EntryDecl) -> bool {
    entry
        .params
        .iter()
        .any(|p: &Param| p.signed_by.is_some() || is_quorum_param(p))
}

fn check_entry(entry: &EntryDecl) -> Result<(), TypeError> {
    if !is_authorized(entry) {
        return Ok(());
    }
    let ctx = kind_sets(entry);
    let no_locals = HashSet::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                scan(&ctx, expr, &no_locals)?
            }
            Clause::After { target, from, .. } => {
                if let AfterTarget::Expr(expr) = target {
                    scan(&ctx, expr, &no_locals)?;
                }
                if let Some(expr) = from {
                    scan(&ctx, expr, &no_locals)?;
                }
            }
            _ => {}
        }
    }
    let mut locals: HashSet<&str> = HashSet::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => scan(&ctx, expr, &locals)?,
            Stmt::Let { name, value, .. } => {
                scan(&ctx, value, &locals)?;
                locals.insert(name.text.as_str());
            }
            Stmt::Emit { args, .. } => {
                for arg in args {
                    scan(&ctx, arg, &locals)?;
                }
            }
            Stmt::Assign { target, value, .. } => {
                scan(&ctx, target, &locals)?;
                scan(&ctx, value, &locals)?;
            }
        }
    }
    Ok(())
}

fn scan(ctx: &Authorized, expr: &Expr, locals: &HashSet<&str>) -> Result<(), TypeError> {
    let violation = match expr {
        Expr::Field { base, name, span } => {
            if let Expr::Ident(id) = base.as_ref() {
                if ctx.params.contains(id.text.as_str()) && !locals.contains(id.text.as_str()) {
                    ctx.read_field(&id.text, &name.text, *span)
                } else {
                    return scan(ctx, base, locals);
                }
            } else {
                return scan(ctx, base, locals);
            }
        }
        Expr::Ident(Ident { text, span }) => {
            if ctx.params.contains(text.as_str()) && !locals.contains(text.as_str()) {
                ctx.read_bare(text, *span)
            } else {
                None
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            return scan(ctx, expr, locals)
        }
        Expr::Binary { left, right, .. } => {
            scan(ctx, left, locals)?;
            return scan(ctx, right, locals);
        }
        Expr::Call { callee, args, .. } => {
            scan(ctx, callee, locals)?;
            for arg in args {
                scan(ctx, arg, locals)?;
            }
            None
        }
        _ => None,
    };
    match violation {
        Some(err) => Err(err),
        None => Ok(()),
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
    fn a_bare_value_param_a_signed_entry_reads_is_rejected() {
        let src = "contract C { state { owner: Q_Address; count: u64; } \
                   entry act(order: ActOrder signed by owner, extra: u64) writes(count) \
                   { count = checked(count + order.step); count = checked(count + extra); } }";
        assert!(error_for(src).contains("no signature binds"));
    }

    #[test]
    fn a_bare_address_param_a_signed_entry_reads_is_rejected() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry payout(order: PayOrder signed by owner, dest: Q_Address) writes(balances) \
                   { balances.credit(dest, order.amount); } }";
        assert!(error_for(src).contains("no signature binds"));
    }

    #[test]
    fn all_authorized_values_inside_the_signed_order_compile() {
        let src = "contract C { state { owner: Q_Address; count: u64; } \
                   entry act(order: ActOrder signed by owner) writes(count) \
                   { count = checked(count + order.step); count = checked(count + order.extra); } }";
        ok(src);
    }

    #[test]
    fn a_second_unsigned_order_a_signed_entry_reads_is_rejected() {
        let src = "contract C { state { owner: Q_Address; count: u64; } \
                   entry act(order: ActOrder signed by owner, side: SideNote) writes(count) \
                   { count = checked(count + order.step); count = checked(count + side.bonus); } }";
        assert!(error_for(src).contains("does not bind"));
    }

    #[test]
    fn a_bare_value_param_a_quorum_entry_reads_is_rejected() {
        let src = "contract C { state { board: GuardianSet<3>; count: u64; } \
                   entry act(order: ActOrder, approvals: Quorum<2 of 3, board>, extra: u64) \
                   writes(count) { count = checked(count + order.step); count = checked(count + extra); } }";
        assert!(error_for(src).contains("no signature binds"));
    }

    #[test]
    fn a_quorum_entry_binding_a_second_order_field_compiles() {
        let src = "contract C { state { board: GuardianSet<3>; count: u64; } \
                   entry act(order: ActOrder, approvals: Quorum<2 of 3, board>) writes(count) \
                   { count = checked(count + order.step); } }";
        ok(src);
    }

    #[test]
    fn a_quorum_rotation_reads_the_new_set_and_compiles() {
        let src = "contract C { state { board: GuardianSet<3>; } \
                   entry rotate(new_board: GuardianSet<3>, approvals: Quorum<2 of 3, board>) \
                   writes(board) { board = new_board; } }";
        ok(src);
    }

    #[test]
    fn an_unauthorized_transfer_reading_a_bare_address_compiles() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry transfer(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(balances) \
                   { balances.credit(to, funds.amount); } }";
        ok(src);
    }

    #[test]
    fn a_signed_entry_reading_only_order_fields_and_assets_compiles() {
        let src = "contract C { state { owner: Q_Address; vault: Q_Asset<QTOV>; } \
                   entry withdraw(order: WithdrawOrder signed by owner, payment: Q_Asset<QTOV>) \
                   conserves QTOV writes(vault) \
                   { vault.merge(payment); send(order.to, vault.split(order.amount)); } }";
        ok(src);
    }
}
