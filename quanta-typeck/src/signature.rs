// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_quorum_param, Model};
use quanta_ast::{BinOp, Clause, EntryDecl, Expr, GenericArg, Stmt, UnaryOp};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let signed: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.signed_by.is_some())
        .map(|p| p.name.text.as_str())
        .collect();
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let derived = param_derived_locals(entry, &params, &signed);

    for clause in &entry.clauses {
        let expr = match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => expr,
            _ => continue,
        };
        if let Some(err) = forged(model, &params, &signed, &derived, expr) {
            return Err(err);
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if let Some(err) = forged(model, &params, &signed, &derived, expr) {
                return Err(err);
            }
        }
    }
    if let Some(err) = forged_map_authority(model, entry, &params, &signed, &derived) {
        return Err(err);
    }
    if let Some(err) = forged_caller_anchor(model, entry, &signed) {
        return Err(err);
    }
    Ok(())
}

fn forged_caller_anchor(model: &Model, entry: &EntryDecl, signed: &HashSet<&str>) -> Option<TypeError> {
    if !entry_sends(entry) || !signed.is_empty() || entry.params.iter().any(is_quorum_param) {
        return None;
    }
    if entry_binds_caller(model, entry, signed) {
        return None;
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, span } => {
                if let Some(anchor) = forgeable_anchor(model, expr, false) {
                    return Some(forgeable_anchor_error(&anchor, *span));
                }
            }
            Clause::Denies { expr, span } => {
                if let Some(anchor) = forgeable_anchor(model, expr, true) {
                    return Some(forgeable_anchor_error(&anchor, *span));
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, span } = stmt {
            if let Some(anchor) = forgeable_anchor(model, expr, false) {
                return Some(forgeable_anchor_error(&anchor, *span));
            }
        }
    }
    None
}

fn forgeable_anchor(model: &Model, expr: &Expr, denied: bool) -> Option<String> {
    let mut found = None;
    walk(expr, &mut |e| {
        if found.is_some() {
            return;
        }
        let anchor = if denied {
            anchor_of_denied(model, e)
        } else {
            anchor_of(model, e)
        };
        if let Some(a) = anchor {
            if !authority_anchor_protected(model, a) {
                found = Some(a.to_string());
            }
        }
    });
    found
}

fn forgeable_anchor_error(anchor: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged authority: this entry moves value gated on `caller` against `{anchor}`, but an \
             entry with no authority can write `{anchor}`, so the check is forgeable; write the \
             authority only from an authorized entry or from genesis"
        ),
        span,
    )
}

fn authority_anchor_protected(model: &Model, field: &str) -> bool {
    let mut stack = HashSet::new();
    let mut memo = HashMap::new();
    anchor_protected(model, field, &mut stack, &mut memo).0
}

fn anchor_protected(
    model: &Model,
    field: &str,
    stack: &mut HashSet<String>,
    memo: &mut HashMap<String, bool>,
) -> (bool, bool) {
    if let Some(&resolved) = memo.get(field) {
        return (resolved, false);
    }
    if stack.contains(field) {
        return (true, true);
    }
    stack.insert(field.to_string());
    let mut protected = true;
    let mut tainted = false;
    for entry in &model.entries {
        if entry_writes_field(entry, field) {
            let (authorized, sub_tainted) = writer_authorized(model, entry, stack, memo);
            if !authorized {
                protected = false;
                break;
            }
            tainted |= sub_tainted;
        }
    }
    stack.remove(field);
    if !protected {
        memo.insert(field.to_string(), false);
        return (false, false);
    }
    if !tainted {
        memo.insert(field.to_string(), true);
    }
    (true, tainted)
}

fn writer_authorized(
    model: &Model,
    entry: &EntryDecl,
    stack: &mut HashSet<String>,
    memo: &mut HashMap<String, bool>,
) -> (bool, bool) {
    let signed: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.signed_by.is_some())
        .map(|p| p.name.text.as_str())
        .collect();
    if !signed.is_empty() || entry.params.iter().any(is_quorum_param) {
        return (true, false);
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => {
                let (authorized, tainted) = gate_necessary_protected(model, expr, stack, memo);
                if authorized {
                    return (true, tainted);
                }
            }
            Clause::Denies { expr, .. } => {
                let (authorized, tainted) =
                    gate_necessary_denied_protected(model, expr, stack, memo);
                if authorized {
                    return (true, tainted);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let (authorized, tainted) = gate_necessary_protected(model, expr, stack, memo);
            if authorized {
                return (true, tainted);
            }
        }
    }
    (false, false)
}

fn gate_necessary_protected(
    model: &Model,
    expr: &Expr,
    stack: &mut HashSet<String>,
    memo: &mut HashMap<String, bool>,
) -> (bool, bool) {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_protected(model, left, stack, memo);
            let (rp, rt) = gate_necessary_protected(model, right, stack, memo);
            (lp || rp, lt || rt)
        }
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_protected(model, left, stack, memo);
            let (rp, rt) = gate_necessary_protected(model, right, stack, memo);
            (lp && rp, lt || rt)
        }
        _ => match anchor_of(model, expr) {
            Some(a) => anchor_protected(model, a, stack, memo),
            None => (false, false),
        },
    }
}

fn gate_necessary_denied_protected(
    model: &Model,
    expr: &Expr,
    stack: &mut HashSet<String>,
    memo: &mut HashMap<String, bool>,
) -> (bool, bool) {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_denied_protected(model, left, stack, memo);
            let (rp, rt) = gate_necessary_denied_protected(model, right, stack, memo);
            (lp && rp, lt || rt)
        }
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_denied_protected(model, left, stack, memo);
            let (rp, rt) = gate_necessary_denied_protected(model, right, stack, memo);
            (lp || rp, lt || rt)
        }
        _ => match anchor_of_denied(model, expr) {
            Some(a) => anchor_protected(model, a, stack, memo),
            None => (false, false),
        },
    }
}

fn entry_writes_field(entry: &EntryDecl, field: &str) -> bool {
    let mut writes = false;
    for stmt in &entry.body {
        match stmt {
            Stmt::Assign { target, .. } => {
                if matches!(target, Expr::Ident(id) if id.text == field) {
                    writes = true;
                }
            }
            _ => {}
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(
                        name.text.as_str(),
                        "set" | "credit" | "debit" | "insert" | "remove" | "clear"
                    ) && matches!(base.as_ref(), Expr::Ident(id) if id.text == field)
                    {
                        writes = true;
                    }
                }
            }
        });
    }
    writes
}

fn param_derived_locals(
    entry: &EntryDecl,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
) -> HashSet<String> {
    let mut derived: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            if taints_from_param(value, params, signed, &derived) {
                derived.insert(name.text.clone());
            }
        }
    }
    derived
}

fn taints_from_param(
    expr: &Expr,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
) -> bool {
    let mut tainted = false;
    walk(expr, &mut |e| {
        if let Expr::Ident(id) = e {
            let name = id.text.as_str();
            if (params.contains(name) && !signed.contains(name)) || derived.contains(name) {
                tainted = true;
            }
        }
    });
    tainted
}

fn forged_map_authority(
    model: &Model,
    entry: &EntryDecl,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
) -> Option<TypeError> {
    if !entry_sends(entry) || entry_binds_caller(model, entry, signed) {
        return None;
    }
    let mut gate_expr = |expr: &Expr| map_lookup_on_param(model, params, signed, derived, expr);
    for clause in &entry.clauses {
        if let Clause::Limits { expr, .. } | Clause::Denies { expr, .. } = clause {
            if let Some((field, span)) = gate_expr(expr) {
                return Some(map_authority_error(&field, span));
            }
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if let Some((field, span)) = gate_expr(expr) {
                return Some(map_authority_error(&field, span));
            }
        }
    }
    None
}

fn map_authority_error(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged authority: this entry moves value gated only by looking up self declared \
             parameter data `{field}` in a state map, with no `caller` check or `signed by` \
             binding; authority must come from `caller` or a signature"
        ),
        span,
    )
}

fn entry_sends(entry: &EntryDecl) -> bool {
    let mut sends = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") {
                    sends = true;
                }
            }
        });
    }
    sends
}

fn entry_binds_caller(model: &Model, entry: &EntryDecl, signed: &HashSet<&str>) -> bool {
    if !signed.is_empty() || entry.params.iter().any(is_quorum_param) {
        return true;
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => {
                if caller_necessary(model, expr) {
                    return true;
                }
            }
            Clause::Denies { expr, .. } => {
                if caller_necessary_denied(model, expr) {
                    return true;
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if caller_necessary(model, expr) {
                return true;
            }
        }
    }
    false
}

fn caller_necessary_denied(model: &Model, expr: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => caller_necessary_denied(model, left) && caller_necessary_denied(model, right),
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => caller_necessary_denied(model, left) || caller_necessary_denied(model, right),
        _ => caller_constrains_denied(model, expr),
    }
}

fn caller_constrains_denied(model: &Model, expr: &Expr) -> bool {
    anchor_of_denied(model, expr).is_some_and(|a| authority_anchor_protected(model, a))
}

fn caller_necessary(model: &Model, expr: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => caller_necessary(model, left) || caller_necessary(model, right),
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => caller_necessary(model, left) && caller_necessary(model, right),
        _ => caller_constrains(model, expr),
    }
}

fn caller_constrains(model: &Model, expr: &Expr) -> bool {
    anchor_of(model, expr).is_some_and(|a| authority_anchor_protected(model, a))
}

fn anchor_of<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Binary {
        op: BinOp::Eq,
        left,
        right,
        ..
    } = expr
    {
        if is_caller(left) {
            if let Some(a) = state_addr_ident(model, right) {
                return Some(a);
            }
            if let Some(m) = map_value_addr(model, right) {
                return Some(m);
            }
        }
        if is_caller(right) {
            if let Some(a) = state_addr_ident(model, left) {
                return Some(a);
            }
            if let Some(m) = map_value_addr(model, left) {
                return Some(m);
            }
        }
    }
    if let Some(m) = membership_map(model, expr) {
        return Some(m);
    }
    if caller_membership_present(model, expr) {
        if let Expr::Binary { left, right, .. } = expr {
            if let Some(m) = membership_map(model, left) {
                return Some(m);
            }
            if let Some(m) = membership_map(model, right) {
                return Some(m);
            }
        }
    }
    None
}

fn anchor_of_denied<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Binary {
        op: BinOp::Ne,
        left,
        right,
        ..
    } = expr
    {
        if is_caller(left) {
            if let Some(a) = state_addr_ident(model, right) {
                return Some(a);
            }
        }
        if is_caller(right) {
            if let Some(a) = state_addr_ident(model, left) {
                return Some(a);
            }
        }
    }
    if let Expr::Unary {
        op: UnaryOp::Not,
        expr,
        ..
    } = expr
    {
        return anchor_of(model, expr);
    }
    None
}

fn state_addr_ident<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Ident(id) = expr {
        if model
            .state
            .get(id.text.as_str())
            .is_some_and(|f| f.ty.name.text == "Q_Address")
        {
            return Some(id.text.as_str());
        }
    }
    None
}

fn membership_map<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Call { callee, args, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if matches!(name.text.as_str(), "contains" | "get" | "has") {
                if let Expr::Ident(map_id) = base.as_ref() {
                    if is_addr_keyed(model, map_id.text.as_str())
                        && args.len() == 1
                        && is_caller(&args[0])
                    {
                        return Some(map_id.text.as_str());
                    }
                }
            }
        }
    }
    None
}

fn map_value_addr<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Call { callee, args, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "get" && args.len() == 1 {
                if let Expr::Ident(map_id) = base.as_ref() {
                    if is_addr_valued(model, map_id.text.as_str()) {
                        return Some(map_id.text.as_str());
                    }
                }
            }
        }
    }
    None
}

fn is_addr_valued(model: &Model, ident: &str) -> bool {
    if let Some(f) = model.state.get(ident) {
        if f.ty.name.text == "Map" {
            if let Some(GenericArg::Type(v)) = f.ty.args.get(1) {
                return v.name.text == "Q_Address";
            }
        }
    }
    false
}

fn is_caller_membership(model: &Model, expr: &Expr) -> bool {
    membership_map(model, expr).is_some()
}

fn caller_membership_present(model: &Model, expr: &Expr) -> bool {
    let Expr::Binary { op, left, right, .. } = expr else {
        return false;
    };
    let threshold = if is_caller_membership(model, left) {
        right.as_ref()
    } else if is_caller_membership(model, right) {
        left.as_ref()
    } else {
        return false;
    };
    let lookup_left = is_caller_membership(model, left);
    match (op, lookup_left) {
        (BinOp::Ge, true) | (BinOp::Le, false) => is_positive_int(threshold),
        (BinOp::Gt, true) | (BinOp::Lt, false) => is_nonnegative_int(threshold),
        (BinOp::Ne, _) => is_zero_int(threshold),
        (BinOp::Eq, _) => is_positive_int(threshold),
        _ => false,
    }
}

fn is_caller(expr: &Expr) -> bool {
    matches!(expr, Expr::Caller { .. })
}

fn is_positive_int(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(lit) if lit.text.replace('_', "").parse::<u128>().map_or(false, |v| v >= 1))
}

fn is_nonnegative_int(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(_))
}

fn is_zero_int(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(lit) if lit.text.replace('_', "").parse::<u128>() == Ok(0))
}

fn map_lookup_on_param(
    model: &Model,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
    expr: &Expr,
) -> Option<(String, Span)> {
    let mut found = None;
    walk(expr, &mut |e| {
        if found.is_some() {
            return;
        }
        if let Expr::Call { callee, args, span } = e {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if matches!(name.text.as_str(), "contains" | "get" | "has") {
                    if let Expr::Ident(map_id) = base.as_ref() {
                        if is_addr_keyed(model, map_id.text.as_str()) {
                            for a in args {
                                if let Some(field) = param_field(params, signed, derived, a) {
                                    found = Some((field, *span));
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    found
}

fn is_addr_keyed(model: &Model, ident: &str) -> bool {
    if let Some(f) = model.state.get(ident) {
        if matches!(f.ty.name.text.as_str(), "Map" | "Set") {
            if let Some(GenericArg::Type(k)) = f.ty.args.first() {
                return k.name.text == "Q_Address";
            }
        }
    }
    false
}

fn stmt_exprs(stmt: &Stmt, f: &mut impl FnMut(&Expr)) {
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
        _ => {}
    }
}

fn forged(
    model: &Model,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
    expr: &Expr,
) -> Option<TypeError> {
    if let Expr::Binary {
        op: BinOp::Eq | BinOp::Ne,
        left,
        right,
        span,
    } = expr
    {
        if let Some(field) = authority_gate(model, params, signed, derived, left, right) {
            return Some(TypeError::new(
                format!(
                    "forged authority: gating on `{field}` compares self declared parameter data \
                     to state; authority must come from a `signed by` binding"
                ),
                *span,
            ));
        }
    }
    match expr {
        Expr::Unary { expr, .. } => forged(model, params, signed, derived, expr),
        Expr::Binary { left, right, .. } => forged(model, params, signed, derived, left)
            .or_else(|| forged(model, params, signed, derived, right)),
        _ => None,
    }
}

fn authority_gate(
    model: &Model,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
    a: &Expr,
    b: &Expr,
) -> Option<String> {
    param_field(params, signed, derived, a)
        .filter(|_| is_state_address(model, b))
        .or_else(|| param_field(params, signed, derived, b).filter(|_| is_state_address(model, a)))
}

fn param_field(
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
    expr: &Expr,
) -> Option<String> {
    match expr {
        Expr::Field { .. } => {
            let root = root_ident(expr)?;
            if (params.contains(root) && !signed.contains(root)) || derived.contains(root) {
                field_path(expr)
            } else {
                None
            }
        }
        Expr::Ident(id) => {
            let name = id.text.as_str();
            if (params.contains(name) && !signed.contains(name)) || derived.contains(name) {
                Some(id.text.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn root_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(id) => Some(id.text.as_str()),
        Expr::Field { base, .. } => root_ident(base),
        _ => None,
    }
}

fn field_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.text.clone()),
        Expr::Field { base, name, .. } => Some(format!("{}.{}", field_path(base)?, name.text)),
        _ => None,
    }
}

fn is_state_address(model: &Model, expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(id) if model.state.get(id.text.as_str()).is_some_and(|f| f.ty.name.text == "Q_Address"))
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
    fn comparing_parameter_data_to_a_party_is_forged() {
        let src = "contract C { state { owner: Q_Address; } \
                   entry withdraw(order: WithdrawOrder) limits order.sender == owner { } }";
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_signed_by_parameter_is_real_authority() {
        let src = "contract C { state { owner: Q_Address; } \
                   entry withdraw(order: WithdrawOrder signed by owner) writes(owner) { } }";
        ok(src);
    }

    #[test]
    fn comparing_state_to_a_literal_is_not_authority() {
        let src = "contract C { state { released: u8; } \
                   entry release(order: Order) writes(released) denies released == 1 { } }";
        ok(src);
    }

    #[test]
    fn a_body_guard_comparing_a_field_to_a_state_address_is_forged() {
        let src = "contract C { state { owner: Q_Address; } \
                   entry withdraw(order: WithdrawOrder) writes(owner) { guard order.sender == owner; } }";
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_bare_parameter_compared_to_a_state_address_is_forged() {
        let src = "contract C { state { owner: Q_Address; } \
                   entry withdraw(claimed: Q_Address) limits claimed == owner { } }";
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_body_guard_comparing_a_bare_parameter_to_a_state_address_is_forged() {
        let src = "contract C { state { owner: Q_Address; } \
                   entry withdraw(claimed: Q_Address) writes(owner) { guard claimed == owner; } }";
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_value_precondition_comparing_an_amount_to_a_price_is_not_authority() {
        let src = "contract C { state { price: u64; } \
                   entry fund(order: FundOrder) writes(price) { guard order.amount == price; } }";
        ok(src);
    }

    #[test]
    fn comparing_a_parameter_to_a_literal_is_not_authority() {
        let src = "contract C { state { released: u8; } \
                   entry release(flag: u64) writes(released) { guard flag == 1; } }";
        ok(src);
    }

    #[test]
    fn a_caller_disjunction_with_a_parameter_branch_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard members.contains(caller) || members.contains(claim.who);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_tautological_caller_check_does_not_authorize() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard caller == caller;
                    guard members.contains(claim.who);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_genuine_caller_membership_check_is_real_authority() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard members.contains(caller);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        ok(src);
    }

    #[test]
    fn a_caller_equals_state_owner_is_real_authority() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard caller == owner;
                    guard members.contains(claim.who);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        ok(src);
    }

    #[test]
    fn a_let_aliased_parameter_map_key_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    let who = claim.who;
                    guard members.contains(who);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_denies_caller_not_owner_is_real_authority() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { admin: Q_Address; registered: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry payout(order: Order) conserves QTOV writes(vault)
                  denies caller != admin
                { guard registered.contains(order.to); send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_caller_membership_value_check_is_real_authority() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { allowed: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry payout(order: Order) conserves QTOV writes(vault)
                { guard allowed.get(caller) >= 1; guard allowed.contains(order.to);
                  send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_decoy_caller_argument_does_not_bind_authority() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault)
                { guard members.contains(claim.who, caller); send(claim.to, vault.split(claim.amount)); }
            }"#;
        assert!(error_for(src).contains("forged authority"));
    }

    #[test]
    fn a_caller_check_against_a_settable_authority_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; }
                entry claim(a: Q_Address) writes(owner) { owner = a; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_caller_check_against_a_genesis_only_authority_is_real() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; }
                genesis { owner = deployer; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_caller_check_against_an_owner_gated_rotation_is_real() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; }
                genesis { owner = deployer; }
                entry rotate(new: Q_Address) writes(owner) { guard caller == owner; owner = new; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_two_hop_forgeable_authority_chain_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { admin: Q_Address; owner: Q_Address; vault: Q_Asset<QTOV>; }
                genesis { admin = deployer; owner = deployer; }
                entry set_admin(a: Q_Address) writes(admin) { admin = a; }
                entry rotate(new: Q_Address) writes(owner) { guard caller == admin; owner = new; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_two_hop_chain_grounded_in_genesis_is_real() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { admin: Q_Address; owner: Q_Address; vault: Q_Asset<QTOV>; }
                genesis { admin = deployer; owner = deployer; }
                entry rotate(new: Q_Address) writes(owner) { guard caller == admin; owner = new; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_settable_map_value_authority_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner_of: Map<Q_Id, Q_Address>; vault: Q_Asset<QTOV>; }
                entry set_owner(order: SetOwner) writes(owner_of) { owner_of.set(order.id, order.who); }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard owner_of.get(order.id) == caller; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_deep_authority_chain_checks_in_polynomial_time() {
        let n = 30;
        let mut src = String::from("import { Q_Asset } from \"quantova/primitives\";\ncontract C {\n  state {");
        for i in 0..n {
            src.push_str(&format!(" f{i}: Q_Address;"));
        }
        src.push_str(" vault: Q_Asset<QTOV>; }\n");
        src.push_str(&format!("  genesis {{ f{} = deployer; }}\n", n - 1));
        for i in 0..n - 1 {
            src.push_str(&format!(
                "  entry wa{i}(x: Q_Address) writes(f{i}) {{ guard caller == f{}; f{i} = x; }}\n",
                i + 1
            ));
            src.push_str(&format!(
                "  entry wb{i}(x: Q_Address) writes(f{i}) {{ guard caller == f{}; f{i} = x; }}\n",
                i + 1
            ));
        }
        src.push_str("  entry drain(order: Rel) conserves QTOV writes(vault) { guard caller == f0; send(order.to, vault.split(order.amount)); }\n}");
        ok(&src);
    }

    #[test]
    fn authority_laundered_through_a_primer_gate_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { admin: Q_Address; x: Q_Address; owner: Q_Address; vault: Q_Asset<QTOV>; }
                genesis { admin = deployer; }
                entry set_x(a: Q_Address) writes(x) { x = a; }
                entry w1(new: Q_Address) writes(owner) { guard caller == x; guard caller == admin; owner = new; }
                entry w2(new: Q_Address) writes(owner) { guard caller == x; owner = new; }
                entry drain(order: Rel) conserves QTOV writes(vault)
                { guard caller == owner; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_nested_field_parameter_map_key_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard members.contains(claim.inner.who);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        assert!(error_for(src).contains("forged authority"));
    }
}
