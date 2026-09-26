// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{asset_inner, is_quorum_param, Model};
use quanta_ast::{AssignOp, BinOp, Clause, EntryDecl, Expr, GenericArg, Param, Stmt, UnaryOp};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    if entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .count()
        > 1
    {
        if let Some(second) = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .nth(1)
        {
            return Err(TypeError::new(
                "more than one incoming asset parameter: the call carries a single value word, so each \
                 asset param binds the same inflow; take at most one asset parameter per entry"
                    .to_string(),
                second.name.span,
            ));
        }
    }
    let signed: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.signed_by.is_some())
        .map(|p| p.name.text.as_str())
        .collect();
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let derived = param_derived_locals(entry, &params, &signed);
    if entry
        .params
        .iter()
        .any(|p| p.signed_by.is_some() || crate::model::is_quorum_param(p))
    {
        if let Some(span) = entry.body.iter().find_map(caller_outside_guard) {
            return Err(TypeError::new(
                "a signed or quorum order does not bind who submits it, so `caller` may only be \
                 compared in a guard here; carry the recipient inside the order"
                    .to_string(),
                span,
            ));
        }
    }

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
    if let Some(err) = forged_meta_flow(model, entry) {
        return Err(err);
    }
    if let Some(err) = forged_caller_anchor(model, entry, &signed) {
        return Err(err);
    }
    if let Some(err) = forged_recipient(model, entry) {
        return Err(err);
    }
    if let Some(err) = forged_signed_authority(model, entry) {
        return Err(err);
    }
    if let Some(err) = unconditional_self_claim(model, entry) {
        return Err(err);
    }
    if let Some(err) = forged_ownership_transfer(model, entry, &signed) {
        return Err(err);
    }
    if entry_moves_ledger_value(model, entry)
        && !entry_binds_caller(model, entry, &signed)
        && !ledger_move_is_paid_for_by_the_caller(model, entry)
        && !spends_an_allowance_its_owner_granted(model, entry)
        && !foreign_rows_are_paid_for_at_par(entry)
        && !credits_drawn_from_an_inflow_only_total(model, entry)
    {
        return Err(no_ledger_authority_error(entry));
    }
    if entry_moves_asset(entry)
        && !entry_binds_caller(model, entry, &signed)
        && !asset_outflow_is_paid_for_by_the_caller(model, entry)
    {
        return Err(no_asset_authority_error(entry));
    }
    if (entry_moves_asset(entry) || entry_moves_ledger_value(model, entry))
        && authority_is_membership_only(model, entry, &signed)
        && (moved_amount_is_caller_chosen(model, entry)
            || outflow_amount_is_a_self_written_row(model, entry))
        && !outflow_is_bounded_by_an_entitlement(model, entry)
    {
        return Err(unbacked_membership_error(entry));
    }
    Ok(())
}

fn moved_amount_is_caller_chosen(model: &Model, entry: &EntryDecl) -> bool {
    let free: Vec<&str> = entry
        .params
        .iter()
        .filter(|p| !crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    if free.is_empty() {
        return false;
    }
    let signed: HashSet<&str> = HashSet::new();

    let mut backed: HashSet<&str> = HashSet::new();
    for name in &free {
        let one: HashSet<&str> = std::iter::once(*name).collect();
        let derived = param_derived_locals(entry, &one, &signed);
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { name: m, .. } = callee.as_ref() {
                        if m.text == "debit"
                            && matches!(args.first(), Some(Expr::Caller { .. }))
                            && args
                                .get(1)
                                .map(|a| {
                                    debit_covers_the_parameter(a, name)
                                        && taints_from_param(a, &one, &signed, &derived)
                                })
                                .unwrap_or(false)
                        {
                            if let Expr::Field { base, .. } = callee.as_ref() {
                                if let Expr::Ident(map) = base.as_ref() {
                                    if credit_cancels_the_debit(entry, map.text.as_str(), name) {
                                        return;
                                    }
                                }
                            }
                            backed.insert(*name);
                        }
                    }
                }
            });
        }
    }

    let unbacked: HashSet<&str> = free
        .iter()
        .copied()
        .filter(|n| !backed.contains(n))
        .collect();
    if unbacked.is_empty() {
        return false;
    }
    let mut derived = param_derived_locals(entry, &unbacked, &signed);
    for field in tainted_state_fields(entry, &unbacked, &signed, &derived) {
        derived.insert(field);
    }
    let mut caller_chosen = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                let amount = match callee.as_ref() {
                    Expr::Ident(id) if id.text == "send_asset" => args.get(2),
                    Expr::Ident(id) if id.text == "send" => args.get(1),
                    Expr::Field { name, .. } if name.text == "split" => args.first(),
                    Expr::Field { name, .. }
                        if matches!(name.text.as_str(), "credit" | "set" | "insert") =>
                    {
                        args.get(1)
                    }
                    _ => None,
                };
                if let Some(a) = amount {
                    if !amount_is_a_trusted_state_read(model, entry, a)
                        && taints_from_param(a, &unbacked, &signed, &derived)
                    {
                        caller_chosen = true;
                    }
                }
            }
        });
    }
    caller_chosen
}

fn reads_a_caller_row(model: &Model, expr: &Expr) -> bool {
    let mut found = false;
    walk(expr, &mut |e| {
        if let Expr::Call { callee, args, .. } = e {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" && matches!(args.first(), Some(Expr::Caller { .. })) {
                    if let Expr::Ident(m) = base.as_ref() {
                        if authority_anchor_protected(model, m.text.as_str()) {
                            found = true;
                        }
                    }
                }
            }
        }
    });
    found
}

fn tainted_state_fields(
    entry: &EntryDecl,
    free: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        if let Stmt::Assign { target, value, .. } = stmt {
            if taints_from_param(value, free, signed, derived) {
                if let Expr::Ident(id) = target {
                    out.insert(id.text.clone());
                }
            }
        }
    }
    out
}

fn asset_outflow_is_paid_for_by_the_caller(model: &Model, entry: &EntryDecl) -> bool {
    let paid_in = entry.params.iter().any(crate::model::is_asset_param);
    let mut burns_its_own_row = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(_))
                        && name.text == "debit"
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                    {
                        burns_its_own_row = true;
                    }
                }
            }
        });
    }
    if !paid_in && !burns_its_own_row {
        return false;
    }
    if moved_amount_is_caller_chosen(model, entry) {
        return false;
    }
    let mut sends_only_to_caller = true;
    let mut saw_send = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Ident(id) = callee.as_ref() {
                    if id.text == "mint_asset" {
                        sends_only_to_caller = false;
                    }
                    if id.text == "send_asset" {
                        saw_send = true;
                        if !matches!(args.get(1), Some(Expr::Caller { .. })) {
                            sends_only_to_caller = false;
                        }
                    }
                }
            }
        });
    }
    saw_send && sends_only_to_caller
}

fn ledger_move_is_paid_for_by_the_caller(model: &Model, entry: &EntryDecl) -> bool {
    if moved_amount_is_caller_chosen(model, entry) {
        return false;
    }
    if !entry.params.iter().any(crate::model::is_asset_param) {
        return false;
    }
    let assets: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    let backed_scalars = asset_backed_scalars(model, entry);
    let mut saw = false;
    let mut all_caller_keyed = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(_))
                        && matches!(
                            name.text.as_str(),
                            "credit" | "debit" | "set" | "insert" | "remove"
                        )
                    {
                        saw = true;
                        if !matches!(args.first(), Some(Expr::Caller { .. })) {
                            all_caller_keyed = false;
                        }
                        if matches!(name.text.as_str(), "credit" | "set" | "insert") {
                            let paid = args.get(1).is_some_and(|v| {
                                asset_amount_backer(v.peel(), &assets).is_some()
                                    || matches!(v.peel(), Expr::Ident(id)
                                        if backed_scalars.contains(id.text.as_str()))
                            });
                            if !paid {
                                all_caller_keyed = false;
                            }
                        }
                    }
                }
            }
        });
    }
    saw && all_caller_keyed
}

fn unconditional_self_claim(model: &Model, entry: &EntryDecl) -> Option<TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let mut claimed: Option<(String, String)> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if claimed.is_some() {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(map) = base.as_ref() {
                        if matches!(name.text.as_str(), "set" | "insert")
                            && is_addr_valued(model, map.text.as_str())
                            && matches!(args.get(1), Some(Expr::Caller { .. }))
                        {
                            if let Some(Expr::Ident(k)) = args.first() {
                                if params.contains(k.text.as_str()) {
                                    claimed = Some((map.text.clone(), k.text.clone()));
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    let (map, key) = claimed?;
    let mut conditioned = false;
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            walk(expr, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if matches!(name.text.as_str(), "get" | "contains" | "has")
                                && model.state.contains_key(m.text.as_str())
                            {
                                if let Some(k @ Expr::Ident(kid)) = args.first() {
                                    if kid.text == key
                                        && entry_writes_field_under_key(entry, m.text.as_str(), k)
                                    {
                                        conditioned = true;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    if conditioned {
        return None;
    }
    if !map_is_read_as_caller_authority(model, &map) {
        return None;
    }
    Some(TypeError::new(
        format!(
            "this entry `{}` writes `caller` into `{}` under a key it was given without first \
             checking whether that key is already held, so anyone can take a slot somebody else \
             owns and any later `{}.get(...) == caller` check reads a row they forged; guard the \
             slot before claiming it",
            entry.name.text, map, map
        ),
        entry.name.span,
    ))
}

fn authority_is_membership_only(model: &Model, entry: &EntryDecl, signed: &HashSet<&str>) -> bool {
    if has_protected_signed_authority(model, entry) || entry.params.iter().any(is_quorum_param) {
        return false;
    }
    let mut caller_keyed = false;
    let mut required: Vec<&Expr> = Vec::new();
    let mut denied: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => required.push(expr),
            Clause::Denies { expr, .. } => denied.push(expr),
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            required.push(expr);
        }
    }
    for expr in required.iter().chain(denied.iter()) {
        let is_office = if denied.iter().any(|d| std::ptr::eq(*d, *expr)) {
            denied_office(model, expr)
        } else {
            office_equality(model, expr)
        };
        if is_office {
            return false;
        }
        walk(expr, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if matches!(name.text.as_str(), "get" | "contains" | "has")
                            && model.state.contains_key(m.text.as_str())
                            && matches!(args.first(), Some(Expr::Caller { .. }))
                        {
                            caller_keyed = true;
                        }
                    }
                }
            }
        });
    }
    caller_keyed && entry_binds_caller(model, entry, signed)
}

fn office_equality(model: &Model, expr: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => office_equality(model, left) || office_equality(model, right),
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => office_equality(model, left) && office_equality(model, right),
        Expr::Binary {
            op: BinOp::Eq,
            left,
            right,
            ..
        } => {
            (is_caller(left)
                && (state_addr_ident(model, right).is_some()
                    || map_value_addr(model, right).is_some()))
                || (is_caller(right)
                    && (state_addr_ident(model, left).is_some()
                        || map_value_addr(model, left).is_some()))
        }
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
            ..
        } => denied_office(model, expr),
        _ => false,
    }
}

fn unbacked_membership_error(entry: &EntryDecl) -> TypeError {
    TypeError::new(
        format!(
            "this entry `{}` sends an amount the caller named on the strength of a membership \
             check alone: the guard proves the caller holds a row, not that they are owed this \
             much, so anyone who has ever paid in can drain the whole holding; debit the caller's \
             own row by the amount being sent, or compute the amount from what was paid",
            entry.name.text
        ),
        entry.name.span,
    )
}

fn map_is_read_as_caller_authority(model: &Model, field: &str) -> bool {
    for entry in &model.entries {
        let mut guards: Vec<&Expr> = Vec::new();
        for clause in &entry.clauses {
            match clause {
                Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => guards.push(expr),
                _ => {}
            }
        }
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                guards.push(expr);
            }
        }
        for expr in guards {
            if anchor_of(model, expr) == Some(field) || anchor_of_denied(model, expr) == Some(field)
            {
                return true;
            }
        }
    }
    false
}

fn map_is_ever_paid_out(model: &Model, field: &str) -> bool {
    let reads_through = |e: &Expr, aliases: &HashSet<String>| {
        let mut hit = false;
        walk(e, &mut |x| {
            if let Expr::Call { callee, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == field
                            && matches!(name.text.as_str(), "get" | "contains" | "has")
                        {
                            hit = true;
                        }
                    }
                }
            }
            if let Expr::Ident(id) = x {
                if aliases.contains(id.text.as_str()) {
                    hit = true;
                }
            }
        });
        hit
    };
    for entry in &model.entries {
        let mut aliases: HashSet<String> = HashSet::new();
        for stmt in &entry.body {
            if let Stmt::Let { name, value, .. } = stmt {
                if reads_through(value, &aliases) {
                    aliases.insert(name.text.clone());
                }
            }
        }
        let reads_field = |e: &Expr| reads_through(e, &aliases);
        let mut found = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if found {
                    return;
                }
                if let Expr::Call { callee, args, .. } = e {
                    match callee.as_ref() {
                        Expr::Ident(id) if id.text == "send_asset" => {
                            if args.get(2).is_some_and(reads_field) {
                                found = true;
                            }
                        }
                        Expr::Ident(id) if id.text == "mint_asset" => {
                            if args.get(1).is_some_and(reads_field) {
                                found = true;
                            }
                        }
                        Expr::Ident(id) if id.text == "send" => {
                            if args.get(1).is_some_and(reads_field) {
                                found = true;
                            }
                        }
                        Expr::Field { base, name, .. } => {
                            if let Expr::Ident(m) = base.as_ref() {
                                if (m.text == field && name.text == "debit")
                                    || (matches!(name.text.as_str(), "credit" | "debit")
                                        && args.get(1).is_some_and(reads_field))
                                {
                                    found = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
        if found {
            return true;
        }
    }
    false
}

fn asset_backed_scalars(model: &Model, here: &EntryDecl) -> HashSet<String> {
    let mut candidate: HashSet<String> = HashSet::new();
    let mut disqualified: HashSet<String> = HashSet::new();
    let mut set_here: HashSet<String> = HashSet::new();
    for entry in &model.entries {
        let asset_params: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| p.ty.name.text == "Q_Asset")
            .map(|p| p.name.text.as_str())
            .collect();
        for stmt in &entry.body {
            if let Stmt::Assign {
                target, op, value, ..
            } = stmt
            {
                if let Expr::Ident(id) = target {
                    if matches!(op, AssignOp::Set)
                        && asset_amount_backer(value, &asset_params).is_some()
                    {
                        candidate.insert(id.text.clone());
                        if std::ptr::eq(*entry, here) {
                            set_here.insert(id.text.clone());
                        }
                    } else {
                        disqualified.insert(id.text.clone());
                    }
                }
            }
        }
    }
    candidate.retain(|f| !disqualified.contains(f) && set_here.contains(f));
    candidate
}

fn writes_field_only_into_an_empty_slot(model: &Model, entry: &EntryDecl, field: &str) -> bool {
    let mut guards: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => guards.push(expr),
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            guards.push(expr);
        }
    }
    let mut parts: Vec<&Expr> = Vec::new();
    for expr in &guards {
        split_and(expr, &mut parts);
    }
    let proves_empty = |key: &Expr| {
        let mut found = false;
        for e in &parts {
            {
                let e: &Expr = e;
                if found {
                    break;
                }
                let probe = |m: &str, k: &Expr| {
                    m == field
                        && expr_eq(k, key)
                        && model.state.contains_key(m)
                        && entry_writes_field_under_key(entry, m, key)
                };
                match e {
                    Expr::Binary {
                        op: BinOp::Eq,
                        left,
                        right,
                        ..
                    } => {
                        for (x, y) in [(left, right), (right, left)] {
                            if matches!(y.as_ref(), Expr::Int(n) if n.text == "0") {
                                if let Some((m, k)) = any_map_get(x) {
                                    if probe(m, k) {
                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                    Expr::Unary {
                        op: UnaryOp::Not,
                        expr,
                        ..
                    } => {
                        if let Some((m, k)) = any_map_contains(expr) {
                            if probe(m, k) {
                                found = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        found
    };
    let mut saw = false;
    let mut all_proven = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text != field {
                            return;
                        }
                        if name.text == "remove" {
                            all_proven = false;
                            return;
                        }
                        if matches!(name.text.as_str(), "set" | "insert" | "credit" | "debit") {
                            saw = true;
                            if matches!(args.first(), Some(Expr::Caller { .. })) {
                                all_proven = false;
                                return;
                            }
                            if !args.first().is_some_and(&proves_empty) {
                                all_proven = false;
                            }
                        }
                    }
                }
            }
        });
    }
    saw && all_proven
}

fn any_map_get(e: &Expr) -> Option<(&str, &Expr)> {
    if let Expr::Call { callee, args, .. } = e {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if let Expr::Ident(m) = base.as_ref() {
                if name.text == "get" {
                    return args.first().map(|k| (m.text.as_str(), k));
                }
            }
        }
    }
    None
}

fn any_map_contains(e: &Expr) -> Option<(&str, &Expr)> {
    if let Expr::Call { callee, args, .. } = e {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if let Expr::Ident(m) = base.as_ref() {
                if matches!(name.text.as_str(), "contains" | "has") {
                    return args.first().map(|k| (m.text.as_str(), k));
                }
            }
        }
    }
    None
}

fn entry_writes_field_under_key(entry: &EntryDecl, field: &str, key: &Expr) -> bool {
    let mut hit = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == field
                            && matches!(name.text.as_str(), "set" | "insert" | "credit")
                            && args.first().is_some_and(|k| expr_eq(k, key))
                        {
                            hit = true;
                        }
                    }
                }
            }
        });
    }
    hit
}

fn debit_covers_the_parameter(e: &Expr, param: &str) -> bool {
    match e {
        Expr::Ident(id) => id.text == param,
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => {
            (debit_covers_the_parameter(left, param) && literal_at_least_one(right))
                || (debit_covers_the_parameter(right, param) && literal_at_least_one(left))
        }
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            (debit_covers_the_parameter(left, param) && non_negative(right))
                || (debit_covers_the_parameter(right, param) && non_negative(left))
        }
        Expr::Checked { expr, .. } => debit_covers_the_parameter(expr, param),
        _ => false,
    }
}

fn literal_at_least_one(e: &Expr) -> bool {
    match e {
        Expr::Int(n) => n
            .text
            .replace('_', "")
            .parse::<u128>()
            .map(|v| v >= 1)
            .unwrap_or(false),
        _ => false,
    }
}

fn anchor_writable_without_authority(model: &Model, field: &str) -> bool {
    for entry in &model.entries {
        if !entry_writes_field(entry, field) {
            continue;
        }
        let signed: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| p.signed_by.is_some())
            .map(|p| p.name.text.as_str())
            .collect();
        let paid = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .any(|p| entry_requires_a_positive_amount(entry, p.name.text.as_str()));
        let quorum = entry.params.iter().any(is_quorum_param);
        let bound = entry_binds_caller(model, entry, &signed);
        let holds_the_slot = entry_guards_on_holding(model, entry, field);
        if !bound && !paid && !quorum && signed.is_empty() && !holds_the_slot {
            return true;
        }
    }
    false
}

fn outflow_amount_is_a_self_written_row(model: &Model, entry: &EntryDecl) -> bool {
    let self_row = |x: &Expr, aliases: &HashSet<String>| {
        if let Expr::Ident(id) = x {
            return aliases.contains(id.text.as_str());
        }
        if let Expr::Call { callee, args, .. } = x {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if let Expr::Ident(m) = base.as_ref() {
                    return name.text == "get"
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                        && model.state.contains_key(m.text.as_str())
                        && !authority_anchor_protected(model, m.text.as_str());
                }
            }
        }
        false
    };
    let mut aliases: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let mut hit = false;
            walk(value, &mut |x| {
                if !hit && self_row(x, &aliases) {
                    hit = true;
                }
            });
            if hit {
                aliases.insert(name.text.clone());
            }
        }
    }
    let mut found = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if found {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                let amount = match callee.as_ref() {
                    Expr::Field { name, .. } if name.text == "split" => args.first(),
                    other => crate::model::outflow_value(other, args),
                };
                let Some(a) = amount else { return };
                walk(a, &mut |x| {
                    if !found && self_row(x, &aliases) {
                        found = true;
                    }
                });
            }
        });
    }
    found
}

fn denied_office(model: &Model, expr: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => denied_office(model, left) && denied_office(model, right),
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => denied_office(model, left) || denied_office(model, right),
        Expr::Binary {
            op: BinOp::Ne,
            left,
            right,
            ..
        } => {
            (is_caller(left)
                && (state_addr_ident(model, right).is_some()
                    || map_value_addr(model, right).is_some()))
                || (is_caller(right)
                    && (state_addr_ident(model, left).is_some()
                        || map_value_addr(model, left).is_some()))
        }
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
            ..
        } => office_equality(model, expr),
        _ => false,
    }
}

fn non_negative(e: &Expr) -> bool {
    match e {
        Expr::Int(_) | Expr::Ident(_) | Expr::Field { .. } => true,
        Expr::Call { callee, .. } => {
            matches!(callee.as_ref(), Expr::Field { name, .. } if name.text == "get")
        }
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        }
        | Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => non_negative(left) && non_negative(right),
        Expr::Checked { expr, .. } => non_negative(expr),
        _ => false,
    }
}

fn entry_requires_a_positive_amount(entry: &EntryDecl, param: &str) -> bool {
    let mut required = false;
    let mut exprs: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        if let Clause::Limits { expr, .. } = clause {
            exprs.push(expr);
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            exprs.push(expr);
        }
    }
    let real_bound = |b: &Expr| match b {
        Expr::Int(n) => n
            .text
            .replace('_', "")
            .parse::<u128>()
            .map(|v| v >= 1)
            .unwrap_or(false),
        _ => true,
    };
    for expr in exprs {
        walk(expr, &mut |e| {
            if let Expr::Binary {
                op, left, right, ..
            } = e
            {
                let amount_left = is_asset_amount_expr(left, param);
                let amount_right = is_asset_amount_expr(right, param);
                match op {
                    BinOp::Gt if amount_left => required = true,
                    BinOp::Ge if amount_left && real_bound(right) => required = true,
                    BinOp::Lt if amount_right => required = true,
                    BinOp::Le if amount_right && real_bound(left) => required = true,
                    _ => {}
                }
            }
        });
    }
    required
}

fn entry_guards_on_holding(model: &Model, entry: &EntryDecl, field: &str) -> bool {
    let mut exprs: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => exprs.push(expr),
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            exprs.push(expr);
        }
    }
    let mut holds = false;
    for expr in exprs {
        walk(expr, &mut |e| {
            if let Expr::Binary {
                op: BinOp::Eq,
                left,
                right,
                ..
            } = e
            {
                for (a, b) in [(left, right), (right, left)] {
                    if is_caller(b) {
                        if let Some(m) = map_value_addr(model, a) {
                            if m == field {
                                holds = true;
                            }
                        }
                    }
                }
            }
        });
    }
    holds
}

fn outflow_is_bounded_by_an_entitlement(model: &Model, entry: &EntryDecl) -> bool {
    let leaving = names_in_outflow_amounts(entry);
    if leaving.is_empty() {
        return false;
    }
    let mut exprs: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        if let Clause::Limits { expr, .. } = clause {
            exprs.push(expr);
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            exprs.push(expr);
        }
    }
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let mut bounded = false;
    let mut musts: Vec<&Expr> = Vec::new();
    for expr in exprs {
        collect_conjuncts(expr, &mut musts);
    }
    for expr in musts {
        walk(expr, &mut |e| {
            if bounded {
                return;
            }
            let Expr::Binary {
                op, left, right, ..
            } = e
            else {
                return;
            };
            let (small, large) = match op {
                BinOp::Le | BinOp::Lt => (left.as_ref(), right.as_ref()),
                BinOp::Ge | BinOp::Gt => (right.as_ref(), left.as_ref()),
                _ => return,
            };
            if !mentions_any_name(small, &leaving) {
                return;
            }
            if mentions_any_name(
                large,
                &params
                    .iter()
                    .map(|p| (*p).to_string())
                    .collect::<HashSet<String>>(),
            ) {
                return;
            }
            if !bound_is_trustworthy(model, large) {
                return;
            }
            let accrued = accumulating_state(entry);
            if accrued.is_empty() && !entry_reduces_a_caller_row(entry) {
                return;
            }
            if !accrued.is_empty() {
                let names = std::iter::once(large)
                    .chain(std::iter::once(small))
                    .collect::<Vec<_>>();
                let mut counted = false;
                for part in names {
                    walk(part, &mut |x| {
                        if let Expr::Ident(id) = x {
                            if accrued.contains(id.text.as_str()) {
                                counted = true;
                            }
                        }
                    });
                }
                if !counted {
                    return;
                }
            }
            bounded = true;
        });
    }
    bounded
}

fn names_in_outflow_amounts(entry: &EntryDecl) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                let amount = match callee.as_ref() {
                    Expr::Field { name, .. } if name.text == "split" => args.first(),
                    other => crate::model::outflow_value(other, args),
                };
                if let Some(a) = amount {
                    walk(a, &mut |x| {
                        if let Expr::Ident(id) = x {
                            out.insert(id.text.clone());
                        }
                    });
                }
            }
        });
    }
    out
}

fn mentions_any_name(e: &Expr, names: &HashSet<String>) -> bool {
    let mut hit = false;
    walk(e, &mut |x| {
        if let Expr::Ident(id) = x {
            if names.contains(id.text.as_str()) {
                hit = true;
            }
        }
    });
    hit
}

fn bound_is_trustworthy(model: &Model, e: &Expr) -> bool {
    let mut trustworthy = true;
    let mut saw_state = false;
    walk(e, &mut |x| match x {
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if let Expr::Ident(m) = base.as_ref() {
                    if matches!(name.text.as_str(), "get" | "contains" | "has")
                        && model.state.contains_key(m.text.as_str())
                    {
                        saw_state = true;
                        if !authority_anchor_protected(model, m.text.as_str())
                            || caller_sets_their_own_row(model, m.text.as_str())
                        {
                            trustworthy = false;
                        }
                    }
                }
            }
        }
        Expr::Ident(id) => {
            if model.state.contains_key(id.text.as_str()) {
                saw_state = true;
                if !authority_anchor_protected(model, id.text.as_str())
                    || caller_sets_their_own_row(model, id.text.as_str())
                {
                    trustworthy = false;
                }
            }
        }
        Expr::Field { base, name, .. } => {
            if name.text == "amount" {
                if let Expr::Ident(m) = base.as_ref() {
                    if model.state.contains_key(m.text.as_str()) {
                        saw_state = true;
                        trustworthy = false;
                    }
                }
            }
        }
        _ => {}
    });
    saw_state && trustworthy
}

fn accumulating_state(entry: &EntryDecl) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        if let Stmt::Assign {
            target, op, value, ..
        } = stmt
        {
            if let Expr::Ident(id) = target {
                let compound = matches!(op, AssignOp::Add | AssignOp::Sub);
                let mut self_ref = false;
                walk(value, &mut |x| {
                    if let Expr::Ident(v) = x {
                        if v.text == id.text {
                            self_ref = true;
                        }
                    }
                });
                if compound || self_ref {
                    out.insert(id.text.clone());
                }
            }
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if matches!(args.first(), Some(Expr::Caller { .. }))
                            && (name.text == "credit"
                                || (matches!(name.text.as_str(), "set" | "insert")
                                    && args.get(1).is_some_and(|v| {
                                        let mut reads_self = false;
                                        walk(v, &mut |x| {
                                            if let Expr::Call { callee, .. } = x {
                                                if let Expr::Field { base, name, .. } =
                                                    callee.as_ref()
                                                {
                                                    if let Expr::Ident(mm) = base.as_ref() {
                                                        if mm.text == m.text && name.text == "get" {
                                                            reads_self = true;
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                        reads_self
                                    })))
                        {
                            out.insert(m.text.clone());
                        }
                    }
                }
            }
        });
    }
    out
}

fn adds_a_constant_floor(e: &Expr) -> bool {
    match e {
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            let literal_at_least_one = |x: &Expr| matches!(x, Expr::Int(n) if n.text.replace('_', "").parse::<u128>().map(|v| v >= 1).unwrap_or(false));
            literal_at_least_one(left)
                || literal_at_least_one(right)
                || adds_a_constant_floor(left)
                || adds_a_constant_floor(right)
        }
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        }
        | Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        }
        | Expr::Binary {
            op: BinOp::Div,
            left,
            right,
            ..
        } => adds_a_constant_floor(left) || adds_a_constant_floor(right),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => adds_a_constant_floor(expr),
        _ => false,
    }
}

fn credit_cancels_the_debit(entry: &EntryDecl, field: &str, param: &str) -> bool {
    let mut credited = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == field
                            && name.text == "credit"
                            && matches!(args.first(), Some(Expr::Caller { .. }))
                            && args
                                .get(1)
                                .is_some_and(|a| debit_covers_the_parameter(a, param))
                        {
                            credited = true;
                        }
                    }
                }
            }
        });
    }
    credited
}

fn caller_sets_their_own_row(model: &Model, field: &str) -> bool {
    for entry in &model.entries {
        let free: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| !crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        if free.is_empty() {
            continue;
        }
        let signed: HashSet<&str> = HashSet::new();
        let derived = param_derived_locals(entry, &free, &signed);
        let mut settable = false;
        for stmt in &entry.body {
            if let Stmt::Assign {
                target, op, value, ..
            } = stmt
            {
                if let Expr::Ident(id) = target {
                    if id.text == field
                        && matches!(op, AssignOp::Set)
                        && taints_from_param(value, &free, &signed, &derived)
                    {
                        let mut accumulates = false;
                        walk(value, &mut |x| {
                            if let Expr::Ident(v) = x {
                                if v.text == id.text {
                                    accumulates = true;
                                }
                            }
                        });
                        if !accumulates {
                            settable = true;
                        }
                    }
                }
            }
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if m.text == field
                                && matches!(name.text.as_str(), "set" | "insert" | "credit")
                                && matches!(args.first(), Some(Expr::Caller { .. }))
                                && args
                                    .get(1)
                                    .is_some_and(|v| taints_from_param(v, &free, &signed, &derived))
                            {
                                settable = true;
                            }
                        }
                    }
                }
            });
        }
        if settable {
            return true;
        }
    }
    false
}

fn entry_reduces_a_caller_row(entry: &EntryDecl) -> bool {
    let mut reduces = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(map) = base.as_ref() {
                        if matches!(args.first(), Some(Expr::Caller { .. })) {
                            if name.text == "debit" {
                                reduces = true;
                            }
                            if matches!(name.text.as_str(), "set" | "insert")
                                && row_reduction(&map.text, args)
                            {
                                reduces = true;
                            }
                        }
                    }
                }
            }
        });
    }
    reduces
}

fn writing_your_own_row_only_spends_your_own(model: &Model, field: &str) -> bool {
    let mut saw_a_spender = false;
    let mut all_backed = true;
    for entry in &model.entries {
        let mut guards: Vec<&Expr> = Vec::new();
        for clause in &entry.clauses {
            match clause {
                Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => guards.push(expr),
                _ => {}
            }
        }
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                guards.push(expr);
            }
        }
        for g in guards {
            walk(g, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if m.text == field && name.text == "get" {
                                if let Some(k) = args.first() {
                                    saw_a_spender = true;
                                    if !entry_debits_another_map_under(entry, field, k) {
                                        all_backed = false;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    saw_a_spender && all_backed
}

fn entry_debits_another_map_under(entry: &EntryDecl, field: &str, key: &Expr) -> bool {
    let mut backed = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text != field
                            && name.text == "debit"
                            && args.first().is_some_and(|k| expr_eq(k, key))
                        {
                            backed = true;
                        }
                    }
                }
            }
        });
    }
    backed
}

fn entry_debits_the_row_it_gated_on(entry: &EntryDecl, field: &str, key: &Expr) -> bool {
    let mut debited = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == field
                            && name.text == "debit"
                            && args.len() >= 2
                            && expr_eq(&args[0], key)
                        {
                            debited = true;
                        }
                    }
                }
            }
        });
    }
    debited
}

fn spends_an_allowance_its_owner_granted(model: &Model, entry: &EntryDecl) -> bool {
    let mut conserved: Option<String> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if conserved.is_some() {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if name.text == "debit" {
                            if let Some(amount) = args.get(1) {
                                let mut credited_same = false;
                                for st in &entry.body {
                                    stmt_exprs(st, &mut |x| {
                                        if let Expr::Call { callee, args, .. } = x {
                                            if let Expr::Field { base, name, .. } = callee.as_ref()
                                            {
                                                if let Expr::Ident(m2) = base.as_ref() {
                                                    if m2.text == m.text
                                                        && name.text == "credit"
                                                        && args
                                                            .get(1)
                                                            .is_some_and(|a| expr_eq(a, amount))
                                                    {
                                                        credited_same = true;
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                                if credited_same {
                                    conserved = Some(m.text.clone());
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    let Some(ledger) = conserved else {
        return false;
    };

    let mut guards: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => guards.push(expr),
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            guards.push(expr);
        }
    }
    let debit_keys = |map: &str| {
        let mut keys: Vec<Expr> = Vec::new();
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if m.text == map && name.text == "debit" {
                                if let Some(key) = args.first() {
                                    keys.push(key.clone());
                                }
                            }
                        }
                    }
                }
            });
        }
        keys
    };
    let ledger_keys = debit_keys(&ledger);
    let mut permitted = false;
    for g in guards {
        walk(g, &mut |e| {
            if permitted {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        let Some(key) = args.first() else { return };
                        let allowance_keys = debit_keys(m.text.as_str());
                        if name.text == "get"
                            && m.text != ledger
                            && !allowance_keys.is_empty()
                            && allowance_keys.iter().all(|k| expr_eq(k, key))
                            && !ledger_keys.is_empty()
                            && ledger_keys.iter().all(|k| expr_eq(k, key))
                            && every_grant_is_under_the_granters_own_key(model, m.text.as_str())
                        {
                            permitted = true;
                        }
                    }
                }
            }
        });
    }
    permitted
}

fn every_grant_is_under_the_granters_own_key(model: &Model, field: &str) -> bool {
    let mut saw_grant = false;
    let mut all_own = true;
    for entry in &model.entries {
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if m.text == field
                                && matches!(name.text.as_str(), "set" | "insert" | "credit")
                            {
                                saw_grant = true;
                                if !matches!(args.first(), Some(Expr::Caller { .. })) {
                                    all_own = false;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    saw_grant && all_own
}

fn split_and<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            split_and(left, out);
            split_and(right, out);
        }
        other => out.push(other),
    }
}

fn collect_conjuncts<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            collect_conjuncts(left, out);
            collect_conjuncts(right, out);
        }
        Expr::Binary { op: BinOp::Or, .. }
        | Expr::Unary {
            op: UnaryOp::Not, ..
        } => {}
        other => out.push(other),
    }
}

fn amount_is_a_trusted_state_read(model: &Model, entry: &EntryDecl, amount: &Expr) -> bool {
    if let Expr::Ident(id) = amount {
        for stmt in &entry.body {
            if let Stmt::Let { name, value, .. } = stmt {
                if name.text == id.text {
                    if let Expr::Call { callee, args, .. } = value {
                        if let Expr::Field { name: m, .. } = callee.as_ref() {
                            if m.text == "split" {
                                if let Some(inner) = args.first() {
                                    return amount_is_a_trusted_state_read(model, entry, inner);
                                }
                            }
                        }
                    }
                    return amount_is_a_trusted_state_read(model, entry, value);
                }
            }
        }
        return false;
    }
    let Expr::Call { callee, .. } = amount else {
        return false;
    };
    let Expr::Field { base, name, .. } = callee.as_ref() else {
        return false;
    };
    if name.text != "get" {
        return false;
    }
    let Expr::Ident(m) = base.as_ref() else {
        return false;
    };
    model.state.contains_key(m.text.as_str())
        && authority_anchor_protected(model, m.text.as_str())
        && !caller_sets_their_own_row(model, m.text.as_str())
        && entry_consumes_the_row(entry, m.text.as_str())
}

fn entry_consumes_the_row(entry: &EntryDecl, field: &str) -> bool {
    let mut consumed = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text != field {
                            return;
                        }
                        if matches!(name.text.as_str(), "remove" | "debit") {
                            consumed = true;
                        }
                        if matches!(name.text.as_str(), "set" | "insert") {
                            let zeroed = matches!(args.get(1), Some(Expr::Int(n)) if n.text.replace('_', "") == "0");
                            if zeroed || row_reduction(field, args) {
                                consumed = true;
                            }
                        }
                    }
                }
            }
        });
    }
    consumed
}

fn credits_only_what_was_paid_in(model: &Model, entry: &EntryDecl, field: &str) -> bool {
    let assets: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    if assets.is_empty() {
        return false;
    }
    let backed_scalars = asset_backed_scalars(model, entry);
    let mut saw = false;
    let mut all_paid = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text != field {
                            return;
                        }
                        if matches!(name.text.as_str(), "set" | "insert" | "remove") {
                            saw = true;
                            all_paid = false;
                            return;
                        }
                        if name.text == "credit" {
                            saw = true;
                            let backed = args.get(1).is_some_and(|v| {
                                asset_amount_backer(v, &assets).is_some()
                                    || matches!(v, Expr::Ident(id)
                                        if backed_scalars.contains(id.text.as_str()))
                            });
                            if !backed {
                                all_paid = false;
                            }
                        }
                    }
                }
            }
        });
    }
    saw && all_paid
}

fn row_reduction(field: &str, args: &[Expr]) -> bool {
    let (
        Some(key),
        Some(Expr::Binary {
            op: BinOp::Sub,
            left,
            ..
        }),
    ) = (args.first(), args.get(1))
    else {
        return false;
    };
    let Expr::Call {
        callee, args: read, ..
    } = left.as_ref()
    else {
        return false;
    };
    let Expr::Field { base, name, .. } = callee.as_ref() else {
        return false;
    };
    matches!(base.as_ref(), Expr::Ident(m) if m.text == field)
        && name.text == "get"
        && read.len() == 1
        && expr_eq(&read[0], key)
}

fn only_reduces_the_field(entry: &EntryDecl, field: &str) -> bool {
    let mut saw = false;
    let mut all_reduce = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text != field {
                            return;
                        }
                        match name.text.as_str() {
                            "debit" => saw = true,
                            "credit" | "set" | "insert" | "remove" => {
                                saw = true;
                                let reduces = name.text != "credit" && row_reduction(field, args);
                                if !reduces {
                                    all_reduce = false;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }
    saw && all_reduce
}

fn foreign_rows_are_paid_for_at_par(entry: &EntryDecl) -> bool {
    let assets: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    if assets.is_empty() {
        return false;
    }
    let mut saw_foreign = false;
    let mut all_paid = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if !matches!(base.as_ref(), Expr::Ident(_)) {
                        return;
                    }
                    if !matches!(name.text.as_str(), "credit" | "debit" | "set" | "insert") {
                        return;
                    }
                    if matches!(args.first(), Some(Expr::Caller { .. })) {
                        if name.text == "credit"
                            && !args
                                .get(1)
                                .is_some_and(|v| asset_amount_backer(v, &assets).is_some())
                        {
                            all_paid = false;
                        }
                        return;
                    }
                    saw_foreign = true;
                    if matches!(name.text.as_str(), "set" | "insert") {
                        all_paid = false;
                        return;
                    }
                    if !args
                        .get(1)
                        .is_some_and(|v| asset_amount_backer(v, &assets).is_some())
                    {
                        all_paid = false;
                    }
                }
            }
        });
    }
    saw_foreign && all_paid
}

fn inflow_only_totals(model: &Model) -> HashSet<String> {
    let mut candidate: HashSet<String> = HashSet::new();
    let mut disqualified: HashSet<String> = HashSet::new();
    for entry in &model.entries {
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        for stmt in &entry.body {
            let Stmt::Assign {
                target, op, value, ..
            } = stmt
            else {
                continue;
            };
            let Expr::Ident(id) = target else { continue };
            let mut grows_by_asset = false;
            let shrinks = matches!(op, AssignOp::Sub)
                || matches!(value, Expr::Binary { op: BinOp::Sub, left, .. }
                    if matches!(left.as_ref(), Expr::Ident(t) if t.text == id.text));
            walk(value, &mut |x| {
                if asset_amount_backer(x, &assets).is_some() {
                    grows_by_asset = true;
                }
            });
            if shrinks {
                continue;
            }
            if grows_by_asset {
                candidate.insert(id.text.clone());
            } else {
                disqualified.insert(id.text.clone());
            }
        }
    }
    candidate.retain(|f| !disqualified.contains(f));
    candidate
}

fn credits_drawn_from_an_inflow_only_total(model: &Model, entry: &EntryDecl) -> bool {
    let totals = inflow_only_totals(model);
    if totals.is_empty() {
        return false;
    }
    let mut drawn: Vec<&Expr> = Vec::new();
    for stmt in &entry.body {
        if let Stmt::Assign {
            target, op, value, ..
        } = stmt
        {
            if let Expr::Ident(id) = target {
                if !totals.contains(id.text.as_str()) {
                    continue;
                }
                if matches!(op, AssignOp::Sub) {
                    drawn.push(value);
                } else if let Expr::Binary {
                    op: BinOp::Sub,
                    right,
                    ..
                } = value
                {
                    drawn.push(right);
                }
            }
        }
    }
    if drawn.is_empty() {
        return false;
    }
    let mut saw = false;
    let mut all_drawn = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(_))
                        && matches!(name.text.as_str(), "credit" | "set" | "insert")
                    {
                        saw = true;
                        if !args
                            .get(1)
                            .is_some_and(|v| drawn.iter().any(|d| expr_eq(d, v)))
                        {
                            all_drawn = false;
                        }
                    }
                }
            }
        });
    }
    saw && all_drawn
}

fn entry_moves_asset(entry: &EntryDecl) -> bool {
    let mut found = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if let Expr::Ident(id) = callee.as_ref() {
                    if matches!(id.text.as_str(), "send_asset" | "mint_asset") {
                        found = true;
                    }
                }
            }
        });
    }
    found
}

fn no_asset_authority_error(entry: &EntryDecl) -> TypeError {
    TypeError::new(
        format!(
            "this entry `{}` moves asset value with no authority: it sends the contract's own asset \
             holding or mints new units, but carries no `caller` check, `signed by`, or quorum \
             binding; authority must come from `caller` or a signature",
            entry.name.text
        ),
        entry.name.span,
    )
}

fn no_ledger_authority_error(entry: &EntryDecl) -> TypeError {
    TypeError::new(
        format!(
            "this entry `{}` moves ledger value with no authority: it credits unbacked supply, \
             debits another account, overwrites a ledger map, or sends the contract's asset pool \
             without a matching inflow, but carries no `caller` check, `signed by`, or quorum \
             binding; authority must come from `caller`, an incoming asset, or a signature",
            entry.name.text
        ),
        entry.name.span,
    )
}

fn forged_ownership_transfer(
    model: &Model,
    entry: &EntryDecl,
    signed: &HashSet<&str>,
) -> Option<TypeError> {
    if entry_binds_caller(model, entry, signed) || has_protected_signed_authority(model, entry) {
        return None;
    }
    let mut bound_to_caller = false;
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if let Some(a) = anchor_of(model, expr) {
                if !anchor_writable_without_authority(model, a) {
                    bound_to_caller = true;
                }
            }
        }
    }
    if bound_to_caller {
        return None;
    }
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let empty: HashSet<&str> = HashSet::new();
    let derived = param_derived_locals(entry, &params, &empty);
    let parked = tainted_state_fields(entry, &params, &empty, &derived);
    let handed = |value: &Expr| {
        root_ident(value)
            .is_some_and(|r| params.contains(r) || derived.contains(r) || parked.contains(r))
    };
    let mut forged: Option<String> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if forged.is_some() {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(map) = base.as_ref() {
                        if matches!(name.text.as_str(), "set" | "insert" | "remove")
                            && is_addr_valued(model, map.text.as_str())
                        {
                            if matches!(args.first(), Some(Expr::Caller { .. })) {
                                return;
                            }
                            if name.text == "remove" {
                                let paid = args
                                    .first()
                                    .is_some_and(|key| pays_the_holder(entry, &map.text, key));
                                if !paid {
                                    forged = Some(map.text.clone());
                                }
                                return;
                            }
                            if let Some(value) = args.get(1) {
                                if handed(value) {
                                    forged = Some(map.text.clone());
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    forged.map(|map| {
        TypeError::new(
            format!(
                "this entry `{}` hands ownership in `{}` to an address it was given, with no \
                 authority: it carries no `caller` check, `signed by`, or quorum binding, so \
                 anyone may reassign anything the map holds; either write `caller` so it is a \
                 claim, or guard the current holder against `caller` before reassigning it",
                entry.name.text, map
            ),
            entry.name.span,
        )
    })
}

fn pays_the_holder(entry: &EntryDecl, map: &str, key: &Expr) -> bool {
    let holder_of = |e: &Expr| {
        let Expr::Call { callee, args, .. } = e else {
            return false;
        };
        let Expr::Field { base, name, .. } = callee.as_ref() else {
            return false;
        };
        name.text == "get"
            && matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
            && args.first().is_some_and(|k| expr_eq(k, key))
    };
    let mut paid = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            let Expr::Call { callee, args, .. } = e else {
                return;
            };
            let recipient = match callee.as_ref() {
                Expr::Ident(id) if id.text == "send" => args.first(),
                Expr::Ident(id) if id.text == "send_asset" => args.get(1),
                Expr::Field { name, .. } if name.text == "credit" => args.first(),
                _ => None,
            };
            if recipient.is_some_and(holder_of) {
                paid = true;
            }
        });
    }
    paid
}

fn forged_signed_authority(model: &Model, entry: &EntryDecl) -> Option<TypeError> {
    if !entry_moves_value(model, entry) {
        return None;
    }
    let backing: Vec<(&str, Span)> = entry
        .params
        .iter()
        .filter_map(|p| authority_backing_field(p).map(|f| (f, p.name.span)))
        .collect();
    if backing.is_empty() {
        return None;
    }
    if backing
        .iter()
        .any(|(field, _)| authority_anchor_protected(model, field))
    {
        return None;
    }
    let (field, span) = backing[0];
    Some(forged_signed_authority_error(field, span))
}

fn forged_signed_authority_error(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged authority: this entry moves value under a `signed by` or quorum authority grounded \
             in `{field}`, but an entry with no authority can write `{field}`, so the authority is \
             forgeable; write `{field}` only from an authorized entry or from genesis"
        ),
        span,
    )
}

fn forged_caller_anchor(
    model: &Model,
    entry: &EntryDecl,
    signed: &HashSet<&str>,
) -> Option<TypeError> {
    if !entry_moves_value(model, entry)
        || !signed.is_empty()
        || entry.params.iter().any(is_quorum_param)
    {
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

fn forged_recipient(model: &Model, entry: &EntryDecl) -> Option<TypeError> {
    if !entry_moves_value(model, entry) && !entry_moves_asset(entry) {
        return None;
    }
    let mut alias: HashMap<&str, &str> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            if let Some(field) = recipient_state_field(model, value) {
                alias.insert(name.text.as_str(), field);
            } else if let Expr::Ident(rid) = value {
                if let Some(&field) = alias.get(rid.text.as_str()) {
                    alias.insert(name.text.as_str(), field);
                }
            }
        }
    }
    let mut found: Option<(String, Span)> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if found.is_some() {
                return;
            }
            if let Expr::Call { callee, args, span } = e {
                {
                    let recip = crate::model::outflow_recipient(callee.as_ref(), args);
                    if let Some(recip) = recip {
                        let field = recipient_state_field(model, recip).or_else(|| match recip {
                            Expr::Ident(rid) => alias.get(rid.text.as_str()).copied(),
                            _ => None,
                        });
                        if let Some(field) = field {
                            if !authority_anchor_protected(model, field) {
                                found = Some((field.to_string(), *span));
                            }
                        }
                    }
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found.map(|(field, span)| forged_recipient_error(&field, span))
}

fn recipient_state_field<'e>(model: &Model, recip: &'e Expr) -> Option<&'e str> {
    match recip.peel() {
        Expr::Ident(id) if model.state.contains_key(id.text.as_str()) => Some(id.text.as_str()),
        Expr::Field { base, .. } => match base.as_ref() {
            Expr::Ident(id) if model.state.contains_key(id.text.as_str()) => Some(id.text.as_str()),
            _ => None,
        },
        Expr::Call { callee, .. } => match callee.as_ref() {
            Expr::Field { base, name, .. } if matches!(name.text.as_str(), "get" | "at") => {
                match base.as_ref() {
                    Expr::Ident(id) if model.state.contains_key(id.text.as_str()) => {
                        Some(id.text.as_str())
                    }
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn forged_recipient_error(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged recipient: this entry moves value to a destination read from state `{field}`, but \
             an entry with no authority can write `{field}`, so the destination is forgeable; write the \
             recipient only from an authorized entry or from genesis"
        ),
        span,
    )
}

const AUTHORITY_STEP_BUDGET: u64 = 100_000;

struct Prot {
    stack: HashSet<String>,
    memo: HashMap<String, bool>,
    steps: u64,
}

const COMPILE_STEP_BUDGET: u64 = 2_000_000;

pub(crate) fn authority_anchor_protected(model: &Model, field: &str) -> bool {
    if let Some(&known) = model.protection.borrow().get(field) {
        return known;
    }
    if model.protection_steps.get() > COMPILE_STEP_BUDGET {
        return false;
    }
    let mut prot = Prot {
        stack: HashSet::new(),
        memo: HashMap::new(),
        steps: 0,
    };
    let protected = anchor_protected(model, field, &mut prot).0;
    model
        .protection_steps
        .set(model.protection_steps.get().saturating_add(prot.steps));
    model
        .protection
        .borrow_mut()
        .insert(field.to_string(), protected);
    protected
}

fn signer_field(param: &Param) -> Option<&str> {
    param.signed_by.as_ref().map(|i| i.text.as_str())
}

fn quorum_set_field(param: &Param) -> Option<&str> {
    if !is_quorum_param(param) {
        return None;
    }
    param.ty.args.iter().find_map(|arg| match arg {
        GenericArg::Type(t) => Some(t.name.text.as_str()),
        _ => None,
    })
}

fn authority_backing_field(param: &Param) -> Option<&str> {
    signer_field(param).or_else(|| quorum_set_field(param))
}

pub(crate) fn has_protected_signed_authority(model: &Model, entry: &EntryDecl) -> bool {
    entry
        .params
        .iter()
        .filter_map(authority_backing_field)
        .any(|field| authority_anchor_protected(model, field))
}

fn anchor_protected(model: &Model, field: &str, prot: &mut Prot) -> (bool, bool) {
    prot.steps += 1;
    if prot.steps > AUTHORITY_STEP_BUDGET {
        return (false, false);
    }
    if let Some(&resolved) = prot.memo.get(field) {
        return (resolved, false);
    }
    if prot.stack.contains(field) {
        return (true, true);
    }
    prot.stack.insert(field.to_string());
    let mut protected = true;
    let mut tainted = false;
    for entry in &model.entries {
        if entry_writes_field(entry, field) {
            if writes_field_only_under_the_caller_key(entry, field)
                && credits_caller_only_by_the_paid_amount(model, entry, field, prot)
            {
                continue;
            }
            if writes_field_only_into_an_empty_slot(model, entry, field) {
                continue;
            }
            if credits_only_what_was_paid_in(model, entry, field) {
                continue;
            }
            if credits_drawn_from_an_inflow_only_total(model, entry) {
                continue;
            }
            if only_reduces_the_field(entry, field) {
                continue;
            }
            let (authorized, sub_tainted) = writer_authorized(model, entry, prot);
            if !authorized || copies_an_unprotected_field(model, entry, field, prot) {
                protected = false;
                break;
            }
            tainted |= sub_tainted;
        }
    }
    prot.stack.remove(field);
    if !protected {
        prot.memo.insert(field.to_string(), false);
        return (false, false);
    }
    if !tainted {
        prot.memo.insert(field.to_string(), true);
    }
    (true, tainted)
}

fn copies_an_unprotected_field(
    model: &Model,
    entry: &EntryDecl,
    field: &str,
    prot: &mut Prot,
) -> bool {
    let mut locals: HashMap<&str, HashSet<String>> = HashMap::new();
    let reads = |expr: &Expr, locals: &HashMap<&str, HashSet<String>>| {
        let mut out: HashSet<String> = HashSet::new();
        walk(expr, &mut |e| {
            if let Expr::Ident(id) = e {
                let name = id.text.as_str();
                if name != field && model.state.contains_key(name) {
                    out.insert(name.to_string());
                } else if let Some(from) = locals.get(name) {
                    out.extend(from.iter().cloned());
                }
            }
        });
        out
    };
    let mut sources: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                let from = reads(value, &locals);
                locals.insert(name.text.as_str(), from);
            }
            Stmt::Assign { target, value, .. } if root_ident(target) == Some(field) => {
                sources.extend(reads(value, &locals));
            }
            _ => stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(base.as_ref(), Expr::Ident(id) if id.text == field)
                            && matches!(name.text.as_str(), "set" | "insert")
                        {
                            for a in args.iter().skip(1) {
                                sources.extend(reads(a, &locals));
                            }
                        }
                    }
                }
            }),
        }
    }
    sources
        .iter()
        .any(|source| !anchor_protected(model, source, prot).0)
}

fn writes_field_only_under_the_caller_key(entry: &EntryDecl, field: &str) -> bool {
    let mut saw = false;
    let mut all_caller_keyed = true;
    for stmt in &entry.body {
        if let Stmt::Assign { target, .. } = stmt {
            if let Expr::Ident(id) = target {
                if id.text == field {
                    all_caller_keyed = false;
                }
            }
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(map) = base.as_ref() {
                        if map.text == field
                            && matches!(
                                name.text.as_str(),
                                "credit" | "debit" | "set" | "insert" | "remove"
                            )
                        {
                            saw = true;
                            if !matches!(args.first(), Some(Expr::Caller { .. })) {
                                all_caller_keyed = false;
                            }
                        }
                    }
                }
            }
        });
    }
    saw && all_caller_keyed
}

fn credits_caller_only_by_the_paid_amount(
    model: &Model,
    entry: &EntryDecl,
    field: &str,
    _prot: &mut Prot,
) -> bool {
    let free: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| !crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    let signed: HashSet<&str> = HashSet::new();
    let derived = param_derived_locals(entry, &free, &signed);
    let mut saw = false;
    let mut all_safe = true;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if !matches!(base.as_ref(), Expr::Ident(id) if id.text == field) {
                        return;
                    }
                    if !matches!(
                        name.text.as_str(),
                        "credit" | "debit" | "set" | "insert" | "remove"
                    ) {
                        return;
                    }
                    saw = true;
                    if !matches!(args.first(), Some(Expr::Caller { .. })) {
                        all_safe = false;
                        return;
                    }
                    if name.text == "debit" {
                        return;
                    }
                    let assets: HashSet<&str> = entry
                        .params
                        .iter()
                        .filter(|p| crate::model::is_asset_param(p))
                        .map(|p| p.name.text.as_str())
                        .collect();
                    let no_locals: HashSet<String> = HashSet::new();
                    let _ = &no_locals;
                    let earned = match args.get(1) {
                        Some(a) => {
                            !adds_a_constant_floor(a)
                                && (asset_amount_backer(a.peel(), &assets).is_some()
                                    || reads_a_caller_row(model, a))
                        }
                        None => false,
                    };
                    let caller_named = args
                        .get(1)
                        .map(|a| taints_from_param(a, &free, &signed, &derived))
                        .unwrap_or(true);
                    if caller_named || !earned {
                        all_safe = false;
                    }
                }
            }
        });
    }
    saw && all_safe
}

fn writer_authorized(model: &Model, entry: &EntryDecl, prot: &mut Prot) -> (bool, bool) {
    for param in &entry.params {
        if let Some(field) = authority_backing_field(param) {
            let (protected, tainted) = anchor_protected(model, field, prot);
            if protected {
                return (true, tainted);
            }
        }
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => {
                let (authorized, tainted) = gate_necessary_protected(model, expr, prot);
                if authorized {
                    return (true, tainted);
                }
            }
            Clause::Denies { expr, .. } => {
                let (authorized, tainted) = gate_necessary_denied_protected(model, expr, prot);
                if authorized {
                    return (true, tainted);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let (authorized, tainted) = gate_necessary_protected(model, expr, prot);
            if authorized {
                return (true, tainted);
            }
        }
    }
    (false, false)
}

fn gate_necessary_protected(model: &Model, expr: &Expr, prot: &mut Prot) -> (bool, bool) {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_protected(model, left, prot);
            let (rp, rt) = gate_necessary_protected(model, right, prot);
            (lp || rp, lt || rt)
        }
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_protected(model, left, prot);
            let (rp, rt) = gate_necessary_protected(model, right, prot);
            (lp && rp, lt || rt)
        }
        _ => match anchor_of(model, expr) {
            Some(a) => anchor_protected(model, a, prot),
            None => (false, false),
        },
    }
}

fn gate_necessary_denied_protected(model: &Model, expr: &Expr, prot: &mut Prot) -> (bool, bool) {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_denied_protected(model, left, prot);
            let (rp, rt) = gate_necessary_denied_protected(model, right, prot);
            (lp && rp, lt || rt)
        }
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => {
            let (lp, lt) = gate_necessary_denied_protected(model, left, prot);
            let (rp, rt) = gate_necessary_denied_protected(model, right, prot);
            (lp || rp, lt || rt)
        }
        _ => match anchor_of_denied(model, expr) {
            Some(a) => anchor_protected(model, a, prot),
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
    if !entry_moves_value(model, entry) || entry_binds_caller(model, entry, signed) {
        return None;
    }
    let gate_expr = |expr: &Expr| {
        map_lookup_on_param(model, params, signed, derived, expr)
            .filter(|(map, _, _, key)| !entry_debits_the_row_it_gated_on(entry, map, key))
            .map(|(_, field, span, _)| (field, span))
    };
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

fn meta_maps<'a>(model: &Model<'a>) -> HashSet<&'a str> {
    model
        .state
        .iter()
        .filter(|(_, f)| f.meta && f.ty.name.text == "Map")
        .map(|(n, _)| *n)
        .collect()
}

fn is_meta_map(model: &Model, name: &str) -> bool {
    model
        .state
        .get(name)
        .is_some_and(|f| f.meta && f.ty.name.text == "Map")
}

fn meta_read_span(
    meta: &HashSet<&str>,
    meta_locals: &HashSet<String>,
    expr: &Expr,
) -> Option<Span> {
    let mut hit = None;
    walk(expr, &mut |e| {
        if hit.is_some() {
            return;
        }
        if let Expr::Call { callee, span, .. } = e {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" {
                    if let Expr::Ident(m) = base.as_ref() {
                        if meta.contains(m.text.as_str()) {
                            hit = Some(*span);
                        }
                    }
                }
            }
        }
        if let Expr::Ident(id) = e {
            if meta_locals.contains(id.text.as_str()) {
                hit = Some(id.span);
            }
        }
    });
    hit
}

fn meta_write_target<'a>(model: &Model, expr: &'a Expr) -> Option<&'a str> {
    if let Expr::Call { callee, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if matches!(name.text.as_str(), "set" | "insert" | "remove") {
                if let Expr::Ident(m) = base.as_ref() {
                    if is_meta_map(model, m.text.as_str()) {
                        return Some(m.text.as_str());
                    }
                }
            }
        }
    }
    None
}

fn forged_meta_flow(model: &Model, entry: &EntryDecl) -> Option<TypeError> {
    let meta = meta_maps(model);
    if meta.is_empty() {
        return None;
    }
    let (reads_of, _) = local_seize_taint(entry);
    let meta_locals: HashSet<String> = reads_of
        .iter()
        .filter(|(_, maps)| maps.iter().any(|m| meta.contains(m.as_str())))
        .map(|(local, _)| local.clone())
        .collect();
    for stmt in &entry.body {
        let mut ledger_op = None;
        stmt_exprs(stmt, &mut |e| {
            if ledger_op.is_some() {
                return;
            }
            if let Expr::Call { callee, .. } = e {
                if let Expr::Field { base, name, span } = callee.as_ref() {
                    if matches!(name.text.as_str(), "credit" | "debit") {
                        if let Expr::Ident(m) = base.as_ref() {
                            if meta.contains(m.text.as_str()) {
                                ledger_op = Some(*span);
                            }
                        }
                    }
                }
            }
        });
        if let Some(span) = ledger_op {
            return Some(meta_value_error(span));
        }
    }
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { .. } | Stmt::Emit { .. } | Stmt::Let { .. } => {}
            Stmt::Assign { value, .. } => {
                if let Some(span) = meta_read_span(&meta, &meta_locals, value) {
                    return Some(meta_value_error(span));
                }
            }
            Stmt::Expr { expr, .. } => {
                if meta_write_target(model, expr).is_some() {
                    continue;
                }
                if let Some(span) = meta_read_span(&meta, &meta_locals, expr) {
                    return Some(meta_value_error(span));
                }
            }
        }
    }
    None
}

fn meta_value_error(span: Span) -> TypeError {
    TypeError::new(
        "a `meta` map holds non fungible metadata and cannot enter a value flow: its stored \
         value may only be compared in a guard or emitted, never credited, debited, sent, split, \
         or written into another balance; drop the `meta` marker from any map that moves value"
            .to_string(),
        span,
    )
}

fn entry_moves_value(model: &Model, entry: &EntryDecl) -> bool {
    entry_value_move(model, entry, false)
}

fn entry_moves_ledger_value(model: &Model, entry: &EntryDecl) -> bool {
    entry_value_move(model, entry, true)
}

fn entry_value_move(model: &Model, entry: &EntryDecl, ledger_only: bool) -> bool {
    let (reads_of, sub_locals) = local_seize_taint(entry);
    let ledgers = ledger_maps(model);
    let signed_params: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.signed_by.is_some())
        .map(|p| p.name.text.as_str())
        .collect();
    let all_params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let derived_params = param_derived_locals(entry, &all_params, &signed_params);
    let asset_params: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.ty.name.text == "Q_Asset")
        .map(|p| p.name.text.as_str())
        .collect();
    let mut spends = self_spend_amounts(&ledgers, entry, &reads_of, &sub_locals);
    let backed_scalars = asset_backed_scalars(model, entry);
    let backs = |value: &Expr| match value {
        Expr::Ident(id) => backed_scalars.contains(id.text.as_str()),
        _ => false,
    };
    let mut used_asset_backers: HashSet<&str> = HashSet::new();
    let mut pool_locals: HashMap<&str, (&str, Option<&Expr>)> = HashMap::new();
    let asset_param_name: Option<&str> = entry
        .params
        .iter()
        .find(|p| crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str());
    let mut asset_inflow_unspent = asset_param_name.is_some();
    let merged_pool: Option<&str> =
        asset_param_name.and_then(|param| asset_merged_into(model, entry, param));
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            if let Some(target) = pool_send_target(model, value) {
                pool_locals.insert(name.text.as_str(), target);
            }
        }
    }
    let mut moves = false;
    for stmt in &entry.body {
        if let Stmt::Assign { target, .. } = stmt {
            if let Expr::Ident(id) = target {
                if ledgers.contains(&id.text) || is_addr_keyed(model, id.text.as_str()) {
                    moves = true;
                }
            }
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                match callee.as_ref() {
                    Expr::Ident(id)
                        if matches!(id.text.as_str(), "send" | "send_asset" | "mint_asset") =>
                    {
                        if !ledger_only {
                            moves = true;
                        } else if id.text == "send" {
                            let target = args.get(1).and_then(|v| {
                                pool_send_target(model, v).or_else(|| {
                                    if let Expr::Ident(vid) = v {
                                        pool_locals.get(vid.text.as_str()).copied()
                                    } else {
                                        None
                                    }
                                })
                            });
                            if let Some((pool, amt_opt)) = target {
                                let backed = match amt_opt {
                                    Some(amt) => {
                                        let self_backed =
                                            match spends.iter().position(|sp| expr_eq(sp, amt)) {
                                                Some(pos) => {
                                                    spends.remove(pos);
                                                    true
                                                }
                                                None => false,
                                            };
                                        if self_backed {
                                            true
                                        } else if asset_inflow_unspent
                                            && merged_pool == Some(pool)
                                            && asset_param_name
                                                .map(|n| is_asset_amount_expr(amt, n))
                                                .unwrap_or(false)
                                        {
                                            asset_inflow_unspent = false;
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    None => false,
                                };
                                if !backed {
                                    moves = true;
                                }
                            }
                        }
                    }
                    Expr::Field { name, .. } if name.text == "debit" => {
                        let self_debit = matches!(args.first(), Some(Expr::Caller { .. }));
                        if !self_debit {
                            moves = true;
                        }
                    }
                    Expr::Field { base, name, .. } if name.text == "credit" => {
                        if let Expr::Ident(map) = base.as_ref() {
                            if ledgers.contains(&map.text)
                                && map_is_ever_paid_out(model, map.text.as_str())
                            {
                                let asset_backed = args
                                    .get(1)
                                    .and_then(|v| asset_amount_backer(v, &asset_params))
                                    .is_some_and(|a| used_asset_backers.insert(a))
                                    || args.get(1).is_some_and(&backs);
                                let spend_backed = !asset_backed
                                    && args.get(1).is_some_and(|v| {
                                        match spends.iter().position(|s| expr_eq(s, v)) {
                                            Some(pos) => {
                                                spends.remove(pos);
                                                true
                                            }
                                            None => false,
                                        }
                                    });
                                if !asset_backed && !spend_backed {
                                    moves = true;
                                }
                            }
                        }
                    }
                    Expr::Field { base, name, .. }
                        if matches!(name.text.as_str(), "set" | "insert" | "remove") =>
                    {
                        let foreign_key = !matches!(args.first(), Some(Expr::Caller { .. }));
                        if let Expr::Ident(map) = base.as_ref() {
                            if is_meta_map(model, map.text.as_str()) {
                                return;
                            }
                            if foreign_key {
                                if ledgers.contains(&map.text) {
                                    moves = true;
                                }
                                let schedule_write =
                                    writes_field_only_into_an_empty_slot(
                                        model,
                                        entry,
                                        map.text.as_str(),
                                    ) && !map_is_ever_paid_out(model, map.text.as_str());
                                if matches!(name.text.as_str(), "set" | "insert")
                                    && is_addr_keyed(model, map.text.as_str())
                                    && is_amount_valued(model, map.text.as_str())
                                    && !schedule_write
                                {
                                    let caller_chosen_key = args.first().is_some_and(|k| {
                                        param_field(&all_params, &signed_params, &derived_params, k)
                                            .is_some()
                                    });
                                    if let Some(value) = args.get(1) {
                                        if caller_chosen_key
                                            && !expr_reads_map(&map.text, value, &reads_of)
                                        {
                                            moves = true;
                                        }
                                    }
                                    if let Some(value) = args.get(1) {
                                        let reads = expr_reads_map(&map.text, value, &reads_of);
                                        let decrement = reads && expr_has_sub(value, &sub_locals);
                                        let backed = asset_amount_backer(value, &asset_params)
                                            .is_some_and(|a| used_asset_backers.insert(a));
                                        let merge_backed = merged_pool.is_some()
                                            && asset_param_name.is_some_and(|p| {
                                                args.first().is_some_and(|k| {
                                                    read_add_amount_bound(value, &map.text, k, p)
                                                }) && used_asset_backers.insert(p)
                                            });
                                        if reads && !decrement && !backed && !merge_backed {
                                            moves = true;
                                        }
                                    }
                                }
                                if let Some(value) = args.get(1) {
                                    if set_seizes_map(&map.text, value, &reads_of, &sub_locals) {
                                        moves = true;
                                    }
                                }
                            } else if matches!(name.text.as_str(), "set" | "insert") {
                                if let Some(value) = args.get(1) {
                                    let reads = expr_reads_map(&map.text, value, &reads_of);
                                    let decrement = reads && expr_has_sub(value, &sub_locals);
                                    let backed = asset_amount_backer(value, &asset_params)
                                        .is_some_and(|a| used_asset_backers.insert(a));
                                    let approves_own_holdings =
                                        writing_your_own_row_only_spends_your_own(
                                            model,
                                            map.text.as_str(),
                                        );
                                    if !decrement
                                        && !backed
                                        && !approves_own_holdings
                                        && (ledgers.contains(&map.text) || reads)
                                    {
                                        moves = true;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    moves
}

fn is_asset_amount_expr(amt: &Expr, asset_param: &str) -> bool {
    if let Expr::Field { base, name, .. } = amt {
        if name.text == "amount" {
            if let Expr::Ident(id) = base.as_ref() {
                return id.text == asset_param;
            }
        }
    }
    false
}

fn state_asset_field(model: &Model, name: &str) -> bool {
    model
        .state
        .get(name)
        .and_then(|f| asset_inner(&f.ty))
        .is_some()
}

fn pool_send_target<'a>(model: &Model, e: &'a Expr) -> Option<(&'a str, Option<&'a Expr>)> {
    match e {
        Expr::Call { callee, args, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "split" {
                    if let Expr::Ident(id) = base.as_ref() {
                        if state_asset_field(model, id.text.as_str()) {
                            return Some((id.text.as_str(), args.first()));
                        }
                    }
                }
            }
            None
        }
        Expr::Ident(id) if state_asset_field(model, id.text.as_str()) => {
            Some((id.text.as_str(), None))
        }
        _ => None,
    }
}

fn merge_pool_in<'a>(model: &Model, e: &'a Expr, param: &str) -> Option<&'a str> {
    if let Expr::Call { callee, args, .. } = e {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "merge" {
                if let Expr::Ident(pool) = base.as_ref() {
                    let arg_is_param =
                        matches!(args.first(), Some(Expr::Ident(a)) if a.text == param);
                    if arg_is_param && state_asset_field(model, pool.text.as_str()) {
                        return Some(pool.text.as_str());
                    }
                }
            }
        }
    }
    None
}

fn asset_merged_into<'a>(model: &Model, entry: &'a EntryDecl, param: &str) -> Option<&'a str> {
    for stmt in &entry.body {
        let expr = match stmt {
            Stmt::Expr { expr, .. } => Some(expr),
            Stmt::Let { value, .. } => Some(value),
            Stmt::Assign { value, .. } => Some(value),
            _ => None,
        };
        if let Some(pool) = expr.and_then(|e| merge_pool_in(model, e, param)) {
            return Some(pool);
        }
    }
    None
}

fn asset_amount_backer<'a>(value: &Expr, asset_params: &HashSet<&'a str>) -> Option<&'a str> {
    if let Expr::Field { base, name, .. } = value {
        if name.text == "amount" {
            if let Expr::Ident(id) = base.as_ref() {
                return asset_params.get(id.text.as_str()).copied();
            }
        }
    }
    None
}

fn read_add_amount_bound(value: &Expr, map: &str, set_key: &Expr, asset_param: &str) -> bool {
    if let Expr::Binary {
        op: BinOp::Add,
        left,
        right,
        ..
    } = value
    {
        return (reads_map_key(map, left, set_key) && is_asset_amount_expr(right, asset_param))
            || (reads_map_key(map, right, set_key) && is_asset_amount_expr(left, asset_param));
    }
    false
}

fn self_spend_amounts(
    ledgers: &HashSet<String>,
    entry: &EntryDecl,
    reads_of: &HashMap<String, HashSet<String>>,
    sub_locals: &HashSet<String>,
) -> Vec<Expr> {
    let mut amounts = Vec::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if !matches!(args.first(), Some(Expr::Caller { .. })) {
                        return;
                    }
                    if name.text == "debit" {
                        if let Some(amt) = args.get(1) {
                            amounts.push(amt.clone());
                        }
                    }
                    if matches!(name.text.as_str(), "set" | "insert") {
                        if let Expr::Ident(map) = base.as_ref() {
                            if ledgers.contains(&map.text) {
                                if let Some(value) = args.get(1) {
                                    if expr_reads_map(&map.text, value, reads_of)
                                        && expr_has_sub(value, sub_locals)
                                    {
                                        if let Some(sub) = subtracted_amount(value) {
                                            amounts.push(sub.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    amounts
}

fn subtracted_amount(expr: &Expr) -> Option<&Expr> {
    if let Expr::Binary {
        op: BinOp::Sub,
        right,
        ..
    } = expr
    {
        return Some(right);
    }
    None
}

fn expr_eq(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Int(x), Expr::Int(y)) => x.text.replace('_', "") == y.text.replace('_', ""),
        (Expr::Str(x), Expr::Str(y)) => x.value == y.value,
        (Expr::Ident(x), Expr::Ident(y)) => x.text == y.text,
        (Expr::Caller { .. }, Expr::Caller { .. }) => true,
        (Expr::Now { .. }, Expr::Now { .. }) => true,
        (
            Expr::Field {
                base: ba, name: na, ..
            },
            Expr::Field {
                base: bb, name: nb, ..
            },
        ) => na.text == nb.text && expr_eq(ba, bb),
        (
            Expr::Unary {
                op: oa, expr: ea, ..
            },
            Expr::Unary {
                op: ob, expr: eb, ..
            },
        ) => oa == ob && expr_eq(ea, eb),
        (
            Expr::Binary {
                op: oa,
                left: la,
                right: ra,
                ..
            },
            Expr::Binary {
                op: ob,
                left: lb,
                right: rb,
                ..
            },
        ) => oa == ob && expr_eq(la, lb) && expr_eq(ra, rb),
        (
            Expr::Call {
                callee: ca,
                args: aa,
                ..
            },
            Expr::Call {
                callee: cb,
                args: ab,
                ..
            },
        ) => {
            expr_eq(ca, cb) && aa.len() == ab.len() && aa.iter().zip(ab).all(|(x, y)| expr_eq(x, y))
        }
        (Expr::Checked { expr: ea, .. }, Expr::Checked { expr: eb, .. }) => expr_eq(ea, eb),
        (Expr::Wrapping { expr: ea, .. }, Expr::Wrapping { expr: eb, .. }) => expr_eq(ea, eb),
        _ => false,
    }
}

fn ledger_maps(model: &Model) -> HashSet<String> {
    let mut maps = HashSet::new();
    for entry in &model.entries {
        let (reads_of, sub_locals) = local_seize_taint(entry);
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(id) = base.as_ref() {
                            if matches!(name.text.as_str(), "credit" | "debit") {
                                maps.insert(id.text.clone());
                            } else if matches!(name.text.as_str(), "set" | "insert") {
                                if let Some(value) = args.get(1) {
                                    if expr_reads_map(&id.text, value, &reads_of)
                                        && expr_has_sub(value, &sub_locals)
                                    {
                                        maps.insert(id.text.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    maps
}

fn set_seizes_map(
    map: &str,
    value: &Expr,
    reads_of: &HashMap<String, HashSet<String>>,
    sub_locals: &HashSet<String>,
) -> bool {
    expr_reads_map(map, value, reads_of) && expr_has_sub(value, sub_locals)
}

fn expr_reads_map(map: &str, expr: &Expr, reads_of: &HashMap<String, HashSet<String>>) -> bool {
    let mut found = false;
    walk(expr, &mut |e| {
        if reads_map(map, e) {
            found = true;
        }
        if let Expr::Ident(id) = e {
            if reads_of
                .get(id.text.as_str())
                .is_some_and(|s| s.contains(map))
            {
                found = true;
            }
        }
    });
    found
}

fn expr_has_sub(expr: &Expr, sub_locals: &HashSet<String>) -> bool {
    let mut found = false;
    walk(expr, &mut |e| {
        if matches!(e, Expr::Binary { op: BinOp::Sub, .. }) {
            found = true;
        }
        if let Expr::Ident(id) = e {
            if sub_locals.contains(id.text.as_str()) {
                found = true;
            }
        }
    });
    found
}

fn local_seize_taint(entry: &EntryDecl) -> (HashMap<String, HashSet<String>>, HashSet<String>) {
    let mut reads_of: HashMap<String, HashSet<String>> = HashMap::new();
    let mut sub_locals: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let mut maps: HashSet<String> = HashSet::new();
            walk(value, &mut |e| {
                if let Expr::Call { callee, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if name.text == "get" {
                            if let Expr::Ident(id) = base.as_ref() {
                                maps.insert(id.text.clone());
                            }
                        }
                    }
                }
                if let Expr::Ident(id) = e {
                    if let Some(s) = reads_of.get(id.text.as_str()) {
                        maps.extend(s.iter().cloned());
                    }
                }
            });
            if !maps.is_empty() {
                reads_of.insert(name.text.clone(), maps);
            }
            if expr_has_sub(value, &sub_locals) {
                sub_locals.insert(name.text.clone());
            }
        }
    }
    (reads_of, sub_locals)
}

fn reads_map(map: &str, expr: &Expr) -> bool {
    if let Expr::Call { callee, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "get" {
                return matches!(base.as_ref(), Expr::Ident(id) if id.text == map);
            }
        }
    }
    false
}

fn reads_map_key(map: &str, expr: &Expr, key: &Expr) -> bool {
    if let Expr::Call { callee, args, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "get" && matches!(base.as_ref(), Expr::Ident(id) if id.text == map) {
                return args.first().is_some_and(|k| expr_eq(k, key));
            }
        }
    }
    false
}

fn caller_outside_guard(stmt: &Stmt) -> Option<quanta_lexer::Span> {
    match stmt {
        Stmt::Guard { .. } => None,
        Stmt::Let { value, .. } => caller_in(value),
        Stmt::Emit { args, .. } => args.iter().find_map(caller_in),
        Stmt::Assign { target, value, .. } => caller_in(target).or_else(|| caller_in(value)),
        Stmt::Expr { expr, .. } => caller_in(expr),
    }
}

fn caller_in(expr: &Expr) -> Option<quanta_lexer::Span> {
    match expr {
        Expr::Caller { span } => Some(*span),
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            caller_in(expr)
        }
        Expr::Binary { left, right, .. } => caller_in(left).or_else(|| caller_in(right)),
        Expr::Field { base, .. } => caller_in(base),
        Expr::Call { callee, args, .. } => {
            caller_in(callee).or_else(|| args.iter().find_map(caller_in))
        }
        _ => None,
    }
}

fn entry_binds_caller(model: &Model, entry: &EntryDecl, _signed: &HashSet<&str>) -> bool {
    if has_protected_signed_authority(model, entry) {
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
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
            ..
        } => caller_necessary_denied(model, expr),
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
    if let Expr::Ident(id) = expr.peel() {
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
    if let Expr::Call { callee, args, .. } = expr.peel() {
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
    let Expr::Binary {
        op, left, right, ..
    } = expr
    else {
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
        (BinOp::Ge, true) | (BinOp::Le, false) => {
            is_positive_int(threshold) || !is_int_literal(threshold)
        }
        (BinOp::Gt, true) | (BinOp::Lt, false) => {
            is_nonnegative_int(threshold) || !is_int_literal(threshold)
        }
        (BinOp::Ne, _) => is_zero_int(threshold),
        (BinOp::Eq, _) => is_positive_int(threshold),
        _ => false,
    }
}

fn is_int_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(_))
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
) -> Option<(String, String, Span, Expr)> {
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
                                    found = Some((map_id.text.clone(), field, *span, a.clone()));
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
        if matches!(f.ty.name.text.as_str(), "Map" | "Registry") {
            if let Some(GenericArg::Type(k)) = f.ty.args.first() {
                return k.name.text == "Q_Address";
            }
        }
    }
    false
}

fn is_amount_valued(model: &Model, ident: &str) -> bool {
    if let Some(f) = model.state.get(ident) {
        if f.ty.name.text == "Map" {
            if let Some(GenericArg::Type(v)) = f.ty.args.get(1) {
                return crate::model::is_integer_type(v.name.text.as_str());
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
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            forged(model, params, signed, derived, expr)
        }
        Expr::Binary { left, right, .. } => forged(model, params, signed, derived, left)
            .or_else(|| forged(model, params, signed, derived, right)),
        Expr::Field { base, .. } => forged(model, params, signed, derived, base),
        Expr::Call { callee, args, .. } => {
            forged(model, params, signed, derived, callee).or_else(|| {
                args.iter()
                    .find_map(|arg| forged(model, params, signed, derived, arg))
            })
        }
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
    let expr = expr.peel();
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
    match expr.peel() {
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
    if map_value_addr(model, expr).is_some() {
        return true;
    }
    matches!(expr.peel(), Expr::Ident(id) if model.state.get(id.text.as_str()).is_some_and(|f| f.ty.name.text == "Q_Address"))
}

#[cfg(test)]
mod tests {
    use crate::model::Model;

    fn accepts(src: &str) {
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        if let Err(e) = super::check(&model) {
            panic!("checker should accept this contract, got {}", e.message);
        }
    }

    #[test]
    fn removing_a_row_the_caller_does_not_hold_needs_authority() {
        let burn = "contract C { state { owner_of: Map<Q_Id, Q_Address>; } \
                    entry burn(id: Q_Id) writes(owner_of) { owner_of.remove(id); } }";
        assert!(error_for(burn).contains("hands ownership"));
        let own_burn = "contract C { state { owner_of: Map<Q_Id, Q_Address>; } \
                        entry burn(id: Q_Id) writes(owner_of) \
                        { guard owner_of.get(id) == caller; owner_of.remove(id); } }";
        accepts(own_burn);
    }

    #[test]
    fn a_free_removal_leaves_a_deny_list_unprotected() {
        let src = "contract C { state { owner: Q_Address; vault: Q_Asset<QTOV>; \
                   frozen: Registry<Q_Address>; balances: Map<Q_Address, u64>; } \
                   genesis { owner = deployer; } \
                   entry freeze(order: FreezeOrder signed by owner) writes(frozen) \
                   { frozen.insert(order.who); } \
                   entry thaw(who: Q_Address) writes(frozen) { frozen.remove(who); } \
                   entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(vault, balances) \
                   { guard in_asset == native; balances.credit(caller, funds.amount); vault.merge(funds); } \
                   entry withdraw(amount: u64) conserves QTOV writes(vault, balances) \
                   denies frozen.contains(caller) \
                   { balances.debit(caller, amount); let out = vault.split(amount); send(caller, out); } }";
        assert!(!super::authority_anchor_protected(
            &crate::model::Model::build(&quanta_parser::parse(src).unwrap().contracts[0]),
            "frozen"
        ));
    }

    #[test]
    fn a_row_paid_out_through_mint_asset_cannot_be_credited_freely() {
        let src = "contract C { asset TKN; state { owner: Q_Address; supply: u128; \
                   rewards: Map<Q_Address, u64>; } genesis { owner = deployer; } \
                   entry accrue() writes(rewards) { rewards.credit(caller, 1000); } \
                   entry payout(order: PayoutOrder signed by owner) mints TKN writes(supply) \
                   { mint_asset(order.to, rewards.get(order.to)); } }";
        assert!(error_for(src).contains("moves ledger value with no authority"));
    }

    #[test]
    fn a_registry_lookup_on_a_handed_address_is_forged_authority() {
        let src = "contract C { state { owner: Q_Address; members: Registry<Q_Address>; \
                   vault: Q_Asset<QTOV>; } genesis { owner = deployer; } \
                   entry admit(order: AdmitOrder signed by owner) writes(members) \
                   { members.insert(order.who); } \
                   entry pay(who: Q_Address, amount: u64) conserves QTOV writes(vault) \
                   { guard members.contains(who); let out = vault.split(amount); send(who, out); } }";
        assert!(error_for(src).contains("looking up self declared"));
    }

    #[test]
    fn membership_of_the_caller_in_a_protected_registry_binds_the_caller() {
        let src = "contract C { state { owner: Q_Address; staff: Registry<Q_Address>; \
                   holder: Map<u64, Q_Address>; } genesis { owner = deployer; } \
                   entry hire(order: HireOrder signed by owner) writes(staff) \
                   { staff.insert(order.who); } \
                   entry assign(id: u64, to: Q_Address) writes(holder) \
                   { guard staff.contains(caller); holder.set(id, to); } }";
        accepts(src);
    }

    #[test]
    fn reassigning_ownership_to_a_handed_address_with_no_authority_is_refused() {
        let src = "contract C { state { holder: Map<u64, Q_Address>; } \
                   entry seize(id: u64, to: Q_Address) writes(holder) { holder.set(id, to); } }";
        assert!(error_for(src).contains("hands ownership"));
    }

    #[test]
    fn claiming_ownership_for_the_caller_is_not_a_takeover() {
        let src = "contract C { state { holder: Map<u64, Q_Address>; } \
                   entry claim(id: u64) writes(holder) { holder.set(id, caller); } }";
        accepts(src);
    }

    #[test]
    fn handing_ownership_on_is_allowed_once_the_holder_is_bound_to_the_caller() {
        let src = "contract C { state { holder: Map<u64, Q_Address>; } \
                   entry transfer(id: u64, to: Q_Address) reads(holder) writes(holder) \
                   { guard holder.get(id) == caller; holder.set(id, to); } }";
        accepts(src);
    }

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
    fn an_absolute_self_set_mint_on_a_set_get_balance_ledger_is_rejected_like_a_credit() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry inflate(amount: u64) writes(balances) { balances.set(caller, amount); } \
                   entry transfer(to: Q_Address, amount: u64) writes(balances) \
                   { guard balances.get(caller) >= amount; \
                     balances.set(caller, balances.get(caller) - amount); \
                     balances.set(to, balances.get(to) + amount); } }";
        let msg = error_for(src);
        assert!(
            !msg.is_empty(),
            "a set/get balance ledger (a map that is spent by a derived decrement) must mint protect its absolute overwrites exactly like a credit/debit ledger"
        );
    }

    #[test]
    fn the_credit_debit_form_of_the_same_mint_is_also_rejected() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; pool: Q_Asset<QTOV>; } \
                   entry inflate(amount: u64) writes(balances) { balances.credit(caller, amount); } entry withdraw(n: u64) conserves QTOV reads(balances, pool) writes(balances, pool) { guard balances.get(caller) >= n; balances.debit(caller, n); let out = pool.split(n); send(caller, out); } }";
        assert!(
            error_for(src).contains("no authority") || error_for(src).contains("forgeable"),
            "minting a balance that can be withdrawn must be refused"
        );
    }

    #[test]
    fn a_payout_to_a_settable_recipient_is_a_forged_destination() {
        let src = "contract C { state { owner: Q_Address; beneficiary: Q_Address; pool: Q_Asset<QTOV>; } \
                   genesis { owner = deployer; } \
                   entry setben(b: Q_Address) writes(beneficiary) { beneficiary = b; } \
                   entry payout(order: PayOrder) conserves QTOV writes(pool) \
                   { guard caller == owner; let out = pool.split(order.amount); send(beneficiary, out); } }";
        assert!(error_for(src).contains("forged recipient"));
    }

    #[test]
    fn a_payout_to_a_genesis_set_recipient_is_accepted() {
        let src = "contract C { state { owner: Q_Address; beneficiary: Q_Address; pool: Q_Asset<QTOV>; } \
                   genesis { owner = deployer; beneficiary = deployer; } \
                   entry payout(order: PayOrder) conserves QTOV writes(pool) \
                   { guard caller == owner; let out = pool.split(order.amount); send(beneficiary, out); } }";
        ok(src);
    }

    #[test]
    fn debiting_another_account_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u128>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; balances.debit(order.victim, order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn seizing_another_account_via_a_set_debit_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.set(order.victim, balances.get(order.victim) - order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn seizing_another_account_via_an_insert_debit_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.insert(order.victim, balances.get(order.victim) - order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn seizing_another_account_via_a_let_aliased_map_read_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     let cur = balances.get(order.victim); \
                     balances.set(order.victim, cur - order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn seizing_another_account_via_a_split_statement_debit_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     let cur = balances.get(order.victim); \
                     let newbal = cur - order.amount; \
                     balances.set(order.victim, newbal); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn seizing_another_account_via_arithmetic_wrapped_map_read_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.insert(order.victim, (balances.get(order.victim) + 0) - order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn zeroing_another_ledger_entry_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.credit(caller, balances.get(order.victim)); \
                     balances.set(order.victim, 0); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn removing_another_ledger_entry_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.credit(caller, balances.get(order.victim)); \
                     balances.remove(order.victim); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn reducing_a_ledger_entry_from_a_mirror_map_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; shadow: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.set(order.victim, shadow.get(order.victim) - order.amount); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_non_ledger_foreign_set_to_zero_is_not_a_value_move() {
        let src = "contract C { state { owner: Q_Address; listings: Map<Q_Id, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry delist(order: Delist) writes(listings) \
                   { guard caller == owner; listings.set(order.id, 0); } }";
        ok(src);
    }

    #[test]
    fn a_self_set_decrement_transfer_needs_no_extra_authority() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry transfer(to: Q_Address, amount: u64) writes(balances) \
                   { guard balances.get(caller) >= amount; \
                     balances.set(caller, balances.get(caller) - amount); \
                     balances.credit(to, amount); } }";
        ok(src);
    }

    #[test]
    fn a_self_debit_transfer_needs_no_extra_authority() {
        let src = "contract C { state { balances: Map<Q_Address, u128>; } \
                   entry transfer(to: Q_Address, amount: u128) writes(balances) \
                   { guard balances.get(caller) >= amount; balances.debit(caller, amount); \
                     balances.credit(to, amount); } }";
        ok(src);
    }

    #[test]
    fn inflating_your_own_ledger_via_credit_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; pool: Q_Asset<QTOV>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry inflate(amount: u64) writes(balances) \
                   { guard caller == owner; balances.credit(caller, amount); } entry withdraw(n: u64) conserves QTOV reads(balances, pool) writes(balances, pool) { guard balances.get(caller) >= n; balances.debit(caller, n); let out = pool.split(n); send(caller, out); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn minting_ledger_balance_to_any_account_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry transfer(to: Q_Address, amount: u64) writes(balances) \
                   { balances.debit(caller, amount); balances.credit(to, amount); } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { guard caller == owner; balances.credit(to, amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn inflating_your_own_entry_via_a_self_set_increment_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry inflate(amount: u64) writes(balances) \
                   { guard caller == owner; balances.set(caller, balances.get(caller) + amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn overwriting_your_own_ledger_entry_to_a_chosen_amount_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry give(to: Q_Address, amount: u64) writes(balances) { balances.credit(to, amount); } \
                   entry inflate(amount: u64) writes(balances) \
                   { guard caller == owner; balances.set(caller, amount); } }";
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn an_unrelated_credit_in_an_asset_taking_entry_under_a_settable_owner_is_forged() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; rewards: Map<Q_Address, u128>; }
                entry set_owner(a: Q_Address) writes(owner) { owner = a; }
                entry give(to: Q_Address, amount: u128) writes(rewards) { rewards.credit(to, amount); }
                entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(vault, rewards) {
                    guard caller == owner;
                    vault.merge(funds);
                    rewards.credit(caller, 100);
                }
                entry withdraw(n: u128) conserves QTOV reads(rewards, vault) writes(rewards, vault) { guard rewards.get(caller) >= n; rewards.debit(caller, n); let out = vault.split(n); send(caller, out); }
            }"#;
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn a_self_credit_backed_by_an_incoming_asset_is_not_a_forged_move() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; pool: Q_Asset<QTOV>; stakes: Map<Q_Address, u128>; }
                entry set_owner(a: Q_Address) writes(owner) { owner = a; }
                entry stake(funds: Q_Asset<QTOV>) conserves QTOV writes(pool, stakes) {
                    guard caller == owner;
                    pool.merge(funds);
                    stakes.credit(caller, funds.amount);
                }
            }"#;
        ok(src);
    }

    #[test]
    fn a_credit_above_the_incoming_asset_amount_is_a_forged_move() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; pool: Q_Asset<QTOV>; stakes: Map<Q_Address, u128>; }
                entry set_owner(a: Q_Address) writes(owner) { owner = a; }
                entry stake(funds: Q_Asset<QTOV>) conserves QTOV writes(pool, stakes) {
                    guard caller == owner;
                    pool.merge(funds);
                    stakes.credit(caller, funds.amount * 2);
                }
            
                entry unstake(n: u128) conserves QTOV reads(stakes, pool) writes(stakes, pool) { guard stakes.get(caller) >= n; stakes.debit(caller, n); let out = pool.split(n); send(caller, out); }
            }"#;
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn an_incoming_asset_backs_only_one_credit() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; pool: Q_Asset<QTOV>; stakes: Map<Q_Address, u128>; }
                entry set_owner(a: Q_Address) writes(owner) { owner = a; }
                entry stake(other: Q_Address, funds: Q_Asset<QTOV>) conserves QTOV writes(pool, stakes) {
                    guard caller == owner;
                    pool.merge(funds);
                    stakes.credit(caller, funds.amount);
                    stakes.credit(other, funds.amount);
                }
            
                entry unstake(n: u128) conserves QTOV reads(stakes, pool) writes(stakes, pool) { guard stakes.get(caller) >= n; stakes.debit(caller, n); let out = pool.split(n); send(caller, out); }
            }"#;
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn a_zero_self_debit_does_not_back_a_self_credit() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; balances.debit(caller, 0); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_zero_self_debit_does_not_back_a_mint_to_another_account() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry mint(order: MintOrder) writes(balances) \
                   { guard caller == owner; balances.debit(caller, 0); \
                     balances.credit(order.to, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_self_debit_of_a_mismatched_amount_does_not_back_a_credit() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; balances.debit(caller, order.pad); \
                     balances.credit(caller, order.amount); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_zero_self_set_decrement_does_not_back_a_credit() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; pool: Q_Asset<QTOV>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.set(caller, balances.get(caller) - 0); \
                     balances.credit(caller, order.amount); } entry withdraw(n: u64) conserves QTOV reads(balances, pool) writes(balances, pool) { guard balances.get(caller) >= n; balances.debit(caller, n); let out = pool.split(n); send(caller, out); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn a_self_spend_does_not_back_an_absolute_self_overwrite() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry give(to: Q_Address, amount: u64) writes(balances) { balances.credit(to, amount); } \
                   entry inflate(order: In) writes(balances) \
                   { guard caller == owner; balances.debit(caller, 0); \
                     balances.set(caller, order.amount); } }";
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn a_matched_self_debit_transfer_under_a_settable_owner_is_allowed() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry pay(order: PayOrder) writes(balances) \
                   { guard caller == owner; balances.debit(caller, order.amount); \
                     balances.credit(order.to, order.amount); } }";
        ok(src);
    }

    #[test]
    fn overwriting_a_whole_ledger_by_assignment_under_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; other: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry give(to: Q_Address, amount: u64) writes(balances) { balances.credit(to, amount); } \
                   entry swap() writes(balances) { guard caller == owner; balances = other; } }";
        let e = error_for(src);
        assert!(e.contains("forgeable") || e.contains("no authority"), "{e}");
    }

    #[test]
    fn a_send_signed_by_a_settable_owner_is_forged() {
        let src = "contract C { state { owner: Q_Address; vault: Q_Asset<QTOV>; } \
                   entry claim(a: Q_Address) writes(owner) { owner = a; } \
                   entry drain(order: Rel signed by owner) conserves QTOV writes(vault) \
                   { send(order.to, vault.split(order.amount)); } }";
        assert!(error_for(src).contains("forgeable"));
    }

    #[test]
    fn an_unauthenticated_asset_send_is_rejected() {
        let src = "contract C { asset TKN; state { owner: Q_Address; } genesis { owner = deployer; } \
                   entry transfer(order: sealed TransferOrder) { send_asset(self, order.to, order.amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn an_owner_signed_asset_send_is_accepted() {
        let src = "contract C { asset TKN; state { owner: Q_Address; } genesis { owner = deployer; } \
                   entry transfer(order: TransferOrder signed by owner) { send_asset(self, order.to, order.amount); } }";
        ok(src);
    }

    #[test]
    fn an_unauthenticated_asset_mint_is_rejected() {
        let src = "contract C { asset TKN; state { owner: Q_Address; supply: u128; } \
                   genesis { owner = deployer; supply = 0; } \
                   entry issue(order: MintOrder) mints TKN writes(supply) \
                   { supply += order.amount; mint_asset(order.to, order.amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_pool_send_backed_by_an_asset_that_is_handed_back_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry drain(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(pool) \
                   { send(to, pool.split(funds.amount)); send(caller, funds); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_pool_send_backed_by_an_asset_merged_into_another_pool_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; sink: Q_Asset<QTOV>; } \
                   entry drain(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(pool, sink) \
                   { send(to, pool.split(funds.amount)); sink.merge(funds); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_pool_send_of_an_asset_merged_into_that_pool_is_accepted() {
        ok("contract C { state { pool: Q_Asset<QTOV>; } \
            entry route(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(pool) \
            { pool.merge(funds); send(to, pool.split(funds.amount)); } }");
    }

    #[test]
    fn a_send_under_a_quorum_over_a_settable_board_is_forged() {
        let src = "contract C { state { board: GuardianSet<3>; vault: Q_Asset<QTOV>; } \
                   entry set_board(nb: GuardianSet<3>) writes(board) { board = nb; } \
                   entry disburse(order: Disbursement, approvals: Quorum<2 of 3, board>) conserves QTOV writes(vault) \
                   { send(order.to, vault.split(order.amount)); } }";
        assert!(error_for(src).contains("forgeable"));
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
            
                entry unstake(n: u128) conserves QTOV reads(balances, pool) writes(balances, pool) { guard balances.get(caller) >= n; balances.debit(caller, n); let out = pool.split(n); send(caller, out); }
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
                entry withdraw(claim: Claim) conserves QTOV writes(vault, members) {
                    guard members.contains(caller);
                    members.debit(caller, claim.amount);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        ok(src);
    }

    #[test]
    fn spelling_membership_with_contains_does_not_licence_an_arbitrary_amount() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { members: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry withdraw(claim: Claim) conserves QTOV writes(vault) {
                    guard members.contains(caller);
                    send(claim.to, vault.split(claim.amount));
                }
            }"#;
        assert!(
            error_for(src).contains("membership"),
            "a membership drain must be refused however the check is spelled"
        );
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
                entry payout(order: Order) conserves QTOV writes(vault, allowed)
                { guard allowed.get(caller) >= 1; guard allowed.contains(order.to);
                  allowed.debit(caller, order.amount);
                  send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_caller_membership_does_not_authorise_an_arbitrary_amount() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { allowed: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry payout(order: Order) conserves QTOV writes(vault)
                { guard allowed.get(caller) >= 1; guard allowed.contains(order.to);
                  send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(
            error_for(src).contains("membership"),
            "a membership drain must be refused"
        );
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
        let e = error_for(src);
        assert!(
            e.contains("forgeable") || e.contains("hands ownership"),
            "a settable owner map must be refused, got {e}"
        );
    }

    #[test]
    fn a_deep_authority_chain_checks_in_polynomial_time() {
        let n = 30;
        let mut src = String::from(
            "import { Q_Asset } from \"quantova/primitives\";\ncontract C {\n  state {",
        );
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
    fn a_pure_mint_only_absolute_set_to_an_address_balance_is_rejected() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry set_balance(to: Q_Address, amount: u64) writes(balances) \
                   { balances.set(to, amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_caller_guarded_absolute_set_to_an_address_balance_is_accepted() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   genesis { owner = deployer; } \
                   entry set_balance(to: Q_Address, amount: u64) writes(balances) \
                   { guard caller == owner; balances.set(to, amount); } }";
        ok(src);
    }

    #[test]
    fn a_signed_by_absolute_set_to_an_address_balance_is_accepted() {
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   genesis { owner = deployer; } \
                   entry set_balance(order: MintOrder signed by owner) writes(balances) \
                   { balances.set(order.to, order.amount); } }";
        ok(src);
    }

    #[test]
    fn a_self_referential_credit_to_a_foreign_address_is_rejected() {
        let src = "contract Airdrop { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { balances.set(to, balances.get(to) + amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_self_referential_credit_with_insert_to_a_foreign_address_is_rejected() {
        let src = "contract Airdrop { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { balances.insert(to, balances.get(to) + amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_self_referential_credit_on_a_wide_value_map_is_rejected() {
        let src = "contract Airdrop { state { balances: Map<Q_Address, u128>; } \
                   entry mint(to: Q_Address, amount: u128) writes(balances) \
                   { balances.set(to, balances.get(to) + amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_self_referential_credit_with_reversed_operands_is_rejected() {
        let src = "contract Airdrop { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { balances.set(to, amount + balances.get(to)); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_self_referential_credit_through_a_let_alias_is_rejected() {
        let src = "contract Airdrop { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { let cur = balances.get(to); balances.set(to, cur + amount); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_caller_guarded_self_referential_credit_to_a_foreign_address_is_accepted() {
        let src = "contract Airdrop { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   genesis { owner = deployer; } \
                   entry mint(to: Q_Address, amount: u64) writes(balances) \
                   { guard caller == owner; balances.set(to, balances.get(to) + amount); } }";
        ok(src);
    }

    #[test]
    fn a_signed_by_self_referential_credit_to_a_foreign_address_is_accepted() {
        let src = "contract Airdrop { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   genesis { owner = deployer; } \
                   entry mint(order: MintOrder signed by owner) writes(balances) \
                   { balances.set(order.to, balances.get(order.to) + order.amount); } }";
        ok(src);
    }

    #[test]
    fn a_paid_read_and_add_credit_bound_to_the_incoming_asset_amount_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, balances.get(to) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        ok(src);
    }

    #[test]
    fn a_paid_read_and_add_credit_reading_a_foreign_map_key_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, src: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, balances.get(src) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_paid_read_and_add_credit_reading_the_caller_key_into_a_foreign_key_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, balances.get(caller) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_paid_read_and_add_credit_reading_the_written_key_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, src: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, balances.get(to) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        ok(src);
    }

    #[test]
    fn a_read_and_add_extension_unbound_to_the_merged_asset_amount_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Lease {
                state { expiry_of: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry extend(who: Q_Address, years: u64, payment: Q_Asset<QTOV>) conserves QTOV writes(expiry_of, vault) {
                    guard payment.amount >= years;
                    expiry_of.set(who, expiry_of.get(who) + years * 31536000);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_constant_credit_masked_by_a_merged_dust_asset_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, dust: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, balances.get(to) + 1000000000000000000);
                    vault.merge(dust);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
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

    #[test]
    fn a_now_absolute_set_to_an_unmarked_address_balance_is_rejected() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address, bonus: u64) writes(balances) \
                   { balances.set(to, now + bonus); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_now_scaled_absolute_set_to_an_unmarked_address_balance_is_rejected() {
        let src = "contract C { state { balances: Map<Q_Address, u64>; } \
                   entry mint(to: Q_Address) writes(balances) \
                   { balances.set(to, now * 1000000000); } }";
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_now_plus_a_paid_amount_is_still_a_forged_move_because_now_is_unbacked() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, now + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_paid_amount_plus_a_nested_bonus_read_is_a_forged_move() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, bonus: u64, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, payment.amount + (balances.get(to) + bonus));
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_nested_bonus_read_then_a_paid_amount_is_a_forged_move() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, bonus: u64, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, (balances.get(to) + bonus) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_paid_amount_plus_a_scaled_balance_read_is_a_forged_move() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { balances: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(to: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(balances, vault) {
                    balances.set(to, payment.amount + balances.get(to) * 1000000);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_single_asset_cannot_back_two_paid_credits_on_two_maps() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Airdrop {
                state { a: Map<Q_Address, u64>; b: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry mint(x: Q_Address, y: Q_Address, payment: Q_Asset<QTOV>) conserves QTOV writes(a, b, vault) {
                    a.set(x, a.get(x) + payment.amount);
                    b.set(y, b.get(y) + payment.amount);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_meta_map_exempts_a_now_derived_absolute_set() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Lease {
                state { meta expiry_of: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry rent(name: Q_Address, years: u64, payment: Q_Asset<QTOV>) conserves QTOV writes(expiry_of, vault) {
                    guard years >= 1;
                    expiry_of.set(name, now + years * 31536000);
                    vault.merge(payment);
                }
            }"#;
        ok(src);
    }

    #[test]
    fn an_unmarked_map_of_the_same_name_is_still_mint_checked() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Lease {
                state { expiry_of: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry rent(name: Q_Address, years: u64, payment: Q_Asset<QTOV>) conserves QTOV writes(expiry_of, vault) {
                    guard years >= 1;
                    expiry_of.set(name, now + years * 31536000);
                    vault.merge(payment);
                }
            }"#;
        assert!(
            error_for(src).contains("no authority"),
            "{}",
            error_for(src)
        );
    }

    #[test]
    fn a_meta_map_value_cannot_be_split_into_a_send() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Launder {
                state { owner: Q_Address; meta bal: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                genesis { owner = deployer; }
                entry inflate(to: Q_Address) writes(bal) { bal.set(to, now + 1000000000000000000); }
                entry withdraw() conserves QTOV writes(vault) {
                    guard caller == owner;
                    send(caller, vault.split(bal.get(caller)));
                }
            }"#;
        assert!(error_for(src).contains("meta"), "{}", error_for(src));
    }

    #[test]
    fn a_meta_map_value_cannot_be_credited_into_another_balance() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Launder {
                state { meta bal: Map<Q_Address, u64>; real: Map<Q_Address, u64>; }
                entry inflate(to: Q_Address) writes(bal) { bal.set(to, now + 1000000000000000000); }
                entry drain(to: Q_Address) writes(real) { real.credit(to, bal.get(to)); }
            }"#;
        assert!(error_for(src).contains("meta"), "{}", error_for(src));
    }

    #[test]
    fn a_meta_map_cannot_be_credited_directly() {
        let src = "contract Launder { state { meta bal: Map<Q_Address, u64>; } \
                   entry give(to: Q_Address, amount: u64) writes(bal) { bal.credit(to, amount); } }";
        assert!(error_for(src).contains("meta"), "{}", error_for(src));
    }

    #[test]
    fn a_meta_map_value_cannot_be_laundered_through_a_scalar_field() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract Launder {
                state { owner: Q_Address; meta bal: Map<Q_Address, u64>; total: u128; vault: Q_Asset<QTOV>; }
                genesis { owner = deployer; }
                entry inflate(to: Q_Address) writes(bal) { bal.set(to, now + 1000000000000000000); }
                entry drain() conserves QTOV writes(total, vault) {
                    guard caller == owner;
                    total = bal.get(caller);
                    send(caller, vault.split(total));
                }
            }"#;
        assert!(error_for(src).contains("meta"), "{}", error_for(src));
    }
}
