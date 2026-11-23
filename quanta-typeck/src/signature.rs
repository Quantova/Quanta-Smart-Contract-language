// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{asset_inner, is_quorum_param, Model};
use quanta_ast::{AssignOp, BinOp, Clause, EntryDecl, Expr, GenericArg, Param, Stmt, UnaryOp};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

pub fn check(model: &Model) -> Result<(), TypeError> {
    validate_public_declarations(model)?;
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    Ok(())
}

fn public_asset_fields<'a>(model: &Model<'a>) -> HashSet<&'a str> {
    model
        .state
        .iter()
        .filter(|(_, f)| f.public && f.ty.name.text == "Q_Asset")
        .map(|(n, _)| *n)
        .collect()
}

fn entry_merges_into(entry: &EntryDecl, vault: &str) -> bool {
    let mut hit = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "merge"
                        && matches!(base.as_ref(), Expr::Ident(m) if m.text == vault)
                    {
                        hit = true;
                    }
                }
            }
        });
    }
    hit
}

fn public_vault_is_deployer_only_funded(model: &Model, vault: &str) -> bool {
    for entry in &model.entries {
        if entry_merges_into(entry, vault) && !entry_guarded_by_owner(model, entry) {
            return false;
        }
    }
    true
}

fn validate_public_declarations(model: &Model) -> Result<(), TypeError> {
    for (name, f) in model.state.iter() {
        if f.public
            && f.ty.name.text == "Q_Asset"
            && !public_vault_is_deployer_only_funded(model, name)
        {
            return Err(TypeError::new(
                format!(
                    "ledger `{}` is declared `public` but an entry lets a non-deployer deposit into \
                     it, so it pools third-party funds rather than a deployer-funded giveaway; a \
                     public ledger must be funded solely by the deployer or genesis",
                    f.name.text
                ),
                f.span,
            ));
        }
    }
    Ok(())
}

fn vault_balance_guarded_ge(entry: &EntryDecl, vault: &str, amt: &Expr) -> bool {
    let is_amount_field = |e: &Expr| {
        matches!(e.peel(), Expr::Field { base, name, .. }
            if name.text == "amount" && matches!(base.as_ref(), Expr::Ident(v) if v.text == vault))
    };
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    let hit = match op {
                        BinOp::Ge | BinOp::Gt => {
                            is_amount_field(left) && expr_eq(right.peel(), amt)
                        }
                        BinOp::Le | BinOp::Lt => {
                            is_amount_field(right) && expr_eq(left.peel(), amt)
                        }
                        _ => false,
                    };
                    if hit {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn expr_has_value_op(e: &Expr) -> bool {
    let mut hit = false;
    walk(e, &mut |x| {
        if let Expr::Call { callee, .. } = x {
            match callee.as_ref() {
                Expr::Ident(id)
                    if matches!(id.text.as_str(), "send" | "send_asset" | "mint_asset") =>
                {
                    hit = true;
                }
                Expr::Field { name, .. }
                    if matches!(
                        name.text.as_str(),
                        "credit" | "debit" | "insert" | "set" | "remove" | "merge" | "split"
                    ) =>
                {
                    hit = true;
                }
                _ => {}
            }
        }
    });
    hit
}

fn faucet_payout_proven(model: &Model, entry: &EntryDecl) -> bool {
    let valid: HashSet<&str> = public_asset_fields(model)
        .into_iter()
        .filter(|v| public_vault_is_deployer_only_funded(model, v))
        .collect();
    if valid.is_empty() {
        return false;
    }
    let mut lets: HashMap<String, Expr> = HashMap::new();
    let mut sends = 0usize;
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { .. } | Stmt::Emit { .. } => {}
            Stmt::Let { name, value, .. } => {
                if expr_has_value_op(value) {
                    return false;
                }
                let r = resolve_locals(value, &lets, 0);
                lets.insert(name.text.clone(), r);
            }
            Stmt::Assign { .. } => return false,
            Stmt::Expr { expr, .. } => {
                let mut ok = false;
                if let Expr::Call { callee, args, .. } = expr.peel() {
                    if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send")
                        && args.len() == 2
                        && !expr_has_value_op(&args[0])
                    {
                        if let Expr::Call {
                            callee: sc,
                            args: sa,
                            ..
                        } = args[1].peel()
                        {
                            if let Expr::Field { base, name, .. } = sc.as_ref() {
                                if name.text == "split" && sa.len() == 1 {
                                    if let Expr::Ident(v) = base.as_ref() {
                                        if valid.contains(v.text.as_str()) {
                                            let ra = resolve_locals(&sa[0], &lets, 0);
                                            if vault_balance_guarded_ge(entry, v.text.as_str(), &ra)
                                            {
                                                sends += 1;
                                                ok = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !ok {
                    return false;
                }
            }
        }
    }
    sends == 1
}

fn map_get_row(e: &Expr) -> Option<(&str, &Expr)> {
    if let Expr::Call { callee, args, .. } = e.peel() {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "get" && args.len() == 1 {
                if let Expr::Ident(m) = base.as_ref() {
                    return Some((m.text.as_str(), &args[0]));
                }
            }
        }
    }
    None
}

fn row_zero_makes_guard_false(op: &BinOp, lit: &Expr, row_on_left: bool) -> bool {
    if row_on_left {
        match op {
            BinOp::Ge | BinOp::Eq => is_positive_int(lit),
            BinOp::Gt => is_nonnegative_int(lit),
            BinOp::Ne => is_zero_int(lit),
            _ => false,
        }
    } else {
        match op {
            BinOp::Le | BinOp::Eq => is_positive_int(lit),
            BinOp::Lt => is_nonnegative_int(lit),
            BinOp::Ne => is_zero_int(lit),
            _ => false,
        }
    }
}

fn expr_mentions_ident(expr: &Expr, name: &str) -> bool {
    let mut found = false;
    walk(expr, &mut |e| {
        if matches!(e, Expr::Ident(id) if id.text == name) {
            found = true;
        }
    });
    found
}

fn guard_dead_after_full_debit(entry: &EntryDecl) -> Option<Span> {
    let mut fresh: HashMap<&str, (&str, &Expr)> = HashMap::new();
    let mut zeroed: Vec<(&str, &Expr)> = Vec::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => match map_get_row(value) {
                Some(row) => {
                    fresh.insert(name.text.as_str(), row);
                }
                None => {
                    fresh.remove(name.text.as_str());
                }
            },
            Stmt::Guard { expr, span } => {
                let mut parts: Vec<&Expr> = Vec::new();
                split_and(expr, &mut parts);
                for p in parts {
                    if let Expr::Binary {
                        op, left, right, ..
                    } = p.peel()
                    {
                        let dead = if let Some((m, k)) = map_get_row(left) {
                            zeroed.iter().any(|(zm, zk)| *zm == m && expr_eq(zk, k))
                                && row_zero_makes_guard_false(op, right, true)
                        } else if let Some((m, k)) = map_get_row(right) {
                            zeroed.iter().any(|(zm, zk)| *zm == m && expr_eq(zk, k))
                                && row_zero_makes_guard_false(op, left, false)
                        } else {
                            false
                        };
                        if dead {
                            return Some(*span);
                        }
                    }
                }
            }
            Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } => {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        let mname = m.text.as_str();
                        if matches!(
                            name.text.as_str(),
                            "debit" | "credit" | "set" | "insert" | "remove"
                        ) {
                            if let Some(k) = args.first() {
                                let full_debit = name.text == "debit"
                                    && args.get(1).is_some_and(|a| {
                                        matches!(a.peel(), Expr::Ident(b)
                                            if fresh.get(b.text.as_str()).is_some_and(|(fm, fk)| *fm == mname && expr_eq(fk, k)))
                                    });
                                zeroed.retain(|(zm, zk)| !(*zm == mname && expr_eq(zk, k)));
                                if full_debit {
                                    zeroed.push((mname, k));
                                }
                                let stale: Vec<&str> = fresh
                                    .iter()
                                    .filter(|(_, (fm, fk))| *fm == mname && expr_eq(fk, k))
                                    .map(|(n, _)| *n)
                                    .collect();
                                for n in stale {
                                    fresh.remove(n);
                                }
                            }
                        }
                    }
                }
            }
            Stmt::Assign {
                target: Expr::Ident(id),
                ..
            } => {
                let name = id.text.as_str();
                zeroed.retain(|(_, zk)| !expr_mentions_ident(zk, name));
                let stale: Vec<&str> = fresh
                    .iter()
                    .filter(|(_, (_, fk))| expr_mentions_ident(fk, name))
                    .map(|(n, _)| *n)
                    .collect();
                for n in stale {
                    fresh.remove(n);
                }
            }
            _ => {}
        }
    }
    None
}

fn entry_has_value_outflow(entry: &EntryDecl) -> bool {
    let mut found = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if found {
                return;
            }
            if let Expr::Call { callee, .. } = e {
                match callee.as_ref() {
                    Expr::Ident(id)
                        if matches!(id.text.as_str(), "send" | "send_asset" | "mint_asset") =>
                    {
                        found = true;
                    }
                    Expr::Field { name, .. } if name.text == "split" => {
                        found = true;
                    }
                    _ => {}
                }
            }
        });
    }
    found
}

fn positive_balance_guard_key<'a>(op: &BinOp, left: &'a Expr, right: &'a Expr) -> Option<&'a Expr> {
    if let Some((_, k)) = map_get_row(left) {
        if row_zero_makes_guard_false(op, right, true) {
            return Some(k);
        }
    }
    if let Some((_, k)) = map_get_row(right) {
        if row_zero_makes_guard_false(op, left, false) {
            return Some(k);
        }
    }
    None
}

fn resolve_through_lets<'a>(e: &'a Expr, lets: &HashMap<&'a str, &'a Expr>) -> &'a Expr {
    let mut cur = e.peel();
    let mut hops = 0;
    while let Expr::Ident(id) = cur {
        match lets.get(id.text.as_str()) {
            Some(v) if hops < 16 => {
                hops += 1;
                cur = v.peel();
            }
            _ => break,
        }
    }
    cur
}

fn resolves_to_caller_or_param<'a>(
    e: &'a Expr,
    lets: &HashMap<&'a str, &'a Expr>,
    params: &HashSet<&str>,
) -> bool {
    match resolve_through_lets(e, lets) {
        Expr::Caller { .. } => true,
        Expr::Ident(id) => params.contains(id.text.as_str()),
        _ => false,
    }
}

fn guard_keyed_on_stale_reassigned_scalar(entry: &EntryDecl) -> Option<Span> {
    if !entry_has_value_outflow(entry) {
        return None;
    }
    let mut assigned_rhs: HashMap<&str, &Expr> = HashMap::new();
    let mut lets: HashMap<&str, &Expr> = HashMap::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Assign {
                target: Expr::Ident(id),
                value,
                ..
            } => {
                assigned_rhs.insert(id.text.as_str(), value);
            }
            Stmt::Let { name, value, .. } => {
                lets.insert(name.text.as_str(), value);
            }
            _ => {}
        }
    }
    if assigned_rhs.is_empty() {
        return None;
    }
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    for stmt in &entry.body {
        if let Stmt::Guard { expr, span } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    if let Some(k) = positive_balance_guard_key(op, left, right) {
                        if let Expr::Ident(base) = resolve_through_lets(k, &lets) {
                            if let Some(rhs) = assigned_rhs.get(base.text.as_str()) {
                                if !resolves_to_caller_or_param(rhs, &lets, &params) {
                                    return Some(*span);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn has_uncensused_exit(model: &Model, entry: &EntryDecl) -> bool {
    let mut gap = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if gap {
                return;
            }
            if let Expr::Call { callee, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "mint_asset") {
                    gap = true;
                    return;
                }
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        let cashable = map_feeds_self_service_send(model, m.text.as_str())
                            && !map_is_deposit_backed_pool(model, m.text.as_str(), None);
                        if name.text == "set"
                            && (cashable || is_addr_valued(model, m.text.as_str()))
                        {
                            gap = true;
                        }
                    }
                }
            }
        });
    }
    gap
}

fn positively_safe(model: &Model, entry: &EntryDecl, signed: &HashSet<&str>) -> bool {
    if has_protected_signed_authority(model, entry)
        || entry_guarded_by_owner(model, entry)
        || faucet_payout_proven(model, entry)
    {
        return true;
    }
    if has_uncensused_exit(model, entry) {
        return false;
    }
    entry_binds_caller(model, entry, signed)
        || asset_outflow_is_paid_for_by_the_caller(model, entry)
        || ledger_move_is_paid_for_by_the_caller(model, entry)
        || self_service_payout_exceeds_backing(model, entry).is_none()
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    if let Some(span) = guard_dead_after_full_debit(entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` can never run: a guard requires a positive balance in a map row that \
                 a preceding full debit of that same row has already forced to zero, so every call \
                 reverts and any funds the contract holds stay locked; place the balance guard before \
                 the debit",
                entry.name.text
            ),
            span,
        ));
    }
    if let Some(span) = guard_keyed_on_stale_reassigned_scalar(entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` can never protect the funds it moves: the balance guard reads a map \
                 row keyed by a state scalar that the entry reassigns from another field rather than \
                 from the caller, so the guard checks a stale row while a different row is debited and \
                 sent; every call either reverts and locks the funds or pays out unguarded; key the \
                 balance guard on the same account whose row is debited",
                entry.name.text
            ),
            span,
        ));
    }
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
    if let Some(err) = forged_guardian_authority(model, entry, &params, &signed, &derived) {
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
    let faucet = faucet_payout_proven(model, entry);
    if !faucet
        && (entry_moves_ledger_value(model, entry) || entry_moves_asset(entry))
        && !entry_binds_caller(model, entry, &signed)
        && inflow_backed_caller_moves_exceed_inflow(model, entry)
    {
        return Err(no_ledger_authority_error(entry));
    }
    if !faucet
        && entry_moves_ledger_value(model, entry)
        && !entry_binds_caller(model, entry, &signed)
        && !ledger_move_is_paid_for_by_the_caller(model, entry)
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
    if !faucet
        && (entry_moves_asset(entry) || entry_moves_ledger_value(model, entry))
        && !entry_binds_caller(model, entry, &signed)
        && !every_backing_is_consumed_once(model, entry)
    {
        return Err(no_ledger_authority_error(entry));
    }
    if !faucet
        && (entry_moves_asset(entry) || entry_moves_ledger_value(model, entry))
        && !has_protected_signed_authority(model, entry)
        && caller_binding_rests_on_first_come_slots(model, entry)
        && !asset_outflow_is_paid_for_by_the_caller(model, entry)
        && !ledger_move_is_paid_for_by_the_caller(model, entry)
    {
        return Err(no_ledger_authority_error(entry));
    }
    if (entry_moves_asset(entry) || entry_moves_ledger_value(model, entry))
        && authority_is_membership_only(model, entry, &signed)
        && (moved_amount_is_caller_chosen(model, entry)
            || outflow_amount_is_a_self_written_row(model, entry))
        && !outflow_is_bounded_by_an_entitlement(model, entry)
    {
        return Err(unbacked_membership_error(entry));
    }
    if entry_moves_asset(entry) && !every_caller_asset_payout_is_token_sourced(model, entry) {
        return Err(no_asset_authority_error(entry));
    }
    if (entry_moves_asset(entry) || entry_moves_ledger_value(model, entry))
        && !positively_safe(model, entry, &signed)
    {
        return Err(no_ledger_authority_error(entry));
    }
    if backing_amount_rewritten_before_payout(model, entry) {
        return Err(no_ledger_authority_error(entry));
    }
    if payout_issuer_rewritten_before_send(model, entry) {
        return Err(no_asset_authority_error(entry));
    }
    if pays_unconsumed_entitlement(model, entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` pays out an amount read from a caller's authority-written \
                 entitlement without consuming it, so the same grant can be redeemed again; \
                 debit, remove or zero the entitlement row it pays from in this entry",
                entry.name.text
            ),
            entry.name.span,
        ));
    }
    if caller_paid_from_foreign_row(model, entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` pays the caller an amount read from a protected row keyed by \
                 someone else, so any caller can drain another holder's entitlement; pay the \
                 holder of the consumed row, or prove the caller owns the row it pays from",
                entry.name.text
            ),
            entry.name.span,
        ));
    }
    if native_payout_backed_by_custom_ledger(model, entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` pays out native value on the strength of a ledger funded by a \
                 custom asset, so attacker-issued units can drain the native pool; a credit \
                 ledger may only authorize a payout of the same asset that funded it",
                entry.name.text
            ),
            entry.name.span,
        ));
    }
    if let Some(span) = self_credit_of_stale_scalar(model, entry) {
        return Err(TypeError::new(
            format!(
                "this entry `{}` credits the caller from a stored amount that is not yet backed by \
                 the caller's own incoming asset where it is read, so a later assignment from the \
                 inflow cannot authorize the earlier credit and the caller is credited a prior \
                 depositor's amount; assign the current inflow before the credit, or credit the \
                 amount read directly from the incoming asset",
                entry.name.text
            ),
            span,
        ));
    }
    if !faucet {
        if let Some(span) = self_service_payout_exceeds_backing(model, entry) {
            return Err(TypeError::new(
                format!(
                    "this entry `{}` pays out more value than it removes from the caller's own \
                     ledger row, so the surplus is drawn from other holders' deposits; a \
                     self-service payout may only send the amount it debits from the caller",
                    entry.name.text
                ),
                span,
            ));
        }
    }
    Ok(())
}

fn self_credit_of_stale_scalar(model: &Model, entry: &EntryDecl) -> Option<Span> {
    let assets: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();
    let backed_scalars = asset_backed_scalars(model, entry);
    let mut inflow_bound: HashSet<String> = HashSet::new();
    let mut found: Option<Span> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if found.is_some() {
                return;
            }
            if let Expr::Call {
                callee, args, span, ..
            } = e
            {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if name.text == "credit"
                            && matches!(args.first(), Some(Expr::Caller { .. }))
                            && map_is_ever_paid_out(model, m.text.as_str())
                        {
                            if let Some(v) = args.get(1) {
                                if let Expr::Ident(id) = v.peel() {
                                    if model.state.contains_key(id.text.as_str())
                                        && backed_scalars.contains(id.text.as_str())
                                        && !inflow_bound.contains(id.text.as_str())
                                    {
                                        found = Some(*span);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op: AssignOp::Set,
            value,
            ..
        } = stmt
        {
            if asset_amount_backer(value, &assets).is_some() {
                inflow_bound.insert(id.text.clone());
            } else {
                inflow_bound.remove(&id.text);
            }
        }
    }
    found
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

fn inflow_backed_caller_moves_exceed_inflow(model: &Model, entry: &EntryDecl) -> bool {
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
    let mut moves = 0usize;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                let amount: Option<&Expr> = match callee.as_ref() {
                    Expr::Field { name, .. } if name.text == "credit" => args.get(1),
                    Expr::Field { name, .. }
                        if matches!(name.text.as_str(), "set" | "insert")
                            && matches!(args.first(), Some(Expr::Caller { .. })) =>
                    {
                        args.get(1)
                    }
                    Expr::Ident(id) if id.text == "send_asset" => args.get(2),
                    _ => None,
                };
                if let Some(v) = amount {
                    let backed = asset_amount_backer(v.peel(), &assets).is_some()
                        || matches!(v.peel(), Expr::Ident(id)
                            if backed_scalars.contains(id.text.as_str()));
                    if backed {
                        moves += 1;
                    }
                }
            }
        });
    }
    moves > assets.len()
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
    saw_send && sends_only_to_caller && every_payout_consumes_its_own_backing(model, entry)
}

fn ledger_funding_tokens(model: &Model, map: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for entry in &model.entries {
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        let mut funds = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                            && matches!(name.text.as_str(), "credit" | "set" | "insert")
                            && args.get(1).is_some_and(|v| {
                                resolved_asset_backer(entry, v, &assets, 0).is_some()
                            })
                        {
                            funds = true;
                        }
                    }
                }
            });
        }
        if !funds {
            continue;
        }
        for condition in required_conditions(entry) {
            let mut parts = Vec::new();
            split_and(&condition, &mut parts);
            for part in parts {
                if let Expr::Binary {
                    op: BinOp::Eq,
                    left,
                    right,
                    ..
                } = part
                {
                    match (left.peel(), right.peel()) {
                        (Expr::InAsset { .. }, Expr::Ident(t))
                        | (Expr::Ident(t), Expr::InAsset { .. }) => {
                            out.insert(t.text.clone());
                        }
                        (Expr::InAsset { .. }, Expr::Native { .. })
                        | (Expr::Native { .. }, Expr::InAsset { .. }) => {
                            out.insert("native".to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

fn admitted_inflow_token(entry: &EntryDecl) -> Option<String> {
    let mut found: Option<String> = None;
    for condition in required_conditions(entry) {
        let mut parts = Vec::new();
        split_and(&condition, &mut parts);
        for part in parts {
            if let Expr::Binary {
                op: BinOp::Eq,
                left,
                right,
                ..
            } = part
            {
                let tok = match (left.peel(), right.peel()) {
                    (Expr::InAsset { .. }, Expr::Ident(t))
                    | (Expr::Ident(t), Expr::InAsset { .. }) => Some(t.text.clone()),
                    _ => None,
                };
                if let Some(t) = tok {
                    if found.as_deref().is_some_and(|f| f != t) {
                        return None;
                    }
                    found = Some(t);
                }
            }
        }
    }
    found
}

fn backing_token_mismatch(backing: &Option<String>, payout: Option<&str>) -> bool {
    matches!((backing.as_deref(), payout), (Some(b), Some(p)) if b != p)
}

fn caller_asset_payout_tokens(entry: &EntryDecl) -> Vec<String> {
    let mut out = Vec::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send_asset")
                    && matches!(args.get(1), Some(Expr::Caller { .. }))
                {
                    match args.first().map(Expr::peel) {
                        Some(Expr::Ident(t)) => out.push(t.text.clone()),
                        Some(_) => out.push("\u{0}unresolved_issuer".to_string()),
                        None => {}
                    }
                }
            }
        });
    }
    out
}

fn every_caller_asset_payout_is_token_sourced(model: &Model, entry: &EntryDecl) -> bool {
    let payouts = caller_asset_payout_tokens(entry);
    if payouts.is_empty() {
        return true;
    }
    let mut sources: HashSet<String> = HashSet::new();
    if let Some(t) = admitted_inflow_token(entry) {
        sources.insert(t);
    }
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "debit" && matches!(args.first(), Some(Expr::Caller { .. })) {
                        if let Expr::Ident(m) = base.as_ref() {
                            for t in ledger_funding_tokens(model, &m.text) {
                                sources.insert(t);
                            }
                        }
                    }
                }
            }
        });
    }
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(r),
            op,
            value,
            ..
        } = stmt
        {
            if !model.state.contains_key(r.text.as_str()) {
                continue;
            }
            let lowers = match op {
                AssignOp::Sub => true,
                AssignOp::Set => matches!(
                    value.peel(),
                    Expr::Binary { op: BinOp::Sub, left, .. }
                        if matches!(left.peel(), Expr::Ident(l) if l.text == r.text)
                ),
                AssignOp::Add => false,
            };
            if lowers {
                if let Some(t) = reserve_token(model, &r.text) {
                    sources.insert(t);
                }
            }
        }
    }
    if sources.is_empty() {
        return true;
    }
    payouts.iter().all(|t| sources.contains(t))
}

fn every_payout_consumes_its_own_backing(model: &Model, entry: &EntryDecl) -> bool {
    let mut debits: Vec<Expr> = Vec::new();
    let mut debit_maps: Vec<String> = Vec::new();
    let mut payouts: Vec<Expr> = Vec::new();
    let mut payout_tokens: Vec<Option<String>> = Vec::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                match callee.as_ref() {
                    Expr::Field { base, name, .. }
                        if name.text == "debit"
                            && matches!(base.as_ref(), Expr::Ident(_))
                            && matches!(args.first(), Some(Expr::Caller { .. })) =>
                    {
                        if let (Some(amount), Expr::Ident(map)) = (args.get(1), base.as_ref()) {
                            debits.push(amount.clone());
                            debit_maps.push(map.text.clone());
                        }
                    }
                    Expr::Ident(id) if id.text == "send_asset" => {
                        if let Some(value) = args.get(2) {
                            payouts.push(value.clone());
                            payout_tokens.push(match args.first().map(Expr::peel) {
                                Some(Expr::Ident(t)) => Some(t.text.clone()),
                                _ => None,
                            });
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    let inflows: Vec<Expr> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| Expr::Field {
            base: Box::new(Expr::Ident(p.name.clone())),
            name: quanta_ast::Ident {
                text: "amount".to_string(),
                span: p.name.span,
            },
            span: p.name.span,
        })
        .collect();
    let mut backing: Vec<Expr> = debits.iter().chain(inflows.iter()).cloned().collect();
    let admitted = admitted_inflow_token(entry);
    let mut backing_tokens: Vec<Option<String>> = Vec::with_capacity(backing.len());
    for i in 0..backing.len() {
        if i < debit_maps.len() {
            let funding = ledger_funding_tokens(model, &debit_maps[i]);
            backing_tokens.push(if funding.len() == 1 {
                funding.into_iter().next()
            } else {
                None
            });
        } else {
            backing_tokens.push(admitted.clone());
        }
    }
    let mut consumed: Vec<Expr> = Vec::new();
    let mut reserves: Vec<String> = Vec::new();
    for (value, token) in payouts.iter().zip(payout_tokens.iter()) {
        let raw_amount = match value.peel() {
            Expr::Call { callee, args, .. } if matches!(callee.as_ref(), Expr::Field { name, .. } if name.text == "split") => {
                match args.first() {
                    Some(a) => a,
                    None => return false,
                }
            }
            _ => value,
        };
        let amount = raw_amount.peel();
        if let Some(pos) = backing.iter().position(|b| expr_eq(b.peel(), amount)) {
            if backing_token_mismatch(&backing_tokens[pos], token.as_deref()) {
                return false;
            }
            if pos < debit_maps.len() {
                debit_maps.remove(pos);
            }
            backing_tokens.remove(pos);
            consumed.push(backing.remove(pos));
            continue;
        }
        if consumed.iter().any(|c| expr_eq(c.peel(), amount)) {
            return false;
        }
        match backing
            .iter()
            .position(|b| payout_is_bounded_by(raw_amount, b.peel()))
        {
            Some(pos) => {
                if backing_token_mismatch(&backing_tokens[pos], token.as_deref()) {
                    return false;
                }
                if pos < debit_maps.len() {
                    debit_maps.remove(pos);
                }
                backing_tokens.remove(pos);
                consumed.push(backing.remove(pos));
            }
            None => match reserve_bounding_payout(model, entry, amount, &inflows, token.as_deref())
            {
                Some(reserve) if !reserves.contains(&reserve) => {
                    reserves.push(reserve);
                }
                _ => return false,
            },
        }
    }
    true
}

fn resolved_asset_backer(
    entry: &EntryDecl,
    value: &Expr,
    assets: &HashSet<&str>,
    depth: u32,
) -> Option<String> {
    if depth > 6 {
        return None;
    }
    if let Some(a) = asset_amount_backer(value.peel(), assets) {
        return Some(a.to_string());
    }
    match value.peel() {
        Expr::Ident(id) => {
            for stmt in &entry.body {
                if let Stmt::Assign {
                    target: Expr::Ident(t),
                    value: v,
                    ..
                } = stmt
                {
                    if t.text == id.text {
                        if let Some(a) = resolved_asset_backer(entry, v, assets, depth + 1) {
                            return Some(a);
                        }
                    }
                }
            }
            None
        }
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" {
                    if let Expr::Ident(m) = base.as_ref() {
                        let mut cand: Vec<Expr> = Vec::new();
                        for stmt in &entry.body {
                            stmt_exprs(stmt, &mut |x| {
                                if let Expr::Call {
                                    callee: c2,
                                    args: a2,
                                    ..
                                } = x
                                {
                                    if let Expr::Field {
                                        base: b2, name: n2, ..
                                    } = c2.as_ref()
                                    {
                                        if matches!(n2.text.as_str(), "set" | "credit" | "insert")
                                            && matches!(b2.as_ref(), Expr::Ident(mm) if mm.text == m.text)
                                        {
                                            if let Some(v) = a2.get(1) {
                                                cand.push(v.clone());
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        for v in &cand {
                            if let Some(a) = resolved_asset_backer(entry, v, assets, depth + 1) {
                                return Some(a);
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn entry_accrual_row(entry: &EntryDecl, amount: &Expr) -> Option<String> {
    let mut row: Option<String> = None;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |x| {
            if row.is_some() {
                return;
            }
            if let Expr::Call { callee, args, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "credit" && matches!(args.first(), Some(Expr::Caller { .. })) {
                        if let (Expr::Ident(m), Some(v)) = (base.as_ref(), args.get(1)) {
                            if expr_eq(v.peel(), amount.peel()) && !folds_to_zero(v) {
                                row = Some(m.text.clone());
                            }
                        }
                    }
                }
            }
        });
        if row.is_some() {
            break;
        }
    }
    row
}

fn row_survives_fold(expr: &Expr, row: &str) -> bool {
    match expr.peel() {
        Expr::Call { callee, args, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get"
                    && matches!(base.as_ref(), Expr::Ident(m) if m.text == row)
                    && matches!(args.first(), Some(Expr::Caller { .. }))
                {
                    return true;
                }
            }
            false
        }
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => {
            if folds_to_zero(left) || folds_to_zero(right) {
                return false;
            }
            row_survives_fold(left, row) || row_survives_fold(right, row)
        }
        Expr::Binary {
            op: BinOp::Div | BinOp::Shr | BinOp::Rem,
            left,
            ..
        } => !folds_to_zero(left) && row_survives_fold(left, row),
        Expr::Binary { left, right, .. } => {
            row_survives_fold(left, row) || row_survives_fold(right, row)
        }
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => row_survives_fold(expr, row),
        _ => false,
    }
}

fn guard_counts_row(entry: &EntryDecl, row: &str) -> bool {
    required_conditions(entry)
        .iter()
        .any(|c| row_survives_fold(c, row))
}

fn collateral_row_for(entry: &EntryDecl, accrued_row: &str) -> Option<String> {
    for cond in required_conditions(entry) {
        if let Expr::Binary {
            op, left, right, ..
        } = cond.peel()
        {
            let (small, large) = match op {
                BinOp::Le | BinOp::Lt => (left.as_ref(), right.as_ref()),
                BinOp::Ge | BinOp::Gt => (right.as_ref(), left.as_ref()),
                _ => continue,
            };
            if row_survives_fold(small, accrued_row) {
                let mut c: Option<String> = None;
                walk(large, &mut |e| {
                    if c.is_some() {
                        return;
                    }
                    if let Expr::Call { callee, args, .. } = e {
                        if let Expr::Field { base, name, .. } = callee.as_ref() {
                            if name.text == "get"
                                && matches!(args.first(), Some(Expr::Caller { .. }))
                            {
                                if let Expr::Ident(m) = base.as_ref() {
                                    c = Some(m.text.clone());
                                }
                            }
                        }
                    }
                });
                if c.is_some() {
                    return c;
                }
            }
        }
    }
    None
}

fn row_is_freely_withdrawn(model: &Model, collateral: &str, debt: &str) -> bool {
    for e in &model.entries {
        let mut debits_collateral = false;
        let mut reduces_debt = false;
        let mut pays = false;
        for stmt in &e.body {
            stmt_exprs(stmt, &mut |x| {
                if let Expr::Call { callee, .. } = x {
                    match callee.as_ref() {
                        Expr::Field { base, name, .. } if name.text == "debit" => {
                            if let Expr::Ident(m) = base.as_ref() {
                                if m.text == collateral {
                                    debits_collateral = true;
                                }
                                if m.text == debt {
                                    reduces_debt = true;
                                }
                            }
                        }
                        Expr::Ident(id) if id.text == "send" || id.text == "send_asset" => {
                            pays = true;
                        }
                        _ => {}
                    }
                }
            });
        }
        if debits_collateral && pays && !reduces_debt {
            return true;
        }
    }
    false
}

fn pool_is_deposit_backed(model: &Model, pool: Option<&str>) -> bool {
    for e in &model.entries {
        let assets: HashSet<&str> = e
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        if assets.is_empty() {
            continue;
        }
        let mut found = false;
        for stmt in &e.body {
            stmt_exprs(stmt, &mut |x| {
                if let Expr::Call { callee, args, .. } = x {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if name.text == "merge"
                            && matches!(base.as_ref(), Expr::Ident(b) if pool.is_none_or(|p| b.text == p))
                        {
                            if let Some(Expr::Ident(f)) = args.first().map(|a| a.peel()) {
                                if assets.contains(f.text.as_str()) {
                                    found = true;
                                }
                            }
                        }
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

fn row_inflated_before(entry: &EntryDecl, map: &str, before: usize) -> bool {
    for stmt in entry.body.iter().take(before) {
        let mut hit = false;
        stmt_exprs(stmt, &mut |x| {
            if let Expr::Call { callee, args, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "credit" | "set" | "insert")
                        && matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                    {
                        hit = true;
                    }
                }
            }
        });
        if hit {
            return true;
        }
    }
    false
}

fn names_written_before(entry: &EntryDecl, before: usize) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for stmt in entry.body.iter().take(before) {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            ..
        } = stmt
        {
            out.insert(id.text.clone());
        }
        stmt_exprs(stmt, &mut |x| {
            if let Expr::Call { callee, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(
                        name.text.as_str(),
                        "credit" | "debit" | "set" | "insert" | "remove"
                    ) {
                        if let Expr::Ident(m) = base.as_ref() {
                            out.insert(m.text.clone());
                        }
                    }
                }
            }
        });
    }
    out
}

fn amount_reads_written_state(amount: &Expr, written: &HashSet<String>) -> bool {
    let mut dirty = false;
    walk(amount, &mut |x| match x {
        Expr::Ident(id) if written.contains(id.text.as_str()) => dirty = true,
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" {
                    if let Expr::Ident(m) = base.as_ref() {
                        if written.contains(m.text.as_str()) {
                            dirty = true;
                        }
                    }
                }
            }
        }
        _ => {}
    });
    dirty
}

fn map_is_deposit_backed_pool(model: &Model, map: &str, pool: Option<&str>) -> bool {
    for e in &model.entries {
        let asset_params: HashSet<&str> = e
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        if asset_params.is_empty() {
            continue;
        }
        let mut credited_from: HashSet<String> = HashSet::new();
        let mut merged_in: HashSet<String> = HashSet::new();
        for stmt in &e.body {
            stmt_exprs(stmt, &mut |x| {
                if let Expr::Call { callee, args, .. } = x {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(name.text.as_str(), "credit" | "set" | "insert")
                            && matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                        {
                            if let Some(v) = args.get(1) {
                                if let Some(p) = resolved_asset_backer(e, v, &asset_params, 0) {
                                    credited_from.insert(p);
                                }
                            }
                        }
                        if name.text == "merge"
                            && matches!(base.as_ref(), Expr::Ident(b) if pool.is_none_or(|p| b.text == p))
                        {
                            if let Some(Expr::Ident(f)) = args.first().map(|a| a.peel()) {
                                if asset_params.contains(f.text.as_str()) {
                                    merged_in.insert(f.text.clone());
                                }
                            }
                        }
                    }
                }
            });
        }
        if credited_from.iter().any(|f| merged_in.contains(f)) {
            return true;
        }
    }
    false
}

fn payout_is_proportional_to_debit(
    model: &Model,
    entry: &EntryDecl,
    payout: &Expr,
    debit: &Expr,
) -> bool {
    let Expr::Binary {
        op: BinOp::Div,
        left,
        right,
        ..
    } = payout.peel()
    else {
        return false;
    };
    let total = right.peel();
    let Expr::Ident(id) = total else {
        return false;
    };
    if !model.state.contains_key(id.text.as_str()) {
        return false;
    }
    let mut references_debit = false;
    walk(left, &mut |e| {
        if expr_eq(e, debit) {
            references_debit = true;
        }
    });
    if !references_debit {
        return false;
    }
    entry_guards_total_at_least_debit(entry, total, debit)
        && entry_consumes_total_by_debit(entry, id.text.as_str(), debit)
        && total_backed_by_an_inflow(model, id.text.as_str())
        && share_denominator_is_conservative(model, entry, id.text.as_str(), debit)
        && pool_grows_in_lockstep_with_total(model, left, id.text.as_str())
        && total_shrinks_only_in_lockstep(model, left, id.text.as_str())
}

fn total_decrement<'a>(stmt: &'a Stmt, total: &str) -> Option<&'a Expr> {
    if let Stmt::Assign {
        target: Expr::Ident(id),
        op,
        value,
        ..
    } = stmt
    {
        if id.text != total {
            return None;
        }
        match op {
            AssignOp::Sub => return Some(value),
            AssignOp::Set => {
                if let Expr::Binary {
                    op: BinOp::Sub,
                    left,
                    right,
                    ..
                } = value.peel()
                {
                    if matches!(left.peel(), Expr::Ident(t) if t.text == total) {
                        return Some(right);
                    }
                }
            }
            AssignOp::Add => {}
        }
    }
    None
}

fn entry_redeems_pool_proportionally(entry: &EntryDecl, pool: &str, total: &str, z: &Expr) -> bool {
    let mut hit = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if hit {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "split"
                        && matches!(base.as_ref(), Expr::Ident(p) if p.text == pool)
                    {
                        if let Some(Expr::Binary {
                            op: BinOp::Div,
                            left,
                            right,
                            ..
                        }) = args.first().map(|a| a.peel())
                        {
                            if matches!(right.peel(), Expr::Ident(t) if t.text == total) {
                                walk(left, &mut |x| {
                                    if expr_eq(x, z.peel()) {
                                        hit = true;
                                    }
                                });
                            }
                        }
                    }
                }
            }
        });
    }
    hit
}

fn total_shrinks_only_in_lockstep(model: &Model, numerator: &Expr, total: &str) -> bool {
    let Some(pool) = find_pool_asset(model, numerator) else {
        return true;
    };
    for entry in &model.entries {
        for stmt in &entry.body {
            if let Some(z) = total_decrement(stmt, total) {
                if has_protected_signed_authority(model, entry)
                    || entry_guarded_by_owner(model, entry)
                {
                    continue;
                }
                if entry_redeems_pool_proportionally(entry, pool, total, z) {
                    continue;
                }
                return false;
            }
        }
    }
    true
}

fn find_pool_asset<'a>(model: &Model, numerator: &'a Expr) -> Option<&'a str> {
    match numerator {
        Expr::Field { base, name, .. } if name.text == "amount" => {
            if let Expr::Ident(id) = base.as_ref() {
                if model
                    .state
                    .get(id.text.as_str())
                    .is_some_and(|f| f.ty.name.text == "Q_Asset")
                {
                    return Some(id.text.as_str());
                }
            }
            None
        }
        Expr::Binary { left, right, .. } => {
            find_pool_asset(model, left).or_else(|| find_pool_asset(model, right))
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            find_pool_asset(model, expr)
        }
        _ => None,
    }
}

fn total_grows_by_param_amount(entry: &EntryDecl, total: &str, param: &str) -> bool {
    let is_param_amount = |e: &Expr| {
        matches!(e.peel(), Expr::Field { base, name, .. }
            if name.text == "amount" && matches!(base.as_ref(), Expr::Ident(p) if p.text == param))
    };
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op,
            value,
            ..
        } = stmt
        {
            if id.text != total {
                continue;
            }
            match op {
                AssignOp::Add => {
                    if is_param_amount(value) {
                        return true;
                    }
                }
                AssignOp::Set => {
                    if let Expr::Binary {
                        op: BinOp::Add,
                        left,
                        right,
                        ..
                    } = value.peel()
                    {
                        if matches!(left.peel(), Expr::Ident(t) if t.text == total)
                            && is_param_amount(right)
                        {
                            return true;
                        }
                        if matches!(right.peel(), Expr::Ident(t) if t.text == total)
                            && is_param_amount(left)
                        {
                            return true;
                        }
                    }
                }
                AssignOp::Sub => {}
            }
        }
    }
    false
}

fn pool_grows_in_lockstep_with_total(model: &Model, numerator: &Expr, total: &str) -> bool {
    let Some(pool) = find_pool_asset(model, numerator) else {
        return true;
    };
    for entry in &model.entries {
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        for stmt in &entry.body {
            if let Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } = stmt
            {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "merge"
                        && matches!(base.as_ref(), Expr::Ident(b) if b.text == pool)
                    {
                        if let Some(Expr::Ident(p)) = args.first().map(|a| a.peel()) {
                            if assets.contains(p.text.as_str())
                                && !total_grows_by_param_amount(entry, total, p.text.as_str())
                            {
                                return false;
                            }
                        }
                    }
                }
            }
        }
    }
    true
}

fn debited_map_for<'a>(entry: &'a EntryDecl, debit: &Expr) -> Option<&'a str> {
    for stmt in &entry.body {
        if let Stmt::Expr {
            expr: Expr::Call { callee, args, .. },
            ..
        } = stmt
        {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "debit" {
                    if let Expr::Ident(m) = base.as_ref() {
                        if args.get(1).is_some_and(|a| expr_eq(a, debit)) {
                            return Some(m.text.as_str());
                        }
                    }
                }
            }
        }
    }
    None
}

fn entry_guards_total_zero(entry: &EntryDecl, total: &str) -> bool {
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op: BinOp::Eq,
                    left,
                    right,
                    ..
                } = p.peel()
                {
                    if matches!(left.peel(), Expr::Ident(t) if t.text == total)
                        && is_zero_int(right)
                    {
                        return true;
                    }
                    if matches!(right.peel(), Expr::Ident(t) if t.text == total)
                        && is_zero_int(left)
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn entry_total_backings<'a>(
    model: &Model,
    entry: &'a EntryDecl,
    share_map: &str,
    total: &str,
    visiting: &mut HashSet<String>,
) -> Vec<&'a Expr> {
    let mut out: Vec<&Expr> = Vec::new();
    let zero_seed = entry_guards_total_zero(entry, total);
    for stmt in &entry.body {
        match stmt {
            Stmt::Assign {
                target: Expr::Ident(id),
                op,
                value,
                ..
            } if id.text == total => match op {
                AssignOp::Add => out.push(value.peel()),
                AssignOp::Set => {
                    if let Expr::Binary {
                        op: BinOp::Add,
                        left,
                        right,
                        ..
                    } = value.peel()
                    {
                        if matches!(left.peel(), Expr::Ident(t) if t.text == total) {
                            out.push(right.peel());
                        } else if matches!(right.peel(), Expr::Ident(t) if t.text == total) {
                            out.push(left.peel());
                        }
                    } else if zero_seed {
                        out.push(value.peel());
                    }
                }
                AssignOp::Sub => {}
            },
            Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } => {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "debit" {
                        if let Expr::Ident(other) = base.as_ref() {
                            if other.text != share_map {
                                if let Some(a) = args.get(1) {
                                    if share_map_is_conservative(
                                        model,
                                        other.text.as_str(),
                                        total,
                                        visiting,
                                    ) {
                                        out.push(a);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn share_map_is_conservative(
    model: &Model,
    share_map: &str,
    total: &str,
    visiting: &mut HashSet<String>,
) -> bool {
    if !visiting.insert(share_map.to_string()) {
        return true;
    }
    let mut ok = true;
    'outer: for entry in &model.entries {
        let mut credits: Vec<&Expr> = Vec::new();
        for stmt in &entry.body {
            if let Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } = stmt
            {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "credit" | "insert")
                        && matches!(base.as_ref(), Expr::Ident(m) if m.text == share_map)
                    {
                        if let Some(a) = args.get(1) {
                            credits.push(a);
                        }
                    }
                }
            }
        }
        if credits.is_empty() {
            continue;
        }
        let backings = entry_total_backings(model, entry, share_map, total, visiting);
        let mut used = vec![false; backings.len()];
        for c in &credits {
            let mut matched = false;
            for (i, b) in backings.iter().enumerate() {
                if !used[i] && expr_eq(strip_value_noops(c), strip_value_noops(b)) {
                    used[i] = true;
                    matched = true;
                    break;
                }
            }
            if !matched {
                ok = false;
                break 'outer;
            }
        }
    }
    visiting.remove(share_map);
    ok
}

fn share_denominator_is_conservative(
    model: &Model,
    entry: &EntryDecl,
    total: &str,
    debit: &Expr,
) -> bool {
    match debited_map_for(entry, debit) {
        Some(m) => {
            let mut visiting = HashSet::new();
            share_map_is_conservative(model, m, total, &mut visiting)
        }
        None => true,
    }
}

fn total_backed_by_an_inflow(model: &Model, total: &str) -> bool {
    for entry in &model.entries {
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        let mut credited: Vec<&Expr> = Vec::new();
        for stmt in &entry.body {
            if let Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } = stmt
            {
                if let Expr::Field { name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "credit" | "insert") {
                        if let Some(a) = args.get(1) {
                            credited.push(a);
                        }
                    }
                }
            }
        }
        for stmt in &entry.body {
            if let Stmt::Assign {
                target: Expr::Ident(id),
                op,
                value,
                ..
            } = stmt
            {
                if id.text != total {
                    continue;
                }
                let increment = match op {
                    AssignOp::Add => Some(value.peel()),
                    AssignOp::Set => {
                        if let Expr::Binary {
                            op: BinOp::Add,
                            left,
                            right,
                            ..
                        } = value.peel()
                        {
                            if matches!(left.peel(), Expr::Ident(t) if t.text == total) {
                                Some(right.peel())
                            } else if matches!(right.peel(), Expr::Ident(t) if t.text == total) {
                                Some(left.peel())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    AssignOp::Sub => None,
                };
                if let Some(e) = increment {
                    if !assets.is_empty() && asset_amount_backer(e, &assets).is_some() {
                        return true;
                    }
                    if credited
                        .iter()
                        .any(|c| expr_eq(strip_value_noops(c), strip_value_noops(e)))
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn entry_consumes_total_by_debit(entry: &EntryDecl, total: &str, debit: &Expr) -> bool {
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op,
            value,
            ..
        } = stmt
        {
            if id.text != total {
                continue;
            }
            match op {
                AssignOp::Sub => {
                    if expr_eq(strip_value_noops(value), debit) {
                        return true;
                    }
                }
                AssignOp::Set => {
                    if let Expr::Binary {
                        op: BinOp::Sub,
                        left,
                        right,
                        ..
                    } = value.peel()
                    {
                        if matches!(left.peel(), Expr::Ident(l) if l.text == total)
                            && expr_eq(strip_value_noops(right), debit)
                        {
                            return true;
                        }
                    }
                }
                AssignOp::Add => {}
            }
        }
    }
    false
}

fn row_is_authority_mintable(model: &Model, m: &str) -> bool {
    for entry in &model.entries {
        if !(has_protected_signed_authority(model, entry) || entry_guarded_by_owner(model, entry)) {
            continue;
        }
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        let mut mints = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(map) = base.as_ref() {
                            if map.text == m
                                && matches!(name.text.as_str(), "credit" | "set" | "insert")
                            {
                                if let Some(v) = args.get(1) {
                                    if !is_zero_literal(v)
                                        && asset_amount_backer(v, &assets).is_none()
                                    {
                                        mints = true;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        if mints {
            return true;
        }
    }
    false
}

fn entry_guards_total_at_least_debit(entry: &EntryDecl, total: &Expr, debit: &Expr) -> bool {
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    let holds = match op {
                        BinOp::Ge | BinOp::Gt => {
                            expr_eq(left.peel(), total) && expr_eq(right.peel(), debit)
                        }
                        BinOp::Le | BinOp::Lt => {
                            expr_eq(left.peel(), debit) && expr_eq(right.peel(), total)
                        }
                        _ => false,
                    };
                    if holds {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn payout_within_debit(amount: &Expr, debit: &Expr) -> bool {
    if payout_is_bounded_by(amount, debit) {
        return true;
    }
    if let Expr::Ident(p) = amount.peel() {
        if debit_covers_the_parameter(debit, &p.text) {
            return true;
        }
    }
    false
}

fn scalar_never_assigned(model: &Model, name: &str) -> bool {
    !model.entries.iter().any(|e| {
        e.body
            .iter()
            .any(|s| matches!(s, Stmt::Assign { target: Expr::Ident(id), .. } if id.text == name))
    })
}

fn payout_is_authority_bound(model: &Model, amount: &Expr, params: &HashSet<String>) -> bool {
    match amount.peel() {
        Expr::Int(_) => true,
        Expr::Ident(id) => {
            params.contains(id.text.as_str())
                || (model.state.contains_key(id.text.as_str())
                    && scalar_never_assigned(model, &id.text))
        }
        Expr::Field { base, name, .. } => {
            matches!(base.as_ref(), Expr::Ident(id) if params.contains(id.text.as_str()))
                || (name.text == "amount"
                    && matches!(base.as_ref(), Expr::Ident(id) if model.state.contains_key(id.text.as_str())))
        }
        Expr::Binary {
            op: BinOp::Sub | BinOp::Div | BinOp::Shr | BinOp::Rem,
            left,
            ..
        } => payout_is_authority_bound(model, left, params),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            payout_is_authority_bound(model, expr, params)
        }
        _ => false,
    }
}

fn entry_guarded_by_owner(model: &Model, entry: &EntryDecl) -> bool {
    let conds = required_conditions(entry);
    let mut parts: Vec<&Expr> = Vec::new();
    for c in &conds {
        collect_conjuncts(c, &mut parts);
    }
    for p in parts {
        if let Expr::Binary {
            op: BinOp::Eq,
            left,
            right,
            ..
        } = p.peel()
        {
            for (a, b) in [
                (left.as_ref(), right.as_ref()),
                (right.as_ref(), left.as_ref()),
            ] {
                if matches!(a.peel(), Expr::Caller { .. }) {
                    if let Expr::Ident(x) = b.peel() {
                        if authority_anchor_protected(model, &x.text) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn map_feeds_self_service_send(model: &Model, m: &str) -> bool {
    for entry in &model.entries {
        let mut debits_caller_row = false;
        let mut has_send = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    match callee.as_ref() {
                        Expr::Field { base, name, .. }
                            if name.text == "debit"
                                && matches!(base.as_ref(), Expr::Ident(id) if id.text == m)
                                && matches!(args.first(), Some(Expr::Caller { .. })) =>
                        {
                            debits_caller_row = true;
                        }
                        Expr::Ident(id) if matches!(id.text.as_str(), "send" | "send_asset") => {
                            has_send = true;
                        }
                        _ => {}
                    }
                }
            });
        }
        if debits_caller_row && has_send {
            return true;
        }
    }
    false
}

fn proportional_denominators(model: &Model) -> HashSet<String> {
    let mut out = HashSet::new();
    for entry in &model.entries {
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Binary {
                    op: BinOp::Div,
                    right,
                    ..
                } = e
                {
                    if let Expr::Ident(s) = right.peel() {
                        if model.state.contains_key(s.text.as_str()) {
                            out.insert(s.text.clone());
                        }
                    }
                }
            });
        }
    }
    out
}

fn entry_grows_denominator_by(entry: &EntryDecl, denoms: &HashSet<String>, amt: &Expr) -> bool {
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op,
            value,
            ..
        } = stmt
        {
            if !denoms.contains(id.text.as_str()) {
                continue;
            }
            match op {
                AssignOp::Add => {
                    if expr_eq(strip_value_noops(value), strip_value_noops(amt)) {
                        return true;
                    }
                }
                AssignOp::Set => {
                    if let Expr::Binary {
                        op: BinOp::Add,
                        left,
                        right,
                        ..
                    } = value.peel()
                    {
                        if matches!(left.peel(), Expr::Ident(l) if l.text == id.text)
                            && expr_eq(strip_value_noops(right), strip_value_noops(amt))
                        {
                            return true;
                        }
                        if matches!(right.peel(), Expr::Ident(l) if l.text == id.text)
                            && expr_eq(strip_value_noops(left), strip_value_noops(amt))
                        {
                            return true;
                        }
                    } else if entry_guards_total_zero(entry, id.text.as_str())
                        && expr_eq(strip_value_noops(value), strip_value_noops(amt))
                    {
                        return true;
                    }
                }
                AssignOp::Sub => {}
            }
        }
    }
    false
}

fn unwrap_checked(e: &Expr) -> &Expr {
    match e {
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => unwrap_checked(expr),
        _ => e,
    }
}

fn scalar_inflow_backed(model: &Model, scalar: &str) -> bool {
    for entry in &model.entries {
        let assets: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        if assets.is_empty() {
            continue;
        }
        let mut inc_param: Option<String> = None;
        for stmt in &entry.body {
            if let Stmt::Assign {
                target: Expr::Ident(id),
                op,
                value,
                ..
            } = stmt
            {
                if id.text != scalar {
                    continue;
                }
                let inc: Option<&Expr> = match op {
                    AssignOp::Add => Some(unwrap_checked(value.peel())),
                    AssignOp::Set => match unwrap_checked(value.peel()) {
                        Expr::Binary {
                            op: BinOp::Add,
                            left,
                            right,
                            ..
                        } if matches!(left.peel(), Expr::Ident(t) if t.text == scalar) => {
                            Some(right.peel())
                        }
                        Expr::Binary {
                            op: BinOp::Add,
                            left,
                            right,
                            ..
                        } if matches!(right.peel(), Expr::Ident(t) if t.text == scalar) => {
                            Some(left.peel())
                        }
                        _ => None,
                    },
                    AssignOp::Sub => None,
                };
                if let Some(e) = inc {
                    if let Some(p) = asset_amount_backer(e, &assets) {
                        inc_param = Some(p.to_string());
                    }
                }
            }
        }
        if let Some(p) = inc_param {
            if asset_merged_into(model, entry, &p).is_some() {
                return true;
            }
        }
    }
    false
}

fn gov_map_read(e: &Expr) -> Option<(&str, &Expr)> {
    if let Expr::Call { callee, args, .. } = e.peel() {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "get" && args.len() == 1 {
                if let Expr::Ident(m) = base.as_ref() {
                    return Some((m.text.as_str(), &args[0]));
                }
            }
        }
    }
    None
}

fn scalar_guarded_ge(entry: &EntryDecl, scalar: &str, amt: &Expr) -> bool {
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    let hit = match op {
                        BinOp::Ge | BinOp::Gt => {
                            matches!(left.peel(), Expr::Ident(s) if s.text == scalar)
                                && expr_eq(right.peel(), amt)
                        }
                        BinOp::Le | BinOp::Lt => {
                            matches!(right.peel(), Expr::Ident(s) if s.text == scalar)
                                && expr_eq(left.peel(), amt)
                        }
                        _ => false,
                    };
                    if hit {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn vote_map_guarded_on_key<'a>(entry: &'a EntryDecl, key: &Expr) -> Option<&'a str> {
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    let read = match op {
                        BinOp::Ge | BinOp::Gt if matches!(right.peel(), Expr::Int(_)) => {
                            gov_map_read(left)
                        }
                        BinOp::Le | BinOp::Lt if matches!(left.peel(), Expr::Int(_)) => {
                            gov_map_read(right)
                        }
                        _ => None,
                    };
                    if let Some((v, k)) = read {
                        if expr_eq(k, key) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    None
}

fn map_credited_from_a_caller_row(model: &Model, vmap: &str) -> bool {
    for entry in &model.entries {
        let mut found = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if name.text == "credit"
                            && matches!(base.as_ref(), Expr::Ident(m) if m.text == vmap)
                        {
                            if let Some(v) = args.get(1) {
                                if let Some((_, k)) = gov_map_read(v) {
                                    if matches!(k.peel(), Expr::Caller { .. }) {
                                        found = true;
                                    }
                                }
                            }
                        }
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

fn map_writer_is_stake_gated(model: &Model, pmap: &str) -> bool {
    for entry in &model.entries {
        let mut writes = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(name.text.as_str(), "set" | "insert")
                            && matches!(base.as_ref(), Expr::Ident(m) if m.text == pmap)
                        {
                            writes = true;
                        }
                    }
                }
            });
        }
        if !writes {
            continue;
        }
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                if anchor_of(model, expr).is_some() {
                    return true;
                }
                let mut parts: Vec<&Expr> = Vec::new();
                split_and(expr, &mut parts);
                for p in parts {
                    if let Expr::Binary {
                        op: BinOp::Gt | BinOp::Ge,
                        left,
                        right,
                        ..
                    } = p.peel()
                    {
                        if matches!(right.peel(), Expr::Int(_)) {
                            if let Some((_, k)) = gov_map_read(left) {
                                if matches!(k.peel(), Expr::Caller { .. }) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn entry_removes_key(entry: &EntryDecl, pmap: &str, key: &Expr) -> bool {
    let mut removed = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(m) if m.text == pmap)
                        && args.first().is_some_and(|k| expr_eq(k, key))
                    {
                        match name.text.as_str() {
                            "remove" => removed = true,
                            "set" if args.get(1).is_some_and(is_zero_int) => removed = true,
                            _ => {}
                        }
                    }
                }
            }
        });
    }
    removed
}

fn governance_credit_proven(
    model: &Model,
    entry: &EntryDecl,
    _credited_map: &str,
    amt: &Expr,
) -> bool {
    let Some((pmap, key)) = gov_map_read(amt) else {
        return false;
    };
    let mut lets: HashMap<String, Expr> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let r = resolve_locals(value, &lets, 0);
            lets.insert(name.text.clone(), r);
        }
    }
    let mut scalar: Option<&str> = None;
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op,
            value,
            ..
        } = stmt
        {
            let rv = resolve_locals(value, &lets, 0);
            let dec = match op {
                AssignOp::Sub => expr_eq(rv.peel(), amt),
                AssignOp::Set => {
                    matches!(rv.peel(), Expr::Binary { op: BinOp::Sub, left, right, .. }
                    if matches!(left.peel(), Expr::Ident(l) if l.text == id.text) && expr_eq(right.peel(), amt))
                }
                AssignOp::Add => false,
            };
            if dec {
                scalar = Some(id.text.as_str());
            }
        }
    }
    let Some(s) = scalar else {
        return false;
    };
    if !scalar_guarded_ge(entry, s, amt) {
        return false;
    }
    if !scalar_inflow_backed(model, s) {
        return false;
    }
    if !entry_removes_key(entry, pmap, key) {
        return false;
    }
    if !map_writer_is_stake_gated(model, pmap) {
        return false;
    }
    match vote_map_guarded_on_key(entry, key) {
        Some(v) => map_credited_from_a_caller_row(model, v),
        None => false,
    }
}

fn amount_guard_bounded_by(entry: &EntryDecl, amount: &Expr, inflow: &Expr) -> bool {
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            for p in parts {
                if let Expr::Binary {
                    op, left, right, ..
                } = p.peel()
                {
                    let (hi, lo) = match op {
                        BinOp::Gt | BinOp::Ge => (left.peel(), right.peel()),
                        BinOp::Lt | BinOp::Le => (right.peel(), left.peel()),
                        _ => continue,
                    };
                    if expr_eq(hi, inflow.peel()) && expr_eq(lo, amount.peel()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn row_reinflated_after(entry: &EntryDecl, map: &str, debit_idx: usize) -> bool {
    for (i, stmt) in entry.body.iter().enumerate() {
        if i <= debit_idx {
            continue;
        }
        let mut hit = false;
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "set" | "credit" | "insert")
                        && matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                    {
                        hit = true;
                    }
                }
            }
        });
        if hit {
            return true;
        }
    }
    false
}

fn value_reads_map_row(value: &Expr, map: &str) -> bool {
    let mut reads = false;
    walk(value, &mut |e| {
        if let Expr::Call { callee, .. } = e {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" && matches!(base.as_ref(), Expr::Ident(m) if m.text == map) {
                    reads = true;
                }
            }
        }
    });
    reads
}

fn self_service_payout_exceeds_backing(model: &Model, entry: &EntryDecl) -> Option<Span> {
    let has_auth =
        has_protected_signed_authority(model, entry) || entry_guarded_by_owner(model, entry);
    let all_params: HashSet<String> = entry.params.iter().map(|p| p.name.text.clone()).collect();
    let inflows: Vec<Expr> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| Expr::Field {
            base: Box::new(Expr::Ident(p.name.clone())),
            name: quanta_ast::Ident {
                text: "amount".to_string(),
                span: p.name.span,
            },
            span: p.name.span,
        })
        .collect();
    let mut lets: HashMap<String, Expr> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let resolved = resolve_locals(value, &lets, 0);
            lets.insert(name.text.clone(), resolved);
        }
    }
    let mut debits: Vec<(String, Expr, bool)> = Vec::new();
    for (idx, stmt) in entry.body.iter().enumerate() {
        let written = names_written_before(entry, idx);
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "debit" && matches!(args.first(), Some(Expr::Caller { .. })) {
                        if let (Expr::Ident(m), Some(amount)) = (base.as_ref(), args.get(1)) {
                            let valid = !row_inflated_before(entry, &m.text, idx)
                                && !row_reinflated_after(entry, &m.text, idx)
                                && !amount_reads_written_state(amount, &written);
                            debits.push((m.text.clone(), resolve_locals(amount, &lets, 0), valid));
                        }
                    }
                }
            }
        });
    }
    let mut splits: Vec<(String, Expr, Span)> = Vec::new();
    let mut mergebacks: Vec<(String, Expr)> = Vec::new();
    let mut sa_direct: Vec<(Expr, Option<String>, Span)> = Vec::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, span } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "split" {
                        if let (Expr::Ident(pool), Some(raw)) = (base.as_ref(), args.first()) {
                            splits.push((pool.text.clone(), resolve_locals(raw, &lets, 0), *span));
                        }
                    }
                    if name.text == "merge" {
                        if let (Expr::Ident(pool), Some(arg)) = (base.as_ref(), args.first()) {
                            let r = resolve_locals(arg, &lets, 0);
                            if let Expr::Call {
                                callee: ic,
                                args: ia,
                                ..
                            } = r.peel()
                            {
                                if let Expr::Field {
                                    base: ib,
                                    name: inm,
                                    ..
                                } = ic.as_ref()
                                {
                                    if inm.text == "split"
                                        && matches!(ib.as_ref(), Expr::Ident(p) if p.text == pool.text)
                                    {
                                        if let Some(amt) = ia.first() {
                                            mergebacks.push((pool.text.clone(), amt.clone()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send_asset") {
                    if let Some(value) = args.get(2) {
                        let rv = resolve_locals(value, &lets, 0);
                        let is_split = matches!(rv.peel(), Expr::Call { callee, .. }
                            if matches!(callee.as_ref(), Expr::Field { name, .. } if name.text == "split"));
                        if !is_split {
                            let tok = match args.first().map(|t| t.peel()) {
                                Some(Expr::Ident(t)) => Some(t.text.clone()),
                                _ => None,
                            };
                            sa_direct.push((rv, tok, *span));
                        }
                    }
                }
            }
        });
    }
    for (pool, amt) in &mergebacks {
        if let Some(pos) = splits
            .iter()
            .position(|(p, a, _)| p == pool && expr_eq(a.peel(), amt.peel()))
        {
            splits.remove(pos);
        }
    }
    let denoms = proportional_denominators(model);
    let mut credit_outflows: Vec<(Expr, Span)> = Vec::new();
    for stmt in &entry.body {
        if let Stmt::Expr {
            expr: Expr::Call { callee, args, span },
            ..
        } = stmt
        {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if matches!(name.text.as_str(), "credit" | "insert" | "set") {
                    if let Expr::Ident(m) = base.as_ref() {
                        if map_feeds_self_service_send(model, m.text.as_str()) {
                            if let Some(amt) = args.get(1) {
                                let resolved = resolve_locals(amt, &lets, 0);
                                let set_increment = name.text == "set"
                                    && value_reads_map_row(&resolved, m.text.as_str());
                                if !set_increment
                                    && !entry_grows_denominator_by(entry, &denoms, &resolved)
                                    && !governance_credit_proven(
                                        model,
                                        entry,
                                        m.text.as_str(),
                                        &resolved,
                                    )
                                {
                                    credit_outflows.push((resolved, *span));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let entitlement_bounded = outflow_is_bounded_by_an_entitlement(model, entry);
    let mut debit_used = vec![false; debits.len()];
    let mut inflow_used = vec![false; inflows.len()];
    let mut consume = |pool: Option<&str>, amount: &Expr, payout_token: Option<&str>| -> bool {
        if !pool_is_deposit_backed(model, pool) {
            return true;
        }
        if has_auth && payout_is_authority_bound(model, amount, &all_params) {
            return true;
        }
        for j in 0..inflows.len() {
            if !inflow_used[j] && payout_is_bounded_by(amount, inflows[j].peel()) {
                inflow_used[j] = true;
                return true;
            }
        }
        for j in 0..inflows.len() {
            if !inflow_used[j] && amount_guard_bounded_by(entry, amount, inflows[j].peel()) {
                inflow_used[j] = true;
                return true;
            }
        }
        let priced_off_inflow = {
            let mut hit = false;
            walk(amount, &mut |e| {
                if inflows.iter().any(|i| expr_eq(i.peel(), e)) {
                    hit = true;
                }
            });
            hit
        };
        if reserve_bounding_payout(model, entry, amount.peel(), &inflows, payout_token).is_some()
            || (entitlement_bounded
                && (priced_off_inflow
                    || entry_accrual_row(entry, amount).is_some_and(|row| {
                        guard_counts_row(entry, &row)
                            && collateral_row_for(entry, &row)
                                .is_some_and(|c| !row_is_freely_withdrawn(model, &c, &row))
                    })))
        {
            return true;
        }
        for i in 0..debits.len() {
            if debit_used[i] || !debits[i].2 {
                continue;
            }
            let m = &debits[i].0;
            let funding = ledger_funding_tokens(model, m);
            let token_ok = funding.len() <= 1
                && match payout_token {
                    Some(t) => funding.is_empty() || funding.contains(t),
                    None => true,
                };
            if !token_ok {
                continue;
            }
            let backs_pool = match pool {
                Some(p) => map_is_deposit_backed_pool(model, m, Some(p)),
                None => map_is_deposit_backed_pool(model, m, None),
            };
            let is_deposit_ledger = map_is_deposit_backed_pool(model, m, None);
            if backs_pool {
                if payout_within_debit(amount, debits[i].1.peel()) {
                    debit_used[i] = true;
                    return true;
                }
            } else if !is_deposit_ledger && !folds_to_zero(&debits[i].1) {
                let debit_amt = debits[i].1.peel();
                if payout_within_debit(amount, debit_amt) {
                    debit_used[i] = true;
                    return true;
                }
                if payout_is_proportional_to_debit(model, entry, amount, debit_amt)
                    && !row_is_authority_mintable(model, m)
                {
                    return true;
                }
            }
        }
        false
    };
    for (pool, amount, span) in &splits {
        if !consume(Some(pool.as_str()), amount, None) {
            return Some(*span);
        }
    }
    for (amount, tok, span) in &sa_direct {
        if !consume(None, amount, tok.as_deref()) {
            return Some(*span);
        }
    }
    for (amount, span) in &credit_outflows {
        if !consume(None, amount, None) {
            return Some(*span);
        }
    }
    None
}

fn reserve_bounding_payout(
    model: &Model,
    entry: &EntryDecl,
    amount: &Expr,
    inflows: &[Expr],
    payout_token: Option<&str>,
) -> Option<String> {
    let mut priced = false;
    walk(amount, &mut |e| {
        if inflows.iter().any(|i| expr_eq(i.peel(), e)) {
            priced = true;
        }
    });
    if !priced {
        return None;
    }
    let mut guarded: Vec<String> = Vec::new();
    let mut reduced: Vec<String> = Vec::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { expr, .. } => {
                if let Expr::Binary {
                    op, left, right, ..
                } = expr.peel()
                {
                    let (reserve, bound) = match op {
                        BinOp::Gt | BinOp::Ge => (left.peel(), right.peel()),
                        BinOp::Lt | BinOp::Le => (right.peel(), left.peel()),
                        _ => continue,
                    };
                    if let Expr::Ident(r) = reserve {
                        if model.state.contains_key(r.text.as_str()) && expr_eq(bound, amount) {
                            guarded.push(r.text.clone());
                        }
                    }
                }
            }
            Stmt::Assign {
                target: Expr::Ident(r),
                op,
                value,
                ..
            } if model.state.contains_key(r.text.as_str()) => {
                let lowers = !contains_wrapping(value)
                    && match op {
                        AssignOp::Sub => expr_eq(value.peel(), amount),
                        AssignOp::Set => matches!(
                            value.peel(),
                            Expr::Binary { op: BinOp::Sub, left, right, .. }
                                if matches!(left.peel(), Expr::Ident(l) if l.text == r.text)
                                    && expr_eq(right.peel(), amount)
                        ),
                        AssignOp::Add => false,
                    };
                if lowers {
                    reduced.push(r.text.clone());
                }
            }
            _ => {}
        }
    }
    let token = payout_token?;
    guarded
        .into_iter()
        .find(|r| reduced.contains(r) && reserve_token(model, r).as_deref() == Some(token))
}

fn contains_wrapping(e: &Expr) -> bool {
    let mut found = false;
    walk(e, &mut |x| {
        if matches!(x, Expr::Wrapping { .. }) {
            found = true;
        }
    });
    found
}

fn reserve_token(model: &Model, field: &str) -> Option<String> {
    if let Some(def) = model.state.get(field).and_then(|f| f.default.as_ref()) {
        if !matches!(def.peel(), Expr::Int(i) if i.text.trim_start_matches('_').chars().all(|c| c == '0' || c == '_'))
        {
            return None;
        }
    }
    for item in &model.contract.items {
        if let quanta_ast::Item::Genesis(g) = item {
            for stmt in &g.body {
                if let Stmt::Assign { target, value, .. } = stmt {
                    if matches!(target, Expr::Ident(id) if id.text == field)
                        && !matches!(value.peel(), Expr::Int(i) if i.text.trim_start_matches('_').chars().all(|c| c == '0' || c == '_'))
                    {
                        return None;
                    }
                }
            }
        }
    }
    let mut tokens: HashSet<String> = HashSet::new();
    for entry in &model.entries {
        if !entry_writes_field(entry, field) {
            continue;
        }
        let inflows: Vec<&str> = entry
            .params
            .iter()
            .filter(|p| crate::model::is_asset_param(p))
            .map(|p| p.name.text.as_str())
            .collect();
        let mut admitted: Vec<&str> = Vec::new();
        let mut debits: Vec<(String, Expr)> = Vec::new();
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                if let Expr::Binary {
                    op: BinOp::Eq,
                    left,
                    right,
                    ..
                } = expr.peel()
                {
                    match (left.peel(), right.peel()) {
                        (Expr::InAsset { .. }, Expr::Ident(t))
                        | (Expr::Ident(t), Expr::InAsset { .. }) => admitted.push(t.text.as_str()),
                        _ => {}
                    }
                }
            }
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if name.text == "debit" && matches!(args.first(), Some(Expr::Caller { .. }))
                        {
                            if let (Expr::Ident(m), Some(a)) = (base.as_ref(), args.get(1)) {
                                debits.push((m.text.clone(), a.clone()));
                            }
                        }
                    }
                }
            });
        }
        for stmt in &entry.body {
            let Stmt::Assign {
                target: Expr::Ident(r),
                op,
                value,
                ..
            } = stmt
            else {
                continue;
            };
            if r.text != field {
                continue;
            }
            let added = match op {
                AssignOp::Sub => continue,
                AssignOp::Add => value.peel(),
                AssignOp::Set => match value.peel() {
                    Expr::Binary {
                        op: BinOp::Sub,
                        left,
                        ..
                    } if matches!(left.peel(), Expr::Ident(l) if l.text == field) => continue,
                    Expr::Binary {
                        op: BinOp::Add,
                        left,
                        right,
                        ..
                    } if matches!(left.peel(), Expr::Ident(l) if l.text == field) => right.peel(),
                    other => other,
                },
            };
            let paid = matches!(added, Expr::Field { base, name, .. }
                if name.text == "amount"
                    && matches!(base.as_ref(), Expr::Ident(a) if inflows.contains(&a.text.as_str())));
            if paid {
                let mut double_used = false;
                for s in &entry.body {
                    stmt_exprs(s, &mut |e| {
                        if let Expr::Call { callee, args, .. } = e {
                            if let Expr::Field { name, .. } = callee.as_ref() {
                                if matches!(name.text.as_str(), "credit" | "set" | "insert")
                                    && args.get(1).is_some_and(|v| expr_eq(v.peel(), added))
                                {
                                    double_used = true;
                                }
                            }
                        }
                    });
                }
                if double_used {
                    return None;
                }
                if admitted.len() != 1 {
                    return None;
                }
                tokens.insert(admitted[0].to_string());
                continue;
            }
            match debits.iter().find(|(_, a)| expr_eq(a.peel(), added)) {
                Some((map, _)) => {
                    let funding = ledger_funding_tokens(model, map);
                    if funding.len() != 1 {
                        return None;
                    }
                    tokens.extend(funding);
                }
                None => return None,
            }
        }
    }
    if tokens.len() == 1 {
        tokens.into_iter().next()
    } else {
        None
    }
}

fn resolve_locals(expr: &Expr, lets: &HashMap<String, Expr>, depth: u32) -> Expr {
    if depth > 16 {
        return expr.clone();
    }
    match expr.peel() {
        Expr::Ident(id) => match lets.get(&id.text) {
            Some(v) => resolve_locals(v, lets, depth + 1),
            None => expr.peel().clone(),
        },
        Expr::Binary {
            op,
            left,
            right,
            span,
        } => Expr::Binary {
            op: *op,
            left: Box::new(resolve_locals(left, lets, depth + 1)),
            right: Box::new(resolve_locals(right, lets, depth + 1)),
            span: *span,
        },
        other => other.clone(),
    }
}

fn every_backing_is_consumed_once(model: &Model, entry: &EntryDecl) -> bool {
    let ledgers = ledger_maps(model);
    let mut lets: HashMap<String, Expr> = HashMap::new();
    let mut backing: Vec<Expr> = entry
        .params
        .iter()
        .filter(|p| crate::model::is_asset_param(p))
        .map(|p| Expr::Field {
            base: Box::new(Expr::Ident(p.name.clone())),
            name: quanta_ast::Ident {
                text: "amount".to_string(),
                span: p.name.span,
            },
            span: p.name.span,
        })
        .collect();
    let mut uses: Vec<(Expr, bool)> = Vec::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let resolved = resolve_locals(value, &lets, 0);
            lets.insert(name.text.clone(), resolved);
        }
        stmt_exprs(stmt, &mut |e| {
            let Expr::Call { callee, args, .. } = e else {
                return;
            };
            match callee.as_ref() {
                Expr::Field { base, name, .. } => {
                    let Expr::Ident(m) = base.as_ref() else {
                        return;
                    };
                    match name.text.as_str() {
                        "debit"
                            if ledgers.contains(&m.text)
                                && matches!(args.first(), Some(Expr::Caller { .. })) =>
                        {
                            if let Some(a) = args.get(1) {
                                backing.push(resolve_locals(a, &lets, 0));
                            }
                        }
                        "credit" if ledgers.contains(&m.text) => {
                            if let Some(a) = args.get(1) {
                                uses.push((resolve_locals(a, &lets, 0), true));
                            }
                        }
                        "split" => {
                            if let Some(a) = args.first() {
                                uses.push((resolve_locals(a, &lets, 0), false));
                            }
                        }
                        _ => {}
                    }
                }
                Expr::Ident(id) if id.text == "send_asset" => {
                    if let Some(a) = args.get(2) {
                        let a = a.peel();
                        let split = matches!(a, Expr::Call { callee, .. }
                            if matches!(callee.as_ref(), Expr::Field { name, .. } if name.text == "split"));
                        if !split {
                            uses.push((resolve_locals(a, &lets, 0), false));
                        }
                    }
                }
                _ => {}
            }
        });
    }
    if uses.len() < 2 {
        return true;
    }
    let mut credits_unbacked = false;
    for (used, credit) in &uses {
        match backing
            .iter()
            .position(|b| payout_is_bounded_by(used.peel(), b.peel()))
        {
            Some(pos) => {
                backing.remove(pos);
            }
            None => {
                if *credit {
                    credits_unbacked = true;
                }
                if uses
                    .iter()
                    .filter(|(u, _)| expr_eq(u.peel(), used.peel()))
                    .count()
                    > 1
                {
                    return false;
                }
            }
        }
    }
    !credits_unbacked
}

fn payout_is_bounded_by(amount: &Expr, backing: &Expr) -> bool {
    bounded_by_backing(amount, backing, false)
}

fn bounded_by_backing(amount: &Expr, backing: &Expr, wrapping: bool) -> bool {
    if expr_eq(backing, amount.peel()) {
        return true;
    }
    match amount {
        Expr::Checked { expr, .. } => bounded_by_backing(expr, backing, false),
        Expr::Wrapping { expr, .. } => bounded_by_backing(expr, backing, true),
        Expr::Binary {
            op: BinOp::Sub,
            left,
            ..
        } if !wrapping => bounded_by_backing(left, backing, wrapping),
        Expr::Binary {
            op: BinOp::Div | BinOp::Shr | BinOp::Rem,
            left,
            ..
        } => bounded_by_backing(left, backing, wrapping),
        _ => false,
    }
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
    if assets
        .iter()
        .any(|a| asset_merged_into(model, entry, a).is_none())
    {
        return false;
    }
    let backed_scalars = asset_backed_scalars(model, entry);
    let mut scalar_backer: HashMap<String, String> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op: AssignOp::Set,
            value,
            ..
        } = stmt
        {
            if backed_scalars.contains(id.text.as_str()) {
                if let Some(param) = asset_amount_backer(value, &assets) {
                    scalar_backer.insert(id.text.clone(), param.to_string());
                }
            }
        }
    }
    let mut used: HashSet<String> = HashSet::new();
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
                            let backer = args.get(1).and_then(|v| {
                                asset_amount_backer(v.peel(), &assets)
                                    .map(str::to_string)
                                    .or_else(|| match v.peel() {
                                        Expr::Ident(id) => scalar_backer.get(&id.text).cloned(),
                                        _ => None,
                                    })
                            });
                            let paid = backer.is_some_and(|b| used.insert(b));
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
    let is_slot_call = |e: &Expr, methods: &[&str]| -> bool {
        if let Expr::Call { callee, args, .. } = e.peel() {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if methods.contains(&name.text.as_str()) {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == map && model.state.contains_key(m.text.as_str()) {
                            return matches!(args.first(), Some(Expr::Ident(k)) if k.text == key);
                        }
                    }
                }
            }
        }
        false
    };
    let is_slot_contains = |e: &Expr| -> bool { is_slot_call(e, &["contains", "has"]) };
    let is_slot_get = |e: &Expr| -> bool { is_slot_call(e, &["get"]) };
    let get_cmp_zero = |e: &Expr, eq: bool| -> bool {
        if let Expr::Binary {
            op, left, right, ..
        } = e.peel()
        {
            let wanted = if eq { BinOp::Eq } else { BinOp::Ne };
            if *op == wanted {
                return (is_slot_get(left) && is_zero_int(right))
                    || (is_slot_get(right) && is_zero_int(left));
            }
        }
        false
    };
    let requires_slot_empty = |e: &Expr| -> bool {
        matches!(e.peel(), Expr::Unary { op: UnaryOp::Not, expr, .. } if is_slot_contains(expr))
            || get_cmp_zero(e, true)
    };
    let denies_protective = |e: &Expr| -> bool { is_slot_contains(e) || get_cmp_zero(e, false) };
    let is_contains_eq_false = |e: &Expr| -> bool {
        matches!(e.peel(), Expr::Binary { op: BinOp::Eq, left, right, .. }
            if (is_slot_contains(left) && matches!(right.peel(), Expr::Ident(b) if b.text == "false"))
                || (is_slot_contains(right) && matches!(left.peel(), Expr::Ident(b) if b.text == "false")))
    };
    let is_get_eq_caller = |e: &Expr| -> bool {
        matches!(e.peel(), Expr::Binary { op: BinOp::Eq, left, right, .. }
            if (is_slot_get(left) && matches!(right.peel(), Expr::Caller { .. }))
                || (is_slot_get(right) && matches!(left.peel(), Expr::Caller { .. })))
    };
    let proves_empty_or_owner = |e: &Expr| -> bool {
        matches!(e.peel(), Expr::Unary { op: UnaryOp::Not, expr, .. } if is_slot_contains(expr))
            || is_contains_eq_false(e)
            || get_cmp_zero(e, true)
            || is_get_eq_caller(e)
    };
    let reads_slot = |e: &Expr, written: bool| -> bool {
        let mut hit = false;
        walk(e, &mut |x| {
            if let Expr::Call { callee, args, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if matches!(name.text.as_str(), "get" | "contains" | "has") {
                            if let Some(k @ Expr::Ident(kid)) = args.first() {
                                let hits = if written {
                                    m.text == map
                                } else {
                                    m.text != map
                                        && model.state.contains_key(m.text.as_str())
                                        && entry_writes_field_under_key(entry, m.text.as_str(), k)
                                };
                                if hits && kid.text == key {
                                    hit = true;
                                }
                            }
                        }
                    }
                }
            }
        });
        hit
    };
    let guard_clears = |e: &Expr| -> bool {
        if proves_empty_or_owner(e) {
            return true;
        }
        if reads_slot(e, true) {
            return false;
        }
        reads_slot(e, false)
    };
    let mut conditioned = false;
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts = Vec::new();
            split_and(expr, &mut parts);
            if parts
                .iter()
                .any(|part| holds_in_every_branch(part, &guard_clears))
            {
                conditioned = true;
            }
        }
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => {
                let mut parts = Vec::new();
                split_and(expr, &mut parts);
                if parts
                    .iter()
                    .any(|part| holds_in_every_branch(part, &requires_slot_empty))
                {
                    conditioned = true;
                }
            }
            Clause::Denies { expr, .. } => {
                if denies_protective(expr) {
                    conditioned = true;
                }
            }
            _ => {}
        }
    }
    if conditioned {
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
        let (reads_of, sub_locals) = local_seize_taint(entry);
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
                                let self_decrement = m.text == field
                                    && matches!(name.text.as_str(), "set" | "insert")
                                    && args.get(1).is_some_and(|v| {
                                        expr_reads_map(field, v, &reads_of)
                                            && expr_has_sub(v, &sub_locals)
                                    });
                                if (m.text == field && name.text == "debit")
                                    || self_decrement
                                    || (matches!(
                                        name.text.as_str(),
                                        "credit" | "debit" | "set" | "insert"
                                    ) && m.text != field
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
    let required = required_conditions(entry);
    let mut parts: Vec<&Expr> = Vec::new();
    for expr in &required {
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
    for (idx, stmt) in entry.body.iter().enumerate() {
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
                                return;
                            }
                            if let Some(key) = args.first() {
                                if !empty_slot_key_stable(entry, field, key, idx) {
                                    all_proven = false;
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    saw && all_proven
}

fn guard_part_proves_empty(field: &str, key: &Expr, e: &Expr) -> bool {
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
                        if m == field && expr_eq(k, key) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
            ..
        } => any_map_contains(expr).is_some_and(|(m, k)| m == field && expr_eq(k, key)),
        _ => false,
    }
}

fn empty_slot_key_stable(entry: &EntryDecl, field: &str, key: &Expr, write_idx: usize) -> bool {
    let mut idents: HashSet<String> = HashSet::new();
    walk(key, &mut |x| {
        if let Expr::Ident(id) = x {
            idents.insert(id.text.clone());
        }
    });
    let mut last_reassign: Option<usize> = None;
    for (i, stmt) in entry.body.iter().enumerate() {
        if i >= write_idx {
            break;
        }
        if let Stmt::Assign {
            target: Expr::Ident(id),
            ..
        } = stmt
        {
            if idents.contains(id.text.as_str()) {
                last_reassign = Some(i);
            }
        }
    }
    let Some(reassign) = last_reassign else {
        return true;
    };
    for (i, stmt) in entry.body.iter().enumerate() {
        if i <= reassign {
            continue;
        }
        if i >= write_idx {
            break;
        }
        if let Stmt::Guard { expr, .. } = stmt {
            let mut parts: Vec<&Expr> = Vec::new();
            split_and(expr, &mut parts);
            if parts.iter().any(|p| guard_part_proves_empty(field, key, p)) {
                return true;
            }
        }
    }
    false
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

pub(crate) fn entry_has_write_authority(model: &Model, entry: &EntryDecl) -> bool {
    let signed: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.signed_by.is_some())
        .map(|p| p.name.text.as_str())
        .collect();
    if !signed.is_empty() || entry.params.iter().any(is_quorum_param) {
        return true;
    }
    entry_binds_caller(model, entry, &signed)
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
    let caller_chosen: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| {
            p.signed_by.is_none() && !crate::model::is_asset_param(p) && !is_quorum_param(p)
        })
        .map(|p| p.name.text.as_str())
        .collect();
    let mut floor_lets: HashMap<String, Expr> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let resolved = resolve_locals(value, &floor_lets, 0);
            floor_lets.insert(name.text.clone(), resolved);
        }
    }
    let real_bound = |b: &Expr| match resolve_locals(b, &floor_lets, 0).peel() {
        Expr::Int(n) => n
            .text
            .replace('_', "")
            .parse::<u128>()
            .map(|v| v >= 1)
            .unwrap_or(false),
        Expr::Ident(id) => !caller_chosen.contains(id.text.as_str()),
        _ => true,
    };
    let mut conjuncts: Vec<&Expr> = Vec::new();
    for expr in exprs {
        collect_conjuncts(expr, &mut conjuncts);
    }
    for e in conjuncts {
        if let Expr::Binary {
            op, left, right, ..
        } = e.peel()
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
    }
    required
}

fn entry_guards_on_holding(model: &Model, entry: &EntryDecl, field: &str) -> bool {
    let required = required_conditions(entry);
    let mut holds = false;
    let mut conjuncts: Vec<&Expr> = Vec::new();
    for expr in &required {
        collect_conjuncts(expr, &mut conjuncts);
    }
    for e in conjuncts {
        if let Expr::Binary {
            op: BinOp::Eq,
            left,
            right,
            ..
        } = e.peel()
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
        let mut top = |e: &Expr| {
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
        };
        top(expr.peel());
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
        for g in guards.iter().flat_map(|g| firm_conjuncts(g)) {
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

fn entry_spends_its_own_row(entry: &EntryDecl, field: &str) -> bool {
    let mut saw = false;
    let mut all_backed = true;
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
    for g in guards.iter().flat_map(|g| firm_conjuncts(g)) {
        walk(g, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == field && name.text == "get" {
                            if let Some(k) = args.first() {
                                saw = true;
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
    saw && all_backed
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
                            && args.get(1).is_some_and(|amt| !folds_to_zero(amt))
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

fn entry_gates_on_row(entry: &EntryDecl, map: &str, key: &Expr) -> bool {
    let reads_row = |e: &Expr| {
        let mut found = false;
        walk(e, &mut |x| {
            if let Expr::Call { callee, args, .. } = x {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                        && name.text == "get"
                        && args.first().is_some_and(|a| expr_eq(a, key))
                    {
                        found = true;
                    }
                }
            }
        });
        found
    };
    entry.clauses.iter().any(|c| {
        matches!(c, Clause::Limits { expr, .. } | Clause::Denies { expr, .. } if reads_row(expr))
    }) || entry
        .body
        .iter()
        .any(|s| matches!(s, Stmt::Guard { expr, .. } if reads_row(expr)))
}

fn entry_debits_the_row_it_gated_on(entry: &EntryDecl, field: &str, key: &Expr) -> bool {
    let mut debited = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if args.is_empty() || !expr_eq(&args[0], key) {
                            return;
                        }
                        // The row at the gated key is spent in this entry — debited, removed, or
                        // cleared to zero — so a caller cannot replay the gate to drain again.
                        // The spend may be on the gated map itself or, in a consume-and-forward
                        // state machine, on another map keyed by the same gated key (e.g. a
                        // `payout.remove(id)` that retires a proposal gated by `votes.get(id)`).
                        let same_map = m.text == field;
                        let linked = same_map || entry_gates_on_row(entry, &m.text, key);
                        match name.text.as_str() {
                            "debit" if linked && args.len() >= 2 => debited = true,
                            "remove" if linked => debited = true,
                            "set" if same_map && args.len() >= 2 && is_zero_int(&args[1]) => {
                                debited = true
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }
    debited
}

fn required_conditions(entry: &EntryDecl) -> Vec<Expr> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => out.push(expr.clone()),
            Clause::Denies { expr, .. } => out.extend(negated(expr)),
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            out.push(expr.clone());
        }
    }
    out
}

fn negated(expr: &Expr) -> Vec<Expr> {
    match expr {
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
            ..
        } => vec![expr.as_ref().clone()],
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => {
            let mut out = negated(left);
            out.extend(negated(right));
            out
        }
        Expr::Binary {
            op,
            left,
            right,
            span,
        } => {
            let flipped = match op {
                BinOp::Eq => BinOp::Ne,
                BinOp::Ne => BinOp::Eq,
                BinOp::Lt => BinOp::Ge,
                BinOp::Ge => BinOp::Lt,
                BinOp::Gt => BinOp::Le,
                BinOp::Le => BinOp::Gt,
                _ => return Vec::new(),
            };
            vec![Expr::Binary {
                op: flipped,
                left: left.clone(),
                right: right.clone(),
                span: *span,
            }]
        }
        _ => Vec::new(),
    }
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

fn holds_in_every_branch(e: &Expr, pred: &impl Fn(&Expr) -> bool) -> bool {
    match e.peel() {
        Expr::Binary {
            op: BinOp::Or,
            left,
            right,
            ..
        } => holds_in_every_branch(left, pred) && holds_in_every_branch(right, pred),
        other => pred(other),
    }
}

fn firm_conjuncts(expr: &Expr) -> Vec<&Expr> {
    let mut parts = Vec::new();
    split_and(expr, &mut parts);
    parts.retain(|part| {
        let mut disjunctive = false;
        walk(part, &mut |x| {
            if matches!(x, Expr::Binary { op: BinOp::Or, .. }) {
                disjunctive = true;
            }
        });
        !disjunctive
    });
    parts
}

fn collect_conjuncts<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e.peel() {
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
    let mut holds_inflow: HashMap<String, String> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();
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
                            let budget = args.get(1).and_then(|v| {
                                asset_amount_backer(v, &assets)
                                    .map(str::to_string)
                                    .or_else(|| match v {
                                        Expr::Ident(id)
                                            if backed_scalars.contains(id.text.as_str()) =>
                                        {
                                            Some(
                                                holds_inflow
                                                    .get(&id.text)
                                                    .cloned()
                                                    .unwrap_or_else(|| id.text.clone()),
                                            )
                                        }
                                        _ => None,
                                    })
                            });
                            if !budget.is_some_and(|b| used.insert(b)) {
                                all_paid = false;
                            }
                        }
                    }
                }
            }
        });
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op: AssignOp::Set,
            value,
            ..
        } = stmt
        {
            match asset_amount_backer(value, &assets) {
                Some(param) => {
                    holds_inflow.insert(id.text.clone(), param.to_string());
                }
                None => {
                    holds_inflow.remove(&id.text);
                }
            }
        }
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
                        if matches!(name.text.as_str(), "set" | "insert")
                            || (name.text == "credit"
                                && !args
                                    .get(1)
                                    .is_some_and(|v| asset_amount_backer(v, &assets).is_some()))
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

fn is_zero_literal(e: &Expr) -> bool {
    matches!(e.peel(), Expr::Int(i)
        if i.text.trim_start_matches('_').chars().all(|c| c == '0' || c == '_'))
}

fn entry_consumes_entitlement(entry: &EntryDecl, map: &str, key: &Expr) -> bool {
    let mut consumed = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if let Expr::Ident(m) = base.as_ref() {
                        if m.text == map
                            && args.first().is_some_and(|k| expr_eq(k.peel(), key.peel()))
                        {
                            let zeroed =
                                name.text == "set" && args.get(1).is_some_and(is_zero_literal);
                            if name.text == "remove" || name.text == "debit" || zeroed {
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

fn pays_unconsumed_entitlement(model: &Model, entry: &EntryDecl) -> bool {
    let mut lets: HashMap<String, Expr> = HashMap::new();
    let mut amounts: Vec<Expr> = Vec::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            let resolved = resolve_locals(value, &lets, 0);
            lets.insert(name.text.clone(), resolved);
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                match callee.as_ref() {
                    Expr::Field { name, .. } if name.text == "split" => {
                        if let Some(a) = args.first() {
                            amounts.push(resolve_locals(a, &lets, 0));
                        }
                    }
                    Expr::Ident(id) if id.text == "send_asset" || id.text == "send" => {
                        let idx = if id.text == "send_asset" { 2 } else { 1 };
                        if let Some(a) = args.get(idx) {
                            amounts.push(resolve_locals(a, &lets, 0));
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    for amt in &amounts {
        let mut unconsumed = false;
        walk(amt, &mut |e| {
            if unconsumed {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "get" {
                        if let Expr::Ident(m) = base.as_ref() {
                            if let Some(k) = args.first() {
                                if model.state.contains_key(m.text.as_str())
                                    && is_addr_keyed(model, m.text.as_str())
                                    && is_caller(k)
                                    && !entry_consumes_entitlement(entry, m.text.as_str(), k)
                                {
                                    unconsumed = true;
                                }
                            }
                        }
                    }
                }
            }
        });
        if unconsumed {
            return true;
        }
    }
    false
}

fn trusted_read_key(model: &Model, entry: &EntryDecl, amount: &Expr) -> Option<Expr> {
    if let Expr::Ident(id) = amount {
        for stmt in &entry.body {
            if let Stmt::Let { name, value, .. } = stmt {
                if name.text == id.text {
                    return trusted_read_key(model, entry, value);
                }
            }
        }
        return None;
    }
    let Expr::Call { callee, args, .. } = amount else {
        return None;
    };
    let Expr::Field { base, name, .. } = callee.as_ref() else {
        return None;
    };
    if name.text == "split" {
        return args
            .first()
            .and_then(|inner| trusted_read_key(model, entry, inner));
    }
    if name.text != "get" {
        return None;
    }
    let Expr::Ident(m) = base.as_ref() else {
        return None;
    };
    if model.state.contains_key(m.text.as_str())
        && is_addr_keyed(model, m.text.as_str())
        && authority_anchor_protected(model, m.text.as_str())
        && !caller_sets_their_own_row(model, m.text.as_str())
        && entry_consumes_the_row(entry, m.text.as_str())
    {
        return args.first().cloned();
    }
    None
}

fn caller_paid_from_foreign_row(model: &Model, entry: &EntryDecl) -> bool {
    let mut hit = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if hit {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                let recipient_amount = match callee.as_ref() {
                    Expr::Ident(id) if id.text == "send" => args.first().zip(args.get(1)),
                    Expr::Ident(id) if id.text == "send_asset" => args.get(1).zip(args.get(2)),
                    _ => None,
                };
                if let Some((recipient, amount)) = recipient_amount {
                    if is_caller(recipient) {
                        if let Some(key) = trusted_read_key(model, entry, amount) {
                            if !is_caller(&key) {
                                hit = true;
                            }
                        }
                    }
                }
            }
        });
        if hit {
            return true;
        }
    }
    false
}

fn split_arg(expr: &Expr) -> Option<&Expr> {
    if let Expr::Call { callee, args, .. } = expr {
        if let Expr::Field { name, .. } = callee.as_ref() {
            if name.text == "split" {
                return args.first();
            }
        }
    }
    None
}

fn backing_amount_rewritten_before_payout(model: &Model, entry: &EntryDecl) -> bool {
    let mut debits: Vec<(usize, Expr)> = Vec::new();
    let mut payouts: Vec<(usize, Expr)> = Vec::new();
    for (idx, stmt) in entry.body.iter().enumerate() {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "debit"
                        && matches!(base.as_ref(), Expr::Ident(_))
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                    {
                        if let Some(amt) = args.get(1) {
                            debits.push((idx, amt.clone()));
                        }
                    }
                }
                match callee.as_ref() {
                    Expr::Ident(id) if id.text == "send" => {
                        if let Some(a) = args.get(1).and_then(split_arg) {
                            payouts.push((idx, a.clone()));
                        }
                    }
                    Expr::Ident(id) if id.text == "send_asset" => {
                        if let Some(v) = args.get(2) {
                            payouts.push((idx, split_arg(v).unwrap_or(v).clone()));
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    for (pidx, amt) in &payouts {
        let mut states: HashSet<String> = HashSet::new();
        walk(amt, &mut |e| {
            if let Expr::Ident(id) = e {
                if model.state.contains_key(id.text.as_str()) {
                    states.insert(id.text.clone());
                }
            }
        });
        if states.is_empty() {
            continue;
        }
        for (didx, damt) in &debits {
            if didx >= pidx || !expr_eq(damt.peel(), amt.peel()) {
                continue;
            }
            for (i, stmt) in entry.body.iter().enumerate() {
                if i <= *didx || i >= *pidx {
                    continue;
                }
                if let Stmt::Assign {
                    target: Expr::Ident(t),
                    ..
                } = stmt
                {
                    if states.contains(t.text.as_str()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn payout_issuer_rewritten_before_send(model: &Model, entry: &EntryDecl) -> bool {
    let mut sends: Vec<(usize, String)> = Vec::new();
    for (idx, stmt) in entry.body.iter().enumerate() {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send_asset") {
                    if let Some(Expr::Ident(issuer)) = args.first() {
                        if model.state.contains_key(issuer.text.as_str()) {
                            sends.push((idx, issuer.text.clone()));
                        }
                    }
                }
            }
        });
    }
    for (sidx, issuer) in &sends {
        for (i, stmt) in entry.body.iter().enumerate() {
            if i >= *sidx {
                break;
            }
            if let Stmt::Assign {
                target: Expr::Ident(t),
                ..
            } = stmt
            {
                if t.text == *issuer {
                    return true;
                }
            }
        }
    }
    false
}

fn native_payout_backed_by_custom_ledger(model: &Model, entry: &EntryDecl) -> bool {
    let mut aliases: HashMap<String, Expr> = HashMap::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                let resolved = resolve_locals(value, &aliases, 0);
                aliases.insert(name.text.clone(), resolved);
            }
            Stmt::Assign {
                target: Expr::Ident(id),
                op: AssignOp::Set,
                value,
                ..
            } => {
                let resolved = resolve_locals(value, &aliases, 0);
                aliases.insert(id.text.clone(), resolved);
            }
            _ => {}
        }
    }
    let mut custom_amounts: Vec<Expr> = Vec::new();
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "debit" && matches!(args.first(), Some(Expr::Caller { .. })) {
                        if let Expr::Ident(map) = base.as_ref() {
                            if ledger_funding_tokens(model, map.text.as_str())
                                .iter()
                                .any(|t| t != "native")
                            {
                                if let Some(amt) = args.get(1) {
                                    let resolved = resolve_locals(amt, &aliases, 0);
                                    custom_amounts.push(strip_value_noops(&resolved).clone());
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    if custom_amounts.is_empty() {
        return false;
    }
    let mut hit = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if hit {
                return;
            }
            if let Expr::Call { callee, args, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") {
                    if let Some(val) = args.get(1) {
                        let resolved_val = resolve_locals(val, &aliases, 0);
                        if let Some(amt) = split_arg(&resolved_val) {
                            let resolved_amt = resolve_locals(amt, &aliases, 0);
                            let amt = strip_value_noops(&resolved_amt);
                            if custom_amounts
                                .iter()
                                .any(|d| bounded_by_backing(amt, d, false))
                            {
                                hit = true;
                            }
                        }
                    }
                }
            }
        });
    }
    hit
}

fn entitlement_map_is_authority_written(model: &Model, map: &str) -> bool {
    let signed: HashSet<&str> = HashSet::new();
    for entry in &model.entries {
        let mut creates = false;
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if let Expr::Ident(m) = base.as_ref() {
                            if m.text == map {
                                let zeroing =
                                    name.text == "set" && args.get(1).is_some_and(is_zero_literal);
                                if (matches!(name.text.as_str(), "insert" | "credit")
                                    || name.text == "set")
                                    && !zeroing
                                {
                                    creates = true;
                                }
                            }
                        }
                    }
                }
            });
        }
        if creates && !entry_binds_caller(model, entry, &signed) {
            return false;
        }
    }
    true
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
                        && !(name.text == "set" && args.get(1).is_some_and(is_zero_literal))
                    {
                        saw = true;
                        let consumed = args.get(1).is_some_and(|v| {
                            let (map, key) = match v.peel() {
                                Expr::Call {
                                    callee,
                                    args: getargs,
                                    ..
                                } => match callee.as_ref() {
                                    Expr::Field { base, name, .. } if name.text == "get" => {
                                        match (base.as_ref(), getargs.first()) {
                                            (Expr::Ident(m), Some(k))
                                                if model.state.contains_key(m.text.as_str()) =>
                                            {
                                                (m.text.as_str(), k)
                                            }
                                            _ => return false,
                                        }
                                    }
                                    _ => return false,
                                },
                                _ => return false,
                            };
                            if !entitlement_map_is_authority_written(model, map) {
                                return false;
                            }
                            let recipient_bound_to_key = args.first().is_some_and(|r| {
                                if expr_eq(r.peel(), key.peel()) {
                                    return true;
                                }
                                if let Expr::Call {
                                    callee,
                                    args: rargs,
                                    ..
                                } = r.peel()
                                {
                                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                                        if name.text == "get" {
                                            if let Expr::Ident(rmap) = base.as_ref() {
                                                return rargs.first().is_some_and(|rk| {
                                                    expr_eq(rk.peel(), key.peel())
                                                }) && entitlement_map_is_authority_written(
                                                    model,
                                                    rmap.text.as_str(),
                                                );
                                            }
                                        }
                                    }
                                }
                                false
                            });
                            if !recipient_bound_to_key {
                                return false;
                            }
                            if !entry_consumes_entitlement(entry, map, key) {
                                return false;
                            }
                            match drawn.iter().position(|d| expr_eq(d, v)) {
                                Some(pos) => {
                                    drawn.remove(pos);
                                    true
                                }
                                None => false,
                            }
                        });
                        if !consumed {
                            all_drawn = false;
                        }
                    }
                }
            }
        });
    }
    saw && all_drawn
}

fn credits_field_drawn_from_an_inflow_only_total(
    model: &Model,
    entry: &EntryDecl,
    field: &str,
) -> bool {
    credits_drawn_from_an_inflow_only_total(model, entry)
        && field_is_written_only_by_credits(entry, field)
}

fn field_is_written_only_by_credits(entry: &EntryDecl, field: &str) -> bool {
    let mut credited = false;
    let mut other_write = false;
    for stmt in &entry.body {
        if let Stmt::Assign { target, .. } = stmt {
            if root_ident(target) == Some(field) {
                other_write = true;
            }
        }
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(id) if id.text == field) {
                        match name.text.as_str() {
                            "credit" | "set" | "insert" => credited = true,
                            "debit" | "remove" | "clear" | "merge" | "split" => other_write = true,
                            _ => {}
                        }
                    }
                }
            }
        });
    }
    credited && !other_write
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

fn is_addr_valued_scalar(model: &Model, ident: &str) -> bool {
    model
        .state
        .get(ident)
        .is_some_and(|f| f.ty.name.text == "Q_Address")
}

fn entry_reassigns_authority_scalar(model: &Model, entry: &EntryDecl) -> bool {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let empty: HashSet<&str> = HashSet::new();
    let derived = param_derived_locals(entry, &params, &empty);
    let parked = tainted_state_fields(entry, &params, &empty, &derived);
    let handed = |value: &Expr| {
        root_ident(value)
            .is_some_and(|r| params.contains(r) || derived.contains(r) || parked.contains(r))
    };
    for stmt in &entry.body {
        if let Stmt::Assign {
            target,
            value,
            op: AssignOp::Set,
            ..
        } = stmt
        {
            if let Expr::Ident(id) = target {
                if is_addr_valued_scalar(model, id.text.as_str()) && handed(value) {
                    return true;
                }
            }
        }
    }
    false
}

fn forged_caller_anchor(
    model: &Model,
    entry: &EntryDecl,
    signed: &HashSet<&str>,
) -> Option<TypeError> {
    if (!entry_moves_value(model, entry) && !entry_reassigns_authority_scalar(model, entry))
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
    strict_memo: HashMap<String, bool>,
    steps: u64,
    time_anchor: bool,
    target_field: Option<String>,
    strict: bool,
}

const COMPILE_STEP_BUDGET: u64 = 2_000_000;

pub(crate) fn authority_anchor_protected(model: &Model, field: &str) -> bool {
    protected_as(model, field, false)
}

pub(crate) fn time_anchor_protected(model: &Model, field: &str) -> bool {
    protected_as(model, field, true)
}

fn protected_as(model: &Model, field: &str, time_anchor: bool) -> bool {
    let key = if time_anchor {
        format!("time anchor {field}")
    } else {
        field.to_string()
    };
    if let Some(&known) = model.protection.borrow().get(&key) {
        return known;
    }
    if model.protection_steps.get() > COMPILE_STEP_BUDGET {
        return false;
    }
    if !model.protecting.borrow_mut().insert(key.clone()) {
        return false;
    }
    let mut prot = Prot {
        stack: HashSet::new(),
        memo: HashMap::new(),
        strict_memo: HashMap::new(),
        steps: 0,
        time_anchor,
        target_field: None,
        strict: false,
    };
    let protected = anchor_protected(model, field, &mut prot).0;
    model.protecting.borrow_mut().remove(&key);
    model
        .protection_steps
        .set(model.protection_steps.get().saturating_add(prot.steps));
    model.protection.borrow_mut().insert(key, protected);
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
    if let Some(&resolved) = mode_memo(prot).get(field) {
        return (resolved, false);
    }
    if prot.stack.contains(field) {
        if prot.strict {
            return (field_rooted_at_genesis(model, field), false);
        }
        return (true, true);
    }
    prot.stack.insert(field.to_string());
    let saved_target = prot.target_field.replace(field.to_string());
    let mut protected = true;
    let mut tainted = false;
    for entry in &model.entries {
        if entry_writes_field(entry, field) {
            if prot.time_anchor {
                let (authorized, sub_tainted) = writer_authorized(model, entry, prot);
                if !authorized || copies_an_unprotected_field(model, entry, field, prot) {
                    protected = false;
                    break;
                }
                tainted |= sub_tainted;
                continue;
            }
            if !prot.strict
                && writes_field_only_under_the_caller_key(entry, field)
                && credits_caller_only_by_the_paid_amount(model, entry, field, prot)
            {
                continue;
            }
            if !prot.strict && writes_field_only_into_an_empty_slot(model, entry, field) {
                continue;
            }
            if credits_only_what_was_paid_in(model, entry, field) {
                continue;
            }
            if credits_field_drawn_from_an_inflow_only_total(model, entry, field) {
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
    prot.target_field = saved_target;
    if !protected {
        mode_memo(prot).insert(field.to_string(), false);
        return (false, false);
    }
    if !tainted {
        mode_memo(prot).insert(field.to_string(), true);
    }
    (true, tainted)
}

fn mode_memo(prot: &mut Prot) -> &mut HashMap<String, bool> {
    if prot.strict {
        &mut prot.strict_memo
    } else {
        &mut prot.memo
    }
}

fn field_rooted_at_genesis(model: &Model, field: &str) -> bool {
    for item in &model.contract.items {
        if let quanta_ast::Item::Genesis(g) = item {
            for stmt in &g.body {
                if let Stmt::Assign { target, .. } = stmt {
                    if root_ident(target) == Some(field) {
                        return true;
                    }
                }
                let mut seeded = false;
                stmt_exprs(stmt, &mut |e| {
                    if let Expr::Call { callee, .. } = e {
                        if let Expr::Field { base, name, .. } = callee.as_ref() {
                            if matches!(name.text.as_str(), "set" | "credit" | "insert")
                                && matches!(base.as_ref(), Expr::Ident(id) if id.text == field)
                            {
                                seeded = true;
                            }
                        }
                    }
                });
                if seeded {
                    return true;
                }
            }
        }
    }
    false
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

fn entry_spends_caller_row(entry: &EntryDecl, map: &str) -> bool {
    let mut spent = false;
    for stmt in &entry.body {
        stmt_exprs(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(base.as_ref(), Expr::Ident(m) if m.text == map)
                        && matches!(args.first(), Some(Expr::Caller { .. }))
                    {
                        match name.text.as_str() {
                            "debit" if args.len() >= 2 && !folds_to_zero(&args[1]) => spent = true,
                            "remove" => spent = true,
                            _ => {}
                        }
                    }
                }
            }
        });
    }
    spent
}

fn field_is_authority_address(model: &Model, field: &str) -> bool {
    model
        .state
        .get(field)
        .is_some_and(|f| f.ty.name.text == "Q_Address")
        || is_addr_valued(model, field)
}

fn deposit_gate_cannot_authorize(
    model: &Model,
    entry: &EntryDecl,
    guard: &Expr,
    target: Option<&str>,
) -> bool {
    let Some(a) = anchor_of(model, guard).or_else(|| anchor_of_denied(model, guard)) else {
        return false;
    };
    if !map_is_deposit_backed_pool(model, a, None) {
        return false;
    }
    if target.is_some_and(|t| field_is_authority_address(model, t)) {
        return true;
    }
    !entry_spends_caller_row(entry, a)
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
                if authorized
                    && !deposit_gate_cannot_authorize(
                        model,
                        entry,
                        expr,
                        prot.target_field.as_deref(),
                    )
                {
                    return (true, tainted);
                }
            }
            Clause::Denies { expr, .. } => {
                let (authorized, tainted) = gate_necessary_denied_protected(model, expr, prot);
                if authorized
                    && !deposit_gate_cannot_authorize(
                        model,
                        entry,
                        expr,
                        prot.target_field.as_deref(),
                    )
                {
                    return (true, tainted);
                }
            }
            _ => {}
        }
    }
    let mut assigned_before: HashSet<&str> = HashSet::new();
    let mut lets: HashMap<String, Expr> = HashMap::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { expr, .. } => {
                if !guard_reads_assigned(expr, &assigned_before) {
                    let (authorized, tainted) = gate_necessary_protected(model, expr, prot);
                    if authorized
                        && !deposit_gate_cannot_authorize(
                            model,
                            entry,
                            expr,
                            prot.target_field.as_deref(),
                        )
                    {
                        return (true, tainted);
                    }
                }
            }
            Stmt::Let { name, value, .. } => {
                let resolved = resolve_locals(value, &lets, 0);
                lets.insert(name.text.clone(), resolved);
            }
            Stmt::Assign { target, .. } => {
                if let Some(f) = root_ident(target) {
                    assigned_before.insert(f);
                }
            }
            Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } => {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "set" | "credit" | "insert") {
                        if let Expr::Ident(m) = base.as_ref() {
                            let row_holds_protected_field = args.get(1).is_some_and(|v| {
                                matches!(resolve_locals(v, &lets, 0), Expr::Ident(id) if model.state.contains_key(id.text.as_str()))
                            });
                            if !row_holds_protected_field {
                                assigned_before.insert(m.text.as_str());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (false, false)
}

fn guard_reads_assigned(expr: &Expr, assigned: &HashSet<&str>) -> bool {
    let mut hit = false;
    walk(expr, &mut |e| {
        if let Expr::Ident(id) = e {
            if assigned.contains(id.text.as_str()) {
                hit = true;
            }
        }
    });
    hit
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
            Some(a) => anchor_protected_for_gate(model, a, prot),
            None => (false, false),
        },
    }
}

fn anchor_protected_for_gate(model: &Model, anchor: &str, prot: &mut Prot) -> (bool, bool) {
    let cross = prot.strict || prot.target_field.as_deref() != Some(anchor);
    if !cross {
        return anchor_protected(model, anchor, prot);
    }
    let saved = prot.strict;
    prot.strict = true;
    let result = anchor_protected(model, anchor, prot);
    prot.strict = saved;
    result
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
            Some(a) => anchor_protected_for_gate(model, a, prot),
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
    if entry_binds_caller(model, entry, signed) {
        return None;
    }
    if !entry_moves_value(model, entry) {
        return forged_lookup_permission(model, entry, params, signed, derived);
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
    let mut locals: HashMap<&str, &Expr> = HashMap::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                locals.insert(name.text.as_str(), value);
            }
            Stmt::Guard { expr, .. } => {
                let inlined = inline_locals(expr, &locals, 0);
                if let Some((field, span)) = gate_expr(&inlined) {
                    return Some(map_authority_error(&field, span));
                }
            }
            _ => {}
        }
    }
    None
}

fn entry_writes_any_state(model: &Model, entry: &EntryDecl) -> bool {
    model
        .state
        .keys()
        .any(|field| entry_writes_field(entry, field))
}

fn forged_lookup_permission(
    model: &Model,
    entry: &EntryDecl,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
) -> Option<TypeError> {
    if !entry_writes_any_state(model, entry) {
        return None;
    }
    let scan = PermissionScan {
        model,
        params,
        signed,
        derived,
    };
    for clause in &entry.clauses {
        let found = match clause {
            Clause::Limits { expr, .. } => scan.find(expr, true),
            Clause::Denies { expr, .. } => scan.find(expr, false),
            _ => None,
        };
        if let Some((field, span)) = found {
            return Some(permission_lookup_error(&field, span));
        }
    }
    let mut locals: HashMap<&str, &Expr> = HashMap::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                locals.insert(name.text.as_str(), value);
            }
            Stmt::Guard { expr, .. } => {
                let inlined = inline_locals(expr, &locals, 0);
                if let Some((field, span)) = scan.find(&inlined, true) {
                    return Some(permission_lookup_error(&field, span));
                }
            }
            _ => {}
        }
    }
    None
}

fn inline_locals(expr: &Expr, locals: &HashMap<&str, &Expr>, depth: usize) -> Expr {
    if depth > 16 {
        return expr.clone();
    }
    match expr {
        Expr::Ident(id) => match locals.get(id.text.as_str()) {
            Some(value) => inline_locals(value, locals, depth + 1),
            None => expr.clone(),
        },
        Expr::Unary {
            op,
            expr: inner,
            span,
        } => Expr::Unary {
            op: *op,
            expr: Box::new(inline_locals(inner, locals, depth)),
            span: *span,
        },
        Expr::Binary {
            op,
            left,
            right,
            span,
        } => Expr::Binary {
            op: *op,
            left: Box::new(inline_locals(left, locals, depth)),
            right: Box::new(inline_locals(right, locals, depth)),
            span: *span,
        },
        Expr::Field { base, name, span } => Expr::Field {
            base: Box::new(inline_locals(base, locals, depth)),
            name: name.clone(),
            span: *span,
        },
        Expr::Call { callee, args, span } => Expr::Call {
            callee: Box::new(inline_locals(callee, locals, depth)),
            args: args
                .iter()
                .map(|a| inline_locals(a, locals, depth))
                .collect(),
            span: *span,
        },
        Expr::Checked { expr: inner, span } => Expr::Checked {
            expr: Box::new(inline_locals(inner, locals, depth)),
            span: *span,
        },
        Expr::Wrapping { expr: inner, span } => Expr::Wrapping {
            expr: Box::new(inline_locals(inner, locals, depth)),
            span: *span,
        },
        _ => expr.clone(),
    }
}

struct PermissionScan<'m, 'a> {
    model: &'m Model<'a>,
    params: &'m HashSet<&'m str>,
    signed: &'m HashSet<&'m str>,
    derived: &'m HashSet<String>,
}

impl PermissionScan<'_, '_> {
    fn lookup(&self, expr: &Expr) -> Option<(String, Span)> {
        let Expr::Call { callee, args, span } = expr.peel() else {
            return None;
        };
        let Expr::Field { base, name, .. } = callee.as_ref() else {
            return None;
        };
        if !matches!(name.text.as_str(), "contains" | "get" | "has") {
            return None;
        }
        let Expr::Ident(map_id) = base.as_ref() else {
            return None;
        };
        let map = map_id.text.as_str();
        if !is_lookup_keyed(self.model, map) || !authority_anchor_protected(self.model, map) {
            return None;
        }
        args.iter()
            .find_map(|a| param_field(self.params, self.signed, self.derived, a))
            .map(|field| (field, *span))
    }

    fn signed_lookups(&self, expr: &Expr, sign: i8, out: &mut Vec<(String, Span, i8)>) {
        if let Some((field, span)) = self.lookup(expr) {
            out.push((field, span, sign));
            return;
        }
        match expr {
            Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
                self.signed_lookups(expr, sign, out)
            }
            Expr::Unary {
                op: UnaryOp::Neg,
                expr,
                ..
            } => self.signed_lookups(expr, -sign, out),
            Expr::Binary {
                op, left, right, ..
            } => {
                let right_sign = match op {
                    BinOp::Add | BinOp::Mul => sign,
                    BinOp::Sub | BinOp::Div | BinOp::Shr => -sign,
                    _ => 0,
                };
                let left_sign = match op {
                    BinOp::Add | BinOp::Mul | BinOp::Sub | BinOp::Div | BinOp::Shr => sign,
                    _ => 0,
                };
                self.signed_lookups(left, left_sign, out);
                self.signed_lookups(right, right_sign, out);
            }
            _ => {}
        }
    }

    fn find(&self, expr: &Expr, holds: bool) -> Option<(String, Span)> {
        if let Some(found) = self.lookup(expr) {
            return holds.then_some(found);
        }
        match expr {
            Expr::Unary {
                op: UnaryOp::Not,
                expr,
                ..
            } => self.find(expr, !holds),
            Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => self.find(expr, holds),
            Expr::Binary {
                op: BinOp::And | BinOp::Or,
                left,
                right,
                ..
            } => self.find(left, holds).or_else(|| self.find(right, holds)),
            Expr::Binary {
                op, left, right, ..
            } => {
                let mut sides: Vec<(String, Span, i8, bool)> = Vec::new();
                let mut found = Vec::new();
                self.signed_lookups(left, 1, &mut found);
                sides.extend(found.drain(..).map(|(f, s, g)| (f, s, g, true)));
                self.signed_lookups(right, 1, &mut found);
                sides.extend(found.drain(..).map(|(f, s, g)| (f, s, g, false)));
                for (field, span, sign, on_left) in sides {
                    let direct = if on_left { left } else { right };
                    let other = if on_left { right } else { left };
                    let is_direct = self.lookup(direct).is_some();
                    let presence_helps = match op {
                        BinOp::Eq => !(is_direct && is_zero_int(other)),
                        BinOp::Ne => {
                            !(is_direct
                                && matches!(other.peel(), Expr::Int(_))
                                && !is_zero_int(other))
                        }
                        BinOp::Gt | BinOp::Ge => sign == 0 || ((sign > 0) == on_left),
                        BinOp::Lt | BinOp::Le => sign == 0 || ((sign > 0) != on_left),
                        _ => true,
                    };
                    if presence_helps == holds {
                        return Some((field, span));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

fn permission_lookup_error(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged authority: this entry writes state gated by looking up self declared parameter \
             data `{field}` in a map that only authorized entries write, so a caller passes by \
             naming any key already granted; authority must come from `caller` or a signature, \
             and a check that a key is absent is a restriction and stays allowed"
        ),
        span,
    )
}

fn is_guardian_set(model: &Model, ident: &str) -> bool {
    model
        .state
        .get(ident)
        .is_some_and(|f| f.ty.name.text == "GuardianSet")
}

fn guardian_membership_on_param(
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
                if matches!(name.text.as_str(), "contains" | "has" | "get") {
                    if let Expr::Ident(set_id) = base.as_ref() {
                        if is_guardian_set(model, set_id.text.as_str()) {
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

fn forged_guardian_authority(
    model: &Model,
    entry: &EntryDecl,
    params: &HashSet<&str>,
    signed: &HashSet<&str>,
    derived: &HashSet<String>,
) -> Option<TypeError> {
    if entry_binds_caller(model, entry, signed) {
        return None;
    }
    let gate = |expr: &Expr| guardian_membership_on_param(model, params, signed, derived, expr);
    for clause in &entry.clauses {
        if let Clause::Limits { expr, .. } | Clause::Denies { expr, .. } = clause {
            if let Some((field, span)) = gate(expr) {
                return Some(guardian_authority_error(&field, span));
            }
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if let Some((field, span)) = gate(expr) {
                return Some(guardian_authority_error(&field, span));
            }
        }
    }
    None
}

fn guardian_authority_error(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "forged authority: this entry authorises a guardian only operation by testing self \
             declared parameter data `{field}` for membership in a GuardianSet, with no `caller` \
             check or `signed by` binding; guardian authority must come from `caller` or a signature"
        ),
        span,
    )
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
    let mut scalar_backer: HashMap<&str, &str> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Assign {
            target: Expr::Ident(id),
            op: AssignOp::Set,
            value,
            ..
        } = stmt
        {
            if backed_scalars.contains(id.text.as_str()) {
                if let Some(param) = asset_amount_backer(value, &asset_params) {
                    scalar_backer.insert(id.text.as_str(), param);
                }
            }
        }
    }
    let backer_of = |value: &Expr| {
        asset_amount_backer(value, &asset_params).or_else(|| match value {
            Expr::Ident(id) => scalar_backer.get(id.text.as_str()).copied(),
            _ => None,
        })
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
                                    .and_then(&backer_of)
                                    .is_some_and(|a| used_asset_backers.insert(a));
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
                                        ) && entry_spends_its_own_row(entry, map.text.as_str());
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
    if let Expr::Field { base, name, .. } = strip_amount_identity(value) {
        if name.text == "amount" {
            if let Expr::Ident(id) = base.as_ref() {
                return asset_params.get(id.text.as_str()).copied();
            }
        }
    }
    None
}

fn strip_amount_identity(expr: &Expr) -> &Expr {
    match expr {
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            if folds_to_zero(right) {
                strip_amount_identity(left)
            } else if folds_to_zero(left) {
                strip_amount_identity(right)
            } else {
                expr
            }
        }
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        } if folds_to_zero(right) => strip_amount_identity(left),
        _ => expr.peel(),
    }
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

pub(crate) fn expr_eq(a: &Expr, b: &Expr) -> bool {
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

fn caller_binding_rests_on_first_come_slots(model: &Model, entry: &EntryDecl) -> bool {
    let mut binding = 0usize;
    let mut first_come = 0usize;
    let mut binders: Vec<&Expr> = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } if caller_necessary(model, expr) => binders.push(expr),
            Clause::Denies { expr, .. } if caller_necessary_denied(model, expr) => {
                binders.push(expr)
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if caller_necessary(model, expr) {
                binders.push(expr);
            }
        }
    }
    for expr in binders {
        binding += 1;
        let mut names_first_come = false;
        walk(expr, &mut |e| {
            if let Some(map) = map_value_addr(model, e).or_else(|| membership_map(model, e)) {
                if map_slots_are_first_come(model, map) {
                    names_first_come = true;
                }
            }
        });
        if names_first_come {
            first_come += 1;
        }
    }
    binding > 0 && binding == first_come
}

fn map_slots_are_first_come(model: &Model, map: &str) -> bool {
    model.entries.iter().any(|entry| {
        entry_writes_field(entry, map)
            && writes_field_only_into_an_empty_slot(model, entry, map)
            && !has_protected_signed_authority(model, entry)
    })
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

fn folds_to_zero(expr: &Expr) -> bool {
    if const_eval(expr) == Some(0) {
        return true;
    }
    match expr.peel() {
        Expr::Int(n) => n.text.replace('_', "").trim_start_matches('0').is_empty(),
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        } => {
            if expr_eq(left.peel(), right.peel()) || (folds_to_zero(left) && folds_to_zero(right)) {
                return true;
            }
            if let Expr::Binary {
                op: BinOp::Add,
                left: a,
                right: b,
                ..
            } = left.peel()
            {
                if expr_eq(b.peel(), right.peel()) {
                    return folds_to_zero(a);
                }
                if expr_eq(a.peel(), right.peel()) {
                    return folds_to_zero(b);
                }
            }
            false
        }
        Expr::Binary {
            op: BinOp::Rem,
            left,
            right,
            ..
        } => expr_eq(left.peel(), right.peel()) || folds_to_zero(left),
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => folds_to_zero(left) || folds_to_zero(right),
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => folds_to_zero(left) && folds_to_zero(right),
        Expr::Binary {
            op: BinOp::Div | BinOp::Shr,
            left,
            ..
        } => folds_to_zero(left),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => folds_to_zero(expr),
        _ => false,
    }
}

fn const_eval(expr: &Expr) -> Option<u128> {
    match expr.peel() {
        Expr::Int(n) => n.text.replace('_', "").parse::<u128>().ok(),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => const_eval(expr),
        Expr::Binary {
            op, left, right, ..
        } => {
            let l = const_eval(left)?;
            let r = const_eval(right)?;
            match op {
                BinOp::Add => l.checked_add(r),
                BinOp::Sub => l.checked_sub(r),
                BinOp::Mul => l.checked_mul(r),
                BinOp::Div => (r != 0).then(|| l / r),
                BinOp::Rem => (r != 0).then(|| l % r),
                BinOp::Shr => Some(if r >= 128 { 0 } else { l >> (r as u32) }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_one_literal(e: &Expr) -> bool {
    const_eval(e) == Some(1)
}

fn is_big_u64_literal(e: &Expr) -> bool {
    const_eval(e).is_some_and(|v| v >= u64::MAX as u128)
}

fn strip_value_noops(e: &Expr) -> &Expr {
    let e = e.peel();
    if let Expr::Binary {
        op, left, right, ..
    } = e
    {
        match op {
            BinOp::Add => {
                if folds_to_zero(right) {
                    return strip_value_noops(left);
                }
                if folds_to_zero(left) {
                    return strip_value_noops(right);
                }
            }
            BinOp::Sub => {
                if folds_to_zero(right) {
                    return strip_value_noops(left);
                }
                if let Expr::Binary {
                    op: BinOp::Add,
                    left: a,
                    right: b,
                    ..
                } = left.peel()
                {
                    if expr_eq(strip_value_noops(b), strip_value_noops(right)) {
                        return strip_value_noops(a);
                    }
                    if expr_eq(strip_value_noops(a), strip_value_noops(right)) {
                        return strip_value_noops(b);
                    }
                }
            }
            BinOp::Mul => {
                if is_one_literal(right) {
                    return strip_value_noops(left);
                }
                if is_one_literal(left) {
                    return strip_value_noops(right);
                }
            }
            BinOp::Div => {
                if is_one_literal(right) {
                    return strip_value_noops(left);
                }
            }
            BinOp::Shr => {
                if folds_to_zero(right) {
                    return strip_value_noops(left);
                }
            }
            BinOp::Rem => {
                if is_big_u64_literal(right) {
                    return strip_value_noops(left);
                }
            }
            _ => {}
        }
    }
    e
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
    let bound = !is_int_literal(threshold)
        && !threshold_is_caller_chosen(model, threshold)
        && (!reads_only_state(model, threshold)
            || threshold_is_provably_positive(model, threshold)
            || threshold_is_guarded_positive(model, threshold));
    match (op, lookup_left) {
        (BinOp::Ge, true) | (BinOp::Le, false) => {
            !folds_to_zero(threshold) && (is_positive_int(threshold) || bound)
        }
        (BinOp::Gt, true) | (BinOp::Lt, false) => is_nonnegative_int(threshold) || bound,
        (BinOp::Ne, _) => is_zero_int(threshold),
        (BinOp::Eq, _) => is_positive_int(threshold),
        _ => false,
    }
}

fn reads_only_state(model: &Model, expr: &Expr) -> bool {
    let mut only_state = true;
    walk(expr, &mut |e| match e {
        Expr::Ident(id) if !model.state.contains_key(id.text.as_str()) => only_state = false,
        Expr::Caller { .. } | Expr::Now { .. } | Expr::Native { .. } | Expr::InAsset { .. } => {
            only_state = false
        }
        _ => {}
    });
    only_state
}

fn threshold_is_provably_positive(model: &Model, threshold: &Expr) -> bool {
    let Expr::Ident(id) = threshold else {
        return false;
    };
    let field = id.text.as_str();
    let Some(decl) = model.state.get(field) else {
        return false;
    };
    let mut starts_positive = decl.default.as_ref().is_some_and(is_positive_int);
    for item in &model.contract.items {
        if let quanta_ast::Item::Genesis(g) = item {
            for stmt in &g.body {
                if let Stmt::Assign { target, value, .. } = stmt {
                    if root_ident(target) == Some(field) {
                        starts_positive = is_positive_int(value);
                    }
                }
            }
        }
    }
    if !starts_positive {
        return false;
    }
    let written_by_entries = model.entries.iter().any(|e| entry_writes_field(e, field));
    if !written_by_entries {
        return true;
    }
    if !authority_anchor_protected(model, field) {
        return false;
    }
    model.entries.iter().all(|entry| {
        entry.body.iter().all(|stmt| match stmt {
            Stmt::Assign {
                target, op, value, ..
            } if root_ident(target) == Some(field) => match op {
                AssignOp::Set => is_positive_int(value) || entry_guards_positive(entry, value),
                AssignOp::Add => true,
                AssignOp::Sub => false,
            },
            _ => true,
        })
    })
}

fn threshold_is_guarded_positive(model: &Model, threshold: &Expr) -> bool {
    if model.guarded_positive_thresholds.borrow().is_none() {
        let mut found: HashSet<Span> = HashSet::new();
        for entry in &model.entries {
            let mut gates: Vec<&Expr> = Vec::new();
            for clause in &entry.clauses {
                if let Clause::Limits { expr, .. } = clause {
                    gates.push(expr);
                }
            }
            for stmt in &entry.body {
                if let Stmt::Guard { expr, .. } = stmt {
                    gates.push(expr);
                }
            }
            for gate in gates.iter().flat_map(|g| firm_conjuncts(g)) {
                walk(gate, &mut |e| {
                    let Expr::Binary { left, right, .. } = e else {
                        return;
                    };
                    let candidate = if is_caller_membership(model, left) {
                        right.as_ref()
                    } else if is_caller_membership(model, right) {
                        left.as_ref()
                    } else {
                        return;
                    };
                    let reassigned = matches!(
                        candidate,
                        Expr::Ident(id) if entry_writes_field(entry, id.text.as_str())
                    );
                    if entry_guards_positive(entry, candidate) && !reassigned {
                        found.insert(candidate.span());
                    }
                });
            }
        }
        *model.guarded_positive_thresholds.borrow_mut() = Some(found);
    }
    model
        .guarded_positive_thresholds
        .borrow()
        .as_ref()
        .is_some_and(|set| set.contains(&threshold.span()))
}

fn entry_guards_positive(entry: &EntryDecl, value: &Expr) -> bool {
    entry.body.iter().any(|stmt| match stmt {
        Stmt::Guard {
            expr: Expr::Binary {
                op, left, right, ..
            },
            ..
        } => match op {
            BinOp::Gt => expr_eq(left, value) && is_nonnegative_int(right),
            BinOp::Ge => expr_eq(left, value) && is_positive_int(right),
            BinOp::Lt => expr_eq(right, value) && is_nonnegative_int(left),
            BinOp::Le => expr_eq(right, value) && is_positive_int(left),
            _ => false,
        },
        _ => false,
    })
}

fn threshold_is_caller_chosen(model: &Model, threshold: &Expr) -> bool {
    if model.caller_chosen_thresholds.borrow().is_none() {
        let found = caller_chosen_thresholds(model);
        *model.caller_chosen_thresholds.borrow_mut() = Some(found);
    }
    model
        .caller_chosen_thresholds
        .borrow()
        .as_ref()
        .is_some_and(|set| set.contains(&threshold.span()))
}

fn caller_chosen_thresholds(model: &Model) -> HashSet<Span> {
    let mut out: HashSet<Span> = HashSet::new();
    for entry in &model.entries {
        let signed: HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| p.signed_by.is_some())
            .map(|p| p.name.text.as_str())
            .collect();
        let mut spent: HashSet<String> = HashSet::new();
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, args, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(base.as_ref(), Expr::Ident(_))
                            && matches!(name.text.as_str(), "debit" | "credit")
                            && matches!(args.first(), Some(Expr::Caller { .. }))
                        {
                            if let Some(amount) = args.get(1) {
                                if !folds_to_zero(amount) {
                                    walk(amount, &mut |x| {
                                        if let Expr::Ident(id) = x {
                                            spent.insert(id.text.clone());
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            });
        }
        let mut gates: Vec<&Expr> = Vec::new();
        for clause in &entry.clauses {
            if let Clause::Limits { expr, .. } | Clause::Denies { expr, .. } = clause {
                gates.push(expr);
            }
        }
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                gates.push(expr);
            }
        }
        for gate in gates {
            walk(gate, &mut |e| {
                let Expr::Binary { left, right, .. } = e else {
                    return;
                };
                let threshold = if is_caller_membership(model, left) {
                    right.as_ref()
                } else if is_caller_membership(model, right) {
                    left.as_ref()
                } else {
                    return;
                };
                let mut chosen = false;
                walk(threshold, &mut |x| {
                    if let Expr::Ident(id) = x {
                        let name = id.text.as_str();
                        if !model.state.contains_key(name)
                            && !signed.contains(name)
                            && !spent.contains(name)
                        {
                            chosen = true;
                        }
                    }
                });
                if chosen {
                    out.insert(threshold.span());
                }
            });
        }
    }
    out
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
    match expr {
        Expr::Int(lit) => lit.text.replace('_', "").parse::<u128>() == Ok(0),
        Expr::Ident(id) => id.text == "false",
        _ => false,
    }
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
                        if is_lookup_keyed(model, map_id.text.as_str()) {
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

fn is_lookup_keyed(model: &Model, ident: &str) -> bool {
    model
        .state
        .get(ident)
        .is_some_and(|f| matches!(f.ty.name.text.as_str(), "Map" | "Registry"))
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
    matches!(expr.peel(), Expr::Ident(id) if model.state.get(id.text.as_str()).is_some_and(|f| f.ty.name.text == "Q_Address" || f.ty.name.text == "GuardianSet"))
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
    fn an_unguarded_self_claim_is_rejected_as_a_takeover() {
        let src = "contract C { state { holder: Map<u64, Q_Address>; } \
                   entry claim(id: u64) writes(holder) { holder.set(id, caller); } }";
        assert!(error_for(src).contains("already held"));
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
