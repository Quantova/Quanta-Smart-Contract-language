// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{asset_inner, is_quorum_param, Model};
use quanta_ast::{BinOp, Clause, EntryDecl, Expr, GenericArg, Param, Stmt, UnaryOp};
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
    if let Some(err) = forged_recipient(model, entry) {
        return Err(err);
    }
    if let Some(err) = forged_signed_authority(model, entry) {
        return Err(err);
    }
    if entry_moves_ledger_value(model, entry) && !entry_binds_caller(model, entry, &signed) {
        return Err(no_ledger_authority_error(entry));
    }
    if entry_moves_asset(entry) && !entry_binds_caller(model, entry, &signed) {
        return Err(no_asset_authority_error(entry));
    }
    Ok(())
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
    if backing.iter().any(|(field, _)| authority_anchor_protected(model, field)) {
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

fn forged_caller_anchor(model: &Model, entry: &EntryDecl, signed: &HashSet<&str>) -> Option<TypeError> {
    if !entry_moves_value(model, entry) || !signed.is_empty() || entry.params.iter().any(is_quorum_param) {
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
                if let Expr::Ident(id) = callee.as_ref() {
                    let recip = match id.text.as_str() {
                        "send" => args.first(),
                        "send_asset" => args.get(1),
                        "mint_asset" => args.first(),
                        _ => None,
                    };
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
    match recip {
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

fn authority_anchor_protected(model: &Model, field: &str) -> bool {
    let mut prot = Prot {
        stack: HashSet::new(),
        memo: HashMap::new(),
        steps: 0,
    };
    anchor_protected(model, field, &mut prot).0
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
            let (authorized, sub_tainted) = writer_authorized(model, entry, prot);
            if !authorized {
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
    let gate_expr = |expr: &Expr| map_lookup_on_param(model, params, signed, derived, expr);
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

fn entry_moves_value(model: &Model, entry: &EntryDecl) -> bool {
    entry_value_move(model, entry, false)
}

fn entry_moves_ledger_value(model: &Model, entry: &EntryDecl) -> bool {
    entry_value_move(model, entry, true)
}

fn entry_value_move(model: &Model, entry: &EntryDecl, ledger_only: bool) -> bool {
    let (reads_of, sub_locals) = local_seize_taint(entry);
    let ledgers = ledger_maps(model);
    let asset_params: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| p.ty.name.text == "Q_Asset")
        .map(|p| p.name.text.as_str())
        .collect();
    let mut spends = self_spend_amounts(&ledgers, entry, &reads_of, &sub_locals);
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
                            if ledgers.contains(&map.text) {
                                let asset_backed = args
                                    .get(1)
                                    .and_then(|v| asset_amount_backer(v, &asset_params))
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
                            if foreign_key {
                                if ledgers.contains(&map.text) {
                                    moves = true;
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
                                    if !decrement && !backed && (ledgers.contains(&map.text) || reads)
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
        (Expr::Field { base: ba, name: na, .. }, Expr::Field { base: bb, name: nb, .. }) => {
            na.text == nb.text && expr_eq(ba, bb)
        }
        (Expr::Unary { op: oa, expr: ea, .. }, Expr::Unary { op: ob, expr: eb, .. }) => {
            oa == ob && expr_eq(ea, eb)
        }
        (
            Expr::Binary { op: oa, left: la, right: ra, .. },
            Expr::Binary { op: ob, left: lb, right: rb, .. },
        ) => oa == ob && expr_eq(la, lb) && expr_eq(ra, rb),
        (Expr::Call { callee: ca, args: aa, .. }, Expr::Call { callee: cb, args: ab, .. }) => {
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
        for stmt in &entry.body {
            stmt_exprs(stmt, &mut |e| {
                if let Expr::Call { callee, .. } = e {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(name.text.as_str(), "credit" | "debit") {
                            if let Expr::Ident(id) = base.as_ref() {
                                maps.insert(id.text.clone());
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
            if reads_of.get(id.text.as_str()).is_some_and(|s| s.contains(map)) {
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
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry inflate(amount: u64) writes(balances) \
                   { guard caller == owner; balances.credit(caller, amount); } }";
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
        let src = "contract C { state { owner: Q_Address; balances: Map<Q_Address, u64>; } \
                   entry set_owner(a: Q_Address) writes(owner) { owner = a; } \
                   entry seize(order: SeizeOrder) writes(balances) \
                   { guard caller == owner; \
                     balances.set(caller, balances.get(caller) - 0); \
                     balances.credit(caller, order.amount); } }";
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
        assert!(error_for(src).contains("no authority"), "{}", error_for(src));
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
        assert!(error_for(src).contains("no authority"), "{}", error_for(src));
    }

    #[test]
    fn a_pool_send_backed_by_an_asset_that_is_handed_back_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry drain(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(pool) \
                   { send(to, pool.split(funds.amount)); send(caller, funds); } }";
        assert!(error_for(src).contains("no authority"), "{}", error_for(src));
    }

    #[test]
    fn a_pool_send_backed_by_an_asset_merged_into_another_pool_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; sink: Q_Asset<QTOV>; } \
                   entry drain(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(pool, sink) \
                   { send(to, pool.split(funds.amount)); sink.merge(funds); } }";
        assert!(error_for(src).contains("no authority"), "{}", error_for(src));
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
