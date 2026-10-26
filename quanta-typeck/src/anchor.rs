// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_asset_type, is_quorum_param, Model};
use quanta_ast::{AfterTarget, AssignOp, BinOp, Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

const MAX_LOCAL_DEPTH: usize = 16;

pub fn check(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        check_after_anchors(entry)?;
        check_anchor_liveness(model, entry)?;
        check_guard_liveness(model, entry)?;
    }
    check_guard_anchors(model)
}

fn check_guard_liveness(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let mut gate = GateScan {
        model,
        entry,
        params: &params,
        locals: HashMap::new(),
    };
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => gate.scan(expr, true, &[])?,
            Clause::Denies { expr, .. } => gate.scan(expr, false, &[])?,
            _ => {}
        }
    }
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                gate.locals.insert(name.text.as_str(), value);
            }
            Stmt::Guard { expr, .. } => gate.scan(expr, true, &[])?,
            _ => {}
        }
    }
    Ok(())
}

struct GateScan<'m, 'a> {
    model: &'m Model<'a>,
    entry: &'m EntryDecl,
    params: &'m HashSet<&'m str>,
    locals: HashMap<&'m str, &'m Expr>,
}

impl GateScan<'_, '_> {
    fn scan(&self, expr: &Expr, holds: bool, acked: &[&Expr]) -> Result<(), TypeError> {
        match expr {
            Expr::Unary {
                op: quanta_ast::UnaryOp::Not,
                expr,
                ..
            } => self.scan(expr, !holds, acked),
            Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
                self.scan(expr, holds, acked)
            }
            Expr::Binary {
                op: BinOp::Or,
                left,
                right,
                ..
            } => {
                for (side, other) in [(left, right), (right, left)] {
                    let mut with: Vec<&Expr> = acked.to_vec();
                    if let Some(read) = zero_test(other) {
                        with.push(read);
                    }
                    self.scan(side, holds, &with)?;
                }
                Ok(())
            }
            Expr::Binary {
                op: BinOp::And,
                left,
                right,
                ..
            } => {
                self.scan(left, holds, acked)?;
                self.scan(right, holds, acked)
            }
            Expr::Binary {
                op: op @ (BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge),
                left,
                right,
                span,
            } => {
                let now_left = mentions_now(left);
                let now_right = mentions_now(right);
                if now_left == now_right {
                    return Ok(());
                }
                let greater = matches!(op, BinOp::Gt | BinOp::Ge);
                if (now_left == greater) != holds {
                    return Ok(());
                }
                let mut reads: Vec<&Expr> = Vec::new();
                collect_anchor_reads(self.model, self.params, &self.locals, left, &mut reads, 0);
                collect_anchor_reads(self.model, self.params, &self.locals, right, &mut reads, 0);
                for read in reads {
                    let Some(field) = anchor_field(read) else {
                        continue;
                    };
                    if field_is_asset(self.model, field)
                        || (!records_time(self.model, field) && field_is_written(self.model, field))
                    {
                        continue;
                    }
                    let live = read_starts_nonzero(self.model, read, field)
                        || entry_requires_nonzero(self.entry, read)
                        || acked.iter().any(|a| read_eq(a, read));
                    if !live {
                        return Err(guard_liveness_rejection(field, *span));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn zero_test(expr: &Expr) -> Option<&Expr> {
    if let Expr::Binary {
        op: BinOp::Eq,
        left,
        right,
        ..
    } = expr
    {
        if is_zero(right) {
            return Some(left);
        }
        if is_zero(left) {
            return Some(right);
        }
    }
    None
}

fn writes_field(stmt: &Stmt, field: &str) -> bool {
    match stmt {
        Stmt::Assign { target, .. } => matches!(target, Expr::Ident(id) if id.text == field),
        Stmt::Expr {
            expr: Expr::Call { callee, .. },
            ..
        } => matches!(
            callee.as_ref(),
            Expr::Field { base, name, .. }
                if name.text == "set" && matches!(base.as_ref(), Expr::Ident(id) if id.text == field)
        ),
        _ => false,
    }
}

fn field_is_written(model: &Model, field: &str) -> bool {
    let in_entries = model
        .entries
        .iter()
        .any(|entry| entry.body.iter().any(|stmt| writes_field(stmt, field)));
    let in_genesis = model.contract.items.iter().any(|item| {
        matches!(item, quanta_ast::Item::Genesis(genesis)
            if genesis.body.iter().any(|stmt| writes_field(stmt, field)))
    });
    in_entries || in_genesis
}

fn records_time(model: &Model, field: &str) -> bool {
    let mut timed = false;
    for entry in &model.entries {
        let mut timed_locals: HashSet<&str> = HashSet::new();
        for stmt in &entry.body {
            match stmt {
                Stmt::Let { name, value, .. } => {
                    if derives_from_now(value, &timed_locals) {
                        timed_locals.insert(name.text.as_str());
                    }
                }
                Stmt::Assign { target, value, .. } => {
                    if matches!(target, Expr::Ident(id) if id.text == field)
                        && derives_from_now(value, &timed_locals)
                    {
                        timed = true;
                    }
                }
                Stmt::Expr {
                    expr: Expr::Call { callee, args, .. },
                    ..
                } => {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if name.text == "set"
                            && matches!(base.as_ref(), Expr::Ident(id) if id.text == field)
                            && args
                                .get(1)
                                .is_some_and(|value| derives_from_now(value, &timed_locals))
                        {
                            timed = true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    timed
}

fn derives_from_now(expr: &Expr, timed_locals: &HashSet<&str>) -> bool {
    match expr {
        Expr::Now { .. } => true,
        Expr::Ident(id) => timed_locals.contains(id.text.as_str()),
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            derives_from_now(expr, timed_locals)
        }
        Expr::Binary { left, right, .. } => {
            derives_from_now(left, timed_locals) || derives_from_now(right, timed_locals)
        }
        _ => false,
    }
}

fn guard_liveness_rejection(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "this gate opens once `now` passes a time read from `{field}`, which is zero until it \
             is first recorded, so the delay is skipped on first use; require `{field}` to be \
             nonzero in this entry, or state the first use explicitly with `{field} == 0 || ...`"
        ),
        span,
    )
}

fn check_guard_anchors(model: &Model) -> Result<(), TypeError> {
    for entry in &model.entries {
        let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
        let locals = entry_locals(entry);
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
            let mut anchors: Vec<(&str, Span)> = Vec::new();
            time_compared_fields(model, &params, &locals, gate, &mut anchors);
            for (field, span) in anchors {
                if writes_other_than_time(model, field)
                    && !crate::signature::time_anchor_protected(model, field)
                {
                    return Err(TypeError::new(
                        format!(
                            "a time gate compares `now` with `{field}`, which an entry with no \
                             authority can set to any value, so the delay can be skipped; record \
                             `{field}` with `now` or write it only from an authorized entry"
                        ),
                        span,
                    ));
                }
            }
            let mut bare_anchors: Vec<(&str, Span)> = Vec::new();
            bare_now_compared_fields(model, gate, &locals, &mut bare_anchors);
            for (field, span) in bare_anchors {
                if !field_is_asset(model, field)
                    && field_written_by_entry(model, field)
                    && !crate::signature::time_anchor_protected(model, field)
                {
                    return Err(TypeError::new(
                        format!(
                            "a time gate compares `now` with `{field}`, an absolute deadline, so \
                             an entry with no authority that writes `{field}`, for example \
                             `{field} = now`, can open the lock early; write `{field}` only from \
                             an entry that carries the same authority as the lock"
                        ),
                        span,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn constant_only(expr: &Expr) -> bool {
    match expr {
        Expr::Int(_) => true,
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            constant_only(expr)
        }
        Expr::Binary { left, right, .. } => constant_only(left) && constant_only(right),
        _ => false,
    }
}

fn mentions_now(expr: &Expr) -> bool {
    match expr {
        Expr::Now { .. } => true,
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            mentions_now(expr)
        }
        Expr::Binary { left, right, .. } => mentions_now(left) || mentions_now(right),
        _ => false,
    }
}

fn time_compared_fields<'a>(
    model: &Model,
    params: &HashSet<&str>,
    locals: &HashMap<&'a str, &'a Expr>,
    expr: &'a Expr,
    out: &mut Vec<(&'a str, Span)>,
) {
    match expr {
        Expr::Binary {
            op, left, right, ..
        } => {
            if matches!(op, BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge) {
                for (side, other) in [(left, right), (right, left)] {
                    if mentions_now(side) {
                        let mut reads: Vec<&Expr> = Vec::new();
                        collect_anchor_reads(model, params, locals, other, &mut reads, 0);
                        collect_anchor_reads(model, params, locals, side, &mut reads, 0);
                        for read in reads {
                            if let Some(field) = anchor_field(read) {
                                out.push((field, read.span()));
                            }
                        }
                    }
                }
            }
            time_compared_fields(model, params, locals, left, out);
            time_compared_fields(model, params, locals, right, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            time_compared_fields(model, params, locals, expr, out)
        }
        _ => {}
    }
}

fn is_time_or_constant(value: &Expr) -> bool {
    match value {
        Expr::Now { .. } => true,
        Expr::Checked { expr, .. } => is_time_or_constant(expr),
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            matches!(left.as_ref(), Expr::Now { .. }) || matches!(right.as_ref(), Expr::Now { .. })
        }
        _ => false,
    }
}

fn writes_other_than_time(model: &Model, field: &str) -> bool {
    let mut other = false;
    for entry in &model.entries {
        for stmt in &entry.body {
            match stmt {
                Stmt::Assign {
                    target, op, value, ..
                } => {
                    if matches!(target, Expr::Ident(id) if id.text == field)
                        && (!matches!(op, AssignOp::Set) || !is_time_or_constant(value))
                    {
                        other = true;
                    }
                }
                Stmt::Expr {
                    expr: Expr::Call { callee, args, .. },
                    ..
                } => {
                    if let Expr::Field { base, name, .. } = callee.as_ref() {
                        if matches!(base.as_ref(), Expr::Ident(id) if id.text == field) {
                            let timed =
                                name.text == "set" && args.get(1).is_some_and(is_time_or_constant);
                            let clears = name.text == "remove";
                            if !timed && !clears {
                                other = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    other
}

fn check_anchor_liveness(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let locals = entry_locals(entry);
    for clause in &entry.clauses {
        let Clause::After { target, from, span } = clause else {
            continue;
        };
        let mut reads: Vec<&Expr> = Vec::new();
        if let AfterTarget::Expr(expr) = target {
            collect_anchor_reads(model, &params, &locals, expr, &mut reads, 0);
        }
        if let Some(expr) = from {
            collect_anchor_reads(model, &params, &locals, expr, &mut reads, 0);
        }
        for read in reads {
            let Some(field) = anchor_field(read) else {
                continue;
            };
            if field_is_asset(model, field) {
                continue;
            }
            if !read_starts_nonzero(model, read, field) && !entry_requires_nonzero(entry, read) {
                return Err(liveness_rejection(field, *span));
            }
            if writes_other_than_time(model, field)
                && !crate::signature::time_anchor_protected(model, field)
            {
                return Err(TypeError::new(
                    format!(
                        "a time gate anchors on `{field}`, a state field an entry with no authority can set to any value; record the anchor with `now` so no caller can pre-date the delay"
                    ),
                    *span,
                ));
            }
        }
        if let AfterTarget::Expr(expr) = target {
            let mut exposed: Vec<(&str, Span)> = Vec::new();
            exposed_deadline_fields(model, expr, &locals, 0, &mut exposed);
            for (field, _) in exposed {
                if !field_is_asset(model, field)
                    && field_written_by_entry(model, field)
                    && !crate::signature::time_anchor_protected(model, field)
                {
                    return Err(TypeError::new(
                        format!(
                            "an `after` gate opens at `{field}`, an absolute deadline, so an entry \
                             with no authority that writes `{field}`, for example `{field} = now`, \
                             can open the lock early; write `{field}` only from an entry that \
                             carries the same authority as the lock"
                        ),
                        *span,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn entry_locals(entry: &EntryDecl) -> HashMap<&str, &Expr> {
    let mut locals: HashMap<&str, &Expr> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            locals.insert(name.text.as_str(), value);
        }
    }
    locals
}

fn exposed_deadline_fields<'a>(
    model: &Model,
    expr: &'a Expr,
    locals: &HashMap<&'a str, &'a Expr>,
    depth: usize,
    out: &mut Vec<(&'a str, Span)>,
) {
    if depth > MAX_LOCAL_DEPTH {
        return;
    }
    if const_eval(expr, locals, depth).is_some() {
        return;
    }
    match expr {
        Expr::Ident(id) => {
            let name = id.text.as_str();
            if let Some(inner) = locals.get(name) {
                exposed_deadline_fields(model, inner, locals, depth + 1, out);
            } else if model.state.contains_key(name) {
                out.push((name, id.span));
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            exposed_deadline_fields(model, expr, locals, depth, out)
        }
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            if const_eval(right, locals, depth) == Some(0) {
                exposed_deadline_fields(model, left, locals, depth, out);
            } else if const_eval(left, locals, depth) == Some(0) {
                exposed_deadline_fields(model, right, locals, depth, out);
            }
        }
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => {
            if const_eval(right, locals, depth) == Some(1) {
                exposed_deadline_fields(model, left, locals, depth, out);
            } else if const_eval(left, locals, depth) == Some(1) {
                exposed_deadline_fields(model, right, locals, depth, out);
            }
        }
        Expr::Binary {
            op: BinOp::Sub | BinOp::Div | BinOp::Rem | BinOp::Shr,
            left,
            right,
            ..
        } => {
            exposed_deadline_fields(model, left, locals, depth, out);
            exposed_deadline_fields(model, right, locals, depth, out);
        }
        Expr::Call { .. } => {
            if let Some(field) = anchor_field(expr) {
                if model.state.contains_key(field) {
                    out.push((field, expr.span()));
                }
            }
        }
        _ => {}
    }
}

fn const_eval<'a>(
    expr: &'a Expr,
    locals: &HashMap<&'a str, &'a Expr>,
    depth: usize,
) -> Option<u128> {
    if depth > MAX_LOCAL_DEPTH {
        return None;
    }
    match expr {
        Expr::Int(n) => n.text.replace('_', "").parse::<u128>().ok(),
        Expr::Ident(id) => locals
            .get(id.text.as_str())
            .and_then(|e| const_eval(e, locals, depth + 1)),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => const_eval(expr, locals, depth),
        Expr::Binary {
            op, left, right, ..
        } => {
            if matches!(op, BinOp::Sub) && crate::signature::expr_eq(left, right) {
                return Some(0);
            }
            if matches!(op, BinOp::Div) && crate::signature::expr_eq(left, right) {
                return Some(1);
            }
            let l = const_eval(left, locals, depth)?;
            let r = const_eval(right, locals, depth)?;
            match op {
                BinOp::Add => l.checked_add(r),
                BinOp::Sub => l.checked_sub(r),
                BinOp::Mul => l.checked_mul(r),
                BinOp::Div => l.checked_div(r),
                BinOp::Rem => l.checked_rem(r),
                BinOp::Shr if r < 128 => Some(l >> r),
                BinOp::Shr => Some(0),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_bare_now<'a>(expr: &'a Expr, locals: &HashMap<&'a str, &'a Expr>, depth: usize) -> bool {
    if depth > MAX_LOCAL_DEPTH {
        return false;
    }
    match expr {
        Expr::Now { .. } => true,
        Expr::Ident(id) => locals
            .get(id.text.as_str())
            .is_some_and(|e| is_bare_now(e, locals, depth + 1)),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            is_bare_now(expr, locals, depth)
        }
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            (is_bare_now(left, locals, depth) && const_eval(right, locals, depth) == Some(0))
                || (const_eval(left, locals, depth) == Some(0) && is_bare_now(right, locals, depth))
        }
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        } => is_bare_now(left, locals, depth) && const_eval(right, locals, depth) == Some(0),
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => {
            (is_bare_now(left, locals, depth) && const_eval(right, locals, depth) == Some(1))
                || (const_eval(left, locals, depth) == Some(1) && is_bare_now(right, locals, depth))
        }
        Expr::Binary {
            op: BinOp::Div,
            left,
            right,
            ..
        } => is_bare_now(left, locals, depth) && const_eval(right, locals, depth) == Some(1),
        Expr::Binary {
            op: BinOp::Shr,
            left,
            right,
            ..
        } => is_bare_now(left, locals, depth) && const_eval(right, locals, depth) == Some(0),
        _ => false,
    }
}

fn now_ge<'a>(expr: &'a Expr, locals: &HashMap<&'a str, &'a Expr>, depth: usize) -> bool {
    if depth > MAX_LOCAL_DEPTH {
        return false;
    }
    match expr {
        Expr::Now { .. } => true,
        Expr::Ident(id) => locals
            .get(id.text.as_str())
            .is_some_and(|e| now_ge(e, locals, depth + 1)),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => now_ge(expr, locals, depth),
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => now_ge(left, locals, depth) || now_ge(right, locals, depth),
        Expr::Binary {
            op: BinOp::Mul,
            left,
            right,
            ..
        } => {
            (now_ge(left, locals, depth)
                && const_eval(right, locals, depth).is_some_and(|v| v >= 1))
                || (const_eval(left, locals, depth).is_some_and(|v| v >= 1)
                    && now_ge(right, locals, depth))
        }
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        } => now_ge(left, locals, depth) && const_eval(right, locals, depth) == Some(0),
        Expr::Binary {
            op: BinOp::Div,
            left,
            right,
            ..
        } => now_ge(left, locals, depth) && const_eval(right, locals, depth) == Some(1),
        Expr::Binary {
            op: BinOp::Shr,
            left,
            right,
            ..
        } => now_ge(left, locals, depth) && const_eval(right, locals, depth) == Some(0),
        _ => false,
    }
}

fn bare_now_compared_fields<'a>(
    model: &Model,
    expr: &'a Expr,
    locals: &HashMap<&'a str, &'a Expr>,
    out: &mut Vec<(&'a str, Span)>,
) {
    match expr {
        Expr::Binary {
            op, left, right, ..
        } => {
            if matches!(op, BinOp::Gt | BinOp::Ge) && now_ge(left, locals, 0) {
                exposed_deadline_fields(model, right, locals, 0, out);
            }
            if matches!(op, BinOp::Lt | BinOp::Le) && now_ge(right, locals, 0) {
                exposed_deadline_fields(model, left, locals, 0, out);
            }
            if matches!(op, BinOp::Eq) {
                if is_bare_now(left, locals, 0) {
                    exposed_deadline_fields(model, right, locals, 0, out);
                }
                if is_bare_now(right, locals, 0) {
                    exposed_deadline_fields(model, left, locals, 0, out);
                }
            }
            bare_now_compared_fields(model, left, locals, out);
            bare_now_compared_fields(model, right, locals, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            bare_now_compared_fields(model, expr, locals, out)
        }
        _ => {}
    }
}

fn field_written_by_entry(model: &Model, field: &str) -> bool {
    model
        .entries
        .iter()
        .any(|entry| entry.body.iter().any(|stmt| writes_field(stmt, field)))
}

fn collect_anchor_reads<'a>(
    model: &Model,
    params: &HashSet<&str>,
    locals: &HashMap<&str, &'a Expr>,
    expr: &'a Expr,
    out: &mut Vec<&'a Expr>,
    depth: usize,
) {
    if depth > MAX_LOCAL_DEPTH {
        return;
    }
    match expr {
        Expr::Ident(id) => {
            let name = id.text.as_str();
            if params.contains(name) {
                return;
            }
            if let Some(value) = locals.get(name) {
                collect_anchor_reads(model, params, locals, value, out, depth + 1);
            } else if model.state.contains_key(name) {
                out.push(expr);
            }
        }
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "get" {
                    if let Expr::Ident(map_id) = base.as_ref() {
                        if !params.contains(map_id.text.as_str())
                            && model.state.contains_key(map_id.text.as_str())
                        {
                            out.push(expr);
                        }
                    }
                }
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            collect_anchor_reads(model, params, locals, expr, out, depth)
        }
        Expr::Binary { left, right, .. } => {
            collect_anchor_reads(model, params, locals, left, out, depth);
            collect_anchor_reads(model, params, locals, right, out, depth);
        }
        _ => {}
    }
}

fn anchor_field(read: &Expr) -> Option<&str> {
    match read {
        Expr::Ident(id) => Some(id.text.as_str()),
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, .. } = callee.as_ref() {
                if let Expr::Ident(map_id) = base.as_ref() {
                    return Some(map_id.text.as_str());
                }
            }
            None
        }
        _ => None,
    }
}

fn field_is_asset(model: &Model, field: &str) -> bool {
    model.state.get(field).is_some_and(|f| is_asset_type(&f.ty))
}

fn genesis_arms_nonzero(model: &Model, field: &str) -> bool {
    for item in &model.contract.items {
        let quanta_ast::Item::Genesis(genesis) = item else {
            continue;
        };
        for stmt in &genesis.body {
            if let Stmt::Assign { target, value, .. } = stmt {
                if matches!(target, Expr::Ident(id) if id.text == field) {
                    match value {
                        Expr::Now { .. } | Expr::Date { .. } => return true,
                        Expr::Int(lit) => {
                            if lit.text.replace('_', "").parse::<u128>() != Ok(0) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    false
}

fn read_starts_nonzero(model: &Model, read: &Expr, field: &str) -> bool {
    if !matches!(read, Expr::Ident(_)) {
        return false;
    }
    let has_nonzero_default = match model.state.get(field).and_then(|f| f.default.as_ref()) {
        None => false,
        Some(Expr::Int(lit)) => lit.text.replace('_', "").parse::<u128>() != Ok(0),
        Some(_) => true,
    };
    if !has_nonzero_default && !genesis_arms_nonzero(model, field) {
        return false;
    }
    for e in &model.entries {
        for stmt in &e.body {
            if let Stmt::Assign { target, value, .. } = stmt {
                if matches!(target, Expr::Ident(id) if id.text == field)
                    && !matches!(value, Expr::Now { .. })
                {
                    return false;
                }
            }
        }
    }
    true
}

fn entry_requires_nonzero(entry: &EntryDecl, read: &Expr) -> bool {
    for clause in &entry.clauses {
        if let Clause::Denies { expr, .. } = clause {
            if denies_read_zero(expr, read) {
                return true;
            }
        }
    }
    for stmt in &entry.body {
        if let Stmt::Guard { expr, .. } = stmt {
            if guard_read_nonzero(expr, read) {
                return true;
            }
        }
    }
    false
}

fn denies_read_zero(expr: &Expr, read: &Expr) -> bool {
    if let Expr::Binary {
        op: BinOp::Eq,
        left,
        right,
        ..
    } = expr
    {
        return (read_eq(left, read) && is_zero(right)) || (read_eq(right, read) && is_zero(left));
    }
    false
}

fn guard_read_nonzero(expr: &Expr, read: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::Ne,
            left,
            right,
            ..
        } => (read_eq(left, read) && is_zero(right)) || (read_eq(right, read) && is_zero(left)),
        Expr::Binary {
            op: BinOp::Gt,
            left,
            right,
            ..
        } => read_eq(left, read) && is_zero(right),
        Expr::Binary {
            op: BinOp::Ge,
            left,
            right,
            ..
        } => read_eq(left, read) && is_positive_int(right),
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => guard_read_nonzero(left, read) || guard_read_nonzero(right, read),
        _ => false,
    }
}

fn read_eq(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Ident(x), Expr::Ident(y)) => x.text == y.text,
        (Expr::Caller { .. }, Expr::Caller { .. }) => true,
        (Expr::Now { .. }, Expr::Now { .. }) => true,
        (Expr::Int(x), Expr::Int(y)) => x.text == y.text,
        (
            Expr::Field {
                base: ba, name: na, ..
            },
            Expr::Field {
                base: bb, name: nb, ..
            },
        ) => na.text == nb.text && read_eq(ba, bb),
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
            read_eq(ca, cb) && aa.len() == ab.len() && aa.iter().zip(ab).all(|(x, y)| read_eq(x, y))
        }
        _ => false,
    }
}

fn is_positive_int(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(lit) if lit.text.replace('_', "").parse::<u128>().map_or(false, |v| v >= 1))
}

fn is_zero(expr: &Expr) -> bool {
    match expr {
        Expr::Int(lit) => lit.text.replace('_', "").parse::<u128>() == Ok(0),
        Expr::Ident(id) => id.text == "false",
        _ => false,
    }
}

fn liveness_rejection(field: &str, span: Span) -> TypeError {
    TypeError::new(
        format!(
            "a time gate anchored on `{field}`, which starts at zero, lets the delay pass before \
             the anchor is set; give `{field}` a nonzero default or deny `{field} == 0` in this \
             entry so the cooling off cannot be skipped on the first call"
        ),
        span,
    )
}

fn check_after_anchors(entry: &EntryDecl) -> Result<(), TypeError> {
    let params: HashSet<&str> = entry.params.iter().map(|p| p.name.text.as_str()).collect();
    let quorum_params: HashSet<&str> = entry
        .params
        .iter()
        .filter(|p| is_quorum_param(p))
        .map(|p| p.name.text.as_str())
        .collect();

    let mut authenticated: HashSet<String> = HashSet::new();
    for param in &entry.params {
        if param.signed_by.is_some() {
            for key in collect_signed_fields(entry, &param.name.text) {
                authenticated.insert(key);
            }
        }
    }
    if !quorum_params.is_empty() {
        for param in &entry.params {
            if is_quorum_param(param) || param.ty.name.text == "Q_Asset" {
                continue;
            }
            for key in collect_signed_fields(entry, &param.name.text) {
                authenticated.insert(key);
            }
        }
    }

    for clause in &entry.clauses {
        let Clause::After { target, from, span } = clause else {
            continue;
        };
        if from.as_ref().is_some_and(constant_only) {
            return Err(TypeError::new(
                "an `after` gate anchored on a constant counts from the epoch, so it is already \
                 open; anchor it on a state field recorded with `now`"
                    .to_string(),
                *span,
            ));
        }
        match target {
            AfterTarget::Expr(expr) if constant_only(expr) => {
                return Err(TypeError::new(
                    "an `after` gate with a bare integer compares `now` against absolute time, so \
                     it is open from the epoch; use a duration with a unit such as `after 24 \
                     hours from <anchor>`, or a date"
                        .to_string(),
                    *span,
                ));
            }
            AfterTarget::Duration(_) if from.is_none() => {
                return Err(TypeError::new(
                    "a duration `after` gate needs a `from` anchor, otherwise it compares against \
                     absolute time and is open from the epoch"
                        .to_string(),
                    *span,
                ));
            }
            _ => {}
        }
        if let AfterTarget::Expr(expr) = target {
            check_anchor_expr(expr, &params, &quorum_params, &authenticated, *span)?;
        }
        if let Some(expr) = from {
            check_anchor_expr(expr, &params, &quorum_params, &authenticated, *span)?;
        }
    }
    Ok(())
}

fn check_anchor_expr(
    expr: &Expr,
    params: &HashSet<&str>,
    quorum_params: &HashSet<&str>,
    authenticated: &HashSet<String>,
    span: Span,
) -> Result<(), TypeError> {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if params.contains(id.text.as_str()) {
                    let key = format!("{}.{}", id.text, name.text);
                    if !authenticated.contains(&key) {
                        return Err(anchor_rejection(
                            key,
                            quorum_params.contains(id.text.as_str()),
                            span,
                        ));
                    }
                    return Ok(());
                }
            }
            check_anchor_expr(base, params, quorum_params, authenticated, span)
        }
        Expr::Ident(id) => {
            if params.contains(id.text.as_str()) {
                return Err(anchor_rejection(
                    id.text.clone(),
                    quorum_params.contains(id.text.as_str()),
                    span,
                ));
            }
            Ok(())
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            check_anchor_expr(expr, params, quorum_params, authenticated, span)
        }
        Expr::Binary { left, right, .. } => {
            check_anchor_expr(left, params, quorum_params, authenticated, span)?;
            check_anchor_expr(right, params, quorum_params, authenticated, span)
        }
        Expr::Call { callee, args, .. } => {
            check_anchor_expr(callee, params, quorum_params, authenticated, span)?;
            for arg in args {
                check_anchor_expr(arg, params, quorum_params, authenticated, span)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn anchor_rejection(display: String, is_quorum: bool, span: Span) -> TypeError {
    let source = if is_quorum {
        format!("a time gate anchored on `{display}`, a quorum field that no guardian signs")
    } else {
        format!(
            "a time gate anchored on `{display}`, a caller supplied value that no signature covers"
        )
    };
    TypeError::new(
        format!("{source}; anchor the delay on state that an authorized entry records with `now`"),
        span,
    )
}

fn collect_signed_fields(entry: &EntryDecl, param: &str) -> Vec<String> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                collect_fields_expr(expr, param, &mut out)
            }
            Clause::After { target, from, .. } => {
                if let AfterTarget::Expr(expr) = target {
                    collect_fields_expr(expr, param, &mut out);
                }
                if let Some(expr) = from {
                    collect_fields_expr(expr, param, &mut out);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        collect_fields_stmt(stmt, param, &mut out);
    }
    out
}

fn collect_fields_stmt(stmt: &Stmt, param: &str, out: &mut Vec<String>) {
    match stmt {
        Stmt::Guard { expr, .. } => collect_fields_expr(expr, param, out),
        Stmt::Let { value, .. } => collect_fields_expr(value, param, out),
        Stmt::Emit { args, .. } => {
            for arg in args {
                collect_fields_expr(arg, param, out);
            }
        }
        Stmt::Assign { target, value, .. } => {
            collect_fields_expr(target, param, out);
            collect_fields_expr(value, param, out);
        }
        Stmt::Expr { expr, .. } => collect_fields_expr(expr, param, out),
    }
}

fn collect_fields_expr(expr: &Expr, param: &str, out: &mut Vec<String>) {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if id.text == param {
                    let key = format!("{param}.{}", name.text);
                    if !out.contains(&key) {
                        out.push(key);
                    }
                    return;
                }
            }
            collect_fields_expr(base, param, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            collect_fields_expr(expr, param, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_fields_expr(left, param, out);
            collect_fields_expr(right, param, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_fields_expr(callee, param, out);
            for arg in args {
                collect_fields_expr(arg, param, out);
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

    const GATED: &str = "contract C { state { owner: Q_Address; unlock: Time; opened: u64; } \
        genesis { owner = deployer; } ARM \
        entry open(order: OpenOrder signed by owner) writes(opened) \
        { guard now >= unlock + 86400; opened = 1; } }";

    #[test]
    fn a_time_guard_on_a_field_anyone_can_set_is_refused() {
        let src = GATED.replace("ARM", "entry arm(t: u64) writes(unlock) { unlock = t; }");
        assert!(error_for(&src).contains("a time gate compares `now` with `unlock`"));
    }

    #[test]
    fn a_time_guard_on_a_recorded_or_authorized_field_is_accepted() {
        let recorded = GATED.replace("ARM", "entry arm() writes(unlock) { unlock = now; }");
        assert!(error_for(&recorded).contains("zero until it is first recorded"));
        ok(&recorded.replace("{ guard now >=", "{ guard unlock > 0; guard now >="));
        ok(&recorded.replace("{ guard now >=", "{ guard unlock == 0 || now >="));
        ok(&recorded.replace(
            "{ guard now >= unlock + 86400;",
            "denies now < unlock + 86400 || unlock == 0 {",
        ));
        ok(&GATED.replace(
            "ARM",
            "entry arm(order: ArmOrder signed by owner) writes(unlock) { unlock = order.at; }",
        ));
    }

    #[test]
    fn a_caller_supplied_anchor_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from order.deadline { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("caller supplied value"));
    }

    #[test]
    fn a_signed_anchor_is_authenticated() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { owner: Q_Address; vault: Q_Asset<QTOV>; }
                entry release(order: Rel signed by owner) conserves QTOV writes(vault)
                  after 24 hours from order.deadline { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn an_anchor_on_recorded_state_is_authenticated() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: u64; vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at
                  denies armed_at == 0 { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn an_arm_then_act_anchor_without_a_liveness_guard_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_zero_init_self_recording_anchor_is_refused_and_a_denied_zero_is_accepted() {
        let unsafe_src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { period_reset: u64; vault: Q_Asset<QTOV>; }
                entry roll(order: Rel) conserves QTOV writes(vault, period_reset)
                  after 30 days from period_reset
                  { period_reset = now; send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(unsafe_src).contains("lets the delay pass"));

        let safe_src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { period_reset: u64; vault: Q_Asset<QTOV>; }
                entry roll(order: Rel) conserves QTOV writes(vault, period_reset)
                  after 30 days from period_reset denies period_reset == 0
                  { period_reset = now; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(safe_src);
    }

    #[test]
    fn an_anchor_with_a_non_zero_default_needs_no_liveness_guard() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { start: u64 = 100; vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 365 days from start { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_zero_start_anchor_wrapped_in_arithmetic_is_still_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; grace: u64 = 3600; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed + grace { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_ge_one_liveness_guard_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed: u64; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed) { armed = now; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed
                  { guard armed >= 1; send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_keyed_map_anchor_without_a_liveness_guard_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed_at) { armed_at.set(caller, now); }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at.get(caller) { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn a_keyed_map_anchor_with_a_keyed_guard_is_accepted() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { armed_at: Map<Q_Address, u64>; vault: Q_Asset<QTOV>; }
                entry arm() writes(armed_at) { armed_at.set(caller, now); }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 24 hours from armed_at.get(caller)
                  denies armed_at.get(caller) == 0 { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }

    #[test]
    fn a_nonzero_default_anchor_re_zeroed_by_an_entry_is_rejected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { start: u64 = 2000000000; vault: Q_Asset<QTOV>; }
                entry reset() writes(start) { start = 0; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  after 365 days from start { send(order.to, vault.split(order.amount)); }
            }"#;
        assert!(error_for(src).contains("starts at zero"));
    }

    #[test]
    fn an_entry_without_a_time_gate_is_unaffected() {
        let src = r#"import { Q_Asset } from "quantova/primitives";
            contract C {
                state { vault: Q_Asset<QTOV>; }
                entry release(order: Rel) conserves QTOV writes(vault)
                  { send(order.to, vault.split(order.amount)); }
            }"#;
        ok(src);
    }
}
