// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{asset_inner, Model};
use quanta_ast::{BinOp, Clause, EntryDecl, Expr, Stmt};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

const NATIVE_ASSET: &str = "QTOV";

pub fn check(model: &Model) -> Result<(), TypeError> {
    let pins = issuer_pins(model);
    let mut owner_of_field: HashMap<&str, &str> = HashMap::new();
    let mut kinds: Vec<&String> = pins.keys().collect();
    kinds.sort();
    for kind in kinds {
        let fields = &pins[kind];
        if fields.len() > 1 {
            let mut named: Vec<&str> = fields.iter().map(String::as_str).collect();
            named.sort_unstable();
            return Err(TypeError::new(
                format!(
                    "`{kind}` is received under more than one issuer ({}), so one asset can be \
                     paid in as another",
                    named.join(", ")
                ),
                model.contract.name.span,
            ));
        }
        for field in fields {
            if let Some(other) = owner_of_field.insert(field.as_str(), kind.as_str()) {
                return Err(TypeError::new(
                    format!(
                        "`{field}` is the issuer pinned for both `{other}` and `{kind}`, so the \
                         two kinds are one asset under two names"
                    ),
                    model.contract.name.span,
                ));
            }
        }
    }
    for entry in &model.entries {
        check_entry(model, entry, &pins)?;
    }
    Ok(())
}

fn issuer_pins(model: &Model) -> HashMap<String, HashSet<String>> {
    let mut pins: HashMap<String, HashSet<String>> = HashMap::new();
    for entry in &model.entries {
        for param in &entry.params {
            let Some(kind) = asset_inner(&param.ty) else {
                continue;
            };
            if kind == NATIVE_ASSET {
                continue;
            }
            for stmt in &entry.body {
                if let Stmt::Guard { expr, .. } = stmt {
                    let mut found = Vec::new();
                    in_asset_pins(expr, &mut found);
                    for pin in found {
                        if let Expr::Ident(id) = pin {
                            if model.is_state(&id.text) {
                                pins.entry(kind.to_string())
                                    .or_default()
                                    .insert(id.text.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    pins
}

fn issuer_error(
    model: &Model,
    pins: &HashMap<String, HashSet<String>>,
    kind: &str,
    issuer: &Expr,
    span: Span,
) -> Option<TypeError> {
    if kind == NATIVE_ASSET && !model.is_declared_asset(kind) {
        return Some(TypeError::new(
            "native value moves with send, not send_asset".to_string(),
            span,
        ));
    }
    let named = match issuer {
        Expr::Ident(id) => Some(id.text.as_str()),
        _ => None,
    };
    let fits = if model.is_declared_asset(kind) {
        named == Some("self")
    } else {
        match pins.get(kind) {
            Some(fields) => named.is_some_and(|n| fields.contains(n)),
            None => true,
        }
    };
    (!fits).then(|| {
        TypeError::new(
            format!(
                "this sends `{kind}` value under an issuer that is not the one `{kind}` is \
                 received from, so one pool is drawn down while another asset leaves"
            ),
            span,
        )
    })
}

fn guard_mentions_in_asset(model: &Model, entry: &EntryDecl, stmt: &Stmt) -> bool {
    let Stmt::Guard { expr, .. } = stmt else {
        return false;
    };
    binds_in_asset(model, entry, expr)
}

fn names_a_fixed_asset(model: &Model, entry: &EntryDecl, expr: &Expr) -> bool {
    match expr {
        Expr::Native { .. } => true,
        Expr::Ident(id) => {
            model.is_state(&id.text) && !entry.params.iter().any(|p| p.name.text == id.text)
        }
        _ => false,
    }
}

fn binds_in_asset(model: &Model, entry: &EntryDecl, expr: &Expr) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => binds_in_asset(model, entry, left) || binds_in_asset(model, entry, right),
        Expr::Binary {
            op: BinOp::Eq,
            left,
            right,
            ..
        } => match (&**left, &**right) {
            (Expr::InAsset { .. }, other) | (other, Expr::InAsset { .. })
                if !matches!(other, Expr::InAsset { .. }) =>
            {
                names_a_fixed_asset(model, entry, other)
            }
            _ => false,
        },
        _ => false,
    }
}

fn in_asset_pins<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => {
            in_asset_pins(left, out);
            in_asset_pins(right, out);
        }
        Expr::Binary {
            op: BinOp::Eq,
            left,
            right,
            ..
        } => match (&**left, &**right) {
            (Expr::InAsset { .. }, other) | (other, Expr::InAsset { .. })
                if !matches!(other, Expr::InAsset { .. }) =>
            {
                out.push(other)
            }
            _ => {}
        },
        _ => {}
    }
}

fn pin_matches_kind(model: &Model, entry: &EntryDecl, kind: &str, pin: &Expr) -> bool {
    match pin {
        Expr::Native { .. } => kind == NATIVE_ASSET,
        Expr::Ident(id) => {
            kind != NATIVE_ASSET
                && names_a_fixed_asset(model, entry, pin)
                && crate::signature::authority_anchor_protected(model, &id.text)
        }
        _ => false,
    }
}

fn asset_kind_is_stated(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let Some((param, kind)) = entry
        .params
        .iter()
        .find_map(|p| asset_inner(&p.ty).map(|kind| (p, kind)))
    else {
        return Ok(());
    };
    let stated = entry
        .body
        .iter()
        .any(|stmt| guard_mentions_in_asset(model, entry, stmt));
    if stated {
        let mut pins = Vec::new();
        for stmt in &entry.body {
            if let Stmt::Guard { expr, .. } = stmt {
                in_asset_pins(expr, &mut pins);
            }
        }
        if pins
            .iter()
            .any(|pin| pin_matches_kind(model, entry, kind, pin))
        {
            return Ok(());
        }
        return Err(TypeError::new(
            format!(
                "`{}` is declared `Q_Asset<{kind}>`, but no guard pins `in_asset` to that kind: \
                 native value needs `in_asset == native` and a token needs a Q_Address field \
                 only its owner can set",
                param.name.text
            ),
            param.name.span,
        ));
    }
    Err(TypeError::new(
        "this entry accepts an asset but never says which one, so any asset the caller \
         mints is accepted at the same price. Add `guard in_asset == native;` for native \
         value, or `guard in_asset == <issuer>;` for a specific token"
            .to_string(),
        entry.name.span,
    ))
}

fn check_entry(
    model: &Model,
    entry: &EntryDecl,
    pins: &HashMap<String, HashSet<String>>,
) -> Result<(), TypeError> {
    let mut declared: HashSet<&str> = HashSet::new();
    let mut mint_kind: Option<&str> = None;
    for clause in &entry.clauses {
        match clause {
            Clause::Conserves { asset, .. } | Clause::Burns { asset, .. } => {
                declared.insert(asset.text.as_str());
            }
            Clause::Mints { asset, .. } => {
                declared.insert(asset.text.as_str());
                mint_kind = Some(asset.text.as_str());
            }
            _ => {}
        }
    }

    let mut kinds: HashMap<String, String> = HashMap::new();
    for param in &entry.params {
        if let Some(sym) = asset_inner(&param.ty) {
            if !declared.contains(sym) {
                return Err(TypeError::new(
                    format!(
                        "asset `{}` of kind `{}` moves through this entry, but the entry declares \
                         no `conserves {}`, `mints {}`, or `burns {}`, so its accounting is unstated",
                        param.name.text, sym, sym, sym, sym
                    ),
                    param.name.span,
                ));
            }
            kinds.insert(param.name.text.clone(), sym.to_string());
        }
    }

    for stmt in &entry.body {
        if let Stmt::Let { name, value, span } = stmt {
            if let Expr::Ident(id) = value {
                if !kinds.contains_key(id.text.as_str())
                    && model
                        .state
                        .get(id.text.as_str())
                        .and_then(|f| asset_inner(&f.ty))
                        .is_some()
                {
                    return Err(TypeError::new(
                        "a let cannot alias a state asset pool; split the amount to move a portion"
                            .to_string(),
                        *span,
                    ));
                }
            }
            if let Some(sym) = expr_asset_kind(model, &kinds, mint_kind, value) {
                kinds.insert(name.text.clone(), sym);
            }
        }
        if let Stmt::Assign {
            target,
            value,
            span,
            ..
        } = stmt
        {
            if let Some(into) = expr_asset_kind(model, &kinds, mint_kind, target) {
                if let Some(err) = asset_flow_error(model, &kinds, mint_kind, &into, value, *span) {
                    return Err(err);
                }
            }
        }
        let mut err = None;
        for_each_expr(stmt, &mut |e| {
            if err.is_some() {
                return;
            }
            err = asset_flow_in_expr(model, &kinds, mint_kind, e);
            if err.is_some() {
                return;
            }
            if let Expr::Call { callee, args, span } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send_asset") {
                    if let (Some(issuer), Some(value)) = (args.first(), args.get(2)) {
                        if let Some(kind) = expr_asset_kind(model, &kinds, mint_kind, value) {
                            err = issuer_error(model, pins, &kind, issuer, *span);
                        }
                    }
                }
            }
        });
        if let Some(e) = err {
            return Err(e);
        }
    }
    if let Some(err) = amount_credited_while_sent(entry, &kinds) {
        return Err(err);
    }
    asset_kind_is_stated(model, entry)?;
    Ok(())
}

fn amount_credited_while_sent(
    entry: &EntryDecl,
    kinds: &HashMap<String, String>,
) -> Option<TypeError> {
    let mut tainted: HashMap<String, String> = HashMap::new();
    for stmt in &entry.body {
        if let Stmt::Let { name, value, .. } = stmt {
            if let Some(asset) = credited_asset(value, kinds, &tainted) {
                tainted.insert(name.text.clone(), asset);
            }
        }
    }
    let mut credited: HashMap<String, Span> = HashMap::new();
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| {
            if let Expr::Call { callee, args, span } = e {
                if let Expr::Field { name, .. } = callee.as_ref() {
                    if matches!(name.text.as_str(), "credit" | "set" | "insert") {
                        if let Some(value) = args.last() {
                            if let Some(asset) = credited_asset(value, kinds, &tainted) {
                                credited.entry(asset).or_insert(*span);
                            }
                        }
                    }
                }
            }
        });
    }
    if credited.is_empty() {
        return None;
    }
    let mut edges: Vec<(String, String)> = Vec::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                if let Some(src) = flow_source(value) {
                    edges.push((name.text.clone(), src));
                }
            }
            Stmt::Assign { target, value, .. } => {
                if let Expr::Ident(dest) = target {
                    if let Some(src) = flow_source(value) {
                        edges.push((dest.text.clone(), src));
                    }
                }
            }
            _ => {}
        }
        for_each_expr(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "merge" {
                        if let Expr::Ident(dest) = base.as_ref() {
                            if let Some(src) = args.first().and_then(flow_source) {
                                edges.push((dest.text.clone(), src));
                            }
                        }
                    }
                }
            }
        });
    }
    let mut backing: HashMap<String, HashSet<String>> = HashMap::new();
    for asset in credited.keys() {
        backing
            .entry(asset.clone())
            .or_default()
            .insert(asset.clone());
    }
    loop {
        let mut changed = false;
        for (dest, src) in &edges {
            let inherit: Vec<String> = backing.get(src).into_iter().flatten().cloned().collect();
            let slot = backing.entry(dest.clone()).or_default();
            for asset in inherit {
                if slot.insert(asset) {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut sent: HashSet<String> = HashSet::new();
    for stmt in &entry.body {
        for_each_expr(stmt, &mut |e| {
            if let Expr::Call { callee, args, .. } = e {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") {
                    if let Some(value) = args.get(1) {
                        if let Some(asset) = sent_asset(value, kinds) {
                            sent.insert(asset);
                        }
                        if let Some(backed) = flow_source(value).and_then(|p| backing.get(&p)) {
                            for asset in backed {
                                sent.insert(asset.clone());
                            }
                        }
                    }
                }
            }
        });
    }
    for (asset, span) in &credited {
        if sent.contains(asset) {
            return Some(TypeError::new(
                format!(
                    "asset `{asset}` has its amount credited to a ledger while the asset itself is sent \
                     away; back the credit by merging the asset into a pool, do not return it"
                ),
                *span,
            ));
        }
    }
    None
}

fn credited_asset(
    expr: &Expr,
    kinds: &HashMap<String, String>,
    tainted: &HashMap<String, String>,
) -> Option<String> {
    let mut found = None;
    walk(expr, &mut |e| {
        if found.is_some() {
            return;
        }
        if let Expr::Field { base, name, .. } = e {
            if name.text == "amount" {
                if let Expr::Ident(id) = base.as_ref() {
                    if kinds.contains_key(id.text.as_str()) {
                        found = Some(id.text.clone());
                    }
                }
            }
        }
        if let Expr::Ident(id) = e {
            if let Some(asset) = tainted.get(id.text.as_str()) {
                found = Some(asset.clone());
            }
        }
    });
    found
}

fn sent_asset(expr: &Expr, kinds: &HashMap<String, String>) -> Option<String> {
    match expr {
        Expr::Ident(id) if kinds.contains_key(id.text.as_str()) => Some(id.text.clone()),
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "split" {
                    if let Expr::Ident(id) = base.as_ref() {
                        if kinds.contains_key(id.text.as_str()) {
                            return Some(id.text.clone());
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn split_pool(expr: &Expr) -> Option<String> {
    if let Expr::Call { callee, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "split" {
                if let Expr::Ident(id) = base.as_ref() {
                    return Some(id.text.clone());
                }
            }
        }
    }
    None
}

fn flow_source(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.text.clone()),
        Expr::Call { .. } => split_pool(expr),
        _ => None,
    }
}

fn asset_flow_in_expr(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    expr: &Expr,
) -> Option<TypeError> {
    if let Expr::Call { callee, args, span } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if name.text == "merge" && args.len() == 1 {
                if let Some(into) = expr_asset_kind(model, kinds, mint_kind, base) {
                    return asset_flow_error(model, kinds, mint_kind, &into, &args[0], *span);
                }
            }
        }
        if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") && args.len() == 2 {
            return sent_value_error(model, kinds, mint_kind, &args[1], *span);
        }
    }
    None
}

fn sent_value_error(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    value: &Expr,
    span: Span,
) -> Option<TypeError> {
    match expr_asset_kind(model, kinds, mint_kind, value) {
        None => Some(TypeError::new(
            "a value that is not an asset cannot be sent; send an asset, a split, or a mint"
                .to_string(),
            span,
        )),
        Some(_) if !is_movable_asset(kinds, value) => Some(TypeError::new(
            "an asset pool cannot be sent directly; split the amount to send".to_string(),
            span,
        )),
        Some(kind) if kind != NATIVE_ASSET || model.is_declared_asset(&kind) => Some(TypeError::new(
            format!(
                "a non native asset `{kind}` cannot be moved with send which transfers the native token, move it with send_asset naming its issuer"
            ),
            span,
        )),
        Some(_) => None,
    }
}

fn asset_flow_error(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    into: &str,
    value: &Expr,
    span: Span,
) -> Option<TypeError> {
    match expr_asset_kind(model, kinds, mint_kind, value) {
        None => Some(TypeError::new(
            "a value that is not an asset cannot be moved into an asset slot; move, merge, or \
             split an asset of this kind instead"
                .to_string(),
            span,
        )),
        Some(from) if from != into => Some(TypeError::new(
            format!("asset kinds do not mix: `{from}` and `{into}`"),
            span,
        )),
        Some(_) if !is_movable_asset(kinds, value) => Some(TypeError::new(
            "an asset pool cannot be copied; move or split it".to_string(),
            span,
        )),
        Some(_) => None,
    }
}

fn expr_asset_kind(
    model: &Model,
    kinds: &HashMap<String, String>,
    mint_kind: Option<&str>,
    expr: &Expr,
) -> Option<String> {
    match expr {
        Expr::Ident(id) => kinds.get(id.text.as_str()).cloned().or_else(|| {
            model
                .state
                .get(id.text.as_str())
                .and_then(|f| asset_inner(&f.ty))
                .map(|s| s.to_string())
        }),
        Expr::Call { callee, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if name.text == "split" {
                    return expr_asset_kind(model, kinds, mint_kind, base);
                }
            }
            if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "mint") {
                return mint_kind.map(|s| s.to_string());
            }
            None
        }
        _ => None,
    }
}

fn is_movable_asset(kinds: &HashMap<String, String>, value: &Expr) -> bool {
    match value {
        Expr::Ident(id) => kinds.contains_key(id.text.as_str()),
        Expr::Call { callee, .. } => match callee.as_ref() {
            Expr::Field { name, .. } => name.text == "split",
            Expr::Ident(id) => id.text == "mint",
            _ => false,
        },
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
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            walk(expr, f)
        }
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

    #[test]
    fn a_kind_pinned_to_two_issuers_is_refused() {
        let src = "contract D { state { issuer_a: Q_Address; issuer_b: Q_Address; \
                   reserve_a: Q_Asset<TOKA>; } genesis { issuer_a = deploy_params.a; issuer_b = deploy_params.b; } \
                   entry add(funds: Q_Asset<TOKA>) reads(issuer_a) conserves TOKA writes(reserve_a) \
                   { guard in_asset == issuer_a; reserve_a.merge(funds); } \
                   entry add_too(funds: Q_Asset<TOKA>) reads(issuer_b) conserves TOKA writes(reserve_a) \
                   { guard in_asset == issuer_b; reserve_a.merge(funds); } }";
        assert!(error_for(src).contains("received under more than one issuer"));
    }

    #[test]
    fn a_split_leaves_only_under_its_own_issuer() {
        let dex = |issuer: &str| {
            format!(
                "contract D {{ state {{ operator: Q_Address; issuer_a: Q_Address; issuer_b: Q_Address; \
                 reserve_a: Q_Asset<TOKA>; reserve_b: Q_Asset<TOKB>; }} \
                 genesis {{ operator = deployer; issuer_a = deploy_params.a; issuer_b = deploy_params.b; }} \
                 entry add_b(funds: Q_Asset<TOKB>) reads(issuer_b) conserves TOKB writes(reserve_b) \
                 {{ guard in_asset == issuer_b; reserve_b.merge(funds); }} \
                 entry swap(input: Q_Asset<TOKA>, order: SwapOrder signed by operator) reads(issuer_a) \
                 conserves TOKA conserves TOKB writes(reserve_a, reserve_b) \
                 {{ guard in_asset == issuer_a; guard input.amount == order.in_amt; reserve_a.merge(input); \
                 send_asset({issuer}, order.to, reserve_b.split(order.out)); }} }}"
            )
        };
        assert!(error_for(&dex("issuer_a")).contains("not the one `TOKB` is received from"));
        let program = quanta_parser::parse(&dex("issuer_b")).expect("parses");
        let model = crate::model::Model::build(&program.contracts[0]);
        assert!(super::check(&model).is_ok());
    }

    #[test]
    fn a_non_native_asset_sent_with_send_is_rejected() {
        let src = "contract C { asset TKN; state { x: u64; } \
                   entry transfer(funds: Q_Asset<TKN>, to: Q_Address) conserves TKN writes(x) \
                   { x = funds.amount; send(to, funds); } }";
        let msg = error_for(src);
        assert!(msg.contains("send_asset"), "got: {msg}");
    }

    #[test]
    fn a_declared_asset_that_shadows_the_native_name_cannot_be_sent_with_send() {
        let src = "contract C { asset QTOV; state { x: u64; } \
                   entry t(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(x) \
                   { x = funds.amount; send(to, funds); } }";
        let msg = error_for(src);
        assert!(msg.contains("send_asset"), "got: {msg}");
    }

    #[test]
    fn pinning_in_asset_to_a_parameter_the_caller_picks_is_not_naming_the_asset() {
        let src = "contract C { state { paid: u128; } \
                   entry pay(funds: Q_Asset<QTOV>, pay_token: Q_Address) conserves QTOV writes(paid) \
                   { guard in_asset == pay_token; paid = funds.amount; } }";
        assert!(error_for(src).contains("never says which one"));
    }

    #[test]
    fn pinning_in_asset_to_a_stored_issuer_names_the_asset() {
        let src = "contract C { asset TKN; state { token: Q_Address; paid: u128; } \
                   entry pay(funds: Q_Asset<TKN>) conserves TKN writes(paid) \
                   { guard in_asset == token; paid = funds.amount; } }";
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        let result = super::check(&model);
        assert!(
            result
                .as_ref()
                .err()
                .map_or(true, |e| !e.message.contains("never says which one")),
            "a stored issuer satisfies the rule: {:?}",
            result.err().map(|e| e.message)
        );
    }

    #[test]
    fn sending_the_native_asset_with_send_still_compiles() {
        let src = "contract C { state { x: u64; } \
                   entry pay(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV writes(x) \
                   { guard in_asset == native; x = funds.amount; send(to, funds); } }";
        ok(src);
    }

    #[test]
    fn crediting_an_asset_amount_while_sending_the_asset_is_rejected() {
        let src = "contract C { state { balance: Map<Q_Address, u128>; } \
                   entry inflate(funds: Q_Asset<QTOV>) conserves QTOV writes(balance) \
                   { balance.credit(caller, funds.amount); send(caller, funds); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn crediting_a_wrapped_asset_amount_while_sending_the_asset_is_rejected() {
        let src = "contract C { state { balance: Map<Q_Address, u128>; } \
                   entry cashback(funds: Q_Asset<QTOV>) conserves QTOV writes(balance) \
                   { balance.credit(caller, funds.amount + 0); send(caller, funds); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn crediting_a_let_aliased_asset_amount_while_sending_the_asset_is_rejected() {
        let src = "contract C { state { balance: Map<Q_Address, u128>; } \
                   entry cashback(funds: Q_Asset<QTOV>) conserves QTOV writes(balance) \
                   { let a = funds.amount; balance.credit(caller, a); send(caller, funds); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn crediting_an_asset_amount_while_merging_it_into_a_backing_pool_is_accepted() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; balance: Map<Q_Address, u128>; } \
                   entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(vault, balance) \
                   { guard in_asset == native; balance.credit(caller, funds.amount); vault.merge(funds); } }";
        ok(src);
    }

    #[test]
    fn crediting_an_asset_then_splitting_value_out_of_its_backing_pool_is_rejected() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; balance: Map<Q_Address, u128>; } \
                   entry deposit(funds: Q_Asset<QTOV>, rebate: u128) conserves QTOV writes(vault, balance) \
                   { balance.credit(caller, funds.amount); vault.merge(funds); send(caller, vault.split(rebate)); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn laundering_a_credited_asset_through_a_second_pool_is_rejected() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; treasury: Q_Asset<QTOV>; balance: Map<Q_Address, u128>; } \
                   entry deposit(funds: Q_Asset<QTOV>, amt: u128) conserves QTOV writes(vault, treasury, balance) \
                   { balance.credit(caller, funds.amount); vault.merge(funds); treasury.merge(vault.split(amt)); send(caller, treasury.split(amt)); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn sending_a_credited_pools_value_through_a_local_split_is_rejected() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; balance: Map<Q_Address, u128>; } \
                   entry deposit(funds: Q_Asset<QTOV>, amt: u128) conserves QTOV writes(vault, balance) \
                   { balance.credit(caller, funds.amount); vault.merge(funds); let out = vault.split(amt); send(caller, out); } }";
        assert!(error_for(src).contains("sent away"));
    }

    #[test]
    fn moving_credited_value_between_backing_pools_without_sending_is_accepted() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; treasury: Q_Asset<QTOV>; balance: Map<Q_Address, u128>; } \
                   entry deposit(funds: Q_Asset<QTOV>, amt: u128) conserves QTOV writes(vault, treasury, balance) \
                   { guard in_asset == native; balance.credit(caller, funds.amount); vault.merge(funds); treasury.merge(vault.split(amt)); } }";
        ok(src);
    }

    #[test]
    fn merging_two_different_asset_kinds_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { vault: Q_Asset<GOLD>; } \
                   entry deposit(funds: Q_Asset<DUST>) conserves DUST writes(vault) \
                   { vault.merge(funds); } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn conserving_the_wrong_asset_is_rejected() {
        let src = "contract C { asset TKN; state { poolt: Q_Asset<TKN>; } \
                   entry deposit(funds: Q_Asset<TKN>) conserves QTOV writes(poolt) \
                   { poolt.merge(funds); } }";
        assert!(error_for(src).contains("accounting is unstated"));
    }

    #[test]
    fn moving_an_asset_with_no_accounting_clause_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry deposit(funds: Q_Asset<QTOV>) writes(pool) \
                   { pool.merge(funds); } }";
        assert!(error_for(src).contains("accounting is unstated"));
    }

    #[test]
    fn minting_into_a_pool_of_a_different_kind_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { owner: Q_Address; dustp: Q_Asset<DUST>; } \
                   entry issue(order: Order signed by owner) mints GOLD writes(dustp) \
                   { dustp.merge(mint(order.amount)); } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn storing_an_asset_into_a_pool_of_a_different_kind_is_rejected() {
        let src = "contract C { asset GOLD; asset DUST; state { vault: Q_Asset<GOLD>; } \
                   entry swap(funds: Q_Asset<DUST>) conserves DUST writes(vault) \
                   { vault = funds; } }";
        assert!(error_for(src).contains("do not mix"));
    }

    #[test]
    fn storing_an_asset_amount_scalar_into_an_asset_slot_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) \
                   { pool = funds.amount; } }";
        assert!(error_for(src).contains("not an asset"));
    }

    #[test]
    fn copying_one_asset_pool_into_another_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; pool2: Q_Asset<QTOV>; } \
                   entry dup(order: Order) conserves QTOV writes(pool) { pool = pool2; } }";
        assert!(error_for(src).contains("cannot be copied"));
    }

    #[test]
    fn merging_a_non_asset_scalar_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) \
                   { pool.merge(funds.amount); } }";
        assert!(error_for(src).contains("not an asset"));
    }

    #[test]
    fn sending_a_non_asset_scalar_is_rejected() {
        let src = "contract C { state { a: u64; } \
                   entry drip(funds: Q_Asset<QTOV>, to: Q_Address) conserves QTOV \
                   { send(to, funds.amount); send(caller, funds); } }";
        assert!(error_for(src).contains("not an asset"));
    }

    #[test]
    fn a_let_that_aliases_a_state_pool_is_rejected() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; pool2: Q_Asset<QTOV>; } \
                   entry mv(order: Order) conserves QTOV writes(pool2) \
                   { let x = pool; pool2.merge(x); } }";
        assert!(error_for(src).contains("alias a state asset pool"));
    }

    #[test]
    fn moving_an_asset_into_a_slot_is_accepted() {
        let src = "contract C { state { pool: Q_Asset<QTOV>; } \
                   entry dep(funds: Q_Asset<QTOV>) conserves QTOV writes(pool) { guard in_asset == native; pool = funds; } }";
        ok(src);
    }

    #[test]
    fn merging_the_same_asset_kind_is_accepted() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; } \
                   entry deposit(funds: Q_Asset<QTOV>) conserves QTOV writes(vault) \
                   { guard in_asset == native; vault.merge(funds); } }";
        ok(src);
    }

    #[test]
    fn splitting_a_pool_and_merging_it_back_matches() {
        let src = "contract C { state { vault: Q_Asset<QTOV>; pending: Q_Asset<QTOV>; } \
                   entry shuffle(order: Order) conserves QTOV writes(vault, pending) \
                   { guard in_asset == native; let out = vault.split(order.amount); pending.merge(out); } }";
        ok(src);
    }
}
