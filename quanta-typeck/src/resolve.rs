// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::Model;
use quanta_ast::{AfterTarget, Clause, EntryDecl, Expr, GenericArg, Item, Stmt, Type};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

pub fn check(model: &Model) -> Result<(), TypeError> {
    check_no_duplicate_fields(model)?;
    check_no_duplicate_events(model)?;
    check_one_asset_when_minting(model)?;
    check_no_duplicate_entries(model)?;
    check_no_shadowed_names(model)?;
    check_emit_arity(model)?;
    check_deployer_only_in_genesis(model)?;
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

fn check_no_duplicate_events(model: &Model) -> Result<(), TypeError> {
    let mut seen: HashSet<&str> = HashSet::new();
    for item in &model.contract.items {
        if let Item::Event(decl) = item {
            if !seen.insert(decl.name.text.as_str()) {
                return Err(TypeError::new(
                    format!("event `{}` is declared more than once", decl.name.text),
                    decl.name.span,
                ));
            }
        }
    }
    Ok(())
}

fn mints_asset_in(stmt: &Stmt) -> Option<quanta_lexer::Span> {
    fn in_expr(expr: &Expr) -> Option<quanta_lexer::Span> {
        match expr {
            Expr::Call { callee, args, span } => {
                if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "mint_asset") {
                    return Some(*span);
                }
                in_expr(callee).or_else(|| args.iter().find_map(in_expr))
            }
            Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
                in_expr(expr)
            }
            Expr::Binary { left, right, .. } => in_expr(left).or_else(|| in_expr(right)),
            Expr::Field { base, .. } => in_expr(base),
            _ => None,
        }
    }
    match stmt {
        Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => in_expr(expr),
        Stmt::Let { value, .. } => in_expr(value),
        Stmt::Emit { args, .. } => args.iter().find_map(in_expr),
        Stmt::Assign { target, value, .. } => in_expr(target).or_else(|| in_expr(value)),
    }
}

fn check_one_asset_when_minting(model: &Model) -> Result<(), TypeError> {
    let declared = model
        .contract
        .items
        .iter()
        .filter(|item| matches!(item, Item::Asset(_)))
        .count();
    if declared <= 1 {
        return Ok(());
    }
    let bodies = model.contract.items.iter().flat_map(|item| match item {
        Item::Entry(e) => e.body.as_slice(),
        Item::Genesis(g) => g.body.as_slice(),
        _ => &[],
    });
    for stmt in bodies {
        if let Some(span) = mints_asset_in(stmt) {
            return Err(TypeError::new(
                "`mint_asset` names no asset, and this contract declares more than one, so \
                 every declared asset would share one on chain supply"
                    .to_string(),
                span,
            ));
        }
    }
    Ok(())
}

fn check_no_duplicate_fields(model: &Model) -> Result<(), TypeError> {
    let mut seen: HashSet<&str> = HashSet::new();
    for item in &model.contract.items {
        if let Item::State(block) = item {
            for field in &block.fields {
                if !seen.insert(field.name.text.as_str()) {
                    return Err(TypeError::new(
                        format!(
                            "state field `{}` is declared more than once",
                            field.name.text
                        ),
                        field.name.span,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn check_emit_arity(model: &Model) -> Result<(), TypeError> {
    let mut events: HashMap<&str, usize> = HashMap::new();
    for item in &model.contract.items {
        if let Item::Event(decl) = item {
            events.insert(decl.name.text.as_str(), decl.params.len());
        }
    }
    for entry in &model.entries {
        check_emit_arity_in(&entry.body, &events)?;
    }
    for item in &model.contract.items {
        if let Item::Genesis(genesis) = item {
            check_emit_arity_in(&genesis.body, &events)?;
        }
    }
    Ok(())
}

fn check_emit_arity_in(body: &[Stmt], events: &HashMap<&str, usize>) -> Result<(), TypeError> {
    for stmt in body {
        if let Stmt::Emit { name, args, span } = stmt {
            let Some(declared) = events.get(name.text.as_str()) else {
                return Err(TypeError::new(
                    format!("the event `{}` is emitted but never declared", name.text),
                    *span,
                ));
            };
            if args.len() != *declared {
                return Err(TypeError::new(
                    format!(
                        "the event `{}` is declared with {declared} field(s) but emitted                          with {}, so the record written would not match the signature the                          selector publishes",
                        name.text,
                        args.len()
                    ),
                    *span,
                ));
            }
        }
    }
    Ok(())
}

fn check_no_shadowed_names(model: &Model) -> Result<(), TypeError> {
    let mut fields: HashSet<&str> = HashSet::new();
    for item in &model.contract.items {
        if let Item::State(block) = item {
            for field in &block.fields {
                fields.insert(field.name.text.as_str());
            }
        }
    }
    for entry in &model.entries {
        let mut params: HashSet<&str> = HashSet::new();
        for param in &entry.params {
            let name = param.name.text.as_str();
            if fields.contains(name) {
                return Err(TypeError::new(
                    format!(
                        "the parameter `{name}` has the same name as a state field, and the                          two resolve differently, so the body would read the field where the                          signature says the parameter"
                    ),
                    param.name.span,
                ));
            }
            if !params.insert(name) {
                return Err(TypeError::new(
                    format!("the parameter `{name}` is declared more than once"),
                    param.name.span,
                ));
            }
        }
        check_no_shadowed_lets(&entry.body, &fields, &params)?;
    }
    Ok(())
}

fn check_no_shadowed_lets(
    body: &[Stmt],
    fields: &HashSet<&str>,
    params: &HashSet<&str>,
) -> Result<(), TypeError> {
    for stmt in body {
        if let Stmt::Let { name, span, .. } = stmt {
            let text = name.text.as_str();
            if fields.contains(text) {
                return Err(TypeError::new(
                    format!(
                        "the local `{text}` has the same name as a state field, so an                          invariant or a later read naming it would take the local instead                          of the field"
                    ),
                    *span,
                ));
            }
            if params.contains(text) {
                return Err(TypeError::new(
                    format!("the local `{text}` has the same name as a parameter"),
                    *span,
                ));
            }
        }
    }
    Ok(())
}

fn check_no_duplicate_entries(model: &Model) -> Result<(), TypeError> {
    let mut seen: HashSet<String> = HashSet::new();
    for entry in &model.entries {
        let signature = entry_signature(entry);
        if !seen.insert(signature.clone()) {
            return Err(TypeError::new(
                format!(
                    "entry `{signature}` is declared more than once; it collides on one selector"
                ),
                entry.name.span,
            ));
        }
    }
    Ok(())
}

fn entry_signature(entry: &EntryDecl) -> String {
    let params = entry
        .params
        .iter()
        .map(|p| type_signature(&p.ty))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}({params})", entry.name.text)
}

fn type_signature(ty: &Type) -> String {
    if ty.args.is_empty() {
        return ty.name.text.clone();
    }
    let args = ty
        .args
        .iter()
        .map(|arg| match arg {
            GenericArg::Type(t) => type_signature(t),
            GenericArg::Int(i) => i.text.clone(),
            GenericArg::MofN { m, n, .. } => format!("{} of {}", m.text, n.text),
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{}<{args}>", ty.name.text)
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

fn check_deployer_only_in_genesis(model: &Model) -> Result<(), TypeError> {
    let refuse = |span: Span| {
        TypeError::new(
            "`deployer` is only known while genesis runs. Store it there, for example \
             `owner = deployer;`, and compare against that field; inside an entry it would \
             read as the current caller"
                .to_string(),
            span,
        )
    };
    for item in &model.contract.items {
        let mut exprs: Vec<&Expr> = Vec::new();
        match item {
            Item::Invariant(decl) => exprs.push(&decl.expr),
            Item::Entry(entry) => {
                for param in &entry.params {
                    if let Some(signer) = &param.signed_by {
                        if signer.text == "deployer" {
                            return Err(refuse(signer.span));
                        }
                    }
                }
                for clause in &entry.clauses {
                    match clause {
                        Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                            exprs.push(expr)
                        }
                        Clause::After { target, from, .. } => {
                            if let AfterTarget::Expr(expr) = target {
                                exprs.push(expr);
                            }
                            if let Some(expr) = from {
                                exprs.push(expr);
                            }
                        }
                        _ => {}
                    }
                }
                let mut found: Option<Span> = None;
                for stmt in &entry.body {
                    for_each_expr(stmt, &mut |expr| note_deployer(expr, &mut found));
                }
                if let Some(span) = found {
                    return Err(refuse(span));
                }
            }
            _ => {}
        }
        let mut found: Option<Span> = None;
        for expr in exprs {
            walk(expr, &mut |e| note_deployer(e, &mut found));
        }
        if let Some(span) = found {
            return Err(refuse(span));
        }
    }
    Ok(())
}

fn note_deployer(expr: &Expr, found: &mut Option<Span>) {
    if found.is_none() {
        if let Expr::Ident(id) = expr {
            if id.text == "deployer" {
                *found = Some(id.span);
            }
        }
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
        Expr::Int(_)
        | Expr::Date { .. }
        | Expr::Str(_)
        | Expr::Ident(_)
        | Expr::Caller { .. }
        | Expr::Native { .. }
        | Expr::InAsset { .. }
        | Expr::Now { .. } => {}
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

    fn accepted(src: &str) -> bool {
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        super::check(&model).is_ok()
    }

    #[test]
    fn deployer_inside_an_entry_is_refused_because_it_would_read_as_the_caller() {
        let guard = "contract Admin { state { owner: Q_Address; fee: u64; } \
                     genesis { owner = deployer; } \
                     entry set_fee(bps: u64) writes(fee) { guard caller == deployer; fee = bps; } }";
        assert!(error_for(guard).contains("only known while genesis runs"));

        let denies = "contract Admin { state { owner: Q_Address; fee: u64; } \
                      genesis { owner = deployer; } \
                      entry set_fee(bps: u64) writes(fee) denies caller != deployer { fee = bps; } }";
        assert!(error_for(denies).contains("only known while genesis runs"));

        let assign = "contract Admin { state { owner: Q_Address; } \
                      genesis { owner = deployer; } \
                      entry reset() writes(owner) { owner = deployer; } }";
        assert!(error_for(assign).contains("only known while genesis runs"));
    }

    #[test]
    fn a_genesis_emit_of_the_wrong_arity_is_refused() {
        let src = "contract C { state { a: u64; } event Minted(amount: u64); \
                   genesis { emit Minted(1, 2, 3); } entry f() writes(a) { a = 1; } }";
        assert!(error_for(src).contains("declared with 1 field"));
    }

    #[test]
    fn deployer_in_genesis_and_the_stored_owner_in_an_entry_are_accepted() {
        let src = "contract Admin { state { owner: Q_Address; fee: u64; } \
                   genesis { owner = deployer; } \
                   entry set_fee(bps: u64) writes(fee) { guard caller == owner; fee = bps; } }";
        assert!(accepted(src));
    }

    #[test]
    fn writes_must_name_a_state_field() {
        let src = "contract C { state { a: u64; } entry f() writes(b) { } }";
        assert!(error_for(src).contains("not a state field"));
    }

    #[test]
    fn a_field_declared_twice_is_rejected() {
        let src = "contract C { state { a: u64; a: Q_Address; } entry f() { } }";
        assert!(error_for(src).contains("declared more than once"));
    }

    #[test]
    fn two_entries_that_collide_on_one_selector_are_rejected() {
        let src = "contract C { state { a: u64; } \
                   entry e() writes(a) { a = 1; } entry e() writes(a) { a = 2; } }";
        assert!(error_for(src).contains("collides on one selector"));
    }

    #[test]
    fn entries_overloaded_by_parameter_type_are_accepted() {
        let src = "contract C { state { a: u64; } \
                   entry e(x: u64) writes(a) { a = x; } entry e(t: Q_Address) writes(a) { a = 1; } }";
        let program = quanta_parser::parse(src).expect("source parses");
        let model = Model::build(&program.contracts[0]);
        super::check(&model).expect("a valid overload is accepted");
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
