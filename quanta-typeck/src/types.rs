// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::{is_asset_param, is_integer_type, Model};
use quanta_ast::{
    AfterTarget, AssignOp, BinOp, Clause, EntryDecl, Expr, GenericArg, Item, Stmt, Type, UnaryOp,
};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Int,
    Bool,
    Address,
    Asset,
    Hash,
    Name,
    Time,
    Str,
    Collection,
    Unknown,
}

struct Env<'a> {
    model: &'a Model<'a>,
    params: HashMap<&'a str, Ty>,
    locals: std::cell::RefCell<HashMap<String, Ty>>,
    genesis: bool,
}

const MAX_GUARDIAN_SET: u64 = 256;

fn guardian_bound(ty: &Type) -> Result<(), TypeError> {
    if ty.name.text != "GuardianSet" {
        return Ok(());
    }
    let members = match ty.args.first() {
        Some(GenericArg::Int(i)) => i.text.replace('_', "").parse::<u64>().ok(),
        _ => None,
    };
    match members {
        Some(n) if (1..=MAX_GUARDIAN_SET).contains(&n) => Ok(()),
        _ => Err(TypeError::new(
            format!("a guardian set must declare between 1 and {MAX_GUARDIAN_SET} members"),
            ty.span,
        )),
    }
}

fn storable(ty: &Type) -> Result<(), TypeError> {
    let refuse = |what: String, at| Err(TypeError::new(what, at));
    match ty.name.text.as_str() {
        "Q_Name" => refuse(
            "a name cannot be stored, a slot keeps only its first eight bytes; key a map or \
             registry by the name instead"
                .into(),
            ty.span,
        ),
        keyed @ ("Map" | "Registry") => {
            let arity = if keyed == "Map" { 2 } else { 1 };
            if ty.args.len() != arity {
                return refuse(format!("a {keyed} takes {arity} type arguments"), ty.span);
            }
            for (index, arg) in ty.args.iter().enumerate() {
                let GenericArg::Type(inner) = arg else {
                    return refuse(format!("a {keyed} takes only type arguments"), ty.span);
                };
                let is_key = index == 0;
                let fits = match ty_of_decl(inner) {
                    Ty::Name => is_key || keyed == "Map",
                    Ty::Unknown | Ty::Asset | Ty::Str | Ty::Collection => false,
                    _ => inner.args.is_empty(),
                };
                if !fits {
                    return refuse(
                        format!(
                            "`{}` cannot be a {keyed} {}",
                            type_text(inner),
                            if is_key { "key" } else { "value" }
                        ),
                        inner.span,
                    );
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn type_text(ty: &Type) -> String {
    if ty.args.is_empty() {
        return ty.name.text.clone();
    }
    let args: Vec<String> = ty
        .args
        .iter()
        .map(|arg| match arg {
            GenericArg::Type(inner) => type_text(inner),
            GenericArg::Int(i) => i.text.clone(),
            _ => "_".into(),
        })
        .collect();
    format!("{}<{}>", ty.name.text, args.join(", "))
}

pub fn check(model: &Model) -> Result<(), TypeError> {
    let defaults = Env::new(model, HashMap::new());
    for item in &model.contract.items {
        if let Item::State(block) = item {
            for field in &block.fields {
                storable(&field.ty)?;
                let Some(value) = &field.default else {
                    continue;
                };
                if matches!(
                    field.ty.name.text.as_str(),
                    "Map" | "Registry" | "GuardianSet" | "Q_Asset"
                ) {
                    return Err(TypeError::new(
                        format!("a {} field cannot take a default value", field.ty.name.text),
                        value.span(),
                    ));
                }
                defaults.check_stmt_types(&Stmt::Assign {
                    target: Expr::Ident(field.name.clone()),
                    op: AssignOp::Set,
                    value: value.clone(),
                    span: field.span,
                })?;
            }
        }
    }
    for field in model.state.values() {
        guardian_bound(&field.ty)?;
    }
    for entry in &model.entries {
        for param in &entry.params {
            guardian_bound(&param.ty)?;
        }
    }
    for item in &model.contract.items {
        if let Item::Invariant(inv) = item {
            let env = Env::new(model, HashMap::new());
            env.expect_predicate(&inv.expr)?;
        }
    }
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    check_key_kinds(model)?;
    for item in &model.contract.items {
        if let Item::Genesis(genesis) = item {
            let env = Env::new(model, HashMap::new()).in_genesis();
            for stmt in &genesis.body {
                env.check_stmt_types(stmt)?;
                asset_calls_consumed(stmt)?;
            }
        }
    }
    Ok(())
}

fn wraps(expr: &Expr, wrapped: &std::collections::HashSet<&str>) -> bool {
    match expr {
        Expr::Wrapping { .. } => true,
        Expr::Ident(id) => wrapped.contains(id.text.as_str()),
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } => wraps(expr, wrapped),
        Expr::Binary { left, right, .. } => wraps(left, wrapped) || wraps(right, wrapped),
        Expr::Call { args, .. } => args.iter().any(|a| wraps(a, wrapped)),
        _ => false,
    }
}

fn narrow_wrapping(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let refuse = |at: &Expr, slot: &str| {
        Err(TypeError::new(
            format!(
                "a `wrapping` value reaches the narrow {slot}, which reverts at its maximum rather \
                 than wrapping; widen it to u64 or mask the value explicitly"
            ),
            at.span(),
        ))
    };
    let mut wrapped: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for stmt in &entry.body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                if wraps(value, &wrapped) {
                    wrapped.insert(name.text.as_str());
                }
            }
            Stmt::Assign {
                target: Expr::Ident(id),
                value,
                ..
            } => {
                let narrow = model
                    .state
                    .get(id.text.as_str())
                    .and_then(|field| narrow_max(&field.ty.name.text));
                if narrow.is_some() && wraps(value, &wrapped) {
                    return refuse(value, &format!("field `{}`", id.text));
                }
            }
            Stmt::Expr {
                expr: Expr::Call { callee, args, .. },
                ..
            } => {
                if let Expr::Field { base, name, .. } = callee.as_ref() {
                    if name.text == "set" {
                        if let (Expr::Ident(map), Some(value)) = (base.as_ref(), args.get(1)) {
                            let narrow = model.state.get(map.text.as_str()).and_then(|field| {
                                match field.ty.args.get(1) {
                                    Some(GenericArg::Type(t)) => narrow_max(&t.name.text),
                                    _ => None,
                                }
                            });
                            if narrow.is_some() && wraps(value, &wrapped) {
                                return refuse(value, &format!("values of `{}`", map.text));
                            }
                        }
                    }
                }
            }
            Stmt::Emit { name, args, .. } => {
                let params = model.contract.items.iter().find_map(|item| match item {
                    quanta_ast::Item::Event(e) if e.name.text == name.text => Some(&e.params),
                    _ => None,
                });
                for (index, arg) in args.iter().enumerate() {
                    let narrow = params
                        .and_then(|p| p.get(index))
                        .and_then(|p| narrow_max(&p.ty.name.text));
                    if narrow.is_some() && wraps(arg, &wrapped) {
                        return refuse(arg, &format!("event field of `{}`", name.text));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    narrow_wrapping(model, entry)?;
    let mut params = HashMap::new();
    for param in &entry.params {
        params.insert(param.name.text.as_str(), ty_of_decl(&param.ty));
    }
    let env = Env::new(model, params);

    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                env.expect_predicate(expr)?;
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { expr, .. } => env.expect_predicate(expr)?,
            Stmt::Let { name, value, .. } => {
                let ty = env.ty_of(value)?;
                if ty == Ty::Collection {
                    return Err(TypeError::new(
                        "a map, registry or guardian set cannot be bound to a local",
                        value.span(),
                    ));
                }
                env.locals.borrow_mut().insert(name.text.clone(), ty);
            }
            Stmt::Assign { .. } | Stmt::Expr { .. } => {
                env.check_stmt_types(stmt)?;
                if let Stmt::Expr { expr, .. } = stmt {
                    env.refuse_name_recipient(expr)?;
                }
            }
            Stmt::Emit { name, args, .. } => {
                for arg in args {
                    env.ty_of(arg)?;
                }
                env.check_emit_fields(&name.text, args)?;
            }
        }
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => no_asset_call(expr)?,
            Clause::After { target, from, .. } => {
                if let AfterTarget::Expr(expr) = target {
                    no_asset_call(expr)?;
                }
                if let Some(expr) = from {
                    no_asset_call(expr)?;
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        asset_calls_consumed(stmt)?;
    }
    check_arithmetic(entry, &env.params)?;
    Ok(())
}

impl<'a> Env<'a> {
    fn new(model: &'a Model<'a>, params: HashMap<&'a str, Ty>) -> Env<'a> {
        Env {
            model,
            params,
            locals: std::cell::RefCell::new(HashMap::new()),
            genesis: false,
        }
    }

    fn in_genesis(mut self) -> Env<'a> {
        self.genesis = true;
        self
    }

    fn is_name_param(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Ident(id) if self.params.get(id.text.as_str()) == Some(&Ty::Name))
    }

    fn check_emit_fields(&self, event: &str, args: &[Expr]) -> Result<(), TypeError> {
        let declared = self
            .model
            .contract
            .items
            .iter()
            .find_map(|item| match item {
                Item::Event(ev) if ev.name.text == event => Some(ev),
                _ => None,
            });
        let Some(declared) = declared else {
            return Ok(());
        };
        for (arg, field) in args.iter().zip(&declared.params) {
            let want = ty_of_decl(&field.ty);
            let got = self.ty_of(arg)?;
            let mismatch = match (want, got) {
                (Ty::Name, got) => got != Ty::Name || !self.is_name_param(arg),
                (_, Ty::Name) => true,
                (_, Ty::Collection) | (Ty::Collection, _) => true,
                _ => false,
            };
            if mismatch {
                return Err(TypeError::new(
                    format!(
                        "the event field `{}` is declared {}, so it cannot carry a {} value; \
                         declare a name field as Q_Name and pass a name parameter",
                        field.name.text,
                        type_text(&field.ty),
                        got.describe()
                    ),
                    arg.span(),
                ));
            }
        }
        Ok(())
    }

    fn check_stmt_types(&self, stmt: &Stmt) -> Result<(), TypeError> {
        match stmt {
            Stmt::Assign {
                target, op, value, ..
            } => {
                let slot = self.ty_of(target)?;
                let given = self.ty_of(value)?;
                if slot == Ty::Asset {
                    return Err(TypeError::new(
                        "an asset field changes only by merge, split or send; assigning it \
                         would discard what it already holds",
                        target.span(),
                    ));
                }
                if *op == AssignOp::Set && given == Ty::Name && slot == Ty::Address {
                    if let Expr::Ident(id) = target {
                        let scalar_address = self
                            .model
                            .state
                            .get(id.text.as_str())
                            .is_some_and(|field| field.ty.name.text == "Q_Address");
                        if scalar_address {
                            return Err(TypeError::new(
                                format!(
                                    "a name cannot become an address; `{}` authorises signatures \
                                     and receives sends, and a name window is not a key anyone holds",
                                    id.text
                                ),
                                value.span(),
                            ));
                        }
                    }
                }
                let from_deploy_params = self.genesis
                    && matches!(
                        value,
                        Expr::Field { base, .. } if matches!(base.as_ref(), Expr::Ident(id) if id.text == "deploy_params")
                    );
                let fits = match op {
                    AssignOp::Set => {
                        compatible(slot, given)
                            || (slot == Ty::Collection
                                && given == Ty::Unknown
                                && from_deploy_params)
                    }
                    AssignOp::Add | AssignOp::Sub => numeric(slot) && numeric(given),
                };
                if let Expr::Ident(id) = target {
                    let narrow = self
                        .model
                        .state
                        .get(id.text.as_str())
                        .and_then(|field| narrow_max(&field.ty.name.text));
                    if narrow.is_some() && matches!(value, Expr::Wrapping { .. }) {
                        return Err(TypeError::new(
                            format!(
                                "`wrapping` on the narrow field `{}` reverts at its maximum rather \
                                 than wrapping; widen the field to u64 or mask the value explicitly",
                                id.text
                            ),
                            value.span(),
                        ));
                    }
                }
                if let (Expr::Ident(id), Expr::Int(lit)) = (target, value) {
                    let max = self
                        .model
                        .state
                        .get(id.text.as_str())
                        .and_then(|field| narrow_max(&field.ty.name.text));
                    let literal = lit.text.replace('_', "").parse::<u128>().ok();
                    if let (Some(max), Some(literal)) = (max, literal) {
                        if literal > u128::from(max) {
                            return Err(TypeError::new(
                                format!(
                                    "{literal} does not fit `{}`, whose largest value is {max}",
                                    id.text
                                ),
                                value.span(),
                            ));
                        }
                    }
                }
                if !fits {
                    return Err(TypeError::new(
                        format!(
                            "a {} value cannot be stored in a {} slot",
                            given.describe(),
                            slot.describe()
                        ),
                        value.span(),
                    ));
                }
                Ok(())
            }
            Stmt::Expr { expr, .. } => {
                self.ty_of(expr)?;
                self.check_keyed_call(expr)
            }
            _ => Ok(()),
        }
    }

    fn check_keyed_call(&self, expr: &Expr) -> Result<(), TypeError> {
        let Expr::Call { callee, args, .. } = expr else {
            return Ok(());
        };
        let Expr::Field { base, name, .. } = callee.as_ref() else {
            return Ok(());
        };
        let Some(field) = self.keyed_field(base) else {
            return Ok(());
        };
        let key = declared_arg(&field.ty, 0);
        let value = declared_arg(&field.ty, 1);
        if matches!(name.text.as_str(), "credit" | "debit") {
            if let Some(amount) = args.get(1) {
                if !matches!(self.ty_of(amount)?, Ty::Int | Ty::Asset | Ty::Unknown) {
                    return Err(TypeError::new(
                        format!("`{}` moves only a number or an asset amount", name.text),
                        amount.span(),
                    ));
                }
            }
        }
        let expected: &[Ty] = match name.text.as_str() {
            "set" => &[key, value],
            "insert" | "remove" | "contains" | "get" | "credit" | "debit" => &[key],
            _ => return Ok(()),
        };
        for (index, (arg, want)) in args.iter().zip(expected).enumerate() {
            let got = self.ty_of(arg)?;
            if got == Ty::Name && !self.is_name_param(arg) {
                return Err(TypeError::new(
                    format!(
                        "`{}` takes a name only straight from a Q_Name parameter, whose \
                         characters and length the entry checks",
                        field.name.text
                    ),
                    arg.span(),
                ));
            }
            let named_key = index == 0 && got == Ty::Name;
            if *want == Ty::Name && got != Ty::Name {
                return Err(TypeError::new(
                    format!(
                        "`{}` is keyed by Q_Name, so it takes a Q_Name parameter here",
                        field.name.text
                    ),
                    arg.span(),
                ));
            }
            if !named_key && !compatible(*want, got) {
                return Err(TypeError::new(
                    format!(
                        "`{}` holds {} here, not a {} value",
                        field.name.text,
                        want.describe(),
                        got.describe()
                    ),
                    arg.span(),
                ));
            }
        }
        Ok(())
    }

    fn keyed_field(&self, base: &Expr) -> Option<&'a quanta_ast::FieldDecl> {
        let Expr::Ident(id) = base else {
            return None;
        };
        if self.params.contains_key(id.text.as_str()) {
            return None;
        }
        let field = self.model.state.get(id.text.as_str())?;
        matches!(field.ty.name.text.as_str(), "Map" | "Registry").then_some(*field)
    }

    fn expect_keyed_op(&self, callee: &Expr) -> Result<(), TypeError> {
        let Expr::Field { base, name, .. } = callee else {
            return Ok(());
        };
        let Some(field) = self.keyed_field(base) else {
            return Ok(());
        };
        let method = name.text.as_str();
        let fits = match field.ty.name.text.as_str() {
            "Registry" => matches!(method, "insert" | "remove" | "contains"),
            _ => match method {
                "set" | "get" | "contains" | "remove" => true,
                "credit" | "debit" => declared_arg(&field.ty, 1) == Ty::Int,
                _ => false,
            },
        };
        if fits {
            return Ok(());
        }
        Err(TypeError::new(
            format!(
                "`{method}` does not apply to `{}`, a {}",
                field.name.text,
                type_text(&field.ty)
            ),
            name.span,
        ))
    }

    fn expect_asset_receiver(&self, callee: &Expr) -> Result<(), TypeError> {
        let Expr::Field { base, name, .. } = callee else {
            return Ok(());
        };
        if !matches!(name.text.as_str(), "merge" | "split") {
            return Ok(());
        }
        let pool = match base.as_ref() {
            Expr::Ident(id) if !self.params.contains_key(id.text.as_str()) => {
                self.model.state.get(id.text.as_str())
            }
            _ => None,
        };
        match pool {
            Some(field) if field.ty.name.text == "Q_Asset" => Ok(()),
            _ => Err(TypeError::new(
                format!("`{}` works only on a Q_Asset state field", name.text),
                base.span(),
            )),
        }
    }

    fn expect_predicate(&self, expr: &Expr) -> Result<(), TypeError> {
        let ty = self.ty_of(expr)?;
        if matches!(ty, Ty::Bool | Ty::Unknown) {
            Ok(())
        } else {
            Err(TypeError::new(
                "this clause must be a boolean condition",
                expr.span(),
            ))
        }
    }

    fn refuse_name_recipient(&self, expr: &Expr) -> Result<(), TypeError> {
        let Expr::Call { callee, args, .. } = expr else {
            return Ok(());
        };
        let positions: &[usize] = match callee.as_ref() {
            Expr::Ident(id) if id.text == "send" || id.text == "mint_asset" => &[0],
            Expr::Ident(id) if id.text == "send_asset" => &[0, 1],
            _ => return Ok(()),
        };
        for &index in positions {
            if let Some(arg) = args.get(index) {
                if self.ty_of(arg)? == Ty::Name {
                    return Err(TypeError::new(
                        "a name cannot receive funds or issue an asset; pass the address it resolves to",
                        arg.span(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn ty_of(&self, expr: &Expr) -> Result<Ty, TypeError> {
        match expr {
            Expr::Int(_) => Ok(Ty::Int),
            Expr::Date { .. } => Ok(Ty::Time),
            Expr::Str(_) => Ok(Ty::Str),
            Expr::Caller { .. } => Ok(Ty::Address),
            Expr::Native { .. } | Expr::InAsset { .. } => Ok(Ty::Address),
            Expr::Now { .. } => Ok(Ty::Int),
            Expr::Ident(id) => Ok(self.ty_of_ident(&id.text)),
            Expr::Unary { op, expr, .. } => self.ty_of_unary(*op, expr),
            Expr::Binary {
                op, left, right, ..
            } => self.ty_of_binary(*op, left, right),
            Expr::Field { name, .. } => Ok(match name.text.as_str() {
                "amount" => Ty::Int,
                "digest" => Ty::Hash,
                "first" => Ty::Time,
                "len" => Ty::Int,
                _ => Ty::Unknown,
            }),
            Expr::Call { callee, args, .. } => {
                self.expect_asset_receiver(callee)?;
                self.expect_keyed_op(callee)?;
                for arg in args {
                    self.ty_of(arg)?;
                }
                self.check_keyed_call(expr)?;
                Ok(self.ty_of_call(callee))
            }
            Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => self.ty_of(expr),
        }
    }

    fn ty_of_ident(&self, name: &str) -> Ty {
        if let Some(ty) = self.params.get(name) {
            return *ty;
        }
        if let Some(ty) = self.locals.borrow().get(name) {
            return *ty;
        }
        if let Some(field) = self.model.state.get(name) {
            return ty_of_decl(&field.ty);
        }
        if name == "deployer" {
            return Ty::Address;
        }
        Ty::Unknown
    }

    fn ty_of_call(&self, callee: &Expr) -> Ty {
        match callee {
            Expr::Field { base, name, .. } => match name.text.as_str() {
                "contains" => Ty::Bool,
                "split" => Ty::Asset,
                "get" => match self.keyed_field(base) {
                    Some(field) if field.ty.name.text == "Map" => {
                        match declared_arg(&field.ty, 1) {
                            Ty::Unknown | Ty::Time => Ty::Int,
                            known => known,
                        }
                    }
                    _ => Ty::Int,
                },
                _ => Ty::Unknown,
            },
            Expr::Ident(id) if id.text == "mint" => Ty::Asset,
            _ => Ty::Unknown,
        }
    }

    fn ty_of_unary(&self, op: UnaryOp, inner: &Expr) -> Result<Ty, TypeError> {
        let ty = self.ty_of(inner)?;
        match op {
            UnaryOp::Not => {
                expect_numeric_or(ty, Ty::Bool, inner, "`!` needs a boolean")?;
                Ok(Ty::Bool)
            }
            UnaryOp::Neg => {
                expect_numeric_or(ty, Ty::Int, inner, "`-` needs a number")?;
                Ok(Ty::Int)
            }
        }
    }

    fn ty_of_binary(&self, op: BinOp, left: &Expr, right: &Expr) -> Result<Ty, TypeError> {
        let l = self.ty_of(left)?;
        let r = self.ty_of(right)?;
        match op {
            BinOp::And | BinOp::Or => {
                expect_numeric_or(l, Ty::Bool, left, "a logical operand must be boolean")?;
                expect_numeric_or(r, Ty::Bool, right, "a logical operand must be boolean")?;
                Ok(Ty::Bool)
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem | BinOp::Shr => {
                expect_number(l, left, "arithmetic needs a number")?;
                expect_number(r, right, "arithmetic needs a number")?;
                Ok(Ty::Int)
            }
            BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
                expect_number(l, left, "an ordering needs numbers")?;
                expect_number(r, right, "an ordering needs numbers")?;
                Ok(Ty::Bool)
            }
            BinOp::Eq | BinOp::Ne => {
                if l == Ty::Name || r == Ty::Name {
                    return Err(TypeError::new(
                        "two names cannot be compared directly, the comparison would see only \
                         their first eight bytes; key a map by the name instead",
                        left.span(),
                    ));
                }
                let absent = |ty: Ty, other: &Expr| ty == Ty::Address && is_zero_literal(other);
                if !compatible(l, r) && !absent(l, right) && !absent(r, left) {
                    return Err(TypeError::new(
                        format!(
                            "a {} cannot be compared with a {}",
                            l.describe(),
                            r.describe()
                        ),
                        right.span(),
                    ));
                }
                Ok(Ty::Bool)
            }
        }
    }
}

impl Ty {
    fn describe(self) -> &'static str {
        match self {
            Ty::Int => "number",
            Ty::Bool => "boolean",
            Ty::Address => "address",
            Ty::Asset => "asset",
            Ty::Hash => "hash",
            Ty::Name => "name",
            Ty::Time => "time",
            Ty::Str => "string",
            Ty::Collection => "collection",
            Ty::Unknown => "value",
        }
    }
}

fn numeric(ty: Ty) -> bool {
    matches!(ty, Ty::Int | Ty::Time | Ty::Unknown)
}

fn is_asset_call(expr: &Expr) -> bool {
    let Expr::Call { callee, .. } = expr else {
        return false;
    };
    match callee.as_ref() {
        Expr::Field { name, .. } => name.text == "split",
        Expr::Ident(id) => id.text == "mint",
        _ => false,
    }
}

fn no_asset_call(expr: &Expr) -> Result<(), TypeError> {
    if is_asset_call(expr) {
        return Err(TypeError::new(
            "an asset made here would be dropped; bind it with `let` or pass it straight to \
             send, merge or credit",
            expr.span(),
        ));
    }
    match expr {
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            no_asset_call(expr)
        }
        Expr::Binary { left, right, .. } => {
            no_asset_call(left)?;
            no_asset_call(right)
        }
        Expr::Field { base, .. } => no_asset_call(base),
        Expr::Call { callee, args, .. } => {
            no_asset_call(callee)?;
            args.iter().try_for_each(no_asset_call)
        }
        _ => Ok(()),
    }
}

fn consumed_asset_call(expr: &Expr) -> Result<(), TypeError> {
    match expr {
        Expr::Call { callee, args, .. } if is_asset_call(expr) => {
            no_asset_call(callee)?;
            args.iter().try_for_each(no_asset_call)
        }
        _ => no_asset_call(expr),
    }
}

fn asset_calls_consumed(stmt: &Stmt) -> Result<(), TypeError> {
    match stmt {
        Stmt::Let { value, .. } => consumed_asset_call(value),
        Stmt::Expr {
            expr: Expr::Call { callee, args, .. },
            ..
        } => {
            no_asset_call(callee)?;
            args.iter().try_for_each(consumed_asset_call)
        }
        Stmt::Expr { expr, .. } | Stmt::Guard { expr, .. } => no_asset_call(expr),
        Stmt::Assign { target, value, .. } => {
            no_asset_call(target)?;
            no_asset_call(value)
        }
        Stmt::Emit { args, .. } => args.iter().try_for_each(no_asset_call),
    }
}

fn narrow_max(ty: &str) -> Option<u64> {
    match ty {
        "bool" => Some(1),
        "u8" => Some(u64::from(u8::MAX)),
        "u16" => Some(u64::from(u16::MAX)),
        "u32" => Some(u64::from(u32::MAX)),
        _ => None,
    }
}

fn is_zero_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Int(n) if n.text.replace('_', "").trim_start_matches('0').is_empty())
}

fn one_word(ty: Ty) -> bool {
    matches!(ty, Ty::Int | Ty::Time | Ty::Bool)
}

fn compatible(want: Ty, got: Ty) -> bool {
    if want == Ty::Name || got == Ty::Name {
        return want == got;
    }
    if want == Ty::Collection || got == Ty::Collection {
        return want == got;
    }
    want == got || want == Ty::Unknown || got == Ty::Unknown || (one_word(want) && one_word(got))
}

fn declared_arg(ty: &Type, index: usize) -> Ty {
    match ty.args.get(index) {
        Some(GenericArg::Type(inner)) => ty_of_decl(inner),
        _ => Ty::Unknown,
    }
}

fn expect_number(ty: Ty, at: &Expr, message: &str) -> Result<(), TypeError> {
    if numeric(ty) {
        Ok(())
    } else {
        Err(TypeError::new(message, at.span()))
    }
}

fn expect_numeric_or(ty: Ty, want: Ty, at: &Expr, message: &str) -> Result<(), TypeError> {
    if ty == want || ty == Ty::Unknown {
        Ok(())
    } else {
        Err(TypeError::new(message, at.span()))
    }
}

fn ty_of_decl(ty: &Type) -> Ty {
    if is_integer_type(&ty.name.text) {
        return Ty::Int;
    }
    match ty.name.text.as_str() {
        "bool" => Ty::Bool,
        "Q_Address" => Ty::Address,
        "Q_Asset" => Ty::Asset,
        "Q_Hash" => Ty::Hash,
        "Q_Name" => Ty::Name,
        "Time" => Ty::Time,
        "Q_Id" => Ty::Int,
        "Map" | "Registry" | "GuardianSet" => Ty::Collection,
        _ => Ty::Unknown,
    }
}

fn keyed_calls<'e>(expr: &'e Expr, out: &mut Vec<(&'e str, &'e Expr)>) {
    match expr {
        Expr::Call { callee, args, .. } => {
            if let Expr::Field { base, name, .. } = callee.as_ref() {
                if let (Expr::Ident(map), Some(key)) = (base.as_ref(), args.first()) {
                    if matches!(
                        name.text.as_str(),
                        "set" | "get" | "contains" | "insert" | "remove" | "credit" | "debit"
                    ) {
                        out.push((map.text.as_str(), key));
                    }
                }
            }
            keyed_calls(callee, out);
            for arg in args {
                keyed_calls(arg, out);
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            keyed_calls(expr, out)
        }
        Expr::Binary { left, right, .. } => {
            keyed_calls(left, out);
            keyed_calls(right, out);
        }
        Expr::Field { base, .. } => keyed_calls(base, out),
        _ => {}
    }
}

fn entry_exprs(entry: &EntryDecl) -> Vec<&Expr> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => out.push(expr),
            Clause::After { target, from, .. } => {
                if let AfterTarget::Expr(expr) = target {
                    out.push(expr);
                }
                if let Some(expr) = from {
                    out.push(expr);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        match stmt {
            Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => out.push(expr),
            Stmt::Let { value, .. } => out.push(value),
            Stmt::Assign { target, value, .. } => {
                out.push(target);
                out.push(value);
            }
            Stmt::Emit { args, .. } => out.extend(args.iter()),
        }
    }
    out
}

fn check_key_kinds(model: &Model) -> Result<(), TypeError> {
    let mut kinds: HashMap<&str, (Option<quanta_lexer::Span>, Option<quanta_lexer::Span>)> =
        HashMap::new();
    for entry in &model.entries {
        let names: std::collections::HashSet<&str> = entry
            .params
            .iter()
            .filter(|p| p.ty.name.text == "Q_Name")
            .map(|p| p.name.text.as_str())
            .collect();
        for expr in entry_exprs(entry) {
            let mut calls = Vec::new();
            keyed_calls(expr, &mut calls);
            for (map, key) in calls {
                let keyed = model
                    .state
                    .get(map)
                    .is_some_and(|f| matches!(f.ty.name.text.as_str(), "Map" | "Registry"));
                if !keyed {
                    continue;
                }
                let is_name = matches!(key, Expr::Ident(id) if names.contains(id.text.as_str()));
                let seen = kinds.entry(map).or_insert((None, None));
                if is_name {
                    seen.0.get_or_insert(key.span());
                } else {
                    seen.1.get_or_insert(key.span());
                }
                if let (Some(_), Some(other)) = *seen {
                    return Err(TypeError::new(
                        format!(
                            "`{map}` is keyed by a name in one place and by another value in \
                             another, so a caller could reach a name's row without the name \
                             checks; key each map by one kind of value"
                        ),
                        if is_name { key.span() } else { other },
                    ));
                }
            }
        }
    }
    Ok(())
}

fn check_arithmetic(entry: &EntryDecl, params: &HashMap<&str, Ty>) -> Result<(), TypeError> {
    let entry_mints = entry
        .clauses
        .iter()
        .any(|c| matches!(c, Clause::Mints { .. }));
    let asset_params: Vec<&str> = entry
        .params
        .iter()
        .filter(|p| is_asset_param(p))
        .map(|p| p.name.text.as_str())
        .collect();

    for stmt in &entry.body {
        if let Stmt::Assign { value, .. } = stmt {
            if acknowledged(value) {
                continue;
            }
        }
        let (target, addends, span): (&Expr, Vec<&Expr>, &quanta_lexer::Span) = match stmt {
            Stmt::Assign {
                target,
                op: AssignOp::Add,
                value,
                span,
            } => {
                let mut terms = Vec::new();
                sum_terms(value, &mut terms);
                (target, terms, span)
            }
            Stmt::Assign {
                target,
                op: AssignOp::Set,
                value: value @ Expr::Binary { op: BinOp::Add, .. },
                span,
            } => {
                let mut terms = Vec::new();
                sum_terms(value, &mut terms);
                let Some(at) = terms.iter().position(|t| same_target(target, t)) else {
                    continue;
                };
                terms.remove(at);
                (target, terms, span)
            }
            _ => continue,
        };
        let name = match target {
            Expr::Ident(id) => id.text.as_str(),
            _ => continue,
        };
        if params.get(name).is_some() {
            continue;
        }
        if addends.iter().all(|addend| {
            bounded_addend(addend, &asset_params)
                || (entry_mints && is_minted_amount(addend, entry))
        }) {
            continue;
        }
        if limits_bound(entry, name) {
            continue;
        }
        return Err(TypeError::new(
            format!(
                "unchecked overflow: `{name}` grows by unbounded input with no limits clause; \
                 add a bound or make wrapping explicit"
            ),
            *span,
        ));
    }
    Ok(())
}

fn acknowledged(value: &Expr) -> bool {
    matches!(value, Expr::Checked { .. } | Expr::Wrapping { .. })
}

fn is_minted_amount(value: &Expr, entry: &EntryDecl) -> bool {
    if let Expr::Field { base, name, .. } = value {
        if name.text == "amount" {
            if let Expr::Ident(id) = base.as_ref() {
                return entry.params.iter().any(|p| p.name.text == id.text);
            }
        }
    }
    false
}

fn bounded_addend(value: &Expr, asset_params: &[&str]) -> bool {
    match value {
        Expr::Int(_) => true,
        Expr::Field { base, name, .. } if name.text == "amount" => match base.as_ref() {
            Expr::Ident(id) => asset_params.contains(&id.text.as_str()),
            _ => false,
        },
        _ => false,
    }
}

fn sum_terms<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Binary {
            op: BinOp::Add,
            left,
            right,
            ..
        } => {
            sum_terms(left, out);
            sum_terms(right, out);
        }
        other => out.push(other),
    }
}

fn limits_bound(entry: &EntryDecl, field: &str) -> bool {
    entry.clauses.iter().any(|c| match c {
        Clause::Limits { expr, .. } => caps_from_above(expr, field),
        _ => false,
    })
}

fn caps_from_above(expr: &Expr, field: &str) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::And,
            left,
            right,
            ..
        } => caps_from_above(left, field) || caps_from_above(right, field),
        Expr::Binary {
            op: BinOp::Le | BinOp::Lt,
            left,
            right,
            ..
        } => upper_bounds(left, right, field),
        Expr::Binary {
            op: BinOp::Ge | BinOp::Gt,
            left,
            right,
            ..
        } => upper_bounds(right, left, field),
        _ => false,
    }
}

fn upper_bounds(small: &Expr, large: &Expr, field: &str) -> bool {
    (mentions(small, field) && !mentions(large, field))
        || (!mentions(small, field) && subtracts(large, field))
}

fn subtracts(expr: &Expr, field: &str) -> bool {
    match expr {
        Expr::Binary {
            op: BinOp::Sub,
            left,
            right,
            ..
        } => mentions(right, field) && !mentions(left, field),
        _ => false,
    }
}

fn mentions(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Ident(id) => id.text == name,
        Expr::Unary { expr, .. } => mentions(expr, name),
        Expr::Binary { left, right, .. } => mentions(left, name) || mentions(right, name),
        Expr::Field { base, .. } => mentions(base, name),
        Expr::Call { callee, args, .. } => {
            mentions(callee, name) || args.iter().any(|a| mentions(a, name))
        }
        _ => false,
    }
}

fn same_target(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Ident(x), Expr::Ident(y)) => x.text == y.text,
        _ => false,
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
    fn unbounded_addition_into_a_stored_integer_is_rejected() {
        let src = "contract C { state { counter: u8; } \
                   entry bump(order: BumpOrder) writes(counter) { counter += order.step; } }";
        assert!(error_for(src).contains("unchecked overflow"));
    }

    #[test]
    fn a_bounding_limits_clause_permits_the_addition() {
        let src = "contract C { state { total: u128; cap: u128; } \
                   entry add(order: Order) writes(total) limits total + order.amount <= cap \
                   { total += order.amount; } }";
        ok(src);
    }

    #[test]
    fn an_asset_amount_addend_is_bounded_by_the_asset() {
        let src = "contract C { state { pool: u128; } \
                   entry stake(funds: Q_Asset<QTOV>) writes(pool) { pool += funds.amount; } }";
        ok(src);
    }

    #[test]
    fn an_explicit_checked_addition_is_accepted() {
        let src = "contract C { state { counter: u8; } \
                   entry bump(order: BumpOrder) writes(counter) \
                   { counter = checked(counter + order.step); } }";
        ok(src);
    }

    #[test]
    fn an_explicit_wrapping_addition_is_accepted() {
        let src = "contract C { state { counter: u64; } \
                   entry bump(order: BumpOrder) writes(counter) \
                   { counter = wrapping(counter + order.step); } }";
        ok(src);
    }

    #[test]
    fn a_mint_entry_still_rejects_an_unbounded_add_on_a_non_supply_field() {
        let src = "contract C { asset TKN; state { total_supply: u128; rewards: u64; } \
                   entry mint(order: MintOrder, bonus: u64) mints TKN writes(total_supply, rewards) \
                   { total_supply += order.amount; rewards += bonus; } }";
        let message = error_for(src);
        assert!(message.contains("unchecked overflow"), "{message}");
        assert!(message.contains("rewards"), "{message}");
    }

    #[test]
    fn a_mint_entry_permits_the_supply_field_it_mints() {
        let src = "contract C { asset TKN; state { total_supply: u128; } \
                   entry mint(order: MintOrder) mints TKN writes(total_supply) \
                   { total_supply += order.amount; } }";
        ok(src);
    }

    #[test]
    fn a_value_of_another_type_cannot_be_stored_in_a_slot() {
        let assign = "contract C { state { owner: Q_Address; count: u64; } \
                      entry put() writes(count) { count = owner; } }";
        assert!(error_for(assign).contains("cannot be stored"));
        let map_value =
            "contract C { state { owner: Q_Address; holders: Map<Q_Address, Q_Address>; } \
                         entry put(years: u64) writes(holders) { holders.set(owner, years); } }";
        assert!(error_for(map_value).contains("not a number value"));
        let map_key = "contract C { state { owner: Q_Address; ids: Map<Q_Id, u64>; } \
                       entry put() writes(ids) { ids.set(owner, 1); } }";
        assert!(error_for(map_key).contains("not a address value"));
        let compare = "contract C { state { owner: Q_Address; count: u64; } \
                       entry put() writes(count) { guard owner == count; count = 1; } }";
        assert!(error_for(compare).contains("cannot be compared"));
        let genesis = "contract C { state { owner: Q_Address; count: u64; } \
                       genesis { count = deployer; } }";
        assert!(error_for(genesis).contains("cannot be stored"));
    }

    #[test]
    fn a_name_or_a_nested_map_cannot_be_held_in_a_slot() {
        let named = "contract C { state { label: Q_Name; } }";
        assert!(error_for(named).contains("a name cannot be stored"));
        let named_value = "contract C { state { tags: Map<Q_Address, Q_Name>; } }";
        ok(named_value);
        let registry_value = "contract C { state { tags: Registry<Q_Address, Q_Name>; } }";
        assert!(error_for(registry_value).contains("takes 1 type arguments"));
        let nested = "contract C { state { grid: Map<Q_Address, Map<Q_Address, u64> >; } }";
        assert!(error_for(nested).contains("cannot be a Map value"));
        let arity = "contract C { state { grid: Map<Q_Address>; } }";
        assert!(error_for(arity).contains("takes 2 type arguments"));
    }

    #[test]
    fn an_asset_cannot_be_seeded_from_nothing() {
        let default = "contract C { state { vault: Q_Asset<QTOV> = 1000000; } }";
        assert!(error_for(default).contains("cannot take a default value"));
        let keyed = "contract C { state { balances: Map<Q_Address, u64> = 7; } }";
        assert!(error_for(keyed).contains("cannot take a default value"));
        let genesis = "contract C { state { vault: Q_Asset<QTOV>; } genesis { vault = 1000000; } }";
        assert!(error_for(genesis).contains("changes only by merge"));
        let overwrite = "contract C { state { vault: Q_Asset<QTOV>; } \
                         entry put(funds: Q_Asset<QTOV>) writes(vault) { vault = funds; } }";
        assert!(error_for(overwrite).contains("changes only by merge"));
        let absorbed = "contract C { state { count: u64; } \
                        entry put(funds: Q_Asset<QTOV>) writes(count) { count.merge(funds); } }";
        assert!(error_for(absorbed).contains("works only on a Q_Asset state field"));
        let drawn = "contract C { state { count: u64; } \
                     entry take() writes(count) { send(caller, count.split(5)); } }";
        assert!(error_for(drawn).contains("works only on a Q_Asset state field"));
        let guarded = "contract C { state { vault: Q_Asset<QTOV>; count: u64; } \
                       entry poke() writes(count, vault) \
                       { guard vault.split(5) == vault.split(5); count = 1; } }";
        assert!(error_for(guarded).contains("would be dropped"));
        let clause = "contract C { state { vault: Q_Asset<QTOV>; count: u64; } \
                      entry poke() writes(count, vault) limits vault.split(5) == vault.split(5) \
                      { count = 1; } }";
        assert!(error_for(clause).contains("would be dropped"));
        let emitted = "contract C { state { vault: Q_Asset<QTOV>; } \
                       entry poke() writes(vault) { emit Poked(vault.split(7)); } \
                       event Poked(v: u64); }";
        assert!(error_for(emitted).contains("would be dropped"));
        ok(
            "contract C { state { vault: Q_Asset<QTOV>; pool: Q_Asset<QTOV>; } \
            entry move(order: MoveOrder) writes(vault, pool) \
            { let out = vault.split(order.amount); pool.merge(out); } }",
        );
        let lost_credit = "contract C { state { owner_of: Map<Q_Address, Q_Address>; } \
                           entry put() writes(owner_of) { owner_of.credit(caller, 5); } }";
        assert!(error_for(lost_credit).contains("does not apply"));
        let flag_credit = "contract C { state { members: Registry<Q_Address>; } \
                           entry join() writes(members) { members.credit(caller, 1); } }";
        assert!(error_for(flag_credit).contains("does not apply"));
        let reset = "contract C { state { balances: Map<Q_Address, u64>; } \
                     entry reset() writes(balances) { balances.insert(caller); } }";
        assert!(error_for(reset).contains("does not apply"));
        let named_credit = "contract C { state { balances: Map<Q_Address, u64>; } \
                            entry pay(to: Q_Address) writes(balances) { balances.credit(to, to); } }";
        assert!(error_for(named_credit).contains("moves only a number"));
        let wide_default = "contract C { state { level: u8 = 300; } }";
        assert!(error_for(wide_default).contains("does not fit"));
        let wide_flag =
            "contract C { state { paused: bool; } entry p() writes(paused) { paused = 2; } }";
        assert!(error_for(wide_flag).contains("does not fit"));
        ok("contract C { state { level: u8 = 255; paused: bool = 1; } }");
        ok("contract C { state { owner: Q_Address; unlock: Time; opened: u64; } \
            genesis { owner = deployer; unlock = @2030-01-01; } \
            entry open(order: OpenOrder signed by owner) writes(opened) \
            { guard now >= unlock; guard now < @2040-01-01; guard now >= unlock + 86400; opened = 1; } }");
        let mistyped = "contract C { state { owner: Q_Address; count: u64 = owner; } }";
        assert!(error_for(mistyped).contains("cannot be stored"));
        ok("contract C { state { cap: u64 = 50_000; paused: bool = 0; } }");
    }

    #[test]
    fn same_width_values_and_name_keys_are_accepted() {
        ok("contract C { state { paused: bool; last: Map<Q_Address, Time>; gap: u64; \
            owner_of: Map<Q_Address, Q_Address>; names: Registry<Q_Name>; } \
            entry go(label: Q_Name) writes(paused, last, owner_of, names) \
            { guard now >= last.get(caller) + gap; guard owner_of.get(label) == 0; \
            paused = 1; last.set(caller, now); owner_of.set(label, caller); names.insert(label); } }");
    }
}
