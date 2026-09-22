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
    Unknown,
}

struct Env<'a> {
    model: &'a Model<'a>,
    params: HashMap<&'a str, Ty>,
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
                    Ty::Name => is_key,
                    Ty::Unknown | Ty::Asset | Ty::Str => false,
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
    let defaults = Env {
        model,
        params: HashMap::new(),
    };
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
            let env = Env {
                model,
                params: HashMap::new(),
            };
            env.expect_predicate(&inv.expr)?;
        }
    }
    for entry in &model.entries {
        check_entry(model, entry)?;
    }
    for item in &model.contract.items {
        if let Item::Genesis(genesis) = item {
            let env = Env {
                model,
                params: HashMap::new(),
            };
            for stmt in &genesis.body {
                env.check_stmt_types(stmt)?;
                asset_calls_consumed(stmt)?;
            }
        }
    }
    Ok(())
}

fn check_entry(model: &Model, entry: &EntryDecl) -> Result<(), TypeError> {
    let mut params = HashMap::new();
    for param in &entry.params {
        params.insert(param.name.text.as_str(), ty_of_decl(&param.ty));
    }
    let env = Env { model, params };

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
            Stmt::Let { value, .. } => {
                env.ty_of(value)?;
            }
            Stmt::Assign { .. } | Stmt::Expr { .. } => env.check_stmt_types(stmt)?,
            Stmt::Emit { args, .. } => {
                for arg in args {
                    env.ty_of(arg)?;
                }
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
                let fits = match op {
                    AssignOp::Set => compatible(slot, given),
                    AssignOp::Add | AssignOp::Sub => numeric(slot) && numeric(given),
                };
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
            "insert" | "remove" | "contains" | "credit" | "debit" => &[key],
            _ => return Ok(()),
        };
        for (index, (arg, want)) in args.iter().zip(expected).enumerate() {
            let got = self.ty_of(arg)?;
            let named_key = index == 0 && got == Ty::Name;
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
                Ok(self.ty_of_call(callee))
            }
            Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => self.ty_of(expr),
        }
    }

    fn ty_of_ident(&self, name: &str) -> Ty {
        if let Some(ty) = self.params.get(name) {
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
    want == got
        || want == Ty::Unknown
        || got == Ty::Unknown
        || (one_word(want) && one_word(got))
        || (want == Ty::Address && got == Ty::Name)
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
        _ => Ty::Unknown,
    }
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
        let (target, addend, span) = match stmt {
            Stmt::Assign {
                target,
                op: AssignOp::Add,
                value,
                span,
            } => (target, value, span),
            Stmt::Assign {
                target,
                op: AssignOp::Set,
                value:
                    Expr::Binary {
                        op: BinOp::Add,
                        left,
                        right,
                        ..
                    },
                span,
            } if same_target(target, left) => (target, right.as_ref(), span),
            _ => continue,
        };
        let name = match target {
            Expr::Ident(id) => id.text.as_str(),
            _ => continue,
        };
        if params.get(name).is_some() {
            continue;
        }
        if bounded_addend(addend, &asset_params) {
            continue;
        }
        if entry_mints && is_minted_amount(addend, entry) {
            continue;
        }
        if limits_names(entry, name) {
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

fn limits_names(entry: &EntryDecl, field: &str) -> bool {
    entry.clauses.iter().any(|c| match c {
        Clause::Limits { expr, .. } => mentions(expr, field),
        _ => false,
    })
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
        let src = "contract C { state { counter: u8; } \
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
        assert!(error_for(named_value).contains("cannot be a Map value"));
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
            genesis { owner = deployer; unlock = 2030-01-01; } \
            entry open(order: OpenOrder signed by owner) writes(opened) \
            { guard now >= unlock; guard now < 2040-01-01; guard now >= unlock + 86400; opened = 1; } }");
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
