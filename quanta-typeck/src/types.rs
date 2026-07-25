use crate::error::TypeError;
use crate::model::{is_asset_param, is_integer_type, Model};
use quanta_ast::{AssignOp, BinOp, Clause, EntryDecl, Expr, Item, Stmt, Type, UnaryOp};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Int,
    Bool,
    Address,
    Asset,
    Hash,
    Time,
    Str,
    Unknown,
}

struct Env<'a> {
    model: &'a Model<'a>,
    params: HashMap<&'a str, Ty>,
}

pub fn check(model: &Model) -> Result<(), TypeError> {
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
            Stmt::Assign { value, .. } => {
                env.ty_of(value)?;
            }
            Stmt::Emit { .. } | Stmt::Expr { .. } => {}
        }
    }
    check_arithmetic(entry, &env.params)?;
    Ok(())
}

impl<'a> Env<'a> {
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
        Ty::Unknown
    }

    fn ty_of_call(&self, callee: &Expr) -> Ty {
        match callee {
            Expr::Field { name, .. } => match name.text.as_str() {
                "contains" => Ty::Bool,
                "split" => Ty::Asset,
                "get" => Ty::Int,
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
                expect_numeric_or(l, Ty::Int, left, "arithmetic needs a number")?;
                expect_numeric_or(r, Ty::Int, right, "arithmetic needs a number")?;
                Ok(Ty::Int)
            }
            BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
                expect_numeric_or(l, Ty::Int, left, "an ordering needs numbers")?;
                expect_numeric_or(r, Ty::Int, right, "an ordering needs numbers")?;
                Ok(Ty::Bool)
            }
            BinOp::Eq | BinOp::Ne => Ok(Ty::Bool),
        }
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
        "Time" => Ty::Time,
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
        // A `mints` clause authorizes growing the supply it mints, and the supply grows by the
        // minted amount the order carries in. That single addition is the supply mint the clause
        // governs and is exempt. Every other addition inside the same entry, on a field the mint
        // does not govern, is held to the same bound rule it would face outside a mint entry.
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
}
