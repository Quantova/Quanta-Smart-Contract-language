// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical source pretty printer. Output re-parses to the same tree, and a

use crate::ast::*;

const UNIT: &str = "  ";

/// Renders a program back to Quanta source.
pub fn pretty(program: &Program) -> String {
    let mut p = Printer { out: String::new() };
    p.program(program);
    p.out
}

struct Printer {
    out: String,
}

impl Printer {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str(UNIT);
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn program(&mut self, program: &Program) {
        for import in &program.imports {
            let names = join(import.names.iter().map(|n| n.text.clone()), ", ");
            self.line(
                0,
                &format!("import {{ {} }} from \"{}\";", names, import.path.value),
            );
        }
        if !program.imports.is_empty() && !program.contracts.is_empty() {
            self.out.push('\n');
        }
        for (i, contract) in program.contracts.iter().enumerate() {
            if i > 0 {
                self.out.push('\n');
            }
            self.contract(contract);
        }
    }

    fn contract(&mut self, c: &Contract) {
        self.line(0, &format!("contract {} {{", c.name.text));
        for (i, item) in c.items.iter().enumerate() {
            if i > 0 {
                self.out.push('\n');
            }
            self.item(item, 1);
        }
        self.line(0, "}");
    }

    fn item(&mut self, item: &Item, ind: usize) {
        match item {
            Item::Asset(a) => self.line(ind, &format!("asset {};", a.name.text)),
            Item::State(s) => {
                self.line(ind, "state {");
                for f in &s.fields {
                    self.field(f, ind + 1);
                }
                self.line(ind, "}");
            }
            Item::Genesis(g) => {
                self.line(ind, "genesis {");
                for s in &g.body {
                    self.stmt(s, ind + 1);
                }
                self.line(ind, "}");
            }
            Item::Invariant(inv) => {
                self.line(ind, &format!("invariant {};", expr_str(&inv.expr, 0)));
            }
            Item::Event(e) => {
                let params = join(e.params.iter().map(param_str), ", ");
                self.line(ind, &format!("event {}({});", e.name.text, params));
            }
            Item::Entry(e) => self.entry(e, ind),
        }
    }

    fn field(&mut self, f: &FieldDecl, ind: usize) {
        let ty = type_str(&f.ty);
        match &f.default {
            Some(d) => self.line(
                ind,
                &format!("{}: {} = {};", f.name.text, ty, expr_str(d, 0)),
            ),
            None => self.line(ind, &format!("{}: {};", f.name.text, ty)),
        }
    }

    fn entry(&mut self, e: &EntryDecl, ind: usize) {
        let params = join(e.params.iter().map(param_str), ", ");
        self.line(ind, &format!("entry {}({})", e.name.text, params));
        for clause in &e.clauses {
            self.line(ind + 1, &clause_str(clause));
        }
        self.line(ind, "{");
        for s in &e.body {
            self.stmt(s, ind + 1);
        }
        self.line(ind, "}");
    }

    fn stmt(&mut self, s: &Stmt, ind: usize) {
        let text = match s {
            Stmt::Guard { expr, .. } => format!("guard {};", expr_str(expr, 0)),
            Stmt::Let { name, value, .. } => {
                format!("let {} = {};", name.text, expr_str(value, 0))
            }
            Stmt::Emit { name, args, .. } => {
                let a = join(args.iter().map(|e| expr_str(e, 0)), ", ");
                format!("emit {}({});", name.text, a)
            }
            Stmt::Assign {
                target, op, value, ..
            } => format!(
                "{} {} {};",
                expr_str(target, 0),
                assign_sym(*op),
                expr_str(value, 0)
            ),
            Stmt::Expr { expr, .. } => format!("{};", expr_str(expr, 0)),
        };
        self.line(ind, &text);
    }
}

fn param_str(p: &Param) -> String {
    let mut s = format!("{}: ", p.name.text);
    if p.sealed {
        s.push_str("sealed ");
    }
    s.push_str(&type_str(&p.ty));
    if let Some(signer) = &p.signed_by {
        s.push_str(&format!(" signed by {}", signer.text));
    }
    s
}

fn clause_str(c: &Clause) -> String {
    match c {
        Clause::Writes { names, .. } => {
            format!(
                "writes({})",
                join(names.iter().map(|n| n.text.clone()), ", ")
            )
        }
        Clause::Reads { names, .. } => {
            format!(
                "reads({})",
                join(names.iter().map(|n| n.text.clone()), ", ")
            )
        }
        Clause::Conserves { asset, .. } => format!("conserves {}", asset.text),
        Clause::Mints { asset, .. } => format!("mints {}", asset.text),
        Clause::Burns { asset, .. } => format!("burns {}", asset.text),
        Clause::Limits { expr, .. } => format!("limits {}", expr_str(expr, 0)),
        Clause::Denies { expr, .. } => format!("denies {}", expr_str(expr, 0)),
        Clause::After { target, from, .. } => {
            let mut s = format!("after {}", after_target_str(target));
            if let Some(f) = from {
                s.push_str(&format!(" from {}", expr_str(f, 0)));
            }
            s
        }
    }
}

fn after_target_str(t: &AfterTarget) -> String {
    match t {
        AfterTarget::Duration(d) => format!("{} {}", d.value.text, d.unit.text),
        AfterTarget::Expr(e) => expr_str(e, 0),
    }
}

fn type_str(t: &Type) -> String {
    if t.args.is_empty() {
        t.name.text.clone()
    } else {
        let args = join(t.args.iter().map(generic_arg_str), ", ");
        format!("{}<{}>", t.name.text, args)
    }
}

fn generic_arg_str(a: &GenericArg) -> String {
    match a {
        GenericArg::Type(t) => type_str(t),
        GenericArg::Int(i) => i.text.clone(),
        GenericArg::MofN { m, n, .. } => format!("{} of {}", m.text, n.text),
    }
}

fn assign_sym(op: AssignOp) -> &'static str {
    match op {
        AssignOp::Set => "=",
        AssignOp::Add => "+=",
        AssignOp::Sub => "-=",
    }
}

fn bin_prec(op: BinOp) -> u8 {
    match op {
        BinOp::Or => 1,
        BinOp::And => 2,
        BinOp::Eq | BinOp::Ne => 3,
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => 4,
        BinOp::Shr => 5,
        BinOp::Add | BinOp::Sub => 6,
        BinOp::Mul | BinOp::Div | BinOp::Rem => 7,
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Or => "||",
        BinOp::And => "&&",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Rem => "%",
        BinOp::Shr => ">>",
    }
}

const PREC_UNARY: u8 = 8;
const PREC_POSTFIX: u8 = 9;
const PREC_PRIMARY: u8 = 10;

/// Renders an expression, wrapping in parentheses only where a lower precedence
fn expr_str(e: &Expr, min_prec: u8) -> String {
    let (text, prec) = match e {
        Expr::Int(v) => (v.text.clone(), PREC_PRIMARY),
        Expr::Date { text, .. } => (text.clone(), PREC_PRIMARY),
        Expr::Str(v) => (format!("\"{}\"", v.value), PREC_PRIMARY),
        Expr::Ident(v) => (v.text.clone(), PREC_PRIMARY),
        Expr::Caller { .. } => ("caller".to_string(), PREC_PRIMARY),
        Expr::Now { .. } => ("now".to_string(), PREC_PRIMARY),
        Expr::Unary { op, expr, .. } => {
            let sym = match op {
                UnaryOp::Not => "!",
                UnaryOp::Neg => "-",
            };
            (format!("{}{}", sym, expr_str(expr, PREC_UNARY)), PREC_UNARY)
        }
        Expr::Binary {
            op, left, right, ..
        } => {
            let p = bin_prec(*op);
            let text = format!(
                "{} {} {}",
                expr_str(left, p),
                bin_sym(*op),
                expr_str(right, p + 1)
            );
            (text, p)
        }
        Expr::Field { base, name, .. } => (
            format!("{}.{}", expr_str(base, PREC_POSTFIX), name.text),
            PREC_POSTFIX,
        ),
        Expr::Call { callee, args, .. } => {
            let a = join(args.iter().map(|e| expr_str(e, 0)), ", ");
            (
                format!("{}({})", expr_str(callee, PREC_POSTFIX), a),
                PREC_POSTFIX,
            )
        }
        Expr::Checked { expr, .. } => (format!("checked({})", expr_str(expr, 0)), PREC_POSTFIX),
        Expr::Wrapping { expr, .. } => (format!("wrapping({})", expr_str(expr, 0)), PREC_POSTFIX),
    };
    if prec < min_prec {
        format!("({text})")
    } else {
        text
    }
}

fn join(parts: impl Iterator<Item = String>, sep: &str) -> String {
    parts.collect::<Vec<_>>().join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quanta_lexer::Span;

    fn ident(name: &str) -> Expr {
        Expr::Ident(Ident {
            text: name.to_string(),
            span: Span::default(),
        })
    }

    fn binary(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::Binary {
            op,
            left: Box::new(l),
            right: Box::new(r),
            span: Span::default(),
        }
    }

    #[test]
    fn precedence_inserts_minimal_parentheses() {
        // (a + b) * c must keep its parentheses; a + b * c must not.
        let needs = binary(
            BinOp::Mul,
            binary(BinOp::Add, ident("a"), ident("b")),
            ident("c"),
        );
        assert_eq!(expr_str(&needs, 0), "(a + b) * c");

        let clean = binary(
            BinOp::Add,
            ident("a"),
            binary(BinOp::Mul, ident("b"), ident("c")),
        );
        assert_eq!(expr_str(&clean, 0), "a + b * c");
    }
}
