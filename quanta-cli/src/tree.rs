// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_ast::*;
use quanta_lexer::Span;

pub fn render(program: &Program) -> String {
    let mut t = Tree { out: String::new() };
    t.line(0, &format!("Program {}", at(program.span)));
    for import in &program.imports {
        let names = join(import.names.iter().map(|n| n.text.clone()));
        t.line(1, &format!("Import {} {}", names, at(import.span)));
        t.line(2, &format!("from \"{}\"", import.path.value));
    }
    for c in &program.contracts {
        t.contract(c, 1);
    }
    t.out
}

struct Tree {
    out: String,
}

impl Tree {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str("  ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn contract(&mut self, c: &Contract, ind: usize) {
        self.line(ind, &format!("Contract {} {}", c.name.text, at(c.span)));
        for item in &c.items {
            self.item(item, ind + 1);
        }
    }

    fn item(&mut self, item: &Item, ind: usize) {
        match item {
            Item::Asset(a) => self.line(ind, &format!("Asset {} {}", a.name.text, at(a.span))),
            Item::State(s) => {
                self.line(ind, &format!("State {}", at(s.span)));
                for f in &s.fields {
                    self.line(
                        ind + 1,
                        &format!("Field {}: {} {}", f.name.text, type_str(&f.ty), at(f.span)),
                    );
                    if let Some(d) = &f.default {
                        self.expr(d, ind + 2);
                    }
                }
            }
            Item::Genesis(g) => {
                self.line(ind, &format!("Genesis {}", at(g.span)));
                for s in &g.body {
                    self.stmt(s, ind + 1);
                }
            }
            Item::Invariant(inv) => {
                self.line(ind, &format!("Invariant {}", at(inv.span)));
                self.expr(&inv.expr, ind + 1);
            }
            Item::Event(e) => {
                let params = join(e.params.iter().map(param_str));
                self.line(
                    ind,
                    &format!("Event {}({}) {}", e.name.text, params, at(e.span)),
                );
            }
            Item::Entry(e) => {
                let params = join(e.params.iter().map(param_str));
                self.line(
                    ind,
                    &format!("Entry {}({}) {}", e.name.text, params, at(e.span)),
                );
                for clause in &e.clauses {
                    self.clause(clause, ind + 1);
                }
                self.line(ind + 1, "Body");
                for s in &e.body {
                    self.stmt(s, ind + 2);
                }
            }
        }
    }

    fn clause(&mut self, c: &Clause, ind: usize) {
        match c {
            Clause::Writes { names, span } => self.line(
                ind,
                &format!(
                    "Writes({}) {}",
                    join(names.iter().map(|n| n.text.clone())),
                    at(*span)
                ),
            ),
            Clause::Reads { names, span } => self.line(
                ind,
                &format!(
                    "Reads({}) {}",
                    join(names.iter().map(|n| n.text.clone())),
                    at(*span)
                ),
            ),
            Clause::Conserves { asset, span } => {
                self.line(ind, &format!("Conserves {} {}", asset.text, at(*span)))
            }
            Clause::Mints { asset, span } => {
                self.line(ind, &format!("Mints {} {}", asset.text, at(*span)))
            }
            Clause::Burns { asset, span } => {
                self.line(ind, &format!("Burns {} {}", asset.text, at(*span)))
            }
            Clause::Limits { expr, span } => {
                self.line(ind, &format!("Limits {}", at(*span)));
                self.expr(expr, ind + 1);
            }
            Clause::Denies { expr, span } => {
                self.line(ind, &format!("Denies {}", at(*span)));
                self.expr(expr, ind + 1);
            }
            Clause::After { target, from, span } => {
                self.line(ind, &format!("After {}", at(*span)));
                match target {
                    AfterTarget::Duration(d) => self.line(
                        ind + 1,
                        &format!("Duration {} {}", d.value.text, d.unit.text),
                    ),
                    AfterTarget::Expr(e) => {
                        self.line(ind + 1, "Target");
                        self.expr(e, ind + 2);
                    }
                }
                if let Some(f) = from {
                    self.line(ind + 1, "From");
                    self.expr(f, ind + 2);
                }
            }
        }
    }

    fn stmt(&mut self, s: &Stmt, ind: usize) {
        match s {
            Stmt::Guard { expr, span } => {
                self.line(ind, &format!("Guard {}", at(*span)));
                self.expr(expr, ind + 1);
            }
            Stmt::Let { name, value, span } => {
                self.line(ind, &format!("Let {} {}", name.text, at(*span)));
                self.expr(value, ind + 1);
            }
            Stmt::Emit { name, args, span } => {
                self.line(ind, &format!("Emit {} {}", name.text, at(*span)));
                for a in args {
                    self.expr(a, ind + 1);
                }
            }
            Stmt::Assign {
                target,
                op,
                value,
                span,
            } => {
                let sym = match op {
                    AssignOp::Set => "=",
                    AssignOp::Add => "+=",
                    AssignOp::Sub => "-=",
                };
                self.line(ind, &format!("Assign {} {}", sym, at(*span)));
                self.expr(target, ind + 1);
                self.expr(value, ind + 1);
            }
            Stmt::Expr { expr, span } => {
                self.line(ind, &format!("Expr {}", at(*span)));
                self.expr(expr, ind + 1);
            }
        }
    }

    fn expr(&mut self, e: &Expr, ind: usize) {
        match e {
            Expr::Int(v) => self.line(ind, &format!("Int {} {}", v.text, at(v.span))),
            Expr::Date { text, span } => self.line(ind, &format!("Date {} {}", text, at(*span))),
            Expr::Str(v) => self.line(ind, &format!("Str \"{}\" {}", v.value, at(v.span))),
            Expr::Ident(v) => self.line(ind, &format!("Ident {} {}", v.text, at(v.span))),
            Expr::Caller { span } => self.line(ind, &format!("Caller {}", at(*span))),
            Expr::Now { span } => self.line(ind, &format!("Now {}", at(*span))),
            Expr::Unary { op, expr, span } => {
                let sym = match op {
                    UnaryOp::Not => "!",
                    UnaryOp::Neg => "-",
                };
                self.line(ind, &format!("Unary {} {}", sym, at(*span)));
                self.expr(expr, ind + 1);
            }
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => {
                self.line(ind, &format!("Binary {} {}", bin_sym(*op), at(*span)));
                self.expr(left, ind + 1);
                self.expr(right, ind + 1);
            }
            Expr::Field { base, name, span } => {
                self.line(ind, &format!("Field .{} {}", name.text, at(*span)));
                self.expr(base, ind + 1);
            }
            Expr::Call { callee, args, span } => {
                self.line(ind, &format!("Call {}", at(*span)));
                self.expr(callee, ind + 1);
                for a in args {
                    self.expr(a, ind + 1);
                }
            }
            Expr::Checked { expr, span } => {
                self.line(ind, &format!("Checked {}", at(*span)));
                self.expr(expr, ind + 1);
            }
            Expr::Wrapping { expr, span } => {
                self.line(ind, &format!("Wrapping {}", at(*span)));
                self.expr(expr, ind + 1);
            }
        }
    }
}

fn at(span: Span) -> String {
    format!("[{}..{}]", span.start, span.end)
}

fn join(parts: impl Iterator<Item = String>) -> String {
    parts.collect::<Vec<_>>().join(", ")
}

fn type_str(t: &Type) -> String {
    if t.args.is_empty() {
        t.name.text.clone()
    } else {
        let args = join(t.args.iter().map(generic_str));
        format!("{}<{}>", t.name.text, args)
    }
}

fn generic_str(a: &GenericArg) -> String {
    match a {
        GenericArg::Type(t) => type_str(t),
        GenericArg::Int(i) => i.text.clone(),
        GenericArg::MofN { m, n, .. } => format!("{} of {}", m.text, n.text),
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
