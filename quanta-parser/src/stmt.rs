// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::ParseError;
use crate::parser::Parser;
use quanta_ast::{AssignOp, Expr, Stmt};
use quanta_lexer::TokenKind;

pub fn parse_stmt(src: &str) -> Result<Stmt, ParseError> {
    let mut p = Parser::new(src)?;
    let s = p.statement()?;
    p.expect_eof()?;
    Ok(s)
}

impl Parser {
    pub(crate) fn statement(&mut self) -> Result<Stmt, ParseError> {
        match self.peek() {
            TokenKind::Guard => self.guard_stmt(),
            TokenKind::Let => self.let_stmt(),
            TokenKind::Emit => self.emit_stmt(),
            _ => self.assign_or_expr_stmt(),
        }
    }

    fn guard_stmt(&mut self) -> Result<Stmt, ParseError> {
        let kw = self.bump();
        let expr = self.expr()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Stmt::Guard {
            expr,
            span: kw.span.join(semi.span),
        })
    }

    fn let_stmt(&mut self) -> Result<Stmt, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Eq)?;
        let value = self.expr()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Stmt::Let {
            name,
            value,
            span: kw.span.join(semi.span),
        })
    }

    fn emit_stmt(&mut self) -> Result<Stmt, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let args = self.call_args()?;
        self.expect(&TokenKind::RParen)?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Stmt::Emit {
            name,
            args,
            span: kw.span.join(semi.span),
        })
    }

    fn assign_or_expr_stmt(&mut self) -> Result<Stmt, ParseError> {
        let target = self.expr()?;
        let target_span = target.span();
        let op = match self.peek() {
            TokenKind::Eq => AssignOp::Set,
            TokenKind::PlusEq => AssignOp::Add,
            TokenKind::MinusEq => AssignOp::Sub,
            _ => {
                let semi = self.expect(&TokenKind::Semi)?;
                return Ok(Stmt::Expr {
                    span: target_span.join(semi.span),
                    expr: target,
                });
            }
        };
        if !is_lvalue(&target) {
            return Err(ParseError {
                message: "invalid assignment target".to_string(),
                span: target_span,
            });
        }
        self.bump();
        let value = self.expr()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Stmt::Assign {
            target,
            op,
            value,
            span: target_span.join(semi.span),
        })
    }
}

fn is_lvalue(e: &Expr) -> bool {
    matches!(e, Expr::Ident(_) | Expr::Field { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_assignment() {
        let s = parse_stmt("spent_today += req.amount;").unwrap();
        assert!(matches!(
            s,
            Stmt::Assign {
                op: AssignOp::Add,
                ..
            }
        ));
    }

    #[test]
    fn guard_let_emit_and_call() {
        assert!(matches!(
            parse_stmt("guard reserve.amount >= req.amount;").unwrap(),
            Stmt::Guard { .. }
        ));
        assert!(matches!(
            parse_stmt("let payout = reserve.split(req.amount);").unwrap(),
            Stmt::Let { .. }
        ));
        match parse_stmt("emit Withdrawn(req.to, req.amount);").unwrap() {
            Stmt::Emit { args, .. } => assert_eq!(args.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            parse_stmt("send(req.to, payout);").unwrap(),
            Stmt::Expr { .. }
        ));
    }

    #[test]
    fn a_literal_is_not_an_assignment_target() {
        let err = parse_stmt("1 = 2;").unwrap_err();
        assert!(err.message.contains("assignment target"));
    }
}
