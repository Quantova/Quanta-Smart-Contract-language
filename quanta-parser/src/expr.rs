// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::ParseError;
use crate::parser::Parser;
use quanta_ast::{BinOp, Expr, Ident, IntLit, StrLit, UnaryOp};
use quanta_lexer::TokenKind;

pub fn parse_expr(src: &str) -> Result<Expr, ParseError> {
    let mut p = Parser::new(src)?;
    let e = p.expr()?;
    p.expect_eof()?;
    Ok(e)
}

impl Parser {
    pub(crate) fn expr(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let result = self.logic_or();
        self.leave();
        result
    }

    fn logic_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.logic_and()?;
        let mut links = 0;
        while self.check(&TokenKind::OrOr) {
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.logic_and()?;
            left = fold(BinOp::Or, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn logic_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.equality()?;
        let mut links = 0;
        while self.check(&TokenKind::AndAnd) {
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.equality()?;
            left = fold(BinOp::And, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn equality(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.comparison()?;
        let mut links = 0;
        loop {
            let op = match self.peek() {
                TokenKind::EqEq => BinOp::Eq,
                TokenKind::Ne => BinOp::Ne,
                _ => break,
            };
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.comparison()?;
            left = fold(op, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn comparison(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.shift()?;
        let mut links = 0;
        loop {
            let op = match self.peek() {
                TokenKind::Lt => BinOp::Lt,
                TokenKind::Gt => BinOp::Gt,
                TokenKind::Le => BinOp::Le,
                TokenKind::Ge => BinOp::Ge,
                _ => break,
            };
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.shift()?;
            left = fold(op, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn shift(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.additive()?;
        let mut links = 0;
        while self.check(&TokenKind::Shr) {
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.additive()?;
            left = fold(BinOp::Shr, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.multiplicative()?;
        let mut links = 0;
        loop {
            let op = match self.peek() {
                TokenKind::Plus => BinOp::Add,
                TokenKind::Minus => BinOp::Sub,
                _ => break,
            };
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.multiplicative()?;
            left = fold(op, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        let mut links = 0;
        loop {
            let op = match self.peek() {
                TokenKind::Star => BinOp::Mul,
                TokenKind::Slash => BinOp::Div,
                TokenKind::Percent => BinOp::Rem,
                _ => break,
            };
            self.bump();
            self.enter()?;
            links += 1;
            let right = self.unary()?;
            left = fold(op, left, right);
        }
        self.unwind(links);
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        let op = match self.peek() {
            TokenKind::Bang => UnaryOp::Not,
            TokenKind::Minus => UnaryOp::Neg,
            _ => return self.postfix(),
        };
        let op_span = self.peek_span();
        self.bump();
        self.enter()?;
        let inner = self.unary();
        self.leave();
        let expr = inner?;
        let span = op_span.join(expr.span());
        Ok(Expr::Unary {
            op,
            expr: Box::new(expr),
            span,
        })
    }

    fn postfix(&mut self) -> Result<Expr, ParseError> {
        let mut e = self.primary()?;
        let mut links = 0;
        loop {
            match self.peek() {
                TokenKind::Dot => {
                    self.enter()?;
                    links += 1;
                    self.bump();
                    let name = self.expect_ident()?;
                    let span = e.span().join(name.span);
                    e = Expr::Field {
                        base: Box::new(e),
                        name,
                        span,
                    };
                }
                TokenKind::LParen => {
                    self.enter()?;
                    links += 1;
                    self.bump();
                    let args = self.call_args()?;
                    let rparen = self.expect(&TokenKind::RParen)?;
                    let span = e.span().join(rparen.span);
                    e = Expr::Call {
                        callee: Box::new(e),
                        args,
                        span,
                    };
                }
                _ => break,
            }
        }
        self.unwind(links);
        Ok(e)
    }

    pub(crate) fn call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut args = Vec::new();
        if self.check(&TokenKind::RParen) {
            return Ok(args);
        }
        args.push(self.expr()?);
        while self.eat(&TokenKind::Comma) {
            args.push(self.expr()?);
        }
        Ok(args)
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        let span = self.peek_span();
        let kind = self.peek().clone();
        match kind {
            TokenKind::Int(text) => {
                self.bump();
                Ok(Expr::Int(IntLit { text, span }))
            }
            TokenKind::Date(text) => {
                self.bump();
                Ok(Expr::Date { text, span })
            }
            TokenKind::Str(value) => {
                self.bump();
                Ok(Expr::Str(StrLit { value, span }))
            }
            TokenKind::Ident(text) => {
                self.bump();
                Ok(Expr::Ident(Ident { text, span }))
            }
            TokenKind::Caller => {
                self.bump();
                Ok(Expr::Caller { span })
            }
            TokenKind::Now => {
                self.bump();
                Ok(Expr::Now { span })
            }
            TokenKind::LParen => {
                self.bump();
                let inner = self.expr()?;
                self.expect(&TokenKind::RParen)?;
                Ok(inner)
            }
            TokenKind::Checked => {
                self.bump();
                self.expect(&TokenKind::LParen)?;
                let inner = self.expr()?;
                let rp = self.expect(&TokenKind::RParen)?;
                Ok(Expr::Checked {
                    expr: Box::new(inner),
                    span: span.join(rp.span),
                })
            }
            TokenKind::Wrapping => {
                self.bump();
                self.expect(&TokenKind::LParen)?;
                let inner = self.expr()?;
                let rp = self.expect(&TokenKind::RParen)?;
                Ok(Expr::Wrapping {
                    expr: Box::new(inner),
                    span: span.join(rp.span),
                })
            }
            _ => Err(self.err(format!(
                "expected an expression, found {}",
                self.peek().describe()
            ))),
        }
    }
}

fn fold(op: BinOp, left: Expr, right: Expr) -> Expr {
    let span = left.span().join(right.span());
    Expr::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_binds_tighter_than_addition() {
        let e = parse_expr("a + b * c").unwrap();
        match e {
            Expr::Binary {
                op: BinOp::Add,
                right,
                ..
            } => assert!(matches!(*right, Expr::Binary { op: BinOp::Mul, .. })),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn shift_binds_looser_than_addition_and_tighter_than_comparison() {
        // a + b >> c parses as (a + b) >> c.
        match parse_expr("a + b >> c").unwrap() {
            Expr::Binary { op: BinOp::Shr, left, .. } => {
                assert!(matches!(*left, Expr::Binary { op: BinOp::Add, .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
        // a >> b < c parses as (a >> b) < c.
        match parse_expr("a >> b < c").unwrap() {
            Expr::Binary { op: BinOp::Lt, left, .. } => {
                assert!(matches!(*left, Expr::Binary { op: BinOp::Shr, .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn method_call_on_field_chain() {
        let e = parse_expr("reserve.split(req.amount)").unwrap();
        match e {
            Expr::Call { callee, args, .. } => {
                assert!(matches!(*callee, Expr::Field { .. }));
                assert_eq!(args.len(), 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unary_not_over_call() {
        let e = parse_expr("!holders.contains(order.investor)").unwrap();
        assert!(matches!(
            e,
            Expr::Unary {
                op: UnaryOp::Not,
                ..
            }
        ));
    }

    #[test]
    fn caller_is_an_expression() {
        assert!(matches!(parse_expr("caller").unwrap(), Expr::Caller { .. }));
    }

    #[test]
    fn now_is_an_expression() {
        assert!(matches!(parse_expr("now").unwrap(), Expr::Now { .. }));
        match parse_expr("now > deadline").unwrap() {
            Expr::Binary { op: BinOp::Gt, left, .. } => {
                assert!(matches!(*left, Expr::Now { .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn checked_and_wrapping_wrap_an_arithmetic_expression() {
        match parse_expr("checked(a + b)").unwrap() {
            Expr::Checked { expr, .. } => {
                assert!(matches!(*expr, Expr::Binary { op: BinOp::Add, .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_expr("wrapping(a + b)").unwrap() {
            Expr::Wrapping { expr, .. } => {
                assert!(matches!(*expr, Expr::Binary { op: BinOp::Add, .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
