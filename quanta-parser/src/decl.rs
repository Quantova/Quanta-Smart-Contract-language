use crate::error::ParseError;
use crate::parser::Parser;
use quanta_ast::{
    AfterTarget, AssetDecl, Clause, Duration, EntryDecl, EventDecl, FieldDecl, GenesisBlock, Ident,
    InvariantDecl, Item, Param, StateBlock, Stmt,
};
use quanta_lexer::{Span, TokenKind};

pub fn parse_item(src: &str) -> Result<Item, ParseError> {
    let mut p = Parser::new(src)?;
    let item = p.contract_item()?;
    p.expect_eof()?;
    Ok(item)
}

impl Parser {
    pub(crate) fn contract_item(&mut self) -> Result<Item, ParseError> {
        match self.peek() {
            TokenKind::Asset => self.asset_decl(),
            TokenKind::State => self.state_block(),
            TokenKind::Genesis => self.genesis_block(),
            TokenKind::Invariant => self.invariant_decl(),
            TokenKind::Event => self.event_decl(),
            TokenKind::Entry => self.entry_decl(),
            _ => Err(self.err(format!(
                "expected a contract item, found {}",
                self.peek().describe()
            ))),
        }
    }

    fn asset_decl(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Item::Asset(AssetDecl {
            name,
            span: kw.span.join(semi.span),
        }))
    }

    fn state_block(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        self.expect(&TokenKind::LBrace)?;
        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            fields.push(self.field_decl()?);
        }
        let rb = self.expect(&TokenKind::RBrace)?;
        Ok(Item::State(StateBlock {
            fields,
            span: kw.span.join(rb.span),
        }))
    }

    fn field_decl(&mut self) -> Result<FieldDecl, ParseError> {
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.ty()?;
        let default = if self.eat(&TokenKind::Eq) {
            Some(self.expr()?)
        } else {
            None
        };
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(FieldDecl {
            span: name.span.join(semi.span),
            name,
            ty,
            default,
        })
    }

    fn genesis_block(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        let (body, span) = self.block()?;
        Ok(Item::Genesis(GenesisBlock {
            body,
            span: kw.span.join(span),
        }))
    }

    fn invariant_decl(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        let expr = self.expr()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Item::Invariant(InvariantDecl {
            expr,
            span: kw.span.join(semi.span),
        }))
    }

    fn event_decl(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        let params = self.param_list()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Item::Event(EventDecl {
            name,
            params,
            span: kw.span.join(semi.span),
        }))
    }

    fn entry_decl(&mut self) -> Result<Item, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        let params = self.param_list()?;
        let clauses = self.clauses()?;
        let (body, body_span) = self.block()?;
        Ok(Item::Entry(EntryDecl {
            name,
            params,
            clauses,
            body,
            span: kw.span.join(body_span),
        }))
    }

    pub(crate) fn block(&mut self) -> Result<(Vec<Stmt>, Span), ParseError> {
        let lb = self.expect(&TokenKind::LBrace)?;
        let mut body = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            body.push(self.statement()?);
        }
        let rb = self.expect(&TokenKind::RBrace)?;
        Ok((body, lb.span.join(rb.span)))
    }

    fn param_list(&mut self) -> Result<Vec<Param>, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let mut params = Vec::new();
        if !self.check(&TokenKind::RParen) {
            params.push(self.param()?);
            while self.eat(&TokenKind::Comma) {
                params.push(self.param()?);
            }
        }
        self.expect(&TokenKind::RParen)?;
        Ok(params)
    }

    fn param(&mut self) -> Result<Param, ParseError> {
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Colon)?;
        let sealed = self.eat(&TokenKind::Sealed);
        let ty = self.ty()?;
        let signed_by = if self.check(&TokenKind::Signed) {
            self.bump();
            self.expect(&TokenKind::By)?;
            Some(self.expect_ident()?)
        } else {
            None
        };
        let end = signed_by.as_ref().map(|s| s.span).unwrap_or(ty.span);
        Ok(Param {
            span: name.span.join(end),
            name,
            sealed,
            ty,
            signed_by,
        })
    }

    fn clauses(&mut self) -> Result<Vec<Clause>, ParseError> {
        let mut out = Vec::new();
        loop {
            let kw = self.peek_span();
            let clause = match self.peek() {
                TokenKind::Writes => {
                    self.bump();
                    self.expect(&TokenKind::LParen)?;
                    let names = self.ident_list()?;
                    let rp = self.expect(&TokenKind::RParen)?;
                    Clause::Writes {
                        names,
                        span: kw.join(rp.span),
                    }
                }
                TokenKind::Reads => {
                    self.bump();
                    self.expect(&TokenKind::LParen)?;
                    let names = self.ident_list()?;
                    let rp = self.expect(&TokenKind::RParen)?;
                    Clause::Reads {
                        names,
                        span: kw.join(rp.span),
                    }
                }
                TokenKind::Conserves => {
                    self.bump();
                    let asset = self.expect_ident()?;
                    Clause::Conserves {
                        span: kw.join(asset.span),
                        asset,
                    }
                }
                TokenKind::Mints => {
                    self.bump();
                    let asset = self.expect_ident()?;
                    Clause::Mints {
                        span: kw.join(asset.span),
                        asset,
                    }
                }
                TokenKind::Burns => {
                    self.bump();
                    let asset = self.expect_ident()?;
                    Clause::Burns {
                        span: kw.join(asset.span),
                        asset,
                    }
                }
                TokenKind::Limits => {
                    self.bump();
                    let expr = self.expr()?;
                    Clause::Limits {
                        span: kw.join(expr.span()),
                        expr,
                    }
                }
                TokenKind::Denies => {
                    self.bump();
                    let expr = self.expr()?;
                    Clause::Denies {
                        span: kw.join(expr.span()),
                        expr,
                    }
                }
                TokenKind::After => {
                    self.bump();
                    let (target, target_span) = self.after_target()?;
                    let from = if self.check(&TokenKind::From) {
                        self.bump();
                        Some(self.expr()?)
                    } else {
                        None
                    };
                    let end = from.as_ref().map(|e| e.span()).unwrap_or(target_span);
                    Clause::After {
                        target,
                        from,
                        span: kw.join(end),
                    }
                }
                _ => break,
            };
            out.push(clause);
        }
        Ok(out)
    }

    fn after_target(&mut self) -> Result<(AfterTarget, Span), ParseError> {
        let is_duration = matches!(self.peek(), TokenKind::Int(_))
            && matches!(self.peek2(), TokenKind::Ident(w) if is_duration_unit(w));
        if is_duration {
            let value = self.expect_int()?;
            let unit = self.expect_ident()?;
            let span = value.span.join(unit.span);
            Ok((AfterTarget::Duration(Duration { value, unit, span }), span))
        } else {
            let expr = self.expr()?;
            let span = expr.span();
            Ok((AfterTarget::Expr(expr), span))
        }
    }

    pub(crate) fn ident_list(&mut self) -> Result<Vec<Ident>, ParseError> {
        let mut names = vec![self.expect_ident()?];
        while self.eat(&TokenKind::Comma) {
            names.push(self.expect_ident()?);
        }
        Ok(names)
    }
}

fn is_duration_unit(word: &str) -> bool {
    matches!(
        word,
        "seconds" | "minutes" | "hours" | "days" | "weeks" | "months" | "years"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_and_state_items() {
        assert!(matches!(parse_item("asset QSGD;").unwrap(), Item::Asset(_)));
        let item = parse_item("state { owner: Q_Address; cap: u64 = 50_000; }").unwrap();
        match item {
            Item::State(s) => {
                assert_eq!(s.fields.len(), 2);
                assert!(s.fields[0].default.is_none());
                assert!(s.fields[1].default.is_some());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn entry_gathers_params_clauses_and_body() {
        let src = "entry withdraw(req: WithdrawReq signed by owner) \
                   writes(reserve, spent_today) conserves QTOV \
                   limits req.amount <= cap { spent_today += req.amount; }";
        match parse_item(src).unwrap() {
            Item::Entry(e) => {
                assert_eq!(e.params.len(), 1);
                assert!(e.params[0].signed_by.is_some());
                assert_eq!(e.clauses.len(), 3);
                assert_eq!(e.body.len(), 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn after_reads_a_duration_or_an_expression() {
        let dur = "entry r(a: T, approvals: Quorum<4 of 5, board>) \
                   after 48 hours from approvals.first { }";
        match parse_item(dur).unwrap() {
            Item::Entry(e) => match &e.clauses[0] {
                Clause::After { target, from, .. } => {
                    assert!(matches!(target, AfterTarget::Duration(_)));
                    assert!(from.is_some());
                }
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
        let expr = "entry r(u: Q_Asset<X>) after maturity { }";
        match parse_item(expr).unwrap() {
            Item::Entry(e) => assert!(matches!(
                &e.clauses[0],
                Clause::After {
                    target: AfterTarget::Expr(_),
                    from: None,
                    ..
                }
            )),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn sealed_parameter_is_recorded() {
        match parse_item("entry fund(payment: sealed Q_Asset<QTOV>) { }").unwrap() {
            Item::Entry(e) => assert!(e.params[0].sealed),
            other => panic!("unexpected {other:?}"),
        }
    }
}
