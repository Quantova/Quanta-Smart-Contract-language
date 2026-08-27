// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::ParseError;
use crate::parser::Parser;
use quanta_ast::{GenericArg, Ident, Type};
use quanta_lexer::TokenKind;

pub fn parse_type(src: &str) -> Result<Type, ParseError> {
    let mut p = Parser::new(src)?;
    let t = p.ty()?;
    p.expect_eof()?;
    Ok(t)
}

impl Parser {
    pub(crate) fn ty(&mut self) -> Result<Type, ParseError> {
        let span = self.peek_span();
        let name = match self.peek() {
            TokenKind::Ident(text) => {
                let text = text.clone();
                self.bump();
                Ident { text, span }
            }
            TokenKind::Quorum => {
                self.bump();
                Ident {
                    text: "Quorum".to_string(),
                    span,
                }
            }
            _ => return Err(self.err(format!("expected a type, found {}", self.peek().describe()))),
        };

        let mut args = Vec::new();
        let mut end = name.span;
        if self.check(&TokenKind::Lt) {
            self.bump();
            args = self.generic_args()?;
            let gt = self.expect(&TokenKind::Gt)?;
            end = gt.span;
        }
        Ok(Type {
            span: name.span.join(end),
            name,
            args,
        })
    }

    fn generic_args(&mut self) -> Result<Vec<GenericArg>, ParseError> {
        let mut args = vec![self.generic_arg()?];
        while self.eat(&TokenKind::Comma) {
            args.push(self.generic_arg()?);
        }
        Ok(args)
    }

    fn generic_arg(&mut self) -> Result<GenericArg, ParseError> {
        if matches!(self.peek(), TokenKind::Int(_)) {
            let m = self.expect_int()?;
            if matches!(self.peek(), TokenKind::Ident(w) if w == "of") {
                self.bump();
                let n = self.expect_int()?;
                let span = m.span.join(n.span);
                Ok(GenericArg::MofN { m, n, span })
            } else {
                Ok(GenericArg::Int(m))
            }
        } else {
            self.enter()?;
            let inner = self.ty();
            self.leave();
            Ok(GenericArg::Type(inner?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_threshold_and_set() {
        let t = parse_type("Quorum<3 of 5, issuance_board>").unwrap();
        assert_eq!(t.name.text, "Quorum");
        assert_eq!(t.args.len(), 2);
        assert!(matches!(t.args[0], GenericArg::MofN { .. }));
        assert!(matches!(t.args[1], GenericArg::Type(_)));
    }

    #[test]
    fn two_type_arguments() {
        let t = parse_type("Map<Q_Address, u128>").unwrap();
        assert_eq!(t.name.text, "Map");
        assert_eq!(t.args.len(), 2);
    }

    #[test]
    fn integer_width_argument() {
        let t = parse_type("GuardianSet<5>").unwrap();
        assert!(matches!(t.args[0], GenericArg::Int(_)));
    }

    #[test]
    fn plain_type_has_no_arguments() {
        let t = parse_type("Q_Address").unwrap();
        assert!(t.args.is_empty());
    }
}
