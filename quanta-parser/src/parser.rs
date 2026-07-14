//! The token cursor and the shared expectation helpers used by every grammar

use crate::error::ParseError;
use quanta_ast::{Ident, IntLit};
use quanta_lexer::{tokenize, Span, Token, TokenKind};

pub(crate) struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub(crate) fn new(src: &str) -> Result<Parser, ParseError> {
        let tokens = tokenize(src)?;
        Ok(Parser { tokens, pos: 0 })
    }

    pub(crate) fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    pub(crate) fn peek_span(&self) -> Span {
        self.tokens[self.pos].span
    }

    pub(crate) fn check(&self, kind: &TokenKind) -> bool {
        self.peek() == kind
    }

    pub(crate) fn bump(&mut self) -> Token {
        let tok = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    pub(crate) fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    pub(crate) fn expect(&mut self, kind: &TokenKind) -> Result<Token, ParseError> {
        if self.check(kind) {
            Ok(self.bump())
        } else {
            Err(self.err(format!(
                "expected {}, found {}",
                kind.describe(),
                self.peek().describe()
            )))
        }
    }

    pub(crate) fn expect_ident(&mut self) -> Result<Ident, ParseError> {
        let span = self.peek_span();
        if let TokenKind::Ident(text) = self.peek() {
            let text = text.clone();
            self.bump();
            Ok(Ident { text, span })
        } else {
            Err(self.err(format!(
                "expected identifier, found {}",
                self.peek().describe()
            )))
        }
    }

    pub(crate) fn expect_int(&mut self) -> Result<IntLit, ParseError> {
        let span = self.peek_span();
        if let TokenKind::Int(text) = self.peek() {
            let text = text.clone();
            self.bump();
            Ok(IntLit { text, span })
        } else {
            Err(self.err(format!(
                "expected integer, found {}",
                self.peek().describe()
            )))
        }
    }

    pub(crate) fn expect_eof(&mut self) -> Result<(), ParseError> {
        if self.check(&TokenKind::Eof) {
            Ok(())
        } else {
            Err(self.err(format!("unexpected trailing {}", self.peek().describe())))
        }
    }

    pub(crate) fn err(&self, message: String) -> ParseError {
        ParseError {
            message,
            span: self.peek_span(),
        }
    }
}
