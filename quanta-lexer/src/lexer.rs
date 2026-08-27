// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::token::{is_forbidden, keyword_kind, Span, Token, TokenKind};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LexError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub fn tokenize(src: &str) -> Result<Vec<Token>, LexError> {
    Lexer::new(src).run()
}

struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia();
            let start = self.pos;
            let c = match self.peek() {
                None => {
                    out.push(Token::new(TokenKind::Eof, Span::new(start, start)));
                    return Ok(out);
                }
                Some(c) => c,
            };
            let token = if is_ident_start(c) {
                self.scan_word(start)?
            } else if c.is_ascii_digit() {
                self.scan_number(start)
            } else if c == b'"' {
                self.scan_string(start)?
            } else {
                self.scan_symbol(start)?
            };
            out.push(token);
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => self.pos += 1,
                Some(b'/') if self.peek_at(1) == Some(b'/') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn scan_word(&mut self, start: usize) -> Result<Token, LexError> {
        while let Some(c) = self.peek() {
            if is_ident_continue(c) {
                self.pos += 1;
            } else {
                break;
            }
        }
        let span = Span::new(start, self.pos);
        let word = self.slice(span);
        if is_forbidden(word) {
            return Err(LexError {
                message: format!("forbidden token `{word}` is not part of Quanta"),
                span,
            });
        }
        let kind = keyword_kind(word).unwrap_or_else(|| TokenKind::Ident(word.to_string()));
        Ok(Token::new(kind, span))
    }

    fn scan_number(&mut self, start: usize) -> Token {
        if self.is_date_at(start) {
            self.pos += 10;
            let span = Span::new(start, self.pos);
            return Token::new(TokenKind::Date(self.slice(span).to_string()), span);
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let span = Span::new(start, self.pos);
        Token::new(TokenKind::Int(self.slice(span).to_string()), span)
    }

    fn is_date_at(&self, i: usize) -> bool {
        let b = self.bytes;
        if i + 10 > b.len() {
            return false;
        }
        let d = |o: usize| b[i + o].is_ascii_digit();
        d(0) && d(1)
            && d(2)
            && d(3)
            && b[i + 4] == b'-'
            && d(5)
            && d(6)
            && b[i + 7] == b'-'
            && d(8)
            && d(9)
            && b.get(i + 10).map(|c| !c.is_ascii_digit()).unwrap_or(true)
    }

    fn scan_string(&mut self, start: usize) -> Result<Token, LexError> {
        self.pos += 1;
        let content_start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => {
                    let content = Span::new(content_start, self.pos);
                    self.pos += 1;
                    let span = Span::new(start, self.pos);
                    return Ok(Token::new(
                        TokenKind::Str(self.slice(content).to_string()),
                        span,
                    ));
                }
                Some(b'\n') | None => {
                    return Err(LexError {
                        message: "unterminated string literal".to_string(),
                        span: Span::new(start, self.pos),
                    });
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn scan_symbol(&mut self, start: usize) -> Result<Token, LexError> {
        let c = self.peek().unwrap();
        let next = self.peek_at(1);
        let (kind, len) = match (c, next) {
            (b'+', Some(b'=')) => (TokenKind::PlusEq, 2),
            (b'-', Some(b'=')) => (TokenKind::MinusEq, 2),
            (b'<', Some(b'=')) => (TokenKind::Le, 2),
            (b'>', Some(b'=')) => (TokenKind::Ge, 2),
            (b'>', Some(b'>')) => (TokenKind::Shr, 2),
            (b'=', Some(b'=')) => (TokenKind::EqEq, 2),
            (b'!', Some(b'=')) => (TokenKind::Ne, 2),
            (b'&', Some(b'&')) => (TokenKind::AndAnd, 2),
            (b'|', Some(b'|')) => (TokenKind::OrOr, 2),
            (b'{', _) => (TokenKind::LBrace, 1),
            (b'}', _) => (TokenKind::RBrace, 1),
            (b'(', _) => (TokenKind::LParen, 1),
            (b')', _) => (TokenKind::RParen, 1),
            (b',', _) => (TokenKind::Comma, 1),
            (b';', _) => (TokenKind::Semi, 1),
            (b':', _) => (TokenKind::Colon, 1),
            (b'.', _) => (TokenKind::Dot, 1),
            (b'=', _) => (TokenKind::Eq, 1),
            (b'+', _) => (TokenKind::Plus, 1),
            (b'-', _) => (TokenKind::Minus, 1),
            (b'*', _) => (TokenKind::Star, 1),
            (b'/', _) => (TokenKind::Slash, 1),
            (b'%', _) => (TokenKind::Percent, 1),
            (b'<', _) => (TokenKind::Lt, 1),
            (b'>', _) => (TokenKind::Gt, 1),
            (b'!', _) => (TokenKind::Bang, 1),
            _ => {
                let span = Span::new(start, start + 1);
                return Err(LexError {
                    message: format!("unexpected character `{}`", c as char),
                    span,
                });
            }
        };
        self.pos += len;
        Ok(Token::new(kind, Span::new(start, start + len)))
    }

    fn slice(&self, span: Span) -> &str {
        std::str::from_utf8(&self.bytes[span.start..span.end]).unwrap_or("")
    }
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident_continue(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::FORBIDDEN;

    fn kinds(src: &str) -> Vec<TokenKind> {
        tokenize(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn each_forbidden_token_is_rejected() {
        for word in FORBIDDEN {
            let src = format!("contract C {{ asset {word}; }}");
            let err = tokenize(&src).expect_err("forbidden token must not lex");
            assert!(err.message.contains(word));
        }
    }

    #[test]
    fn keywords_and_idents_are_separated() {
        assert_eq!(
            kinds("contract Vault"),
            vec![
                TokenKind::Contract,
                TokenKind::Ident("Vault".to_string()),
                TokenKind::Eof,
            ]
        );
        assert_eq!(
            kinds("mint"),
            vec![TokenKind::Ident("mint".to_string()), TokenKind::Eof]
        );
    }

    #[test]
    fn numbers_dates_and_underscores() {
        assert_eq!(
            kinds("50_000"),
            vec![TokenKind::Int("50_000".to_string()), TokenKind::Eof]
        );
        assert_eq!(
            kinds("2036-07-01"),
            vec![TokenKind::Date("2036-07-01".to_string()), TokenKind::Eof]
        );
        assert_eq!(
            kinds("50 - 3"),
            vec![
                TokenKind::Int("50".to_string()),
                TokenKind::Minus,
                TokenKind::Int("3".to_string()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn multi_character_operators() {
        assert_eq!(
            kinds("<= >= == != += -= && ||"),
            vec![
                TokenKind::Le,
                TokenKind::Ge,
                TokenKind::EqEq,
                TokenKind::Ne,
                TokenKind::PlusEq,
                TokenKind::MinusEq,
                TokenKind::AndAnd,
                TokenKind::OrOr,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn shift_is_distinct_from_greater_than_and_greater_equal() {
        assert_eq!(
            kinds("a >> 2 > b >= c"),
            vec![
                TokenKind::Ident("a".to_string()),
                TokenKind::Shr,
                TokenKind::Int("2".to_string()),
                TokenKind::Gt,
                TokenKind::Ident("b".to_string()),
                TokenKind::Ge,
                TokenKind::Ident("c".to_string()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn spans_are_byte_accurate() {
        let toks = tokenize("owner = deployer;").unwrap();
        assert_eq!(toks[0].span, Span::new(0, 5));
        assert_eq!(toks[1].span, Span::new(6, 7));
        assert_eq!(toks[2].span, Span::new(8, 16));
        assert_eq!(toks[3].span, Span::new(16, 17));
    }

    #[test]
    fn string_literals_and_line_comments() {
        assert_eq!(
            kinds("\"quantova/primitives\" // note\n"),
            vec![
                TokenKind::Str("quantova/primitives".to_string()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn unterminated_string_is_an_error() {
        let err = tokenize("\"open").unwrap_err();
        assert!(err.message.contains("unterminated"));
    }
}
