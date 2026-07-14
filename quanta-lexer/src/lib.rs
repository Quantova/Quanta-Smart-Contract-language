//! Hand written lexer for the Quanta language.

pub mod token;

pub use token::{is_forbidden, keyword_kind, Span, Token, TokenKind, FORBIDDEN};
