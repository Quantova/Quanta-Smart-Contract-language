//! Hand written lexer for the Quanta language.

pub mod lexer;
pub mod token;

pub use lexer::{tokenize, LexError};
pub use token::{is_forbidden, keyword_kind, Span, Token, TokenKind, FORBIDDEN};
