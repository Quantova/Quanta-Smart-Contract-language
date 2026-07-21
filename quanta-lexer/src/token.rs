//! Token kinds, source spans, and the keyword and forbidden registers.

/// A half open byte range `[start, end)` into the source text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    /// The smallest span covering both operands.
    pub fn join(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl std::fmt::Debug for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TokenKind {
    Ident(String),
    Int(String),
    Date(String),
    Str(String),

    Contract,
    Entry,
    Guard,
    Genesis,
    Caller,
    Now,
    State,
    Invariant,
    Event,
    Emit,
    Asset,
    Let,
    Signed,
    By,
    Sealed,
    Quorum,
    After,
    From,
    Mints,
    Burns,
    Conserves,
    Writes,
    Reads,
    Limits,
    Denies,
    Import,
    Checked,
    Wrapping,

    LBrace,
    RBrace,
    LParen,
    RParen,
    Comma,
    Semi,
    Colon,
    Dot,
    Eq,
    PlusEq,
    MinusEq,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Lt,
    Gt,
    Le,
    Ge,
    EqEq,
    Ne,
    Bang,
    AndAnd,
    OrOr,
    Shr,

    Eof,
}

impl TokenKind {
    /// A short label used in parser error messages.
    pub fn describe(&self) -> String {
        match self {
            TokenKind::Ident(t) => format!("identifier `{t}`"),
            TokenKind::Int(t) => format!("integer `{t}`"),
            TokenKind::Date(t) => format!("date `{t}`"),
            TokenKind::Str(t) => format!("string \"{t}\""),
            TokenKind::Eof => "end of input".to_string(),
            other => format!("`{}`", other.symbol()),
        }
    }

    fn symbol(&self) -> &'static str {
        match self {
            TokenKind::Contract => "contract",
            TokenKind::Entry => "entry",
            TokenKind::Guard => "guard",
            TokenKind::Genesis => "genesis",
            TokenKind::Caller => "caller",
            TokenKind::Now => "now",
            TokenKind::State => "state",
            TokenKind::Invariant => "invariant",
            TokenKind::Event => "event",
            TokenKind::Emit => "emit",
            TokenKind::Asset => "asset",
            TokenKind::Let => "let",
            TokenKind::Signed => "signed",
            TokenKind::By => "by",
            TokenKind::Sealed => "sealed",
            TokenKind::Quorum => "Quorum",
            TokenKind::After => "after",
            TokenKind::From => "from",
            TokenKind::Mints => "mints",
            TokenKind::Burns => "burns",
            TokenKind::Conserves => "conserves",
            TokenKind::Writes => "writes",
            TokenKind::Reads => "reads",
            TokenKind::Limits => "limits",
            TokenKind::Denies => "denies",
            TokenKind::Import => "import",
            TokenKind::Checked => "checked",
            TokenKind::Wrapping => "wrapping",
            TokenKind::LBrace => "{",
            TokenKind::RBrace => "}",
            TokenKind::LParen => "(",
            TokenKind::RParen => ")",
            TokenKind::Comma => ",",
            TokenKind::Semi => ";",
            TokenKind::Colon => ":",
            TokenKind::Dot => ".",
            TokenKind::Eq => "=",
            TokenKind::PlusEq => "+=",
            TokenKind::MinusEq => "-=",
            TokenKind::Plus => "+",
            TokenKind::Minus => "-",
            TokenKind::Star => "*",
            TokenKind::Slash => "/",
            TokenKind::Percent => "%",
            TokenKind::Lt => "<",
            TokenKind::Gt => ">",
            TokenKind::Le => "<=",
            TokenKind::Ge => ">=",
            TokenKind::EqEq => "==",
            TokenKind::Ne => "!=",
            TokenKind::Bang => "!",
            TokenKind::AndAnd => "&&",
            TokenKind::OrOr => "||",
            TokenKind::Shr => ">>",
            _ => "",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Token { kind, span }
    }
}

/// Solidity carryovers that are not part of Quanta. Their appearance in source
pub const FORBIDDEN: &[&str] = &[
    "function",
    "require",
    "constructor",
    "msg",
    "mapping",
    "uint",
    "uint256",
    "ecrecover",
    "pragma",
    "wei",
    "ether",
];

pub fn is_forbidden(word: &str) -> bool {
    FORBIDDEN.contains(&word)
}

/// Maps an identifier spelling to its keyword kind, if it is a keyword.
pub fn keyword_kind(word: &str) -> Option<TokenKind> {
    let kind = match word {
        "contract" => TokenKind::Contract,
        "entry" => TokenKind::Entry,
        "guard" => TokenKind::Guard,
        "genesis" => TokenKind::Genesis,
        "caller" => TokenKind::Caller,
        "now" => TokenKind::Now,
        "state" => TokenKind::State,
        "invariant" => TokenKind::Invariant,
        "event" => TokenKind::Event,
        "emit" => TokenKind::Emit,
        "asset" => TokenKind::Asset,
        "let" => TokenKind::Let,
        "signed" => TokenKind::Signed,
        "by" => TokenKind::By,
        "sealed" => TokenKind::Sealed,
        "Quorum" => TokenKind::Quorum,
        "after" => TokenKind::After,
        "from" => TokenKind::From,
        "mints" => TokenKind::Mints,
        "burns" => TokenKind::Burns,
        "conserves" => TokenKind::Conserves,
        "writes" => TokenKind::Writes,
        "reads" => TokenKind::Reads,
        "limits" => TokenKind::Limits,
        "denies" => TokenKind::Denies,
        "import" => TokenKind::Import,
        "checked" => TokenKind::Checked,
        "wrapping" => TokenKind::Wrapping,
        _ => return None,
    };
    Some(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_map_and_others_do_not() {
        assert_eq!(keyword_kind("contract"), Some(TokenKind::Contract));
        assert_eq!(keyword_kind("Quorum"), Some(TokenKind::Quorum));
        assert_eq!(keyword_kind("checked"), Some(TokenKind::Checked));
        assert_eq!(keyword_kind("wrapping"), Some(TokenKind::Wrapping));
        assert_eq!(keyword_kind("now"), Some(TokenKind::Now));
        assert_eq!(keyword_kind("owner"), None);
        assert_eq!(keyword_kind("mint"), None);
    }

    #[test]
    fn forbidden_register_matches_exact_words() {
        assert!(is_forbidden("function"));
        assert!(is_forbidden("uint256"));
        assert!(is_forbidden("ecrecover"));
        assert!(!is_forbidden("u256"));
        assert!(!is_forbidden("entry"));
    }

    #[test]
    fn span_join_covers_both() {
        let a = Span::new(2, 5);
        let b = Span::new(8, 12);
        assert_eq!(a.join(b), Span::new(2, 12));
    }
}
