//! Code generation errors. Each carries the source span of the offending construct so the front end

use crate::emit::LinkError;
use quanta_lexer::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    /// A construct the code generator does not yet lower.
    Unsupported { what: String, span: Span },
    /// An expression needs more temporary registers than the machine provides.
    RegisterExhausted { span: Span },
    /// An integer literal does not fit a 64 bit machine word.
    IntegerTooWide { text: String, span: Span },
    /// A branch target failed to resolve while linking the code image.
    Link(LinkError),
}

impl CodegenError {
    pub fn span(&self) -> Span {
        match self {
            CodegenError::Unsupported { span, .. }
            | CodegenError::RegisterExhausted { span }
            | CodegenError::IntegerTooWide { span, .. } => *span,
            CodegenError::Link(_) => Span::default(),
        }
    }
}

impl std::fmt::Display for CodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodegenError::Unsupported { what, .. } => {
                write!(f, "code generation does not yet lower {what}")
            }
            CodegenError::RegisterExhausted { .. } => {
                write!(
                    f,
                    "expression needs more registers than the machine provides"
                )
            }
            CodegenError::IntegerTooWide { text, .. } => {
                write!(
                    f,
                    "integer literal {text} does not fit a 64 bit machine word"
                )
            }
            CodegenError::Link(e) => write!(f, "internal link error: {e:?}"),
        }
    }
}
