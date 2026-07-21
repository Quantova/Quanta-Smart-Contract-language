use crate::emit::LinkError;
use quanta_lexer::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    Unsupported { what: String, span: Span },
    RegisterExhausted { span: Span },
    IntegerTooWide { text: String, span: Span },
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
