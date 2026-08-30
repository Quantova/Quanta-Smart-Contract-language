// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use quanta_lexer::Span;

#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub imports: Vec<Import>,
    pub contracts: Vec<Contract>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ident {
    pub text: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StrLit {
    pub value: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IntLit {
    pub text: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    pub names: Vec<Ident>,
    pub path: StrLit,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Contract {
    pub name: Ident,
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Asset(AssetDecl),
    State(StateBlock),
    Genesis(GenesisBlock),
    Invariant(InvariantDecl),
    Entry(EntryDecl),
    Event(EventDecl),
}

#[derive(Clone, Debug, PartialEq)]
pub struct AssetDecl {
    pub name: Ident,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StateBlock {
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldDecl {
    pub name: Ident,
    pub ty: Type,
    pub default: Option<Expr>,
    pub meta: bool,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GenesisBlock {
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InvariantDecl {
    pub expr: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EventDecl {
    pub name: Ident,
    pub params: Vec<Param>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntryDecl {
    pub name: Ident,
    pub params: Vec<Param>,
    pub clauses: Vec<Clause>,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    pub name: Ident,
    pub sealed: bool,
    pub ty: Type,
    pub signed_by: Option<Ident>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Clause {
    Writes {
        names: Vec<Ident>,
        span: Span,
    },
    Reads {
        names: Vec<Ident>,
        span: Span,
    },
    Conserves {
        asset: Ident,
        span: Span,
    },
    Mints {
        asset: Ident,
        span: Span,
    },
    Burns {
        asset: Ident,
        span: Span,
    },
    Limits {
        expr: Expr,
        span: Span,
    },
    Denies {
        expr: Expr,
        span: Span,
    },
    After {
        target: AfterTarget,
        from: Option<Expr>,
        span: Span,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum AfterTarget {
    Duration(Duration),
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Duration {
    pub value: IntLit,
    pub unit: Ident,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Type {
    pub name: Ident,
    pub args: Vec<GenericArg>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GenericArg {
    Type(Type),
    Int(IntLit),
    MofN { m: IntLit, n: IntLit, span: Span },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Guard {
        expr: Expr,
        span: Span,
    },
    Let {
        name: Ident,
        value: Expr,
        span: Span,
    },
    Emit {
        name: Ident,
        args: Vec<Expr>,
        span: Span,
    },
    Assign {
        target: Expr,
        op: AssignOp,
        value: Expr,
        span: Span,
    },
    Expr {
        expr: Expr,
        span: Span,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignOp {
    Set,
    Add,
    Sub,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Int(IntLit),
    Date {
        text: String,
        span: Span,
    },
    Str(StrLit),
    Ident(Ident),
    Caller {
        span: Span,
    },
    Now {
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
    Field {
        base: Box<Expr>,
        name: Ident,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
    Checked {
        expr: Box<Expr>,
        span: Span,
    },
    Wrapping {
        expr: Box<Expr>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::Int(v) => v.span,
            Expr::Date { span, .. } => *span,
            Expr::Str(v) => v.span,
            Expr::Ident(v) => v.span,
            Expr::Caller { span } => *span,
            Expr::Now { span } => *span,
            Expr::Unary { span, .. } => *span,
            Expr::Binary { span, .. } => *span,
            Expr::Field { span, .. } => *span,
            Expr::Call { span, .. } => *span,
            Expr::Checked { span, .. } => *span,
            Expr::Wrapping { span, .. } => *span,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shr,
}
