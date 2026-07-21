use crate::error::ParseError;
use crate::parser::Parser;
use quanta_ast::{Contract, Import, Program};
use quanta_lexer::TokenKind;

pub fn parse(src: &str) -> Result<Program, ParseError> {
    let mut p = Parser::new(src)?;
    let program = p.program()?;
    p.expect_eof()?;
    Ok(program)
}

impl Parser {
    pub(crate) fn program(&mut self) -> Result<Program, ParseError> {
        let start = self.peek_span();
        let mut imports = Vec::new();
        while self.check(&TokenKind::Import) {
            imports.push(self.import_decl()?);
        }
        let mut contracts = Vec::new();
        while self.check(&TokenKind::Contract) {
            contracts.push(self.contract()?);
        }
        let end = contracts
            .last()
            .map(|c| c.span)
            .or_else(|| imports.last().map(|i| i.span))
            .unwrap_or(start);
        Ok(Program {
            imports,
            contracts,
            span: start.join(end),
        })
    }

    fn import_decl(&mut self) -> Result<Import, ParseError> {
        let kw = self.bump();
        self.expect(&TokenKind::LBrace)?;
        let mut names = vec![self.expect_import_name()?];
        while self.eat(&TokenKind::Comma) {
            names.push(self.expect_import_name()?);
        }
        self.expect(&TokenKind::RBrace)?;
        self.expect(&TokenKind::From)?;
        let path = self.expect_str()?;
        let semi = self.expect(&TokenKind::Semi)?;
        Ok(Import {
            names,
            path,
            span: kw.span.join(semi.span),
        })
    }

    fn contract(&mut self) -> Result<Contract, ParseError> {
        let kw = self.bump();
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;
        let mut items = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            items.push(self.contract_item()?);
        }
        let rb = self.expect(&TokenKind::RBrace)?;
        Ok(Contract {
            name,
            items,
            span: kw.span.join(rb.span),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_then_contract() {
        let src = "import { Q_Asset, Quorum } from \"quantova/primitives\";\n\
                   contract C { asset X; }";
        let program = parse(src).unwrap();
        assert_eq!(program.imports.len(), 1);
        assert_eq!(program.imports[0].names.len(), 2);
        assert_eq!(program.contracts.len(), 1);
    }

    #[test]
    fn a_missing_closing_brace_is_a_spanned_error() {
        let err = parse("contract C { asset X;").unwrap_err();
        assert!(err.span.start <= err.span.end);
        assert!(err.message.contains("expected"));
    }

    #[test]
    fn a_stray_token_after_the_program_is_rejected() {
        let err = parse("contract C { } contract").unwrap_err();
        assert!(!err.message.is_empty());
    }
}
