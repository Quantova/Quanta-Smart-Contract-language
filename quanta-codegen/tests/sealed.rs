//! Conformance vector for the sealed parameter. Sealing a parameter is legal and type checks, but

use quanta_codegen::{compile_contract, CodegenError};

const CONFIDENTIAL: &str = "contract Confidential {\n\
  state { total: u64; }\n\
  entry submit(bid: sealed u64) writes(total) {\n\
    total = checked(total + bid);\n\
    emit Recorded(total);\n\
  }\n\
  event Recorded(value: u64);\n\
}\n";

#[test]
fn a_sealed_parameter_type_checks_but_has_no_opening_lowering() {
    let program = quanta_parser::parse(CONFIDENTIAL).expect("parse");
    // Sealing a parameter is legal, so the checker accepts the contract.
    quanta_typeck::check(&program).expect("typecheck");

    // Code generation refuses the sealed opening and flags the missing decapsulation opcode.
    let err = compile_contract(&program.contracts[0]).expect_err("sealed opening has no lowering");
    match err {
        CodegenError::Unsupported { what, .. } => {
            assert!(
                what.contains("sealed"),
                "the refusal names the sealed opening, was: {what}"
            );
        }
        other => panic!("expected an unsupported refusal, got {other:?}"),
    }
}
