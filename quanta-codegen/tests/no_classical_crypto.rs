//! No classical cryptography is emittable. The machine exposes only post quantum cryptographic

use qtv_vm::isa::{decode, OpCode};
use quanta_codegen::compile_contract;

const METER: &str = "contract Meter {\n\
  state { reading: u64; }\n\
  entry advance(step: u64) writes(reading) {\n\
    guard step > 0; reading = checked(reading + step); emit Advanced(reading);\n\
  }\n\
  event Advanced(value: u64);\n\
}\n";

const COUNTER: &str = "contract Counter {\n\
  state { owner: Q_Address; count: u64; }\n\
  genesis { owner = deployer; count = 0; }\n\
  entry bump(order: BumpOrder signed by owner) writes(count) {\n\
    count = checked(count + order.step); emit Bumped(count);\n\
  }\n\
  event Bumped(value: u64);\n\
}\n";

/// The cryptographic opcodes the machine exposes, every one a NIST post quantum primitive or SHA3.
fn is_post_quantum_crypto(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Hash
            | OpCode::VerifyMl
            | OpCode::VerifySlh
            | OpCode::MerkleVerify
            | OpCode::VrfVerify
            | OpCode::Kem
            | OpCode::Addr
    )
}

/// Whether an opcode is cryptographic. The match is exhaustive with no wildcard, so any opcode a
fn is_cryptographic(op: OpCode) -> bool {
    match op {
        OpCode::Hash
        | OpCode::VerifyMl
        | OpCode::VerifySlh
        | OpCode::MerkleVerify
        | OpCode::VrfVerify
        | OpCode::Kem
        | OpCode::Addr => true,
        OpCode::Halt
        | OpCode::Nop
        | OpCode::Mov
        | OpCode::Ldi
        | OpCode::Ldc
        | OpCode::Add
        | OpCode::Sub
        | OpCode::Mul
        | OpCode::Div
        | OpCode::Rem
        | OpCode::AddW
        | OpCode::SubW
        | OpCode::MulW
        | OpCode::MulHi
        | OpCode::And
        | OpCode::Or
        | OpCode::Xor
        | OpCode::Not
        | OpCode::Shl
        | OpCode::Shr
        | OpCode::Eq
        | OpCode::LtU
        | OpCode::GtU
        | OpCode::Push
        | OpCode::Pop
        | OpCode::MLoad
        | OpCode::MStore
        | OpCode::Jmp
        | OpCode::Jz
        | OpCode::Jnz
        | OpCode::Call
        | OpCode::Ret
        | OpCode::SLoad
        | OpCode::SStore
        | OpCode::Send
        | OpCode::Emit => false,
    }
}

fn all_opcodes() -> Vec<OpCode> {
    (0u16..=255)
        .filter_map(|b| OpCode::from_byte(b as u8))
        .collect()
}

fn emitted_opcodes(src: &str) -> Vec<OpCode> {
    let program = quanta_parser::parse(src).expect("parse");
    quanta_typeck::check(&program).expect("typecheck");
    let cc = compile_contract(&program.contracts[0]).expect("compile");
    let code = cc.container.code;
    let mut ops = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let (instr, len) = decode(&code, pc).expect("decode");
        ops.push(instr.opcode());
        pc += len;
    }
    ops
}

#[test]
fn the_machine_exposes_only_post_quantum_crypto_opcodes() {
    let crypto: Vec<OpCode> = all_opcodes()
        .into_iter()
        .filter(|op| is_cryptographic(*op))
        .collect();
    for op in &crypto {
        assert!(is_post_quantum_crypto(*op), "{op:?} is not post quantum");
    }
    // Exactly the seven post quantum cryptographic opcodes exist, the six primitives plus the address
    // derivation. There is no classical signature verify and no ecrecover style recovery opcode.
    assert_eq!(
        crypto.len(),
        7,
        "the crypto opcode set must be the post quantum seven"
    );
}

#[test]
fn the_code_generator_emits_only_post_quantum_crypto() {
    for src in [METER, COUNTER] {
        for op in emitted_opcodes(src) {
            if is_cryptographic(op) {
                assert!(
                    is_post_quantum_crypto(op),
                    "emitted {op:?} must be post quantum"
                );
            }
        }
    }
}

#[test]
fn a_signature_lowering_only_ever_verifies_and_never_recovers() {
    // The only signature opcodes the corpus emits are verify opcodes, which consume a public key and
    // return a boolean. The address opcode the binding also emits derives an address from the public
    // key that is presented, never from a signature alone, so there is still no ecrecover equivalent:
    // nothing recovers a key or an address out of a signature.
    let signature_ops: Vec<OpCode> = emitted_opcodes(COUNTER)
        .into_iter()
        .filter(|op| matches!(op, OpCode::VerifyMl | OpCode::VerifySlh))
        .collect();
    assert!(
        !signature_ops.is_empty(),
        "the signed by lowering must verify"
    );
    for op in signature_ops {
        assert!(is_post_quantum_crypto(op));
    }
}
