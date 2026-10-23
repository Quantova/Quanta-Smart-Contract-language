# Quanta

Quanta is the smart contract language of Quantova. A contract is written in a `.qs` source file and compiles to a QVM container, the unit of code the Quantova virtual machine loads and runs. There is no EVM beneath it.

Quantova is a sovereign post quantum Layer 1 built from scratch, sharing no code, no wire, and no trust assumption with any other chain. It is post quantum end to end and not a classical chain with a post quantum signature bolted on, built on NIST standardized schemes alone with no classical escape hatch anywhere. Consensus is QORUS, the virtual machine is the QVM running compiled containers, addresses are Q1 bech32m, and the asset is QTOV with its base unit the Quon and TQTOV on the testnet.

The defining property of Quanta is that the classic smart contract exploits are not runtime hazards guarded by checks. They are errors that stop the compile. A contract that could reenter, overflow, forge authority, mint without limit, drop value, or be front run does not produce a container, because the shape that carries the exploit is not a valid program.

## Six exploits that fail to compile

- Reentrancy has no expression. The language has no synchronous external call, so control cannot leave an entry and reenter it. The only outward transfer is `send`, which is terminal and returns nothing. A body that tries to call a method on the caller or on a stored address names a call the language does not provide, and the checker rejects it.
- Unchecked overflow is rejected at the type level. Checked arithmetic is the default, so a plain overflow reverts at run time, and on top of that an addition of unbounded external input into a stored integer with no declared bound does not compile. The author clears it by bounding the field with a `limits` clause, by drawing the addend from an asset, or by writing the arithmetic as `checked(..)` or `wrapping(..)`.
- Forged authorization cannot be assembled. Authority over an entry comes only from a parameter written `signed by` a party, a value produced by a real signature verification. Reconstructing authority by comparing self declared parameter data to a stored party is rejected as a forged authority.
- Infinite mint is refused by conservation. Only an entry that declares `mints` or `burns` may change supply, and a mint must be gated by a signed party or a quorum. An entry that creates supply without the declaration, or that mints without authority, does not compile.
- Dropped and double spent value are ruled out by linearity. An asset value must be used exactly once. Consuming it twice copies it and leaving it unused on a path drops it, and both are compile errors.
- Front running is flagged by the sealed rule. An order that competes for a pooled asset and is settled in a later call must be declared `sealed`, and an unsealed competitive order that gates on its own amount is rejected. The declaration marks the order but does not yet hide it. No sealing is applied on the way to the chain today, so a sealed value is readable in the mempool like any other argument.

The repository carries a corpus of six exploit contracts, one per class. Each is valid Quanta syntax and each is rejected by the checker for its own reason, and a test asserts that not one of them compiles clean.

## The checker

The static checker runs a fixed sequence of passes over each contract and returns the first violation with its line and column. The passes are resolve, types, linear, signature, conserve, access, and sealed. resolve binds names and enforces the no external call rule. types carries the numeric and predicate typing and the checked arithmetic rule. linear enforces the exactly once use of assets. signature enforces real authority. conserve enforces conservation of supply. access enforces that an entry writes only the state it names in its `writes` clause and that an invariant ranges only over state. sealed enforces the front running rule.

## From source to container

The code generator lowers a type checked contract to the register machine bytecode of the QVM and packs it into a container with an embedded interface descriptor. Selectors follow SPEC-cid and the container layout follows SPEC-container in the Quantova-Specs repository. The emit crate turns the whole result into one JSON document that carries each contract's container bytes as hex together with the interface a caller needs, every entry with its selector and argument layout and every event with its selector. The command line tool and the browser compiler drive this one path, so the container the editor shows is byte for byte the container the command line produces and the QVM runs.

## Signed orders and provenance

A parameter signed by an owner or a quorum is checked against a fixed message. It opens with the tag QTVSGN04 and then carries the chain id word and the 32 byte genesis hash that the contract copies from the machine context, the contract id, the selector word, the signer address, the signer nonce, an expiry in unix seconds, a 32 byte layout hash and the signed fields. The caller supplies the expiry at the argument slot that emit reports as the parameter name followed by #expiry, and the contract refuses the call once the block time passes it. The layout hash is SHA3 256 over the tag QTVLAYT1, the four selector bytes, the field count as a 32 bit big endian word and, for each signed field in message order, its name and its type each prefixed by a 32 bit big endian byte length and followed by its width in bytes as a 64 bit big endian word. The compiler writes this hash into the message as a constant, so a signature only verifies for the field names and types the contract itself reads. Emit reports it per signed parameter as layout_hash under signed_orders and quorum_orders, next to the fields, field_types and field_widths it was computed from.

When the environment variable QUANTA_PROVENANCE_KEY_FILE names a file that only its owner can read and that holds exactly 64 hex characters, build and emit append a provenance record to each container. The record is the marker QPV2, a compiler id that hashes the compiler version and build commit, the SHA3 hash of the exact source file and an ML DSA signature over the container identifier, the compiler id and the source hash under the context QUANTOVA/QVM/PROVENANCE/v2. The record shows which key holder admitted a container. It is an allow list and does not by itself prove that the container came from checked source, which reviewers confirm by recompiling the published source and comparing the bytes.

## Post quantum with no escape hatch

The QVM exposes only post quantum cryptographic opcodes, and the code generator has no path to a classical one. The cryptographic instructions are the SHA3 hash, the ML DSA verify, the SLH DSA verify, and the Merkle verify. A test classifies every machine opcode with an exhaustive match that has no wildcard and no classical arm, so a future opcode cannot pass as classical without failing the build, and the opcodes emitted over a corpus of contracts are checked to be post quantum only.

The escape hatch is closed earlier still. The lexer refuses a set of foreign identifiers outright, among them function, require, msg, mapping, uint256, ecrecover, pragma, wei, and ether, so source shaped like another chain's language does not even tokenize. The vocabulary is Quanta's own.

## The crates

The compiler is a Rust workspace.

- quanta-lexer turns source into tokens and holds the forbidden identifier list.
- quanta-ast defines the syntax tree and its printer.
- quanta-parser builds the tree and reports position accurate syntax errors.
- quanta-typeck is the static checker and its seven passes.
- quanta-codegen lowers to QVM bytecode and builds the container.
- quanta-emit produces the one JSON document that every front end shares.
- quanta-web is the browser compiler crate. It runs the whole compiler in the user's page with no backend, which keeps the compile off Quantova's servers and gives the IDE the same lexer, parser, checker, and code generator the command line runs.
- quanta-cli is the command line front end, with parse, fmt, tokens, check, build, and emit subcommands.

The QVM and the cryptography arrive as pinned dependencies, qtv-vm at commit 8c6eb5c and qtv-crypto at commit e47d6cd, and are never reimplemented here.

## Examples

The examples directory holds contracts written in Quanta, among them a token, an escrow, an auction, a vault, a payroll, a name registry, and a sovereign stablecoin, which show the language and compile end to end.

## Status and honesty

Quanta is at the testnet stage of Quantova. The compiler and its checker are covered by tests across the workspace, including the exploit corpus. The cryptography it targets is a from scratch reference implementation validated against the NIST test vectors and has not been independently audited. Nothing here is audited, unbreakable, or production secure. Quanta is described by what it does, which is to make a set of exploit classes inexpressible and to emit a post quantum container.

## Governance and license

The crypto policy in the Quantova-Specs repository is the supreme law of the stack and governs this repository. Dual licensed under Apache 2.0 and MIT.
