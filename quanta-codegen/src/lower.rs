//! Expression lowering. A value computes into a stack of temporary registers. A state field reads

use crate::emit::{Builder, Label};
use crate::error::CodegenError;
use crate::layout::Layout;
use qtv_vm::isa::{Instr, Reg, NUM_REGS};
use quanta_ast::{AssignOp, BinOp, EntryDecl, Expr, Stmt, UnaryOp};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

/// Scratch register zero holds transient addresses and keys and is never held across a step.
const SCRATCH: Reg = 0;
/// Temporaries begin above the scratch register.
const FIRST_TEMP: Reg = 1;

/// Base offset of the argument words in scratch memory.
pub const ARG_BASE: u64 = 0;
/// Width of one argument word.
const WORD: u64 = 8;

/// Argument key suffix for the scheme identifier of a signed parameter.
const SIG_SCHEME_SUFFIX: &str = "#scheme";
/// Argument key suffix for the pointer to a signed parameter's verify region.
const SIG_PTR_SUFFIX: &str = "#ptr";
/// Argument key suffix for the length of a signed parameter's verify region.
const SIG_LEN_SUFFIX: &str = "#len";

/// Signature scheme identifiers carried in the envelope. ML DSA is the module lattice scheme and the
const SCHEME_ML: u64 = 0x01;
const SCHEME_SLH: u64 = 0x02;

/// A stack of temporary registers. They allocate and free in stack order.
pub struct Regs {
    next: Reg,
}

impl Regs {
    pub fn new() -> Regs {
        Regs { next: FIRST_TEMP }
    }

    fn alloc(&mut self, span: Span) -> Result<Reg, CodegenError> {
        if (self.next as usize) >= NUM_REGS {
            return Err(CodegenError::RegisterExhausted { span });
        }
        let r = self.next;
        self.next += 1;
        Ok(r)
    }

    fn free(&mut self, r: Reg) {
        debug_assert_eq!(self.next, r + 1, "temporaries free in stack order");
        self.next -= 1;
    }
}

impl Default for Regs {
    fn default() -> Self {
        Regs::new()
    }
}

/// The scratch memory offset each argument value loads from. An argument is a scalar parameter named
#[derive(Default)]
pub struct Args {
    offsets: HashMap<String, u64>,
    order: Vec<String>,
}

impl Args {
    pub fn new() -> Args {
        Args::default()
    }

    fn offset_of(&mut self, key: &str) -> u64 {
        if let Some(off) = self.offsets.get(key) {
            return *off;
        }
        let off = ARG_BASE + self.order.len() as u64 * WORD;
        self.offsets.insert(key.to_string(), off);
        self.order.push(key.to_string());
        off
    }

    /// The argument words in assignment order, each a key and its memory offset.
    pub fn layout(&self) -> Vec<(String, u64)> {
        self.order
            .iter()
            .map(|k| (k.clone(), self.offsets[k]))
            .collect()
    }
}

/// The mutable state threaded through lowering one entry.
pub struct Ctx<'a> {
    layout: &'a Layout,
    params: &'a HashSet<String>,
    b: &'a mut Builder,
    regs: &'a mut Regs,
    args: &'a mut Args,
}

impl<'a> Ctx<'a> {
    pub fn new(
        layout: &'a Layout,
        params: &'a HashSet<String>,
        b: &'a mut Builder,
        regs: &'a mut Regs,
        args: &'a mut Args,
    ) -> Ctx<'a> {
        Ctx {
            layout,
            params,
            b,
            regs,
            args,
        }
    }
}

/// Lowers an expression, returning the temporary register that holds its value. `wrapping` selects
pub fn lower_expr(ctx: &mut Ctx, expr: &Expr, wrapping: bool) -> Result<Reg, CodegenError> {
    match expr {
        Expr::Int(lit) => {
            let value = parse_int(&lit.text, lit.span)?;
            let d = ctx.regs.alloc(lit.span)?;
            ctx.b.op(Instr::Ldi { d, imm: value });
            Ok(d)
        }
        Expr::Ident(id) => lower_ident(ctx, &id.text, id.span),
        Expr::Field { base, name, span } => lower_field(ctx, base, &name.text, *span),
        Expr::Checked { expr, .. } => lower_expr(ctx, expr, false),
        Expr::Wrapping { expr, .. } => lower_expr(ctx, expr, true),
        Expr::Unary { op, expr, span } => lower_unary(ctx, *op, expr, *span, wrapping),
        Expr::Binary {
            op, left, right, ..
        } => lower_binary(ctx, *op, left, right, wrapping),
        Expr::Caller { span } => Err(CodegenError::Unsupported {
            what: "the caller value".into(),
            span: *span,
        }),
        Expr::Str(s) => Err(CodegenError::Unsupported {
            what: "a string literal".into(),
            span: s.span,
        }),
        Expr::Date { span, .. } => Err(CodegenError::Unsupported {
            what: "a date literal".into(),
            span: *span,
        }),
        Expr::Call { span, .. } => Err(CodegenError::Unsupported {
            what: "a call expression".into(),
            span: *span,
        }),
    }
}

fn lower_ident(ctx: &mut Ctx, name: &str, span: Span) -> Result<Reg, CodegenError> {
    if let Some(slot) = ctx.layout.slot(name) {
        load_slot(ctx, slot, span)
    } else if ctx.params.contains(name) {
        let off = ctx.args.offset_of(name);
        load_arg(ctx, off, span)
    } else {
        Err(CodegenError::Unsupported {
            what: format!("the value `{name}`"),
            span,
        })
    }
}

fn lower_field(ctx: &mut Ctx, base: &Expr, field: &str, span: Span) -> Result<Reg, CodegenError> {
    if let Expr::Ident(id) = base {
        if ctx.params.contains(&id.text) {
            let key = format!("{}.{}", id.text, field);
            let off = ctx.args.offset_of(&key);
            return load_arg(ctx, off, span);
        }
    }
    Err(CodegenError::Unsupported {
        what: "a field access outside a parameter".into(),
        span,
    })
}

fn load_arg(ctx: &mut Ctx, off: u64, span: Span) -> Result<Reg, CodegenError> {
    let d = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: off,
    });
    ctx.b.op(Instr::MLoad { d, a: SCRATCH });
    Ok(d)
}

fn lower_unary(
    ctx: &mut Ctx,
    op: UnaryOp,
    expr: &Expr,
    span: Span,
    wrapping: bool,
) -> Result<Reg, CodegenError> {
    match op {
        UnaryOp::Not => {
            let r = lower_expr(ctx, expr, wrapping)?;
            logical_not(ctx, r);
            Ok(r)
        }
        UnaryOp::Neg => Err(CodegenError::Unsupported {
            what: "unary negation".into(),
            span,
        }),
    }
}

fn lower_binary(
    ctx: &mut Ctx,
    op: BinOp,
    left: &Expr,
    right: &Expr,
    wrapping: bool,
) -> Result<Reg, CodegenError> {
    let l = lower_expr(ctx, left, wrapping)?;
    let r = lower_expr(ctx, right, wrapping)?;
    match op {
        BinOp::Add if wrapping => ctx.b.op(Instr::AddW { d: l, a: l, b: r }),
        BinOp::Add => ctx.b.op(Instr::Add { d: l, a: l, b: r }),
        BinOp::Sub if wrapping => ctx.b.op(Instr::SubW { d: l, a: l, b: r }),
        BinOp::Sub => ctx.b.op(Instr::Sub { d: l, a: l, b: r }),
        BinOp::Mul if wrapping => ctx.b.op(Instr::MulW { d: l, a: l, b: r }),
        BinOp::Mul => ctx.b.op(Instr::Mul { d: l, a: l, b: r }),
        BinOp::Div => ctx.b.op(Instr::Div { d: l, a: l, b: r }),
        BinOp::Rem => ctx.b.op(Instr::Rem { d: l, a: l, b: r }),
        BinOp::And => ctx.b.op(Instr::And { d: l, a: l, b: r }),
        BinOp::Or => ctx.b.op(Instr::Or { d: l, a: l, b: r }),
        BinOp::Eq => ctx.b.op(Instr::Eq { d: l, a: l, b: r }),
        BinOp::Lt => ctx.b.op(Instr::LtU { d: l, a: l, b: r }),
        BinOp::Gt => ctx.b.op(Instr::GtU { d: l, a: l, b: r }),
        BinOp::Ne => {
            ctx.b.op(Instr::Eq { d: l, a: l, b: r });
            logical_not(ctx, l);
        }
        BinOp::Le => {
            ctx.b.op(Instr::GtU { d: l, a: l, b: r });
            logical_not(ctx, l);
        }
        BinOp::Ge => {
            ctx.b.op(Instr::LtU { d: l, a: l, b: r });
            logical_not(ctx, l);
        }
    }
    ctx.regs.free(r);
    Ok(l)
}

/// Flips a boolean in `r` between zero and one.
fn logical_not(ctx: &mut Ctx, r: Reg) {
    ctx.b.op(Instr::Ldi { d: SCRATCH, imm: 1 });
    ctx.b.op(Instr::Xor {
        d: r,
        a: r,
        b: SCRATCH,
    });
}

fn parse_int(text: &str, span: Span) -> Result<u64, CodegenError> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    cleaned
        .parse::<u64>()
        .map_err(|_| CodegenError::IntegerTooWide {
            text: text.to_string(),
            span,
        })
}

/// Reads a state slot into a fresh temporary register.
fn load_slot(ctx: &mut Ctx, slot: u64, span: Span) -> Result<Reg, CodegenError> {
    let d = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: slot,
    });
    ctx.b.op(Instr::SLoad { d, a: SCRATCH });
    Ok(d)
}

/// Writes a register value to a state slot.
fn store_slot(ctx: &mut Ctx, slot: u64, value: Reg) {
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: slot,
    });
    ctx.b.op(Instr::SStore {
        a: SCRATCH,
        b: value,
    });
}

/// Refuses to lower an entry that takes a sealed parameter. A sealed value is confidential in the
fn refuse_sealed(entry: &EntryDecl) -> Result<(), CodegenError> {
    for param in &entry.params {
        if param.sealed {
            return Err(CodegenError::Unsupported {
                what: format!(
                    "opening the sealed parameter `{}`, which needs a decapsulation opcode absent \
                     from qtv-vm v0.1.0",
                    param.name.text
                ),
                span: param.span,
            });
        }
    }
    Ok(())
}

/// Lowers the body of one entry into the builder and appends the clean halt. A fresh register stack
pub fn lower_entry(
    layout: &Layout,
    entry: &EntryDecl,
    invariants: &[&Expr],
    b: &mut Builder,
    trap: Label,
) -> Result<Args, CodegenError> {
    refuse_sealed(entry)?;
    let params: HashSet<String> = entry.params.iter().map(|p| p.name.text.clone()).collect();
    let writes_state = !layout.access(entry).writes.is_empty();
    let mut regs = Regs::new();
    let mut args = Args::new();
    {
        let mut ctx = Ctx::new(layout, &params, b, &mut regs, &mut args);
        lower_signed_prologue(&mut ctx, entry, trap)?;
        for stmt in &entry.body {
            lower_stmt(&mut ctx, stmt, trap)?;
        }
        if writes_state {
            for inv in invariants {
                let r = lower_expr(&mut ctx, inv, false)?;
                ctx.b.jz(r, trap);
                ctx.regs.free(r);
            }
        }
    }
    b.op(Instr::Halt);
    Ok(args)
}

/// The verify opcode a scheme identifier dispatches to.
enum VerifyOp {
    Ml,
    Slh,
}

/// Verifies each `signed by` parameter before the body runs, dispatching on the one byte scheme
fn lower_signed_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for param in &entry.params {
        if param.signed_by.is_none() {
            continue;
        }
        let name = &param.name.text;
        let span = param.span;
        let scheme_off = ctx.args.offset_of(&format!("{name}{SIG_SCHEME_SUFFIX}"));
        let ptr_off = ctx.args.offset_of(&format!("{name}{SIG_PTR_SUFFIX}"));
        let len_off = ctx.args.offset_of(&format!("{name}{SIG_LEN_SUFFIX}"));
        dispatch_verify(ctx, scheme_off, ptr_off, len_off, trap, span)?;
    }
    Ok(())
}

/// Dispatches one signature on its one byte scheme identifier and verifies it, reverting to the trap
fn dispatch_verify(
    ctx: &mut Ctx,
    scheme_off: u64,
    ptr_off: u64,
    len_off: u64,
    trap: Label,
    span: Span,
) -> Result<(), CodegenError> {
    let ml_label = ctx.b.label();
    let slh_label = ctx.b.label();
    let done_label = ctx.b.label();

    // Read the scheme identifier and branch to the matching verify, reverting on an unknown one.
    let scheme = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: scheme_off,
    });
    ctx.b.op(Instr::MLoad {
        d: scheme,
        a: SCRATCH,
    });
    let test = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: SCHEME_ML,
    });
    ctx.b.op(Instr::Eq {
        d: test,
        a: scheme,
        b: SCRATCH,
    });
    ctx.b.jnz(test, ml_label);
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: SCHEME_SLH,
    });
    ctx.b.op(Instr::Eq {
        d: test,
        a: scheme,
        b: SCRATCH,
    });
    ctx.b.jnz(test, slh_label);
    ctx.b.jmp(trap);
    ctx.regs.free(test);
    ctx.regs.free(scheme);

    ctx.b.mark(ml_label);
    emit_verify(ctx, VerifyOp::Ml, ptr_off, len_off, trap, span)?;
    ctx.b.jmp(done_label);

    ctx.b.mark(slh_label);
    emit_verify(ctx, VerifyOp::Slh, ptr_off, len_off, trap, span)?;

    ctx.b.mark(done_label);
    Ok(())
}

/// Emits one verify over the parameter region and reverts to the trap when it does not verify.
fn emit_verify(
    ctx: &mut Ctx,
    op: VerifyOp,
    ptr_off: u64,
    len_off: u64,
    trap: Label,
    span: Span,
) -> Result<(), CodegenError> {
    let rptr = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: ptr_off,
    });
    ctx.b.op(Instr::MLoad {
        d: rptr,
        a: SCRATCH,
    });

    let rlen = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: len_off,
    });
    ctx.b.op(Instr::MLoad {
        d: rlen,
        a: SCRATCH,
    });

    let rok = ctx.regs.alloc(span)?;
    let instr = match op {
        VerifyOp::Ml => Instr::VerifyMl {
            a: rptr,
            b: rlen,
            c: rok,
        },
        VerifyOp::Slh => Instr::VerifySlh {
            a: rptr,
            b: rlen,
            c: rok,
        },
    };
    ctx.b.op(instr);
    ctx.b.jz(rok, trap);

    ctx.regs.free(rok);
    ctx.regs.free(rlen);
    ctx.regs.free(rptr);
    Ok(())
}

fn lower_stmt(ctx: &mut Ctx, stmt: &Stmt, trap: Label) -> Result<(), CodegenError> {
    match stmt {
        // A guard evaluates its condition and reverts by jumping to the trap when it is false.
        Stmt::Guard { expr, .. } => {
            let r = lower_expr(ctx, expr, false)?;
            ctx.b.jz(r, trap);
            ctx.regs.free(r);
            Ok(())
        }
        Stmt::Assign {
            target,
            op,
            value,
            span,
        } => lower_assign(ctx, target, *op, value, *span),
        // An emit computes the event operands. Appending the typed event to the event trie has no
        // machine opcode yet, so only the operand evaluation lowers here.
        Stmt::Emit { args, .. } => {
            for arg in args {
                let r = lower_expr(ctx, arg, false)?;
                ctx.regs.free(r);
            }
            Ok(())
        }
        Stmt::Let { span, .. } => Err(CodegenError::Unsupported {
            what: "a let binding".into(),
            span: *span,
        }),
        Stmt::Expr { span, .. } => Err(CodegenError::Unsupported {
            what: "an expression statement".into(),
            span: *span,
        }),
    }
}

fn lower_assign(
    ctx: &mut Ctx,
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: Span,
) -> Result<(), CodegenError> {
    let slot = match target {
        Expr::Ident(id) => ctx.layout.slot(&id.text),
        _ => None,
    };
    let slot = slot.ok_or_else(|| CodegenError::Unsupported {
        what: "an assignment target that is not a state field".into(),
        span,
    })?;

    match op {
        AssignOp::Set => {
            let rv = lower_expr(ctx, value, false)?;
            store_slot(ctx, slot, rv);
            ctx.regs.free(rv);
        }
        AssignOp::Add | AssignOp::Sub => {
            let rv = lower_expr(ctx, value, false)?;
            let rf = load_slot(ctx, slot, span)?;
            match op {
                AssignOp::Add => ctx.b.op(Instr::Add {
                    d: rf,
                    a: rf,
                    b: rv,
                }),
                _ => ctx.b.op(Instr::Sub {
                    d: rf,
                    a: rf,
                    b: rv,
                }),
            }
            store_slot(ctx, slot, rf);
            ctx.regs.free(rf);
            ctx.regs.free(rv);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_vm::interp::Interpreter;
    use quanta_ast::{Item, Stmt};
    use std::collections::BTreeMap;

    // Wrap an expression in a harness contract with state fields x and y and parameters a and b,
    // then hand back the layout, parameter set, and the parsed expression.
    fn harness(expr_src: &str) -> (Layout, HashSet<String>, Expr) {
        let src = format!(
            "contract H {{ state {{ x: u64; y: u64; }} \
             entry e(a: u64, b: u64) writes(x) {{ x = {expr_src}; }} }}"
        );
        let program = quanta_parser::parse(&src).expect("harness parses");
        let contract = &program.contracts[0];
        let layout = Layout::build(contract);
        let entry = contract
            .items
            .iter()
            .find_map(|i| match i {
                Item::Entry(e) => Some(e),
                _ => None,
            })
            .expect("an entry");
        let params = entry.params.iter().map(|p| p.name.text.clone()).collect();
        let value = match &entry.body[0] {
            Stmt::Assign { value, .. } => value.clone(),
            other => panic!("unexpected statement {other:?}"),
        };
        (layout, params, value)
    }

    fn eval(expr_src: &str, state: &[(&str, u64)], argvals: &[(&str, u64)]) -> u64 {
        let (layout, params, expr) = harness(expr_src);
        let mut b = Builder::new();
        let mut regs = Regs::new();
        let mut args = Args::new();
        let dest = {
            let mut ctx = Ctx::new(&layout, &params, &mut b, &mut regs, &mut args);
            lower_expr(&mut ctx, &expr, false).expect("lower")
        };
        b.op(Instr::Halt);
        let code = b.link().expect("link");

        let mut storage = BTreeMap::new();
        for (name, val) in state {
            storage.insert(layout.slot(name).expect("state field"), *val);
        }
        let argmap: HashMap<String, u64> =
            argvals.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let mut mem = vec![0u8; 4096];
        for (key, off) in args.layout() {
            let val = *argmap.get(&key).unwrap_or(&0);
            let at = off as usize;
            mem[at..at + 8].copy_from_slice(&val.to_be_bytes());
        }

        let out = Interpreter::new(&code, &[], 100_000)
            .with_storage(storage)
            .with_memory(&mem)
            .run()
            .expect("halt");
        out.regs[dest as usize]
    }

    #[test]
    fn literal_and_argument_add() {
        assert_eq!(eval("a + 1", &[], &[("a", 41)]), 42);
    }

    #[test]
    fn checked_wrapper_is_transparent_to_the_value() {
        assert_eq!(eval("checked(a + 1)", &[], &[("a", 41)]), 42);
    }

    #[test]
    fn state_and_argument_add() {
        assert_eq!(eval("x + a", &[("x", 100)], &[("a", 5)]), 105);
    }

    #[test]
    fn comparisons_produce_booleans() {
        assert_eq!(eval("a > 5", &[], &[("a", 9)]), 1);
        assert_eq!(eval("a > 5", &[], &[("a", 3)]), 0);
        assert_eq!(eval("x <= y", &[("x", 3), ("y", 3)], &[]), 1);
        assert_eq!(eval("x <= y", &[("x", 4), ("y", 3)], &[]), 0);
        assert_eq!(eval("a != 7", &[], &[("a", 7)]), 0);
    }

    #[test]
    fn wrapping_add_takes_the_modular_result() {
        // Two words that overflow a checked add, so only the wrapping form returns a value.
        let big = u64::MAX;
        assert_eq!(eval("wrapping(a + b)", &[], &[("a", big), ("b", 1)]), 0);
    }
}
