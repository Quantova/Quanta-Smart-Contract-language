//! Expression lowering. A value computes into a stack of temporary registers. A state field reads

use crate::emit::{Builder, Label};
use crate::error::CodegenError;
use crate::layout::Layout;
use qtv_vm::isa::{Instr, Reg, NUM_REGS};
use quanta_ast::{
    AfterTarget, AssignOp, BinOp, Clause, EntryDecl, Expr, GenericArg, Param, Stmt, UnaryOp,
};
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

/// Base offset of the asset local region in scratch memory. A `let` bound asset value keeps its
const ASSET_LOCAL_BASE: u64 = 4096;

/// Argument key suffix for the scheme identifier of a signed parameter.
const SIG_SCHEME_SUFFIX: &str = "#scheme";
/// Argument key suffix for the pointer to a signed parameter's verify region.
const SIG_PTR_SUFFIX: &str = "#ptr";
/// Argument key suffix for the length of a signed parameter's verify region.
const SIG_LEN_SUFFIX: &str = "#len";

/// Argument key of the caller context word. It is not a source level parameter, so its key uses the
const CALLER_KEY: &str = "@caller";

/// Argument key of the consensus time context word, the host supplied time an `after` guard measures
const TIME_KEY: &str = "@time";

/// Seconds in each duration unit an `after` clause can name.
fn unit_seconds(unit: &str) -> Option<u64> {
    match unit {
        "seconds" => Some(1),
        "minutes" => Some(60),
        "hours" => Some(3_600),
        "days" => Some(86_400),
        "weeks" => Some(604_800),
        "months" => Some(2_592_000),
        "years" => Some(31_536_000),
        _ => None,
    }
}

/// Signature scheme identifiers carried in the envelope. ML DSA is the module lattice scheme and the
const SCHEME_ML: u64 = 1;
const SCHEME_SLH: u64 = 2;

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
    /// The subset of the parameters that carry a linear asset value.
    asset_params: &'a HashSet<String>,
    /// Asset values bound by a `let`, each mapped to the scratch memory word that holds its amount.
    asset_locals: HashMap<String, u64>,
    /// The next free word in the asset local region.
    next_asset_local: u64,
    /// Whether the entry declares `mints`, which is the only place a `mint(..)` may create supply.
    entry_mints: bool,
    /// The shared trap a checked overflow jumps to, so a two word arithmetic that carries past the
    trap: Label,
    b: &'a mut Builder,
    regs: &'a mut Regs,
    args: &'a mut Args,
}

impl<'a> Ctx<'a> {
    pub fn new(
        layout: &'a Layout,
        params: &'a HashSet<String>,
        asset_params: &'a HashSet<String>,
        trap: Label,
        b: &'a mut Builder,
        regs: &'a mut Regs,
        args: &'a mut Args,
    ) -> Ctx<'a> {
        Ctx {
            layout,
            params,
            asset_params,
            asset_locals: HashMap::new(),
            next_asset_local: ASSET_LOCAL_BASE,
            entry_mints: false,
            trap,
            b,
            regs,
            args,
        }
    }

    /// Reserves the scratch memory word that holds a `let` bound asset value's amount.
    fn bind_asset_local(&mut self, name: &str) -> u64 {
        if let Some(off) = self.asset_locals.get(name) {
            return *off;
        }
        let off = self.next_asset_local;
        self.next_asset_local += WORD;
        self.asset_locals.insert(name.to_string(), off);
        off
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
        // The caller address arrives as a host provided context word, read like any argument word.
        // The tagged machine has no caller opcode, so the transaction context supplies it in scratch.
        Expr::Caller { span } => {
            let off = ctx.args.offset_of(CALLER_KEY);
            load_arg(ctx, off, *span)
        }
        Expr::Str(s) => Err(CodegenError::Unsupported {
            what: "a string literal".into(),
            span: s.span,
        }),
        Expr::Date { span, .. } => Err(CodegenError::Unsupported {
            what: "a date literal".into(),
            span: *span,
        }),
        Expr::Call { callee, args, span } => lower_call_value(ctx, callee, args, *span),
    }
}

/// Lowers a call used as a value. A `contains` reads a keyed ledger entry, and a `split` or `mint`
fn lower_call_value(
    ctx: &mut Ctx,
    callee: &Expr,
    args: &[Expr],
    span: Span,
) -> Result<Reg, CodegenError> {
    if let Expr::Field { base, name, .. } = callee {
        match name.text.as_str() {
            "contains" => return lower_map_read(ctx, base, args, span),
            "split" => return lower_split(ctx, base, args, span),
            _ => {}
        }
    }
    if let Expr::Ident(id) = callee {
        if id.text == "mint" {
            return lower_mint(ctx, args, span);
        }
    }
    Err(CodegenError::Unsupported {
        what: "a call expression".into(),
        span,
    })
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
        // The amount of an asset value is its one canonical word, so `funds.amount` reads the same
        // word as the bare `funds`, and the two spellings never diverge.
        if field == "amount" && ctx.asset_params.contains(&id.text) {
            let off = ctx.args.offset_of(&id.text);
            return load_arg(ctx, off, span);
        }
        if field == "amount" {
            if let Some(off) = ctx.asset_locals.get(&id.text).copied() {
                return load_arg(ctx, off, span);
            }
        }
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

/// Lowers an asset value to a fresh register holding its amount. An asset parameter reads its
fn asset_amount(ctx: &mut Ctx, value: &Expr, span: Span) -> Result<Reg, CodegenError> {
    match value {
        Expr::Ident(id) if ctx.asset_params.contains(&id.text) => {
            let off = ctx.args.offset_of(&id.text);
            load_arg(ctx, off, id.span)
        }
        Expr::Ident(id) if ctx.asset_locals.contains_key(&id.text) => {
            let off = ctx.asset_locals[&id.text];
            load_arg(ctx, off, id.span)
        }
        Expr::Call { callee, args, span } => match callee.as_ref() {
            Expr::Field { base, name, .. } if name.text == "split" => {
                lower_split(ctx, base, args, *span)
            }
            Expr::Ident(id) if id.text == "mint" => lower_mint(ctx, args, *span),
            _ => Err(CodegenError::Unsupported {
                what: "an asset producing call here".into(),
                span: *span,
            }),
        },
        _ => Err(CodegenError::Unsupported {
            what: "an asset value here".into(),
            span,
        }),
    }
}

/// Splits an amount off an asset state field, a checked balance subtract that yields the amount it
fn lower_split(ctx: &mut Ctx, base: &Expr, args: &[Expr], span: Span) -> Result<Reg, CodegenError> {
    let slot = asset_field_slot(ctx, base, span)?;
    let value = one_arg(args, span)?;
    let amt = lower_expr(ctx, value, false)?;
    let rf = load_slot(ctx, slot, span)?;
    ctx.b.op(Instr::Sub {
        d: rf,
        a: rf,
        b: amt,
    });
    store_slot(ctx, slot, rf);
    ctx.regs.free(rf);
    Ok(amt)
}

/// Mints a fresh asset value of the given amount. Supply is created only inside an entry that
fn lower_mint(ctx: &mut Ctx, args: &[Expr], span: Span) -> Result<Reg, CodegenError> {
    if !ctx.entry_mints {
        return Err(CodegenError::Unsupported {
            what: "a mint outside an entry that declares mints".into(),
            span,
        });
    }
    let amount = one_arg(args, span)?;
    lower_expr(ctx, amount, false)
}

/// True when an expression produces a fresh asset value, a split or a mint.
fn produces_asset(value: &Expr) -> bool {
    match value {
        Expr::Call { callee, .. } => match callee.as_ref() {
            Expr::Field { name, .. } => name.text == "split",
            Expr::Ident(id) => id.text == "mint",
            _ => false,
        },
        _ => false,
    }
}

/// Lowers a `let` that binds an asset value. The value's amount is computed and stored in the local's
fn lower_let(ctx: &mut Ctx, name: &str, value: &Expr, span: Span) -> Result<(), CodegenError> {
    if !produces_asset(value) {
        return Err(CodegenError::Unsupported {
            what: "a let binding that is not an asset split or mint".into(),
            span,
        });
    }
    let off = ctx.bind_asset_local(name);
    let amt = asset_amount(ctx, value, span)?;
    store_mem_word(ctx, off, amt);
    ctx.regs.free(amt);
    Ok(())
}

/// Writes a register value to a scratch memory word.
fn store_mem_word(ctx: &mut Ctx, off: u64, value: Reg) {
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: off,
    });
    ctx.b.op(Instr::MStore {
        a: SCRATCH,
        b: value,
    });
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
    // A comparison where either side is a two word value orders the full wide value, so both sides
    // evaluate to a register pair and the compare reduces them to a one word boolean.
    if matches!(
        op,
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge | BinOp::Eq | BinOp::Ne
    ) && (is_wide_expr(ctx, left) || is_wide_expr(ctx, right))
    {
        let (llo, lhi) = eval_wide(ctx, left, wrapping)?;
        let (rlo, rhi) = eval_wide(ctx, right, wrapping)?;
        return Ok(wide_compare(ctx, op, llo, lhi, rlo, rhi));
    }
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

/// Whether an expression evaluates to a two word value. Only a two word state field is wide, and
fn is_wide_expr(ctx: &Ctx, expr: &Expr) -> bool {
    match expr {
        Expr::Ident(id) => ctx.layout.is_wide(&id.text),
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => is_wide_expr(ctx, expr),
        Expr::Binary { op, left, right, .. } => {
            matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul)
                && (is_wide_expr(ctx, left) || is_wide_expr(ctx, right))
        }
        _ => false,
    }
}

/// Evaluates an expression into a contiguous low and high register pair. A wide state field reads its
fn eval_wide(ctx: &mut Ctx, expr: &Expr, wrapping: bool) -> Result<(Reg, Reg), CodegenError> {
    match expr {
        Expr::Checked { expr, .. } => eval_wide(ctx, expr, false),
        Expr::Wrapping { expr, .. } => eval_wide(ctx, expr, true),
        Expr::Int(lit) => {
            let value = parse_u128(&lit.text, lit.span)?;
            let lo = ctx.regs.alloc(lit.span)?;
            ctx.b.op(Instr::Ldi { d: lo, imm: value as u64 });
            let hi = ctx.regs.alloc(lit.span)?;
            ctx.b.op(Instr::Ldi {
                d: hi,
                imm: (value >> 64) as u64,
            });
            Ok((lo, hi))
        }
        Expr::Ident(id) if ctx.layout.is_wide(&id.text) => {
            let slot = ctx.layout.slot(&id.text).expect("a wide field has a slot");
            let hi_slot = ctx.layout.hi_slot(&id.text).expect("a wide field has a high slot");
            let lo = load_slot(ctx, slot, id.span)?;
            let hi = load_slot(ctx, hi_slot, id.span)?;
            Ok((lo, hi))
        }
        Expr::Binary { op, left, right, span } if matches!(op, BinOp::Add | BinOp::Sub) => {
            let (llo, lhi) = eval_wide(ctx, left, wrapping)?;
            let (rlo, rhi) = eval_wide(ctx, right, wrapping)?;
            match op {
                BinOp::Add => two_word_add(ctx, llo, lhi, rlo, rhi, wrapping),
                _ => two_word_sub(ctx, llo, lhi, rlo, rhi, wrapping),
            }
            let _ = span;
            Ok((llo, lhi))
        }
        // A wide multiply needs the machine's high word multiply, which the pinned qtv-vm v0.2.0 does
        // not expose. It is refused rather than lowered to a truncating single word product, and it
        // waits on a qtv-vm release that carries the high word multiply.
        Expr::Binary { op: BinOp::Mul, span, .. } => Err(CodegenError::Unsupported {
            what: "a u128 multiply, which needs the high word multiply absent from qtv-vm v0.2.0"
                .into(),
            span: *span,
        }),
        _ => {
            let lo = lower_expr(ctx, expr, wrapping)?;
            let hi = ctx.regs.alloc(expr.span())?;
            ctx.b.op(Instr::Ldi { d: hi, imm: 0 });
            Ok((lo, hi))
        }
    }
}

/// Two word add of the right pair into the left pair, carrying the low overflow into the high word.
fn two_word_add(ctx: &mut Ctx, llo: Reg, lhi: Reg, rlo: Reg, rhi: Reg, wrapping: bool) {
    ctx.b.op(Instr::AddW { d: llo, a: llo, b: rlo });
    ctx.b.op(Instr::LtU { d: SCRATCH, a: llo, b: rlo });
    ctx.b.op(Instr::AddW { d: lhi, a: lhi, b: rhi });
    ctx.b.op(Instr::LtU { d: rlo, a: lhi, b: rhi });
    ctx.b.op(Instr::AddW { d: lhi, a: lhi, b: SCRATCH });
    ctx.b.op(Instr::LtU { d: rhi, a: lhi, b: SCRATCH });
    if !wrapping {
        ctx.b.op(Instr::Or { d: rlo, a: rlo, b: rhi });
        ctx.b.jnz(rlo, ctx.trap);
    }
    ctx.regs.free(rhi);
    ctx.regs.free(rlo);
}

/// Two word subtract of the right pair from the left pair, borrowing the low underflow out of the
fn two_word_sub(ctx: &mut Ctx, llo: Reg, lhi: Reg, rlo: Reg, rhi: Reg, wrapping: bool) {
    ctx.b.op(Instr::LtU { d: SCRATCH, a: llo, b: rlo });
    ctx.b.op(Instr::SubW { d: llo, a: llo, b: rlo });
    ctx.b.op(Instr::LtU { d: rlo, a: lhi, b: rhi });
    ctx.b.op(Instr::SubW { d: lhi, a: lhi, b: rhi });
    ctx.b.op(Instr::LtU { d: rhi, a: lhi, b: SCRATCH });
    ctx.b.op(Instr::SubW { d: lhi, a: lhi, b: SCRATCH });
    if !wrapping {
        ctx.b.op(Instr::Or { d: rlo, a: rlo, b: rhi });
        ctx.b.jnz(rlo, ctx.trap);
    }
    ctx.regs.free(rhi);
    ctx.regs.free(rlo);
}

/// A two word comparison of the left pair against the right pair, reducing to a one word boolean held
fn wide_compare(ctx: &mut Ctx, op: BinOp, llo: Reg, lhi: Reg, rlo: Reg, rhi: Reg) -> Reg {
    let t1 = ctx.regs.alloc(Span::default()).expect("a compare temporary");
    let t2 = ctx.regs.alloc(Span::default()).expect("a compare temporary");
    ctx.b.op(Instr::Eq { d: SCRATCH, a: lhi, b: rhi });
    ctx.b.op(Instr::LtU { d: t1, a: llo, b: rlo });
    ctx.b.op(Instr::And { d: t1, a: t1, b: SCRATCH });
    ctx.b.op(Instr::LtU { d: t2, a: lhi, b: rhi });
    ctx.b.op(Instr::Or { d: t2, a: t2, b: t1 });
    ctx.b.op(Instr::LtU { d: t1, a: rlo, b: llo });
    ctx.b.op(Instr::And { d: t1, a: t1, b: SCRATCH });
    ctx.b.op(Instr::LtU { d: llo, a: rhi, b: lhi });
    ctx.b.op(Instr::Or { d: llo, a: llo, b: t1 });
    match op {
        BinOp::Lt => ctx.b.op(Instr::Or { d: llo, a: t2, b: t2 }),
        BinOp::Gt => {}
        BinOp::Le => logical_not(ctx, llo),
        BinOp::Ge => {
            ctx.b.op(Instr::Or { d: llo, a: t2, b: t2 });
            logical_not(ctx, llo);
        }
        BinOp::Eq => {
            ctx.b.op(Instr::Or { d: llo, a: llo, b: t2 });
            logical_not(ctx, llo);
        }
        _ => ctx.b.op(Instr::Or { d: llo, a: llo, b: t2 }),
    }
    ctx.regs.free(t2);
    ctx.regs.free(t1);
    ctx.regs.free(rhi);
    ctx.regs.free(rlo);
    ctx.regs.free(lhi);
    llo
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

/// Parses a numeric literal into a two word value, so a wide field accepts a constant above one
fn parse_u128(text: &str, span: Span) -> Result<u128, CodegenError> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    cleaned
        .parse::<u128>()
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
                     from qtv-vm v0.2.0",
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
    let asset_params: HashSet<String> = entry
        .params
        .iter()
        .filter(|p| p.ty.name.text == "Q_Asset")
        .map(|p| p.name.text.clone())
        .collect();
    let writes_state = !layout.access(entry).writes.is_empty();
    let entry_mints = entry
        .clauses
        .iter()
        .any(|c| matches!(c, quanta_ast::Clause::Mints { .. }));
    let mut regs = Regs::new();
    let mut args = Args::new();
    {
        let mut ctx = Ctx::new(layout, &params, &asset_params, trap, b, &mut regs, &mut args);
        ctx.entry_mints = entry_mints;
        lower_signed_prologue(&mut ctx, entry, trap)?;
        lower_quorum_prologue(&mut ctx, entry, trap)?;
        lower_after_prologue(&mut ctx, entry, trap)?;
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

/// Verifies each quorum parameter before the body runs. A `Quorum<M of N, set>` is constructed only
fn lower_quorum_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for param in &entry.params {
        let Some(threshold) = quorum_threshold(param) else {
            continue;
        };
        let name = &param.name.text;
        let span = param.span;
        for i in 0..threshold {
            let scheme_off = ctx
                .args
                .offset_of(&format!("{name}#{i}{SIG_SCHEME_SUFFIX}"));
            let ptr_off = ctx.args.offset_of(&format!("{name}#{i}{SIG_PTR_SUFFIX}"));
            let len_off = ctx.args.offset_of(&format!("{name}#{i}{SIG_LEN_SUFFIX}"));
            dispatch_verify(ctx, scheme_off, ptr_off, len_off, trap, span)?;
        }
    }
    Ok(())
}

/// Guards every `after` clause on the entry against the host supplied consensus time, so a time
fn lower_after_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for clause in &entry.clauses {
        let Clause::After { target, from, span } = clause else {
            continue;
        };
        let time_off = ctx.args.offset_of(TIME_KEY);
        let time = load_arg(ctx, time_off, *span)?;
        let threshold = match target {
            AfterTarget::Duration(duration) => {
                let unit = unit_seconds(&duration.unit.text).ok_or_else(|| {
                    CodegenError::Unsupported {
                        what: format!("the duration unit `{}`", duration.unit.text),
                        span: duration.span,
                    }
                })?;
                let value = parse_int(&duration.value.text, duration.value.span)?;
                let seconds = value
                    .checked_mul(unit)
                    .ok_or_else(|| CodegenError::IntegerTooWide {
                        text: duration.value.text.clone(),
                        span: duration.span,
                    })?;
                if let Some(base) = from {
                    let reg = lower_expr(ctx, base, false)?;
                    let addend = ctx.regs.alloc(*span)?;
                    ctx.b.op(Instr::Ldi {
                        d: addend,
                        imm: seconds,
                    });
                    ctx.b.op(Instr::Add {
                        d: reg,
                        a: reg,
                        b: addend,
                    });
                    ctx.regs.free(addend);
                    reg
                } else {
                    let reg = ctx.regs.alloc(*span)?;
                    ctx.b.op(Instr::Ldi {
                        d: reg,
                        imm: seconds,
                    });
                    reg
                }
            }
            AfterTarget::Expr(expr) => lower_expr(ctx, expr, false)?,
        };
        // Revert when the consensus time is still below the threshold.
        ctx.b.op(Instr::LtU {
            d: time,
            a: time,
            b: threshold,
        });
        ctx.b.jnz(time, trap);
        ctx.regs.free(threshold);
        ctx.regs.free(time);
    }
    Ok(())
}

/// The threshold M of a `Quorum<M of N, set>` parameter, if the parameter is a quorum.
fn quorum_threshold(param: &Param) -> Option<u64> {
    if param.ty.name.text != "Quorum" {
        return None;
    }
    param.ty.args.iter().find_map(|arg| match arg {
        GenericArg::MofN { m, .. } => m.text.parse::<u64>().ok(),
        _ => None,
    })
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
        Stmt::Let { name, value, span } => lower_let(ctx, &name.text, value, *span),
        // A bare call is a state mutating asset or ledger operation.
        Stmt::Expr {
            expr: Expr::Call { callee, args, span },
            ..
        } => lower_call_effect(ctx, callee, args, *span, trap),
        Stmt::Expr { span, .. } => Err(CodegenError::Unsupported {
            what: "an expression statement".into(),
            span: *span,
        }),
    }
}

/// Lowers a call used as a statement for its side effect. A method on an asset state field or a
fn lower_call_effect(
    ctx: &mut Ctx,
    callee: &Expr,
    args: &[Expr],
    span: Span,
    _trap: Label,
) -> Result<(), CodegenError> {
    if let Expr::Field { base, name, .. } = callee {
        match name.text.as_str() {
            "merge" => return lower_merge(ctx, base, args, span),
            "credit" => return lower_map_credit(ctx, base, args, span, true),
            "debit" => return lower_map_credit(ctx, base, args, span, false),
            "insert" => return lower_map_flag(ctx, base, args, span, 1),
            "remove" => return lower_map_flag(ctx, base, args, span, 0),
            _ => {}
        }
    }
    // A send of an asset to an account lowers to the native transfer the SEND opcode records.
    if matches!(callee, Expr::Ident(id) if id.text == "send") {
        return lower_send(ctx, args, span);
    }
    Err(CodegenError::Unsupported {
        what: "this call statement".into(),
        span,
    })
}

/// Lowers a `send` of an asset to an account to the native transfer the SEND opcode records. The
fn lower_send(ctx: &mut Ctx, args: &[Expr], span: Span) -> Result<(), CodegenError> {
    let (to, value) = two_args(args, span)?;
    let amount = asset_amount(ctx, value, span)?;
    let addr_off = addr_word_offset(ctx, to, span)?;
    let raddr = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: raddr,
        imm: addr_off,
    });
    let rlen = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: rlen, imm: WORD });
    ctx.b.op(Instr::Send {
        a: raddr,
        b: rlen,
        c: amount,
    });
    ctx.regs.free(rlen);
    ctx.regs.free(raddr);
    ctx.regs.free(amount);
    Ok(())
}

/// The scratch memory offset of the recipient address word of a `send`. The recipient is a plain
fn addr_word_offset(ctx: &mut Ctx, to: &Expr, span: Span) -> Result<u64, CodegenError> {
    match to {
        Expr::Caller { .. } => Ok(ctx.args.offset_of(CALLER_KEY)),
        Expr::Ident(id) if ctx.params.contains(&id.text) => Ok(ctx.args.offset_of(&id.text)),
        Expr::Field { base, name, .. } => match base.as_ref() {
            Expr::Ident(id) if ctx.params.contains(&id.text) => {
                Ok(ctx.args.offset_of(&format!("{}.{}", id.text, name.text)))
            }
            _ => Err(CodegenError::Unsupported {
                what: "a send to an address that is not a parameter".into(),
                span,
            }),
        },
        _ => Err(CodegenError::Unsupported {
            what: "a send to an address that is not a parameter".into(),
            span,
        }),
    }
}

/// The keyed base of a `Map` or `Registry` field named as the receiver of a ledger operation.
fn map_base_of(ctx: &Ctx, base: &Expr, span: Span) -> Result<u64, CodegenError> {
    if let Expr::Ident(id) = base {
        if let Some(b) = ctx.layout.map_base(&id.text) {
            return Ok(b);
        }
    }
    Err(CodegenError::Unsupported {
        what: "a ledger operation on a value that is not a map field".into(),
        span,
    })
}

/// The two arguments of a call, or an error when the arity is wrong.
fn two_args(args: &[Expr], span: Span) -> Result<(&Expr, &Expr), CodegenError> {
    match args {
        [a, b] => Ok((a, b)),
        _ => Err(CodegenError::Unsupported {
            what: "a ledger operation with an unexpected argument count".into(),
            span,
        }),
    }
}

/// Computes the storage key of a keyed entry into `addr`: the field base plus the address word the
fn keyed_key(ctx: &mut Ctx, base: u64, addr: Reg, span: Span) -> Result<(), CodegenError> {
    let rbase = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rbase,
        imm: base,
    });
    ctx.b.op(Instr::Add {
        d: addr,
        a: addr,
        b: rbase,
    });
    ctx.regs.free(rbase);
    Ok(())
}

/// Lowers a value that a ledger credit or debit moves: an asset value contributes its amount, and any
fn ledger_amount(ctx: &mut Ctx, value: &Expr, span: Span) -> Result<Reg, CodegenError> {
    if is_asset_value(ctx, value) {
        asset_amount(ctx, value, span)
    } else {
        lower_expr(ctx, value, false)
    }
}

/// True when an expression denotes an asset value rather than a plain integer.
fn is_asset_value(ctx: &Ctx, value: &Expr) -> bool {
    match value {
        Expr::Ident(id) => {
            ctx.asset_params.contains(&id.text) || ctx.asset_locals.contains_key(&id.text)
        }
        Expr::Call { .. } => produces_asset(value),
        _ => false,
    }
}

/// Credits or debits a recipient's ledger balance by a checked add or subtract at the keyed slot, so
fn lower_map_credit(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
    add: bool,
) -> Result<(), CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let (key_expr, value_expr) = two_args(args, span)?;
    let value = ledger_amount(ctx, value_expr, span)?;
    let addr = lower_expr(ctx, key_expr, false)?;
    keyed_key(ctx, mbase, addr, span)?;
    let cur = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::SLoad { d: cur, a: addr });
    if add {
        ctx.b.op(Instr::Add {
            d: cur,
            a: cur,
            b: value,
        });
    } else {
        ctx.b.op(Instr::Sub {
            d: cur,
            a: cur,
            b: value,
        });
    }
    ctx.b.op(Instr::SStore { a: addr, b: cur });
    ctx.regs.free(cur);
    ctx.regs.free(addr);
    ctx.regs.free(value);
    Ok(())
}

/// Sets or clears a keyed flag, the lowering of a freeze insert or an unfreeze remove.
fn lower_map_flag(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
    flag: u64,
) -> Result<(), CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let key_expr = one_arg(args, span)?;
    let addr = lower_expr(ctx, key_expr, false)?;
    keyed_key(ctx, mbase, addr, span)?;
    let v = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: v, imm: flag });
    ctx.b.op(Instr::SStore { a: addr, b: v });
    ctx.regs.free(v);
    ctx.regs.free(addr);
    Ok(())
}

/// Reads a keyed entry, the lowering of `map.contains(key)`. A non zero result means the entry is
fn lower_map_read(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
) -> Result<Reg, CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let key_expr = one_arg(args, span)?;
    let addr = lower_expr(ctx, key_expr, false)?;
    keyed_key(ctx, mbase, addr, span)?;
    ctx.b.op(Instr::SLoad { d: addr, a: addr });
    Ok(addr)
}

/// The storage slot of an asset state field named as the receiver of an asset operation.
fn asset_field_slot(ctx: &Ctx, base: &Expr, span: Span) -> Result<u64, CodegenError> {
    if let Expr::Ident(id) = base {
        if let Some(slot) = ctx.layout.slot(&id.text) {
            return Ok(slot);
        }
    }
    Err(CodegenError::Unsupported {
        what: "an asset operation on a value that is not a state field".into(),
        span,
    })
}

/// The single argument of a call, or an error when the arity is wrong.
fn one_arg(args: &[Expr], span: Span) -> Result<&Expr, CodegenError> {
    match args {
        [only] => Ok(only),
        _ => Err(CodegenError::Unsupported {
            what: "an asset operation with an unexpected argument count".into(),
            span,
        }),
    }
}

/// Merges an asset value into an asset state field, a checked balance add that conserves supply and
fn lower_merge(ctx: &mut Ctx, base: &Expr, args: &[Expr], span: Span) -> Result<(), CodegenError> {
    let slot = asset_field_slot(ctx, base, span)?;
    let value = one_arg(args, span)?;
    let amt = asset_amount(ctx, value, span)?;
    let rf = load_slot(ctx, slot, span)?;
    ctx.b.op(Instr::Add {
        d: rf,
        a: rf,
        b: amt,
    });
    store_slot(ctx, slot, rf);
    ctx.regs.free(rf);
    ctx.regs.free(amt);
    Ok(())
}

fn lower_assign(
    ctx: &mut Ctx,
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: Span,
) -> Result<(), CodegenError> {
    let name = match target {
        Expr::Ident(id) => &id.text,
        _ => {
            return Err(CodegenError::Unsupported {
                what: "an assignment target that is not a state field".into(),
                span,
            })
        }
    };
    let slot = ctx.layout.slot(name).ok_or_else(|| CodegenError::Unsupported {
        what: "an assignment target that is not a state field".into(),
        span,
    })?;

    if ctx.layout.is_wide(name) {
        let hi_slot = ctx.layout.hi_slot(name).expect("a wide field has a high slot");
        match op {
            AssignOp::Set => {
                let (vlo, vhi) = eval_wide(ctx, value, false)?;
                store_slot(ctx, slot, vlo);
                store_slot(ctx, hi_slot, vhi);
                ctx.regs.free(vhi);
                ctx.regs.free(vlo);
            }
            AssignOp::Add | AssignOp::Sub => {
                let flo = load_slot(ctx, slot, span)?;
                let fhi = load_slot(ctx, hi_slot, span)?;
                let (vlo, vhi) = eval_wide(ctx, value, false)?;
                match op {
                    AssignOp::Add => two_word_add(ctx, flo, fhi, vlo, vhi, false),
                    _ => two_word_sub(ctx, flo, fhi, vlo, vhi, false),
                }
                store_slot(ctx, slot, flo);
                store_slot(ctx, hi_slot, fhi);
                ctx.regs.free(fhi);
                ctx.regs.free(flo);
            }
        }
        return Ok(());
    }

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
        let asset_params = HashSet::new();
        let trap = b.label();
        let dest = {
            let mut ctx = Ctx::new(
                &layout,
                &params,
                &asset_params,
                trap,
                &mut b,
                &mut regs,
                &mut args,
            );
            lower_expr(&mut ctx, &expr, false).expect("lower")
        };
        b.op(Instr::Halt);
        b.mark(trap);
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
