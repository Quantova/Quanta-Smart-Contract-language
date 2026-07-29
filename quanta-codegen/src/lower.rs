// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::emit::{Builder, Label};
use crate::error::CodegenError;
use crate::layout::Layout;
use crate::selector::entry_selector;
use qtv_vm::isa::{Instr, Reg, NUM_REGS};
use quanta_ast::{
    AfterTarget, AssignOp, BinOp, Clause, EntryDecl, Expr, GenericArg, Param, Stmt, UnaryOp,
};
use quanta_lexer::Span;
use std::collections::{HashMap, HashSet};

const SCRATCH: Reg = 0;
const FIRST_TEMP: Reg = 1;

pub const ARG_BASE: u64 = 0;
const WORD: u64 = 8;
const ADDR_BYTES: u64 = 32;

const ASSET_LOCAL_BASE: u64 = 4096;

const EVENT_BASE: u64 = 32768;

const SIG_SCHEME_SUFFIX: &str = "#scheme";
const SIG_PTR_SUFFIX: &str = "#ptr";

const DEPLOY_PARAMS: &str = "deploy_params";

const GENESIS_PARAM_SENTINEL: u64 = u64::from_be_bytes(*b"QGENSNTL");

pub(crate) const GENESIS_INIT_GUARD_SLOT: u64 = u64::from_be_bytes(*b"QGINIT01");

const CALLER_KEY: &str = "@caller";

const CONTRACT_KEY: &str = "@contract";

const TIME_KEY: &str = "@time";

// The chain the entry runs on, supplied by the host the same way the contract self address is. It is
// folded into the signed and quorum message tag so a captured authorization cannot be lifted onto
// another chain. A host that leaves it zero reproduces the unbound tag.
const CHAIN_KEY: &str = "@chain";

const SIGNER_ADDR_SCRATCH: u64 = 40960;
const NONCE_PREIMAGE_SCRATCH: u64 = 41088;
const NONCE_DIGEST_SCRATCH: u64 = 41216;
const SCALAR_KEY_SCRATCH: u64 = 41344;
const MAP_PREIMAGE_SCRATCH: u64 = 41408;
const MAP_KEY_SCRATCH: u64 = 41472;
const NAME_KEY_SCRATCH_BASE: u64 = 41536;
const ID_KEY_SCRATCH: u64 = 42048;
const STATE_ADDR_SCRATCH_BASE: u64 = 42112;

const NAME_TYPE: &str = "Q_Name";
const NAME_WINDOW: u64 = 32;
const NAME_LEN_SUFFIX: &str = "#len";

const ADDR_WORDS: u64 = ADDR_BYTES / WORD;

const ADDR_TYPE: &str = "Q_Address";

const WIDE_TYPE: &str = "u128";

const SIGNED_MSG_TAG: u64 = u64::from_be_bytes(*b"QTVSGN01");
pub(crate) const NONCE_TAG: u64 = u64::from_be_bytes(*b"QTVNONCE");

fn deploy_param_name(expr: &Expr) -> Option<&str> {
    if let Expr::Field { base, name, .. } = expr {
        if let Expr::Ident(id) = base.as_ref() {
            if id.text == DEPLOY_PARAMS {
                return Some(&name.text);
            }
        }
    }
    None
}

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

const SCHEME_ML: u64 = 1;
const SCHEME_SLH: u64 = 2;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployParamSlot {
    pub key: String,
    pub offset: u64,
    pub width: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSig {
    pub selector: u32,
    pub field_words: Vec<u64>,
}

#[derive(Default)]
pub struct Args {
    offsets: HashMap<String, u64>,
    order: Vec<String>,
    next: u64,
    deploy_params: Vec<DeployParamSlot>,
}

impl Args {
    pub fn new() -> Args {
        Args::default()
    }

    fn offset_of_width(&mut self, key: &str, bytes: u64) -> u64 {
        if let Some(off) = self.offsets.get(key) {
            return *off;
        }
        let off = ARG_BASE + self.next;
        self.next += bytes;
        self.offsets.insert(key.to_string(), off);
        self.order.push(key.to_string());
        off
    }

    fn offset_of(&mut self, key: &str) -> u64 {
        self.offset_of_width(key, WORD)
    }

    fn deploy_param_offset(&mut self, name: &str, width: u64) -> u64 {
        let key = format!("{DEPLOY_PARAMS}.{name}");
        let existed = self.offsets.contains_key(&key);
        let off = self.offset_of_width(&key, width);
        if !existed {
            self.deploy_params.push(DeployParamSlot {
                key,
                offset: off,
                width,
            });
        }
        off
    }

    fn end(&self) -> u64 {
        ARG_BASE + self.next
    }

    pub fn deploy_params(&self) -> &[DeployParamSlot] {
        &self.deploy_params
    }

    pub fn layout(&self) -> Vec<(String, u64)> {
        self.order
            .iter()
            .map(|k| (k.clone(), self.offsets[k]))
            .collect()
    }
}

pub struct Ctx<'a> {
    layout: &'a Layout,
    params: &'a HashSet<String>,
    asset_params: &'a HashSet<String>,
    asset_locals: HashMap<String, u64>,
    next_asset_local: u64,
    entry_mints: bool,
    is_genesis: bool,
    address_keys: HashSet<String>,
    name_params: HashSet<String>,
    addr_params: HashSet<String>,
    wide_keys: HashSet<String>,
    name_keys: HashMap<String, u64>,
    state_addr_scratch: HashMap<String, u64>,
    map_value_scratch: HashMap<String, u64>,
    next_state_addr_scratch: u64,
    trap: Label,
    b: &'a mut Builder,
    regs: &'a mut Regs,
    args: &'a mut Args,
    events: &'a HashMap<String, EventSig>,
}

impl<'a> Ctx<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layout: &'a Layout,
        params: &'a HashSet<String>,
        asset_params: &'a HashSet<String>,
        events: &'a HashMap<String, EventSig>,
        trap: Label,
        b: &'a mut Builder,
        regs: &'a mut Regs,
        args: &'a mut Args,
    ) -> Ctx<'a> {
        Ctx {
            layout,
            params,
            asset_params,
            address_keys: HashSet::new(),
            name_params: HashSet::new(),
            addr_params: HashSet::new(),
            wide_keys: HashSet::new(),
            name_keys: HashMap::new(),
            state_addr_scratch: HashMap::new(),
            map_value_scratch: HashMap::new(),
            next_state_addr_scratch: STATE_ADDR_SCRATCH_BASE,
            asset_locals: HashMap::new(),
            next_asset_local: ASSET_LOCAL_BASE,
            entry_mints: false,
            is_genesis: false,
            trap,
            b,
            regs,
            args,
            events,
        }
    }

    fn bind_asset_local(&mut self, name: &str) -> u64 {
        if let Some(off) = self.asset_locals.get(name) {
            return *off;
        }
        let off = self.next_asset_local;
        self.next_asset_local += WORD;
        self.asset_locals.insert(name.to_string(), off);
        off
    }

    // A per map scratch region that holds the four words of an address read out of that map. It draws
    // from the same bump pointer as a materialized state address, so the two never overlap, and it is
    // reused across reads of the one map since every read reloads the words before the region is used.
    fn bind_map_value_scratch(&mut self, name: &str) -> u64 {
        if let Some(off) = self.map_value_scratch.get(name) {
            return *off;
        }
        let off = self.next_state_addr_scratch;
        self.next_state_addr_scratch += ADDR_BYTES;
        self.map_value_scratch.insert(name.to_string(), off);
        off
    }
}

fn parse_date_epoch(text: &str, span: Span) -> Result<u64, CodegenError> {
    let bad = || CodegenError::Unsupported {
        what: "a malformed date literal".into(),
        span,
    };
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 3 {
        return Err(bad());
    }
    let y: i64 = parts[0].parse().map_err(|_| bad())?;
    let m: i64 = parts[1].parse().map_err(|_| bad())?;
    let d: i64 = parts[2].parse().map_err(|_| bad())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    let days = days_from_civil(y, m, d);
    if days < 0 {
        return Err(bad());
    }
    Ok((days as u64) * 86_400)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

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
        Expr::Caller { span } => {
            let off = ctx.args.offset_of(CALLER_KEY);
            load_arg(ctx, off, *span)
        }
        Expr::Now { span } => {
            let off = ctx.args.offset_of(TIME_KEY);
            load_arg(ctx, off, *span)
        }
        Expr::Str(s) => Err(CodegenError::Unsupported {
            what: "a string literal".into(),
            span: s.span,
        }),
        Expr::Date { text, span } => {
            let value = parse_date_epoch(text, *span)?;
            let d = ctx.regs.alloc(*span)?;
            ctx.b.op(Instr::Ldi { d, imm: value });
            Ok(d)
        }
        Expr::Call { callee, args, span } => lower_call_value(ctx, callee, args, *span),
    }
}

fn lower_call_value(
    ctx: &mut Ctx,
    callee: &Expr,
    args: &[Expr],
    span: Span,
) -> Result<Reg, CodegenError> {
    if let Expr::Field { base, name, .. } = callee {
        match name.text.as_str() {
            "contains" | "get" => return lower_map_read(ctx, base, args, span),
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
        let off = if ctx.wide_keys.contains(name) {
            ctx.args.offset_of_width(name, 2 * WORD)
        } else {
            ctx.args.offset_of(name)
        };
        load_arg(ctx, off, span)
    } else {
        Err(CodegenError::Unsupported {
            what: format!("the value `{name}`"),
            span,
        })
    }
}

fn lower_field(ctx: &mut Ctx, base: &Expr, field: &str, span: Span) -> Result<Reg, CodegenError> {
    if ctx.is_genesis {
        if let Expr::Ident(id) = base {
            if id.text == DEPLOY_PARAMS {
                let off = ctx.args.deploy_param_offset(field, WORD);
                return load_arg(ctx, off, span);
            }
        }
    }
    if let Expr::Ident(id) = base {
        if field == "amount" && ctx.asset_params.contains(&id.text) {
            let off = ctx.args.offset_of(&id.text);
            return load_arg(ctx, off, span);
        }
        if field == "amount" {
            if let Some(off) = ctx.asset_locals.get(&id.text).copied() {
                return load_arg(ctx, off, span);
            }
        }
        if field == "amount" {
            if let Some(slot) = state_asset_slot(ctx, &id.text) {
                return load_slot(ctx, slot, span);
            }
        }
        if field == "len" && ctx.name_params.contains(&id.text) {
            let off = ctx.args.offset_of(&format!("{}{NAME_LEN_SUFFIX}", id.text));
            return load_arg(ctx, off, span);
        }
        if ctx.params.contains(&id.text) {
            let key = format!("{}.{}", id.text, field);
            let off = if ctx.wide_keys.contains(&key) {
                ctx.args.offset_of_width(&key, 2 * WORD)
            } else {
                ctx.args.offset_of(&key)
            };
            return load_arg(ctx, off, span);
        }
    }
    Err(CodegenError::Unsupported {
        what: "a field access outside a parameter".into(),
        span,
    })
}

/// The storage slot of a state asset field. An asset holds its amount in a single scalar slot, so
fn state_asset_slot(ctx: &Ctx, name: &str) -> Option<u64> {
    let slot = ctx.layout.slot(name)?;
    if ctx.layout.map_base(name).is_some()
        || ctx.layout.is_addr(name)
        || ctx.layout.is_wide(name)
        || ctx.layout.guardian_set(name).is_some()
    {
        return None;
    }
    Some(slot)
}

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
    store_slot(ctx, slot, rf, span)?;
    ctx.regs.free(rf);
    Ok(amt)
}

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
    if matches!(op, BinOp::Eq | BinOp::Ne) {
        if let Some((name, mbase, key)) = addr_map_get(ctx, left) {
            let name = name.to_string();
            return lower_addr_map_eq(ctx, op, &name, mbase, key, right, left.span());
        }
        if let Some((name, mbase, key)) = addr_map_get(ctx, right) {
            let name = name.to_string();
            return lower_addr_map_eq(ctx, op, &name, mbase, key, left, right.span());
        }
        let laddr = is_scalar_addr(ctx, left);
        let raddr = is_scalar_addr(ctx, right);
        if laddr || raddr {
            if laddr != raddr {
                return Err(CodegenError::Unsupported {
                    what: "comparing a Q_Address to a value that is not an address".into(),
                    span: left.span(),
                });
            }
            return lower_scalar_addr_eq(ctx, op, left, right, left.span());
        }
    }
    if matches!(
        op,
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge | BinOp::Eq | BinOp::Ne
    ) && (is_wide_expr(ctx, left) || is_wide_expr(ctx, right))
    {
        let (llo, lhi) = eval_wide(ctx, left, wrapping)?;
        let (rlo, rhi) = eval_wide(ctx, right, wrapping)?;
        return wide_compare(ctx, op, llo, lhi, rlo, rhi, left.span());
    }
    if matches!(op, BinOp::And | BinOp::Or) {
        return lower_short_circuit(ctx, op, left, right, wrapping);
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
        BinOp::Shr => ctx.b.op(Instr::Shr { d: l, a: l, b: r }),
        BinOp::And | BinOp::Or => unreachable!("logical and or short circuit above"),
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

/// Logical `and` and `or` evaluate the right operand only when the left has not already decided the
fn lower_short_circuit(
    ctx: &mut Ctx,
    op: BinOp,
    left: &Expr,
    right: &Expr,
    wrapping: bool,
) -> Result<Reg, CodegenError> {
    let l = lower_expr(ctx, left, wrapping)?;
    let done = ctx.b.label();
    match op {
        BinOp::And => {
            // A false left already decides the whole `and`, so leave the zero in place and skip the
            // right; a true left falls through to combine with it.
            ctx.b.jz(l, done);
            let r = lower_expr(ctx, right, wrapping)?;
            ctx.b.op(Instr::And { d: l, a: l, b: r });
            ctx.regs.free(r);
        }
        BinOp::Or => {
            // A true left already decides the whole `or`, so leave the true value in place and skip
            // the right; a false left falls through to combine with it.
            ctx.b.jnz(l, done);
            let r = lower_expr(ctx, right, wrapping)?;
            ctx.b.op(Instr::Or { d: l, a: l, b: r });
            ctx.regs.free(r);
        }
        _ => unreachable!("only and or short circuit"),
    }
    ctx.b.mark(done);
    Ok(l)
}

fn is_wide_expr(ctx: &Ctx, expr: &Expr) -> bool {
    match expr {
        Expr::Ident(id) => ctx.layout.is_wide(&id.text) || ctx.wide_keys.contains(&id.text),
        Expr::Field { base, name, .. } => {
            matches!(base.as_ref(), Expr::Ident(id) if ctx.wide_keys.contains(&format!("{}.{}", id.text, name.text)))
        }
        Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => is_wide_expr(ctx, expr),
        Expr::Binary { op, left, right, .. } => {
            matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul)
                && (is_wide_expr(ctx, left) || is_wide_expr(ctx, right))
        }
        _ => false,
    }
}

fn collect_wide_keys(
    layout: &Layout,
    params: &HashSet<String>,
    asset_params: &HashSet<String>,
    events: &HashMap<String, EventSig>,
    entry: &EntryDecl,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for p in &entry.params {
        if p.ty.name.text == WIDE_TYPE {
            out.insert(p.name.text.clone());
        }
    }
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                mark_wide_compares(layout, params, asset_params, expr, &mut out)
            }
            Clause::After {
                from: Some(expr), ..
            } => mark_wide_compares(layout, params, asset_params, expr, &mut out),
            _ => {}
        }
    }
    for stmt in &entry.body {
        wide_sinks_stmt(layout, params, asset_params, events, stmt, &mut out);
    }
    out
}

fn wide_sinks_stmt(
    layout: &Layout,
    params: &HashSet<String>,
    asset_params: &HashSet<String>,
    events: &HashMap<String, EventSig>,
    stmt: &Stmt,
    out: &mut HashSet<String>,
) {
    match stmt {
        Stmt::Assign { target, value, .. } => {
            if let Expr::Ident(id) = target {
                if layout.is_wide(&id.text) {
                    mark_wide_field_operands(params, asset_params, value, out);
                }
            }
            mark_wide_compares(layout, params, asset_params, value, out);
        }
        Stmt::Emit { name, args, .. } => {
            if let Some(sig) = events.get(&name.text) {
                for (i, arg) in args.iter().enumerate() {
                    if sig.field_words.get(i).copied() == Some(2) {
                        mark_wide_field_operands(params, asset_params, arg, out);
                    }
                    mark_wide_compares(layout, params, asset_params, arg, out);
                }
            }
        }
        Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => {
            mark_wide_compares(layout, params, asset_params, expr, out)
        }
        Stmt::Let { value, .. } => mark_wide_compares(layout, params, asset_params, value, out),
    }
}

fn mark_wide_field_operands(
    params: &HashSet<String>,
    asset_params: &HashSet<String>,
    expr: &Expr,
    out: &mut HashSet<String>,
) {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if params.contains(&id.text) && !asset_params.contains(&id.text) {
                    out.insert(format!("{}.{}", id.text, name.text));
                    return;
                }
            }
            mark_wide_field_operands(params, asset_params, base, out);
        }
        Expr::Binary { left, right, .. } => {
            mark_wide_field_operands(params, asset_params, left, out);
            mark_wide_field_operands(params, asset_params, right, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            mark_wide_field_operands(params, asset_params, expr, out)
        }
        _ => {}
    }
}

fn mark_wide_compares(
    layout: &Layout,
    params: &HashSet<String>,
    asset_params: &HashSet<String>,
    expr: &Expr,
    out: &mut HashSet<String>,
) {
    match expr {
        Expr::Binary {
            op, left, right, ..
        } => {
            mark_wide_compares(layout, params, asset_params, left, out);
            mark_wide_compares(layout, params, asset_params, right, out);
            if matches!(
                op,
                BinOp::Add
                    | BinOp::Sub
                    | BinOp::Mul
                    | BinOp::Lt
                    | BinOp::Gt
                    | BinOp::Le
                    | BinOp::Ge
                    | BinOp::Eq
                    | BinOp::Ne
            ) && (has_wide_leaf(layout, left, out) || has_wide_leaf(layout, right, out))
            {
                mark_wide_field_operands(params, asset_params, left, out);
                mark_wide_field_operands(params, asset_params, right, out);
            }
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            mark_wide_compares(layout, params, asset_params, expr, out)
        }
        Expr::Call { args, .. } => {
            for a in args {
                mark_wide_compares(layout, params, asset_params, a, out);
            }
        }
        _ => {}
    }
}

fn has_wide_leaf(layout: &Layout, expr: &Expr, out: &HashSet<String>) -> bool {
    match expr {
        Expr::Ident(id) => layout.is_wide(&id.text) || out.contains(&id.text),
        Expr::Field { base, name, .. } => {
            matches!(base.as_ref(), Expr::Ident(id) if out.contains(&format!("{}.{}", id.text, name.text)))
        }
        Expr::Binary { left, right, .. } => {
            has_wide_leaf(layout, left, out) || has_wide_leaf(layout, right, out)
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            has_wide_leaf(layout, expr, out)
        }
        _ => false,
    }
}

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
        Expr::Ident(id) if ctx.wide_keys.contains(&id.text) && ctx.params.contains(&id.text) => {
            let off = ctx.args.offset_of_width(&id.text, 2 * WORD);
            let lo = load_arg(ctx, off, id.span)?;
            let hi = load_arg(ctx, off + WORD, id.span)?;
            Ok((lo, hi))
        }
        Expr::Binary { op, left, right, span }
            if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) =>
        {
            let (llo, lhi) = eval_wide(ctx, left, wrapping)?;
            let (rlo, rhi) = eval_wide(ctx, right, wrapping)?;
            match op {
                BinOp::Add => two_word_add(ctx, llo, lhi, rlo, rhi, wrapping),
                BinOp::Sub => two_word_sub(ctx, llo, lhi, rlo, rhi, wrapping),
                _ => two_word_mul(ctx, llo, lhi, rlo, rhi, wrapping, *span)?,
            }
            Ok((llo, lhi))
        }
        Expr::Field { name, .. } if ctx.is_genesis && deploy_param_name(expr).is_some() => {
            let off = ctx.args.deploy_param_offset(&name.text, 2 * WORD);
            let lo = load_arg(ctx, off, name.span)?;
            let hi = load_arg(ctx, off + WORD, name.span)?;
            Ok((lo, hi))
        }
        Expr::Field { base, name, .. }
            if matches!(base.as_ref(), Expr::Ident(id) if ctx.wide_keys.contains(&format!("{}.{}", id.text, name.text))) =>
        {
            let id = match base.as_ref() {
                Expr::Ident(id) => &id.text,
                _ => unreachable!("the guard matched an ident base"),
            };
            let key = format!("{id}.{}", name.text);
            let off = ctx.args.offset_of_width(&key, 2 * WORD);
            let lo = load_arg(ctx, off, name.span)?;
            let hi = load_arg(ctx, off + WORD, name.span)?;
            Ok((lo, hi))
        }
        _ => {
            let lo = lower_expr(ctx, expr, wrapping)?;
            let hi = ctx.regs.alloc(expr.span())?;
            ctx.b.op(Instr::Ldi { d: hi, imm: 0 });
            Ok((lo, hi))
        }
    }
}

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

fn two_word_mul(
    ctx: &mut Ctx,
    llo: Reg,
    lhi: Reg,
    rlo: Reg,
    rhi: Reg,
    wrapping: bool,
    span: Span,
) -> Result<(), CodegenError> {
    let reslo = ctx.regs.alloc(span)?;
    let reshi = ctx.regs.alloc(span)?;
    let t = ctx.regs.alloc(span)?;
    let ov = if !wrapping {
        Some(ctx.regs.alloc(span)?)
    } else {
        None
    };

    ctx.b.op(Instr::MulW { d: reslo, a: llo, b: rlo });
    ctx.b.op(Instr::MulHi { d: reshi, a: llo, b: rlo });
    if let Some(ov) = ov {
        ctx.b.op(Instr::Ldi { d: ov, imm: 0 });
    }

    ctx.b.op(Instr::MulW { d: t, a: llo, b: rhi });
    ctx.b.op(Instr::AddW { d: reshi, a: reshi, b: t });
    if let Some(ov) = ov {
        ctx.b.op(Instr::LtU { d: SCRATCH, a: reshi, b: t });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: SCRATCH });
    }

    ctx.b.op(Instr::MulW { d: t, a: lhi, b: rlo });
    ctx.b.op(Instr::AddW { d: reshi, a: reshi, b: t });
    if let Some(ov) = ov {
        ctx.b.op(Instr::LtU { d: SCRATCH, a: reshi, b: t });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: SCRATCH });

        ctx.b.op(Instr::MulHi { d: t, a: llo, b: rhi });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: t });
        ctx.b.op(Instr::MulHi { d: t, a: lhi, b: rlo });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: t });
        ctx.b.op(Instr::MulW { d: t, a: lhi, b: rhi });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: t });
        ctx.b.op(Instr::MulHi { d: t, a: lhi, b: rhi });
        ctx.b.op(Instr::Or { d: ov, a: ov, b: t });
    }

    ctx.b.op(Instr::Mov { d: llo, a: reslo });
    ctx.b.op(Instr::Mov { d: lhi, a: reshi });
    if let Some(ov) = ov {
        ctx.b.jnz(ov, ctx.trap);
    }

    if let Some(ov) = ov {
        ctx.regs.free(ov);
    }
    ctx.regs.free(t);
    ctx.regs.free(reshi);
    ctx.regs.free(reslo);
    ctx.regs.free(rhi);
    ctx.regs.free(rlo);
    Ok(())
}

fn wide_compare(
    ctx: &mut Ctx,
    op: BinOp,
    llo: Reg,
    lhi: Reg,
    rlo: Reg,
    rhi: Reg,
    span: Span,
) -> Result<Reg, CodegenError> {
    let t1 = ctx.regs.alloc(span)?;
    let t2 = ctx.regs.alloc(span)?;
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
    Ok(llo)
}

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

fn parse_u128(text: &str, span: Span) -> Result<u128, CodegenError> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    cleaned
        .parse::<u128>()
        .map_err(|_| CodegenError::IntegerTooWide {
            text: text.to_string(),
            span,
        })
}

fn write_scalar_key(ctx: &mut Ctx, slot: u64, key: Reg) {
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: slot,
    });
    ctx.b.op(Instr::Ldi {
        d: key,
        imm: SCALAR_KEY_SCRATCH + ADDR_BYTES - WORD,
    });
    ctx.b.op(Instr::MStore { a: key, b: SCRATCH });
    ctx.b.op(Instr::Ldi {
        d: key,
        imm: SCALAR_KEY_SCRATCH,
    });
}

fn write_scalar_key_reg(ctx: &mut Ctx, slot: Reg, key: Reg) {
    ctx.b.op(Instr::Ldi {
        d: key,
        imm: SCALAR_KEY_SCRATCH + ADDR_BYTES - WORD,
    });
    ctx.b.op(Instr::MStore { a: key, b: slot });
    ctx.b.op(Instr::Ldi {
        d: key,
        imm: SCALAR_KEY_SCRATCH,
    });
}

fn load_slot_reg(ctx: &mut Ctx, slot: Reg, span: Span) -> Result<Reg, CodegenError> {
    let d = ctx.regs.alloc(span)?;
    let key = ctx.regs.alloc(span)?;
    write_scalar_key_reg(ctx, slot, key);
    ctx.b.op(Instr::SLoad { d, a: key });
    ctx.regs.free(key);
    Ok(d)
}

fn load_slot(ctx: &mut Ctx, slot: u64, span: Span) -> Result<Reg, CodegenError> {
    let d = ctx.regs.alloc(span)?;
    let key = ctx.regs.alloc(span)?;
    write_scalar_key(ctx, slot, key);
    ctx.b.op(Instr::SLoad { d, a: key });
    ctx.regs.free(key);
    Ok(d)
}

fn store_slot(ctx: &mut Ctx, slot: u64, value: Reg, span: Span) -> Result<(), CodegenError> {
    let key = ctx.regs.alloc(span)?;
    write_scalar_key(ctx, slot, key);
    ctx.b.op(Instr::SStore { a: key, b: value });
    ctx.regs.free(key);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn lower_entry(
    layout: &Layout,
    entry: &EntryDecl,
    invariants: &[&Expr],
    events: &HashMap<String, EventSig>,
    b: &mut Builder,
    trap: Label,
    is_genesis: bool,
) -> Result<Args, CodegenError> {
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
        let mut ctx = Ctx::new(
            layout,
            &params,
            &asset_params,
            events,
            trap,
            b,
            &mut regs,
            &mut args,
        );
        ctx.entry_mints = entry_mints;
        ctx.is_genesis = is_genesis;
        let address_key_list = collect_address_keys(layout, &params, entry);
        ctx.address_keys = address_key_list.iter().cloned().collect();
        ctx.name_params = entry
            .params
            .iter()
            .filter(|p| p.ty.name.text == NAME_TYPE)
            .map(|p| p.name.text.clone())
            .collect();
        ctx.addr_params = entry
            .params
            .iter()
            .filter(|p| p.ty.name.text == ADDR_TYPE)
            .map(|p| p.name.text.clone())
            .collect();
        ctx.wide_keys = collect_wide_keys(layout, &params, &asset_params, events, entry);
        ctx.args.offset_of_width(CALLER_KEY, ADDR_BYTES);
        ctx.args.offset_of_width(CONTRACT_KEY, ADDR_BYTES);
        ctx.args.offset_of_width(TIME_KEY, WORD);
        // The chain identity the host injects at @chain is a fixed context word, reserved right after
        // @time and ahead of any parameter, so the host always sets it and it never lands in the caller
        // supplied argument region. This word is what binds a signed or quorum order to one chain, so an
        // order captured on one chain does not verify on another.
        ctx.args.offset_of_width(CHAIN_KEY, WORD);
        for param in &entry.params {
            if param.ty.name.text == NAME_TYPE {
                ctx.args.offset_of_width(&param.name.text, NAME_WINDOW);
                ctx.args
                    .offset_of(&format!("{}{NAME_LEN_SUFFIX}", param.name.text));
            }
        }
        for key in &address_key_list {
            if key != CALLER_KEY {
                ctx.args.offset_of_width(key, ADDR_BYTES);
            }
        }
        lower_name_prologue(&mut ctx, entry, trap)?;
        lower_signed_prologue(&mut ctx, entry, trap)?;
        lower_quorum_prologue(&mut ctx, entry, trap)?;
        lower_after_prologue(&mut ctx, entry, trap)?;
        lower_bounds_prologue(&mut ctx, entry, trap)?;
        if ctx.is_genesis {
            lower_genesis_guard(&mut ctx, entry.span)?;
        }
        for stmt in &entry.body {
            lower_stmt(&mut ctx, stmt, trap)?;
        }
        if ctx.is_genesis && !ctx.args.deploy_params().is_empty() {
            let sentinel_off = ctx.args.end();
            let got = load_arg(&mut ctx, sentinel_off, entry.span)?;
            let want = ctx.regs.alloc(entry.span)?;
            ctx.b.op(Instr::Ldi {
                d: want,
                imm: GENESIS_PARAM_SENTINEL,
            });
            ctx.b.op(Instr::Eq {
                d: got,
                a: got,
                b: want,
            });
            ctx.b.jz(got, trap);
            ctx.regs.free(want);
            ctx.regs.free(got);
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

fn lower_genesis_guard(ctx: &mut Ctx, span: Span) -> Result<(), CodegenError> {
    let seen = load_slot(ctx, GENESIS_INIT_GUARD_SLOT, span)?;
    ctx.b.jnz(seen, ctx.trap);
    ctx.regs.free(seen);
    let one = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: one, imm: 1 });
    store_slot(ctx, GENESIS_INIT_GUARD_SLOT, one, span)?;
    ctx.regs.free(one);
    Ok(())
}

enum VerifyOp {
    Ml,
    Slh,
}

fn lower_signed_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for param in &entry.params {
        if param.signed_by.is_none() {
            continue;
        }
        lower_signed_binding(ctx, param, entry, trap)?;
    }
    Ok(())
}

fn lower_quorum_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for param in &entry.params {
        let Some((threshold, count, set)) = quorum_spec(param) else {
            continue;
        };
        let (set_base, set_count) = ctx.layout.guardian_set(&set).ok_or_else(|| {
            CodegenError::Unsupported {
                what: format!("a quorum over `{set}`, which must be a GuardianSet state field"),
                span: param.span,
            }
        })?;
        if count != set_count {
            return Err(CodegenError::Unsupported {
                what: format!(
                    "a quorum whose N does not match the size of the guardian set `{set}`"
                ),
                span: param.span,
            });
        }
        let name = &param.name.text;
        let span = param.span;
        let field_specs = quorum_message_fields(ctx, entry, name);
        let selector_word = u32::from_be_bytes(entry_selector(entry)) as u64;
        let mut prev_index_off: Option<u64> = None;
        for i in 0..threshold {
            let scheme_off = ctx
                .args
                .offset_of(&format!("{name}#{i}{SIG_SCHEME_SUFFIX}"));
            let ptr_off = ctx.args.offset_of(&format!("{name}#{i}{SIG_PTR_SUFFIX}"));
            let index_off = ctx.args.offset_of(&format!("{name}#{i}#index"));
            lower_quorum_member(
                ctx,
                QuorumMember {
                    scheme_off,
                    ptr_off,
                    index_off,
                    prev_index_off,
                    set_base,
                    set_count,
                    selector_word,
                    field_specs: &field_specs,
                },
                trap,
                span,
            )?;
            prev_index_off = Some(index_off);
        }
    }
    Ok(())
}

fn quorum_message_fields(ctx: &mut Ctx, entry: &EntryDecl, quorum_name: &str) -> Vec<(u64, u64)> {
    let mut specs = Vec::new();
    for param in &entry.params {
        let pname = &param.name.text;
        if pname == quorum_name || quorum_spec(param).is_some() || ctx.asset_params.contains(pname) {
            continue;
        }
        for key in collect_signed_fields(entry, pname) {
            let words = if ctx.address_keys.contains(&key) {
                ADDR_WORDS
            } else if ctx.wide_keys.contains(&key) {
                2
            } else {
                1
            };
            specs.push((ctx.args.offset_of_width(&key, words * WORD), words));
        }
    }
    specs
}

struct QuorumMember<'a> {
    scheme_off: u64,
    ptr_off: u64,
    index_off: u64,
    prev_index_off: Option<u64>,
    set_base: u64,
    set_count: u64,
    selector_word: u64,
    field_specs: &'a [(u64, u64)],
}

fn lower_quorum_member(
    ctx: &mut Ctx,
    member: QuorumMember,
    trap: Label,
    span: Span,
) -> Result<(), CodegenError> {
    let ml_label = ctx.b.label();
    let slh_label = ctx.b.label();
    let done_label = ctx.b.label();

    let scheme = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: member.scheme_off,
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
    emit_quorum_member(ctx, VerifyOp::Ml, &member, trap, span)?;
    ctx.b.jmp(done_label);

    ctx.b.mark(slh_label);
    emit_quorum_member(ctx, VerifyOp::Slh, &member, trap, span)?;

    ctx.b.mark(done_label);
    Ok(())
}

fn emit_quorum_member(
    ctx: &mut Ctx,
    op: VerifyOp,
    member: &QuorumMember,
    trap: Label,
    span: Span,
) -> Result<(), CodegenError> {
    let (pk, sig, scheme_id) = match op {
        VerifyOp::Ml => (
            qtv_vm::abi::ML_DSA_PUBLIC_KEY_BYTES as u64,
            qtv_vm::abi::ML_DSA_SIGNATURE_BYTES as u64,
            SCHEME_ML,
        ),
        VerifyOp::Slh => (
            qtv_vm::abi::SLH_DSA_PUBLIC_KEY_BYTES as u64,
            qtv_vm::abi::SLH_DSA_SIGNATURE_BYTES as u64,
            SCHEME_SLH,
        ),
    };
    let msg_start = pk + sig;
    let fields_bytes: u64 = member.field_specs.iter().map(|(_, words)| words * WORD).sum();
    let msg_len = MSG_FIELDS_OFF + fields_bytes;

    let ptr = load_arg(ctx, member.ptr_off, span)?;

    {
        let rscheme = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rscheme,
            imm: scheme_id,
        });
        let rout = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rout,
            imm: SIGNER_ADDR_SCRATCH,
        });
        ctx.b.op(Instr::Addr {
            a: ptr,
            b: rscheme,
            c: rout,
        });
        ctx.regs.free(rout);
        ctx.regs.free(rscheme);
    }

    {
        let rtag = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rtag,
            imm: NONCE_TAG,
        });
        store_mem_word(ctx, NONCE_PREIMAGE_SCRATCH, rtag);
        ctx.regs.free(rtag);
    }
    copy_words_fixed(
        ctx,
        SIGNER_ADDR_SCRATCH,
        NONCE_PREIMAGE_SCRATCH + WORD,
        ADDR_WORDS,
        span,
    )?;
    {
        let ra = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: ra,
            imm: NONCE_PREIMAGE_SCRATCH,
        });
        let rb = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rb,
            imm: WORD + ADDR_BYTES,
        });
        let rc = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rc,
            imm: NONCE_DIGEST_SCRATCH,
        });
        ctx.b.op(Instr::Hash {
            a: ra,
            b: rb,
            c: rc,
        });
        ctx.regs.free(rc);
        ctx.regs.free(rb);
        ctx.regs.free(ra);
    }
    let slot = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: slot,
        imm: NONCE_DIGEST_SCRATCH,
    });
    let nonce = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::SLoad {
        d: nonce,
        a: slot,
    });

    let dst = ctx.regs.alloc(span)?;
    {
        let k = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: k,
            imm: msg_start,
        });
        ctx.b.op(Instr::AddW {
            d: dst,
            a: ptr,
            b: k,
        });
        ctx.regs.free(k);
    }
    {
        let r = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: r,
            imm: SIGNED_MSG_TAG,
        });
        bind_chain_into_tag(ctx, r, span)?;
        store_off(ctx, dst, MSG_TAG_OFF, r);
        ctx.regs.free(r);
    }
    let contract_off = ctx.args.offset_of(CONTRACT_KEY);
    copy_words_to_region(ctx, contract_off, dst, MSG_CONTRACT_OFF, ADDR_WORDS, span)?;
    {
        let r = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: r,
            imm: member.selector_word,
        });
        store_off(ctx, dst, MSG_SELECTOR_OFF, r);
        ctx.regs.free(r);
    }
    copy_words_to_region(ctx, SIGNER_ADDR_SCRATCH, dst, MSG_SIGNER_OFF, ADDR_WORDS, span)?;
    store_off(ctx, dst, MSG_NONCE_OFF, nonce);
    {
        let mut field_off_in_msg = MSG_FIELDS_OFF;
        for (arg_off, words) in member.field_specs {
            copy_words_to_region(ctx, *arg_off, dst, field_off_in_msg, *words, span)?;
            field_off_in_msg += words * WORD;
        }
    }

    {
        let rlen = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rlen,
            imm: msg_start + msg_len,
        });
        let rok = ctx.regs.alloc(span)?;
        let instr = match op {
            VerifyOp::Ml => Instr::VerifyMl {
                a: ptr,
                b: rlen,
                c: rok,
            },
            VerifyOp::Slh => Instr::VerifySlh {
                a: ptr,
                b: rlen,
                c: rok,
            },
        };
        ctx.b.op(instr);
        ctx.b.jz(rok, trap);
        ctx.regs.free(rok);
        ctx.regs.free(rlen);
    }

    let index = load_arg(ctx, member.index_off, span)?;
    {
        let bound = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: bound,
            imm: member.set_count,
        });
        let ok = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::LtU {
            d: ok,
            a: index,
            b: bound,
        });
        ctx.b.jz(ok, trap);
        ctx.regs.free(ok);
        ctx.regs.free(bound);
    }
    if let Some(prev_off) = member.prev_index_off {
        let prev = load_arg(ctx, prev_off, span)?;
        let ok = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::GtU {
            d: ok,
            a: index,
            b: prev,
        });
        ctx.b.jz(ok, trap);
        ctx.regs.free(ok);
        ctx.regs.free(prev);
    }

    {
        let base_idx = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: SCRATCH,
            imm: ADDR_WORDS,
        });
        ctx.b.op(Instr::MulW {
            d: base_idx,
            a: index,
            b: SCRATCH,
        });
        for w in 0..ADDR_WORDS {
            let gslot = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: member.set_base + w,
            });
            ctx.b.op(Instr::AddW {
                d: gslot,
                a: base_idx,
                b: SCRATCH,
            });
            let gword = load_slot_reg(ctx, gslot, span)?;
            let mword = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: SIGNER_ADDR_SCRATCH + w * WORD,
            });
            ctx.b.op(Instr::MLoad {
                d: mword,
                a: SCRATCH,
            });
            ctx.b.op(Instr::Eq {
                d: gword,
                a: gword,
                b: mword,
            });
            ctx.b.jz(gword, trap);
            ctx.regs.free(mword);
            ctx.regs.free(gword);
            ctx.regs.free(gslot);
        }
        ctx.regs.free(base_idx);
    }
    ctx.regs.free(index);

    {
        let one = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi { d: one, imm: 1 });
        ctx.b.op(Instr::AddW {
            d: nonce,
            a: nonce,
            b: one,
        });
        ctx.b.op(Instr::SStore {
            a: slot,
            b: nonce,
        });
        ctx.regs.free(one);
    }

    ctx.regs.free(dst);
    ctx.regs.free(nonce);
    ctx.regs.free(slot);
    ctx.regs.free(ptr);
    Ok(())
}

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
                    // Checked add: an overflowing time gate must fault and revert, not wrap open.
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

/// A `limits` clause states a bound that must hold, and a `denies` clause states a condition that
fn lower_bounds_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } => {
                let r = lower_expr(ctx, expr, false)?;
                ctx.b.jz(r, trap);
                ctx.regs.free(r);
            }
            Clause::Denies { expr, .. } => {
                let r = lower_expr(ctx, expr, false)?;
                ctx.b.jnz(r, trap);
                ctx.regs.free(r);
            }
            _ => {}
        }
    }
    Ok(())
}

fn lower_name_prologue(
    ctx: &mut Ctx,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    let names: Vec<(String, Span)> = entry
        .params
        .iter()
        .filter(|p| p.ty.name.text == NAME_TYPE)
        .map(|p| (p.name.text.clone(), p.span))
        .collect();
    for (i, (name, span)) in names.iter().enumerate() {
        let window_off = ctx.args.offset_of_width(name, NAME_WINDOW);
        let len_off = ctx.args.offset_of(&format!("{name}{NAME_LEN_SUFFIX}"));
        let scratch = NAME_KEY_SCRATCH_BASE + (i as u64) * ADDR_BYTES;

        let len = load_arg(ctx, len_off, *span)?;
        let bound = ctx.regs.alloc(*span)?;
        ctx.b.op(Instr::Ldi {
            d: bound,
            imm: NAME_WINDOW,
        });
        let over = ctx.regs.alloc(*span)?;
        ctx.b.op(Instr::GtU {
            d: over,
            a: len,
            b: bound,
        });
        ctx.b.jnz(over, trap);
        ctx.regs.free(over);
        ctx.regs.free(bound);

        let rptr = ctx.regs.alloc(*span)?;
        ctx.b.op(Instr::Ldi {
            d: rptr,
            imm: window_off,
        });
        let rout = ctx.regs.alloc(*span)?;
        ctx.b.op(Instr::Ldi {
            d: rout,
            imm: scratch,
        });
        ctx.b.op(Instr::Hash {
            a: rptr,
            b: len,
            c: rout,
        });
        ctx.regs.free(rout);
        ctx.regs.free(rptr);
        ctx.regs.free(len);

        ctx.name_keys.insert(name.clone(), scratch);
    }
    Ok(())
}

fn quorum_spec(param: &Param) -> Option<(u64, u64, String)> {
    if param.ty.name.text != "Quorum" {
        return None;
    }
    let mut threshold_of = None;
    let mut set = None;
    for arg in &param.ty.args {
        match arg {
            GenericArg::MofN { m, n, .. } => {
                threshold_of = Some((m.text.parse::<u64>().ok()?, n.text.parse::<u64>().ok()?));
            }
            GenericArg::Type(t) => set = Some(t.name.text.clone()),
            _ => {}
        }
    }
    let (m, n) = threshold_of?;
    Some((m, n, set?))
}


/// Fold the chain identity the host supplies at `@chain` into a message tag register. The signed and
fn bind_chain_into_tag(ctx: &mut Ctx, tag: Reg, span: Span) -> Result<(), CodegenError> {
    let chain_off = ctx.args.offset_of(CHAIN_KEY);
    let chain = load_arg(ctx, chain_off, span)?;
    ctx.b.op(Instr::Xor {
        d: tag,
        a: tag,
        b: chain,
    });
    ctx.regs.free(chain);
    Ok(())
}

fn store_off(ctx: &mut Ctx, base: Reg, off: u64, value: Reg) {
    ctx.b.op(Instr::Ldi {
        d: SCRATCH,
        imm: off,
    });
    ctx.b.op(Instr::AddW {
        d: SCRATCH,
        a: base,
        b: SCRATCH,
    });
    ctx.b.op(Instr::MStore {
        a: SCRATCH,
        b: value,
    });
}

fn copy_words_to_region(
    ctx: &mut Ctx,
    src_off: u64,
    base: Reg,
    dst_off: u64,
    words: u64,
    span: Span,
) -> Result<(), CodegenError> {
    let tmp = ctx.regs.alloc(span)?;
    for i in 0..words {
        ctx.b.op(Instr::Ldi {
            d: SCRATCH,
            imm: src_off + i * WORD,
        });
        ctx.b.op(Instr::MLoad {
            d: tmp,
            a: SCRATCH,
        });
        store_off(ctx, base, dst_off + i * WORD, tmp);
    }
    ctx.regs.free(tmp);
    Ok(())
}

fn copy_words_fixed(
    ctx: &mut Ctx,
    src_off: u64,
    dst_off: u64,
    words: u64,
    span: Span,
) -> Result<(), CodegenError> {
    let tmp = ctx.regs.alloc(span)?;
    for i in 0..words {
        ctx.b.op(Instr::Ldi {
            d: SCRATCH,
            imm: src_off + i * WORD,
        });
        ctx.b.op(Instr::MLoad {
            d: tmp,
            a: SCRATCH,
        });
        store_mem_word(ctx, dst_off + i * WORD, tmp);
    }
    ctx.regs.free(tmp);
    Ok(())
}

// The signed field set is exactly the parameter fields the entry reads, in first read order.
fn collect_signed_fields(entry: &EntryDecl, param: &str) -> Vec<String> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                collect_fields_expr(expr, param, &mut out)
            }
            Clause::After { target, from, .. } => {
                // Both the target and the optional `from` base are read, so both must be signed over.
                if let AfterTarget::Expr(expr) = target {
                    collect_fields_expr(expr, param, &mut out);
                }
                if let Some(expr) = from {
                    collect_fields_expr(expr, param, &mut out);
                }
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        collect_fields_stmt(stmt, param, &mut out);
    }
    out
}

fn collect_fields_stmt(stmt: &Stmt, param: &str, out: &mut Vec<String>) {
    match stmt {
        Stmt::Guard { expr, .. } => collect_fields_expr(expr, param, out),
        Stmt::Let { value, .. } => collect_fields_expr(value, param, out),
        Stmt::Emit { args, .. } => {
            for arg in args {
                collect_fields_expr(arg, param, out);
            }
        }
        Stmt::Assign { target, value, .. } => {
            collect_fields_expr(target, param, out);
            collect_fields_expr(value, param, out);
        }
        Stmt::Expr { expr, .. } => collect_fields_expr(expr, param, out),
    }
}

fn collect_fields_expr(expr: &Expr, param: &str, out: &mut Vec<String>) {
    match expr {
        Expr::Field { base, name, .. } => {
            if let Expr::Ident(id) = base.as_ref() {
                if id.text == param {
                    let key = format!("{param}.{}", name.text);
                    if !out.contains(&key) {
                        out.push(key);
                    }
                    return;
                }
            }
            collect_fields_expr(base, param, out);
        }
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            collect_fields_expr(expr, param, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_fields_expr(left, param, out);
            collect_fields_expr(right, param, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_fields_expr(callee, param, out);
            for arg in args {
                collect_fields_expr(arg, param, out);
            }
        }
        _ => {}
    }
}

const MSG_TAG_OFF: u64 = 0;
const MSG_CONTRACT_OFF: u64 = 8;
const MSG_SELECTOR_OFF: u64 = 40;
const MSG_SIGNER_OFF: u64 = 48;
const MSG_NONCE_OFF: u64 = 80;
const MSG_FIELDS_OFF: u64 = 88;

fn lower_signed_binding(
    ctx: &mut Ctx,
    param: &Param,
    entry: &EntryDecl,
    trap: Label,
) -> Result<(), CodegenError> {
    let owner = param
        .signed_by
        .as_ref()
        .expect("a signed parameter names its signer");
    let owner_slot = match ctx.layout.slot(&owner.text) {
        Some(slot) if ctx.layout.is_addr(&owner.text) => slot,
        _ => {
            return Err(CodegenError::Unsupported {
                what: format!(
                    "`signed by {}`, which must name a Q_Address state field to bind the signer to",
                    owner.text
                ),
                span: param.span,
            })
        }
    };

    let name = &param.name.text;
    let span = param.span;
    let scheme_off = ctx.args.offset_of(&format!("{name}{SIG_SCHEME_SUFFIX}"));
    let ptr_off = ctx.args.offset_of(&format!("{name}{SIG_PTR_SUFFIX}"));
    let field_specs: Vec<(u64, u64)> = collect_signed_fields(entry, name)
        .iter()
        .map(|key| {
            let words = if ctx.address_keys.contains(key) {
                ADDR_WORDS
            } else if ctx.wide_keys.contains(key) {
                2
            } else {
                1
            };
            (ctx.args.offset_of_width(key, words * WORD), words)
        })
        .collect();
    let selector_word = u32::from_be_bytes(entry_selector(entry)) as u64;

    let ml_label = ctx.b.label();
    let slh_label = ctx.b.label();
    let done_label = ctx.b.label();

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
    emit_signed_binding(
        ctx,
        VerifyOp::Ml,
        ptr_off,
        owner_slot,
        selector_word,
        &field_specs,
        trap,
        span,
    )?;
    ctx.b.jmp(done_label);

    ctx.b.mark(slh_label);
    emit_signed_binding(
        ctx,
        VerifyOp::Slh,
        ptr_off,
        owner_slot,
        selector_word,
        &field_specs,
        trap,
        span,
    )?;

    ctx.b.mark(done_label);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_signed_binding(
    ctx: &mut Ctx,
    op: VerifyOp,
    ptr_off: u64,
    owner_slot: u64,
    selector_word: u64,
    field_specs: &[(u64, u64)],
    trap: Label,
    span: Span,
) -> Result<(), CodegenError> {
    let (pk, sig, scheme_id) = match op {
        VerifyOp::Ml => (
            qtv_vm::abi::ML_DSA_PUBLIC_KEY_BYTES as u64,
            qtv_vm::abi::ML_DSA_SIGNATURE_BYTES as u64,
            SCHEME_ML,
        ),
        VerifyOp::Slh => (
            qtv_vm::abi::SLH_DSA_PUBLIC_KEY_BYTES as u64,
            qtv_vm::abi::SLH_DSA_SIGNATURE_BYTES as u64,
            SCHEME_SLH,
        ),
    };
    let msg_start = pk + sig;
    let fields_bytes: u64 = field_specs.iter().map(|(_, words)| words * WORD).sum();
    let msg_len = MSG_FIELDS_OFF + fields_bytes;

    let ptr = load_arg(ctx, ptr_off, span)?;

    {
        let rscheme = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rscheme,
            imm: scheme_id,
        });
        let rout = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rout,
            imm: SIGNER_ADDR_SCRATCH,
        });
        ctx.b.op(Instr::Addr {
            a: ptr,
            b: rscheme,
            c: rout,
        });
        ctx.regs.free(rout);
        ctx.regs.free(rscheme);
    }

    {
        let rtag = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rtag,
            imm: NONCE_TAG,
        });
        store_mem_word(ctx, NONCE_PREIMAGE_SCRATCH, rtag);
        ctx.regs.free(rtag);
    }
    copy_words_fixed(
        ctx,
        SIGNER_ADDR_SCRATCH,
        NONCE_PREIMAGE_SCRATCH + WORD,
        ADDR_BYTES / WORD,
        span,
    )?;
    {
        let ra = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: ra,
            imm: NONCE_PREIMAGE_SCRATCH,
        });
        let rb = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rb,
            imm: WORD + ADDR_BYTES,
        });
        let rc = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rc,
            imm: NONCE_DIGEST_SCRATCH,
        });
        ctx.b.op(Instr::Hash {
            a: ra,
            b: rb,
            c: rc,
        });
        ctx.regs.free(rc);
        ctx.regs.free(rb);
        ctx.regs.free(ra);
    }
    let slot = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: slot,
        imm: NONCE_DIGEST_SCRATCH,
    });
    let nonce = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::SLoad {
        d: nonce,
        a: slot,
    });

    let dst = ctx.regs.alloc(span)?;
    {
        let k = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: k,
            imm: msg_start,
        });
        ctx.b.op(Instr::AddW {
            d: dst,
            a: ptr,
            b: k,
        });
        ctx.regs.free(k);
    }
    {
        let r = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: r,
            imm: SIGNED_MSG_TAG,
        });
        bind_chain_into_tag(ctx, r, span)?;
        store_off(ctx, dst, MSG_TAG_OFF, r);
        ctx.regs.free(r);
    }
    let contract_off = ctx.args.offset_of(CONTRACT_KEY);
    copy_words_to_region(ctx, contract_off, dst, MSG_CONTRACT_OFF, ADDR_BYTES / WORD, span)?;
    {
        let r = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: r,
            imm: selector_word,
        });
        store_off(ctx, dst, MSG_SELECTOR_OFF, r);
        ctx.regs.free(r);
    }
    copy_words_to_region(
        ctx,
        SIGNER_ADDR_SCRATCH,
        dst,
        MSG_SIGNER_OFF,
        ADDR_BYTES / WORD,
        span,
    )?;
    store_off(ctx, dst, MSG_NONCE_OFF, nonce);
    {
        let mut field_off_in_msg = MSG_FIELDS_OFF;
        for (arg_off, words) in field_specs {
            copy_words_to_region(ctx, *arg_off, dst, field_off_in_msg, *words, span)?;
            field_off_in_msg += words * WORD;
        }
    }

    {
        let rlen = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: rlen,
            imm: msg_start + msg_len,
        });
        let rok = ctx.regs.alloc(span)?;
        let instr = match op {
            VerifyOp::Ml => Instr::VerifyMl {
                a: ptr,
                b: rlen,
                c: rok,
            },
            VerifyOp::Slh => Instr::VerifySlh {
                a: ptr,
                b: rlen,
                c: rok,
            },
        };
        ctx.b.op(instr);
        ctx.b.jz(rok, trap);
        ctx.regs.free(rok);
        ctx.regs.free(rlen);
    }

    for i in 0..ADDR_WORDS {
        let ownv = load_slot(ctx, owner_slot + i, span)?;
        let sigv = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: SCRATCH,
            imm: SIGNER_ADDR_SCRATCH + i * WORD,
        });
        ctx.b.op(Instr::MLoad {
            d: sigv,
            a: SCRATCH,
        });
        ctx.b.op(Instr::Eq {
            d: ownv,
            a: ownv,
            b: sigv,
        });
        ctx.b.jz(ownv, trap);
        ctx.regs.free(sigv);
        ctx.regs.free(ownv);
    }

    {
        let one = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi { d: one, imm: 1 });
        ctx.b.op(Instr::AddW {
            d: nonce,
            a: nonce,
            b: one,
        });
        ctx.b.op(Instr::SStore {
            a: slot,
            b: nonce,
        });
        ctx.regs.free(one);
    }

    ctx.regs.free(dst);
    ctx.regs.free(nonce);
    ctx.regs.free(slot);
    ctx.regs.free(ptr);
    Ok(())
}

fn lower_stmt(ctx: &mut Ctx, stmt: &Stmt, trap: Label) -> Result<(), CodegenError> {
    match stmt {
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
        Stmt::Emit { name, args, span } => lower_emit(ctx, &name.text, args, *span),
        Stmt::Let { name, value, span } => lower_let(ctx, &name.text, value, *span),
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
            "set" => return lower_map_set(ctx, base, args, span),
            _ => {}
        }
    }
    if matches!(callee, Expr::Ident(id) if id.text == "send") {
        return lower_send(ctx, args, span);
    }
    Err(CodegenError::Unsupported {
        what: "this call statement".into(),
        span,
    })
}

fn lower_send(ctx: &mut Ctx, args: &[Expr], span: Span) -> Result<(), CodegenError> {
    let (to, value) = two_args(args, span)?;
    let amount = asset_amount(ctx, value, span)?;
    let addr_off = lower_address(ctx, to, span)?;
    let raddr = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: raddr,
        imm: addr_off,
    });
    let rlen = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rlen,
        imm: ADDR_BYTES,
    });
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

fn lower_emit(ctx: &mut Ctx, name: &str, args: &[Expr], span: Span) -> Result<(), CodegenError> {
    let sig = ctx
        .events
        .get(name)
        .ok_or_else(|| CodegenError::Unsupported {
            what: format!("an emit of the undeclared event `{name}`"),
            span,
        })?
        .clone();
    let selector = sig.selector;

    let mut offset = EVENT_BASE;
    for (i, arg) in args.iter().enumerate() {
        let declared = sig.field_words.get(i).copied();
        if declared == Some(ADDR_WORDS) {
            let src_off = lower_address(ctx, arg, span)?;
            copy_words_fixed(ctx, src_off, offset, ADDR_WORDS, span)?;
            offset += ADDR_BYTES;
        } else if declared == Some(2) || (declared.is_none() && is_wide_expr(ctx, arg)) {
            let (lo, hi) = eval_wide(ctx, arg, false)?;
            store_mem_word(ctx, offset, lo);
            store_mem_word(ctx, offset + WORD, hi);
            ctx.regs.free(hi);
            ctx.regs.free(lo);
            offset += 2 * WORD;
        } else {
            let r = lower_expr(ctx, arg, false)?;
            store_mem_word(ctx, offset, r);
            ctx.regs.free(r);
            offset += WORD;
        }
    }

    let len = offset - EVENT_BASE;
    let off_reg = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: off_reg,
        imm: EVENT_BASE,
    });
    let len_reg = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: len_reg, imm: len });
    let sel_reg = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: sel_reg,
        imm: selector as u64,
    });
    ctx.b.op(Instr::Emit {
        a: off_reg,
        b: len_reg,
        c: sel_reg,
    });
    ctx.regs.free(sel_reg);
    ctx.regs.free(len_reg);
    ctx.regs.free(off_reg);
    Ok(())
}

fn addr_key_of(expr: &Expr, params: &HashSet<String>) -> Option<String> {
    match expr {
        Expr::Caller { .. } => Some(CALLER_KEY.to_string()),
        Expr::Ident(id) if id.text == "deployer" => Some(CALLER_KEY.to_string()),
        Expr::Ident(id) if params.contains(&id.text) => Some(id.text.clone()),
        Expr::Field { base, name, .. } => match base.as_ref() {
            Expr::Ident(id) if params.contains(&id.text) => {
                Some(format!("{}.{}", id.text, name.text))
            }
            _ => None,
        },
        _ => None,
    }
}

fn lower_address(ctx: &mut Ctx, expr: &Expr, span: Span) -> Result<u64, CodegenError> {
    if ctx.is_genesis {
        if let Some(name) = deploy_param_name(expr) {
            return Ok(ctx.args.deploy_param_offset(name, ADDR_BYTES));
        }
    }
    if let Expr::Ident(id) = expr {
        if ctx.layout.is_addr(&id.text) {
            return materialize_state_addr(ctx, &id.text.clone(), span);
        }
    }
    if let Some((map_name, mbase, key_expr)) = addr_map_get(ctx, expr) {
        let map_name = map_name.to_string();
        return materialize_map_addr_value(ctx, &map_name, mbase, key_expr, span);
    }
    match addr_key_of(expr, ctx.params) {
        Some(key) => Ok(ctx.args.offset_of_width(&key, ADDR_BYTES)),
        None => Err(CodegenError::Unsupported {
            what: "an address that is not the caller, a parameter, or a parameter field".into(),
            span,
        }),
    }
}

/// A state `Q_Address` field lives in four storage slots, but `send`, an emitted address argument,
fn materialize_state_addr(ctx: &mut Ctx, name: &str, span: Span) -> Result<u64, CodegenError> {
    let slot = ctx
        .layout
        .slot(name)
        .expect("a state address field has a slot");
    let off = match ctx.state_addr_scratch.get(name).copied() {
        Some(off) => off,
        None => {
            let off = ctx.next_state_addr_scratch;
            ctx.next_state_addr_scratch += ADDR_BYTES;
            ctx.state_addr_scratch.insert(name.to_string(), off);
            off
        }
    };
    for i in 0..ADDR_WORDS {
        let w = load_slot(ctx, slot + i, span)?;
        store_mem_word(ctx, off + i * WORD, w);
        ctx.regs.free(w);
    }
    Ok(off)
}

/// An address stored as a keyed map value lives across four hashed word slots. Reading it back for
fn materialize_map_addr_value(
    ctx: &mut Ctx,
    map_name: &str,
    mbase: u64,
    key_expr: &Expr,
    span: Span,
) -> Result<u64, CodegenError> {
    let key_off = map_key_region_named(ctx, map_name, key_expr, span)?;
    let off = ctx.bind_map_value_scratch(map_name);
    for i in 0..ADDR_WORDS {
        compute_map_addr_word_key(ctx, mbase, key_off, i, span)?;
        let w = ctx.regs.alloc(span)?;
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SLoad { d: w, a: key });
        ctx.regs.free(key);
        store_mem_word(ctx, off + i * WORD, w);
        ctx.regs.free(w);
    }
    Ok(off)
}

fn collect_address_keys(
    layout: &Layout,
    params: &HashSet<String>,
    entry: &EntryDecl,
) -> Vec<String> {
    let mut out = Vec::new();
    for clause in &entry.clauses {
        match clause {
            Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => {
                address_keys_expr(expr, layout, params, &mut out)
            }
            _ => {}
        }
    }
    for stmt in &entry.body {
        address_keys_stmt(stmt, layout, params, &mut out);
    }
    out
}

fn push_addr_key(expr: &Expr, params: &HashSet<String>, out: &mut Vec<String>) {
    if let Some(key) = addr_key_of(expr, params) {
        if !out.contains(&key) {
            out.push(key);
        }
    }
}

fn address_keys_stmt(stmt: &Stmt, layout: &Layout, params: &HashSet<String>, out: &mut Vec<String>) {
    match stmt {
        Stmt::Guard { expr, .. } | Stmt::Let { value: expr, .. } | Stmt::Assign { value: expr, .. } => {
            address_keys_expr(expr, layout, params, out)
        }
        Stmt::Expr { expr, .. } => address_keys_expr(expr, layout, params, out),
        Stmt::Emit { .. } => {}
    }
}

fn address_keys_expr(expr: &Expr, layout: &Layout, params: &HashSet<String>, out: &mut Vec<String>) {
    if let Expr::Call { callee, args, .. } = expr {
        if let Expr::Field { base, name, .. } = callee.as_ref() {
            if matches!(
                name.text.as_str(),
                "credit" | "debit" | "insert" | "remove" | "contains" | "get" | "set"
            ) {
                if let Expr::Ident(id) = base.as_ref() {
                    if layout.map_key_is_addr(&id.text) {
                        if let Some(key_expr) = args.first() {
                            push_addr_key(key_expr, params, out);
                        }
                    }
                    if name.text == "set" && layout.map_value_is_addr(&id.text) {
                        if let Some(value_expr) = args.get(1) {
                            push_addr_key(value_expr, params, out);
                        }
                    }
                }
            }
        }
        if matches!(callee.as_ref(), Expr::Ident(id) if id.text == "send") {
            if let Some(to) = args.first() {
                push_addr_key(to, params, out);
            }
        }
        for arg in args {
            address_keys_expr(arg, layout, params, out);
        }
    } else if let Expr::Binary { left, right, .. } = expr {
        address_keys_expr(left, layout, params, out);
        address_keys_expr(right, layout, params, out);
    } else if let Expr::Unary { expr, .. }
    | Expr::Checked { expr, .. }
    | Expr::Wrapping { expr, .. } = expr
    {
        address_keys_expr(expr, layout, params, out);
    }
}

fn map_key_source(ctx: &mut Ctx, key_expr: &Expr, span: Span) -> Result<u64, CodegenError> {
    if let Expr::Ident(id) = key_expr {
        if let Some(off) = ctx.name_keys.get(&id.text).copied() {
            return Ok(off);
        }
    }
    lower_address(ctx, key_expr, span)
}

fn map_key_region(
    ctx: &mut Ctx,
    base: &Expr,
    key_expr: &Expr,
    span: Span,
) -> Result<u64, CodegenError> {
    if let Expr::Ident(id) = base {
        return map_key_region_named(ctx, &id.text.clone(), key_expr, span);
    }
    map_key_source(ctx, key_expr, span)
}

fn map_key_region_named(
    ctx: &mut Ctx,
    map_name: &str,
    key_expr: &Expr,
    span: Span,
) -> Result<u64, CodegenError> {
    if ctx.layout.map_key_is_id(map_name) {
        let id_off = id_word_offset(ctx, key_expr, span)?;
        return promote_id_key(ctx, id_off, span);
    }
    map_key_source(ctx, key_expr, span)
}

fn id_word_offset(ctx: &mut Ctx, key_expr: &Expr, span: Span) -> Result<u64, CodegenError> {
    match key_expr {
        Expr::Ident(id) if ctx.params.contains(&id.text) => Ok(ctx.args.offset_of(&id.text)),
        Expr::Field { base, name, .. } => match base.as_ref() {
            Expr::Ident(id) if ctx.params.contains(&id.text) => {
                Ok(ctx.args.offset_of(&format!("{}.{}", id.text, name.text)))
            }
            _ => Err(CodegenError::Unsupported {
                what: "a token id key that is not a parameter or a parameter field".into(),
                span,
            }),
        },
        _ => Err(CodegenError::Unsupported {
            what: "a token id key that is not a parameter or a parameter field".into(),
            span,
        }),
    }
}

fn promote_id_key(ctx: &mut Ctx, id_off: u64, span: Span) -> Result<u64, CodegenError> {
    let w = load_arg(ctx, id_off, span)?;
    store_mem_word(ctx, ID_KEY_SCRATCH, w);
    ctx.regs.free(w);
    let zero = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: zero, imm: 0 });
    for i in 1..ADDR_WORDS {
        store_mem_word(ctx, ID_KEY_SCRATCH + i * WORD, zero);
    }
    ctx.regs.free(zero);
    Ok(ID_KEY_SCRATCH)
}

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

fn two_args(args: &[Expr], span: Span) -> Result<(&Expr, &Expr), CodegenError> {
    match args {
        [a, b] => Ok((a, b)),
        _ => Err(CodegenError::Unsupported {
            what: "a ledger operation with an unexpected argument count".into(),
            span,
        }),
    }
}

fn compute_map_key(
    ctx: &mut Ctx,
    mbase: u64,
    addr_off: u64,
    span: Span,
) -> Result<(), CodegenError> {
    let tag = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: tag, imm: mbase });
    store_mem_word(ctx, MAP_PREIMAGE_SCRATCH, tag);
    ctx.regs.free(tag);
    copy_words_fixed(ctx, addr_off, MAP_PREIMAGE_SCRATCH + WORD, ADDR_WORDS, span)?;
    let ra = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: ra,
        imm: MAP_PREIMAGE_SCRATCH,
    });
    let rb = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rb,
        imm: WORD + ADDR_BYTES,
    });
    let rc = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rc,
        imm: MAP_KEY_SCRATCH,
    });
    ctx.b.op(Instr::Hash {
        a: ra,
        b: rb,
        c: rc,
    });
    ctx.regs.free(rc);
    ctx.regs.free(rb);
    ctx.regs.free(ra);
    Ok(())
}

fn compute_map_addr_word_key(
    ctx: &mut Ctx,
    mbase: u64,
    addr_off: u64,
    word: u64,
    span: Span,
) -> Result<(), CodegenError> {
    let tag = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: tag, imm: mbase });
    store_mem_word(ctx, MAP_PREIMAGE_SCRATCH, tag);
    ctx.regs.free(tag);
    copy_words_fixed(ctx, addr_off, MAP_PREIMAGE_SCRATCH + WORD, ADDR_WORDS, span)?;
    let widx = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: widx, imm: word });
    store_mem_word(ctx, MAP_PREIMAGE_SCRATCH + WORD + ADDR_BYTES, widx);
    ctx.regs.free(widx);
    let ra = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: ra,
        imm: MAP_PREIMAGE_SCRATCH,
    });
    let rb = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rb,
        imm: WORD + ADDR_BYTES + WORD,
    });
    let rc = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: rc,
        imm: MAP_KEY_SCRATCH,
    });
    ctx.b.op(Instr::Hash {
        a: ra,
        b: rb,
        c: rc,
    });
    ctx.regs.free(rc);
    ctx.regs.free(rb);
    ctx.regs.free(ra);
    Ok(())
}

fn map_key_ptr(ctx: &mut Ctx, span: Span) -> Result<Reg, CodegenError> {
    let key = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi {
        d: key,
        imm: MAP_KEY_SCRATCH,
    });
    Ok(key)
}

fn ledger_amount(ctx: &mut Ctx, value: &Expr, span: Span) -> Result<Reg, CodegenError> {
    if is_asset_value(ctx, value) {
        asset_amount(ctx, value, span)
    } else if is_wide_expr(ctx, value) {
        // A keyed ledger value is one machine word, so a wide amount that carries a high word cannot
        // be held. Rather than truncate it, which would grow a two word total_supply by more than the
        // credited balance and desync the two, evaluate it wide and trap on a nonzero high word.
        let (lo, hi) = eval_wide(ctx, value, false)?;
        ctx.b.jnz(hi, ctx.trap);
        ctx.regs.free(hi);
        Ok(lo)
    } else {
        lower_expr(ctx, value, false)
    }
}

fn is_asset_value(ctx: &Ctx, value: &Expr) -> bool {
    match value {
        Expr::Ident(id) => {
            ctx.asset_params.contains(&id.text) || ctx.asset_locals.contains_key(&id.text)
        }
        Expr::Call { .. } => produces_asset(value),
        _ => false,
    }
}

fn lower_map_credit(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
    add: bool,
) -> Result<(), CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let (key_expr, value_expr) = two_args(args, span)?;
    if map_name_is_value_wide(ctx, base) {
        return lower_map_credit_wide(ctx, base, mbase, key_expr, value_expr, span, add);
    }
    let value = ledger_amount(ctx, value_expr, span)?;
    let addr_off = map_key_region(ctx, base, key_expr, span)?;
    compute_map_key(ctx, mbase, addr_off, span)?;
    let cur = ctx.regs.alloc(span)?;
    let key = map_key_ptr(ctx, span)?;
    ctx.b.op(Instr::SLoad { d: cur, a: key });
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
    ctx.b.op(Instr::SStore { a: key, b: cur });
    ctx.regs.free(key);
    ctx.regs.free(cur);
    ctx.regs.free(value);
    Ok(())
}

fn map_name_is_value_wide(ctx: &Ctx, base: &Expr) -> bool {
    matches!(base, Expr::Ident(id) if ctx.layout.map_value_is_wide(&id.text))
}

fn ledger_amount_wide(ctx: &mut Ctx, value: &Expr, span: Span) -> Result<(Reg, Reg), CodegenError> {
    if is_asset_value(ctx, value) {
        let lo = asset_amount(ctx, value, span)?;
        let hi = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi { d: hi, imm: 0 });
        Ok((lo, hi))
    } else {
        eval_wide(ctx, value, false)
    }
}

fn lower_map_credit_wide(
    ctx: &mut Ctx,
    base: &Expr,
    mbase: u64,
    key_expr: &Expr,
    value_expr: &Expr,
    span: Span,
    add: bool,
) -> Result<(), CodegenError> {
    let key_off = map_key_region(ctx, base, key_expr, span)?;
    compute_map_key(ctx, mbase, key_off, span)?;
    let clo = ctx.regs.alloc(span)?;
    {
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SLoad { d: clo, a: key });
        ctx.regs.free(key);
    }
    compute_map_addr_word_key(ctx, mbase, key_off, 1, span)?;
    let chi = ctx.regs.alloc(span)?;
    {
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SLoad { d: chi, a: key });
        ctx.regs.free(key);
    }
    let (vlo, vhi) = ledger_amount_wide(ctx, value_expr, span)?;
    if add {
        two_word_add(ctx, clo, chi, vlo, vhi, false);
    } else {
        two_word_sub(ctx, clo, chi, vlo, vhi, false);
    }
    compute_map_key(ctx, mbase, key_off, span)?;
    {
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SStore { a: key, b: clo });
        ctx.regs.free(key);
    }
    compute_map_addr_word_key(ctx, mbase, key_off, 1, span)?;
    {
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SStore { a: key, b: chi });
        ctx.regs.free(key);
    }
    ctx.regs.free(chi);
    ctx.regs.free(clo);
    Ok(())
}

fn lower_map_flag(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
    flag: u64,
) -> Result<(), CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let key_expr = one_arg(args, span)?;
    let addr_off = map_key_region(ctx, base, key_expr, span)?;
    compute_map_key(ctx, mbase, addr_off, span)?;
    let v = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: v, imm: flag });
    let key = map_key_ptr(ctx, span)?;
    ctx.b.op(Instr::SStore { a: key, b: v });
    ctx.regs.free(key);
    ctx.regs.free(v);
    Ok(())
}

fn lower_map_read(
    ctx: &mut Ctx,
    base: &Expr,
    args: &[Expr],
    span: Span,
) -> Result<Reg, CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let key_expr = one_arg(args, span)?;
    let addr_off = map_key_region(ctx, base, key_expr, span)?;
    if map_name_is_value_addr(ctx, base) {
        let acc = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi { d: acc, imm: 0 });
        for i in 0..ADDR_WORDS {
            compute_map_addr_word_key(ctx, mbase, addr_off, i, span)?;
            let w = ctx.regs.alloc(span)?;
            let key = map_key_ptr(ctx, span)?;
            ctx.b.op(Instr::SLoad { d: w, a: key });
            ctx.regs.free(key);
            ctx.b.op(Instr::Or {
                d: acc,
                a: acc,
                b: w,
            });
            ctx.regs.free(w);
        }
        ctx.b.op(Instr::Ldi { d: SCRATCH, imm: 0 });
        ctx.b.op(Instr::Eq {
            d: acc,
            a: acc,
            b: SCRATCH,
        });
        logical_not(ctx, acc);
        return Ok(acc);
    }
    compute_map_key(ctx, mbase, addr_off, span)?;
    let d = ctx.regs.alloc(span)?;
    let key = map_key_ptr(ctx, span)?;
    ctx.b.op(Instr::SLoad { d, a: key });
    ctx.regs.free(key);
    Ok(d)
}

fn map_name_is_value_addr(ctx: &Ctx, base: &Expr) -> bool {
    matches!(base, Expr::Ident(id) if ctx.layout.map_value_is_addr(&id.text))
}

fn lower_map_set(ctx: &mut Ctx, base: &Expr, args: &[Expr], span: Span) -> Result<(), CodegenError> {
    let mbase = map_base_of(ctx, base, span)?;
    let (key_expr, value_expr) = two_args(args, span)?;
    let key_off = map_key_region(ctx, base, key_expr, span)?;
    if map_name_is_value_addr(ctx, base) {
        let val_off = lower_address(ctx, value_expr, span)?;
        for i in 0..ADDR_WORDS {
            compute_map_addr_word_key(ctx, mbase, key_off, i, span)?;
            let w = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: val_off + i * WORD,
            });
            ctx.b.op(Instr::MLoad { d: w, a: SCRATCH });
            let key = map_key_ptr(ctx, span)?;
            ctx.b.op(Instr::SStore { a: key, b: w });
            ctx.regs.free(key);
            ctx.regs.free(w);
        }
        return Ok(());
    }
    if map_name_is_value_wide(ctx, base) {
        let (vlo, vhi) = ledger_amount_wide(ctx, value_expr, span)?;
        compute_map_key(ctx, mbase, key_off, span)?;
        {
            let key = map_key_ptr(ctx, span)?;
            ctx.b.op(Instr::SStore { a: key, b: vlo });
            ctx.regs.free(key);
        }
        compute_map_addr_word_key(ctx, mbase, key_off, 1, span)?;
        {
            let key = map_key_ptr(ctx, span)?;
            ctx.b.op(Instr::SStore { a: key, b: vhi });
            ctx.regs.free(key);
        }
        ctx.regs.free(vhi);
        ctx.regs.free(vlo);
        return Ok(());
    }
    let v = lower_expr(ctx, value_expr, false)?;
    compute_map_key(ctx, mbase, key_off, span)?;
    let key = map_key_ptr(ctx, span)?;
    ctx.b.op(Instr::SStore { a: key, b: v });
    ctx.regs.free(key);
    ctx.regs.free(v);
    Ok(())
}

fn addr_map_get<'e>(ctx: &Ctx, expr: &'e Expr) -> Option<(&'e str, u64, &'e Expr)> {
    let Expr::Call { callee, args, .. } = expr else {
        return None;
    };
    let Expr::Field { base, name, .. } = callee.as_ref() else {
        return None;
    };
    if name.text != "get" {
        return None;
    }
    let Expr::Ident(id) = base.as_ref() else {
        return None;
    };
    if !ctx.layout.map_value_is_addr(&id.text) {
        return None;
    }
    let mbase = ctx.layout.map_base(&id.text)?;
    args.first().map(|key| (id.text.as_str(), mbase, key))
}

fn lower_addr_map_eq(
    ctx: &mut Ctx,
    op: BinOp,
    map_name: &str,
    mbase: u64,
    key_expr: &Expr,
    other: &Expr,
    span: Span,
) -> Result<Reg, CodegenError> {
    let key_off = map_key_region_named(ctx, map_name, key_expr, span)?;
    let other_off = lower_address(ctx, other, span)?;
    let acc = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: acc, imm: 1 });
    for i in 0..ADDR_WORDS {
        compute_map_addr_word_key(ctx, mbase, key_off, i, span)?;
        let stored = ctx.regs.alloc(span)?;
        let key = map_key_ptr(ctx, span)?;
        ctx.b.op(Instr::SLoad { d: stored, a: key });
        ctx.regs.free(key);
        let ow = ctx.regs.alloc(span)?;
        ctx.b.op(Instr::Ldi {
            d: SCRATCH,
            imm: other_off + i * WORD,
        });
        ctx.b.op(Instr::MLoad { d: ow, a: SCRATCH });
        ctx.b.op(Instr::Eq {
            d: stored,
            a: stored,
            b: ow,
        });
        ctx.b.op(Instr::And {
            d: acc,
            a: acc,
            b: stored,
        });
        ctx.regs.free(ow);
        ctx.regs.free(stored);
    }
    if op == BinOp::Ne {
        logical_not(ctx, acc);
    }
    Ok(acc)
}

enum AddrLoc {
    State(u64),
    Mem(u64),
}

fn is_scalar_addr(ctx: &Ctx, expr: &Expr) -> bool {
    match expr {
        Expr::Caller { .. } => true,
        Expr::Ident(id) => {
            ctx.layout.is_addr(&id.text)
                || id.text == "deployer"
                || ctx.addr_params.contains(&id.text)
        }
        _ => false,
    }
}

fn scalar_addr_loc(ctx: &mut Ctx, expr: &Expr, span: Span) -> Result<AddrLoc, CodegenError> {
    if let Expr::Ident(id) = expr {
        if ctx.layout.is_addr(&id.text) {
            let slot = ctx
                .layout
                .slot(&id.text)
                .expect("an address field has a slot");
            return Ok(AddrLoc::State(slot));
        }
    }
    Ok(AddrLoc::Mem(lower_address(ctx, expr, span)?))
}

fn load_addr_word(ctx: &mut Ctx, loc: &AddrLoc, word: u64, span: Span) -> Result<Reg, CodegenError> {
    match loc {
        AddrLoc::State(slot) => load_slot(ctx, slot + word, span),
        AddrLoc::Mem(off) => {
            let d = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: off + word * WORD,
            });
            ctx.b.op(Instr::MLoad { d, a: SCRATCH });
            Ok(d)
        }
    }
}

fn lower_scalar_addr_eq(
    ctx: &mut Ctx,
    op: BinOp,
    left: &Expr,
    right: &Expr,
    span: Span,
) -> Result<Reg, CodegenError> {
    let lhs = scalar_addr_loc(ctx, left, span)?;
    let rhs = scalar_addr_loc(ctx, right, span)?;
    let acc = ctx.regs.alloc(span)?;
    ctx.b.op(Instr::Ldi { d: acc, imm: 1 });
    for i in 0..ADDR_WORDS {
        let lw = load_addr_word(ctx, &lhs, i, span)?;
        let rw = load_addr_word(ctx, &rhs, i, span)?;
        ctx.b.op(Instr::Eq { d: lw, a: lw, b: rw });
        ctx.b.op(Instr::And {
            d: acc,
            a: acc,
            b: lw,
        });
        ctx.regs.free(rw);
        ctx.regs.free(lw);
    }
    if op == BinOp::Ne {
        logical_not(ctx, acc);
    }
    Ok(acc)
}

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

fn one_arg(args: &[Expr], span: Span) -> Result<&Expr, CodegenError> {
    match args {
        [only] => Ok(only),
        _ => Err(CodegenError::Unsupported {
            what: "an asset operation with an unexpected argument count".into(),
            span,
        }),
    }
}

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
    store_slot(ctx, slot, rf, span)?;
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

    if let Some((base, count)) = ctx.layout.guardian_set(name) {
        if op != AssignOp::Set {
            return Err(CodegenError::Unsupported {
                what: "an add or subtract on a guardian set field".into(),
                span,
            });
        }
        let words = count * ADDR_WORDS;
        let src_off = match (ctx.is_genesis, deploy_param_name(value), value) {
            (true, Some(pname), _) => ctx.args.deploy_param_offset(pname, words * WORD),
            (_, _, Expr::Ident(id)) if ctx.params.contains(&id.text) => {
                ctx.args.offset_of_width(&id.text, words * WORD)
            }
            _ => {
                return Err(CodegenError::Unsupported {
                    what: "a guardian set set from anything but a genesis deploy parameter or a \
                           guardian set parameter"
                        .into(),
                    span,
                })
            }
        };
        for w in 0..words {
            let r = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: src_off + w * WORD,
            });
            ctx.b.op(Instr::MLoad { d: r, a: SCRATCH });
            store_slot(ctx, base + w, r, span)?;
            ctx.regs.free(r);
        }
        return Ok(());
    }

    if ctx.layout.is_addr(name) {
        if op != AssignOp::Set {
            return Err(CodegenError::Unsupported {
                what: "an add or subtract on an address field".into(),
                span,
            });
        }
        let src_off = lower_address(ctx, value, span)?;
        for i in 0..ADDR_WORDS {
            let w = ctx.regs.alloc(span)?;
            ctx.b.op(Instr::Ldi {
                d: SCRATCH,
                imm: src_off + i * WORD,
            });
            ctx.b.op(Instr::MLoad { d: w, a: SCRATCH });
            store_slot(ctx, slot + i, w, span)?;
            ctx.regs.free(w);
        }
        return Ok(());
    }

    if ctx.layout.is_wide(name) {
        let hi_slot = ctx.layout.hi_slot(name).expect("a wide field has a high slot");
        match op {
            AssignOp::Set => {
                let (vlo, vhi) = eval_wide(ctx, value, false)?;
                store_slot(ctx, slot, vlo, span)?;
                store_slot(ctx, hi_slot, vhi, span)?;
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
                store_slot(ctx, slot, flo, span)?;
                store_slot(ctx, hi_slot, fhi, span)?;
                ctx.regs.free(fhi);
                ctx.regs.free(flo);
            }
        }
        return Ok(());
    }

    match op {
        AssignOp::Set => {
            let rv = lower_expr(ctx, value, false)?;
            store_slot(ctx, slot, rv, span)?;
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
            store_slot(ctx, slot, rf, span)?;
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
        let events: HashMap<String, EventSig> = HashMap::new();
        let trap = b.label();
        let dest = {
            let mut ctx = Ctx::new(
                &layout,
                &params,
                &asset_params,
                &events,
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
            storage.insert(
                qtv_vm::abi::scalar_key(layout.slot(name).expect("state field")),
                *val,
            );
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
        let big = u64::MAX;
        assert_eq!(eval("wrapping(a + b)", &[], &[("a", big), ("b", 1)]), 0);
    }

    #[test]
    fn shift_right_computes_in_vm() {
        assert_eq!(eval("a >> b", &[], &[("a", 256), ("b", 2)]), 64);
        assert_eq!(eval("a >> b", &[], &[("a", 5), ("b", 1)]), 2);
        assert_eq!(eval("a >> b", &[], &[("a", 1), ("b", 0)]), 1);
        assert_eq!(eval("a >> b", &[], &[("a", u64::MAX), ("b", 63)]), 1);
        assert_eq!(eval("a >> b", &[], &[("a", 0xFF00), ("b", 8)]), 0xFF);
    }

    #[test]
    fn shift_binds_looser_than_addition_in_vm() {
        // (x + a) >> b, so 6 + 2 = 8, then 8 >> 1 = 4.
        assert_eq!(eval("x + a >> b", &[("x", 6)], &[("a", 2), ("b", 1)]), 4);
    }
}
