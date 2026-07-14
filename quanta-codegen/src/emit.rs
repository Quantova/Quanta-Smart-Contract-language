//! Low level emission. A builder accumulates machine instructions and symbolic labels, then a link

use qtv_vm::isa::{Instr, Reg};

/// A symbolic branch target resolved during linking.
pub type Label = u32;

/// One emitted line: a plain instruction, a label position, or a branch to a label.
enum Line {
    Op(Instr),
    Mark(Label),
    Jmp(Label),
    Jz(Reg, Label),
    Jnz(Reg, Label),
}

/// Accumulates lines and hands out fresh labels.
#[derive(Default)]
pub struct Builder {
    lines: Vec<Line>,
    next_label: Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    UnplacedLabel(Label),
    ProgramTooLarge,
}

impl Builder {
    pub fn new() -> Builder {
        Builder::default()
    }

    /// A fresh label. It marks nothing until placed with `mark`.
    pub fn label(&mut self) -> Label {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    /// Places a label at the current position.
    pub fn mark(&mut self, label: Label) {
        self.lines.push(Line::Mark(label));
    }

    pub fn op(&mut self, instr: Instr) {
        self.lines.push(Line::Op(instr));
    }

    pub fn jmp(&mut self, label: Label) {
        self.lines.push(Line::Jmp(label));
    }

    pub fn jz(&mut self, cond: Reg, label: Label) {
        self.lines.push(Line::Jz(cond, label));
    }

    pub fn jnz(&mut self, cond: Reg, label: Label) {
        self.lines.push(Line::Jnz(cond, label));
    }

    /// Resolves every label to an offset and emits the bytecode.
    pub fn link(self) -> Result<Vec<u8>, LinkError> {
        let mut offsets: Vec<Option<u32>> = vec![None; self.next_label as usize];
        let mut at: u32 = 0;
        for line in &self.lines {
            if let Line::Mark(l) = line {
                offsets[*l as usize] = Some(at);
            } else {
                at = at
                    .checked_add(line_len(line))
                    .ok_or(LinkError::ProgramTooLarge)?;
            }
        }

        let mut code = Vec::new();
        for line in &self.lines {
            match line {
                Line::Mark(_) => {}
                Line::Op(instr) => instr.encode(&mut code),
                Line::Jmp(l) => Instr::Jmp {
                    target: resolve(&offsets, *l)?,
                }
                .encode(&mut code),
                Line::Jz(cond, l) => Instr::Jz {
                    a: *cond,
                    target: resolve(&offsets, *l)?,
                }
                .encode(&mut code),
                Line::Jnz(cond, l) => Instr::Jnz {
                    a: *cond,
                    target: resolve(&offsets, *l)?,
                }
                .encode(&mut code),
            }
        }
        Ok(code)
    }
}

fn line_len(line: &Line) -> u32 {
    match line {
        Line::Op(instr) => instr.encoded_len() as u32,
        Line::Jmp(_) => Instr::Jmp { target: 0 }.encoded_len() as u32,
        Line::Jz(_, _) | Line::Jnz(_, _) => Instr::Jz { a: 0, target: 0 }.encoded_len() as u32,
        Line::Mark(_) => 0,
    }
}

fn resolve(offsets: &[Option<u32>], label: Label) -> Result<u32, LinkError> {
    offsets
        .get(label as usize)
        .copied()
        .flatten()
        .ok_or(LinkError::UnplacedLabel(label))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_vm::interp::Interpreter;

    #[test]
    fn straight_line_program_runs() {
        let mut b = Builder::new();
        b.op(Instr::Ldi { d: 0, imm: 5 });
        b.op(Instr::Ldi { d: 1, imm: 7 });
        b.op(Instr::Add { d: 2, a: 0, b: 1 });
        b.op(Instr::Halt);
        let code = b.link().expect("link");
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[2], 12);
    }

    #[test]
    fn forward_branch_skips_a_block() {
        let mut b = Builder::new();
        let skip = b.label();
        b.op(Instr::Ldi { d: 1, imm: 5 });
        b.op(Instr::Ldi { d: 2, imm: 0 });
        b.jz(2, skip); // register two is zero, so jump over the overwrite
        b.op(Instr::Ldi { d: 1, imm: 99 });
        b.mark(skip);
        b.op(Instr::Halt);
        let code = b.link().expect("link");
        let out = Interpreter::new(&code, &[], 100).run().expect("halt");
        assert_eq!(out.regs[1], 5);
    }

    #[test]
    fn an_unplaced_label_is_an_error() {
        let mut b = Builder::new();
        let missing = b.label();
        b.jmp(missing);
        assert_eq!(b.link(), Err(LinkError::UnplacedLabel(missing)));
    }
}
