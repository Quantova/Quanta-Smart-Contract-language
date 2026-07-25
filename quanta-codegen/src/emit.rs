// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_vm::isa::{Instr, Reg};

pub type Label = u32;

enum Line {
    Op(Instr),
    Mark(Label),
    Jmp(Label),
    Jz(Reg, Label),
    Jnz(Reg, Label),
}

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

    pub fn label(&mut self) -> Label {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

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

    pub fn link(self) -> Result<Vec<u8>, LinkError> {
        self.link_with_offsets().map(|(code, _)| code)
    }

    pub fn link_with_offsets(self) -> Result<(Vec<u8>, Vec<Option<u32>>), LinkError> {
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
        Ok((code, offsets))
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
        b.jz(2, skip);
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

    #[test]
    fn link_reports_the_offset_of_each_marked_label() {
        let mut b = Builder::new();
        let head = b.label();
        let tail = b.label();
        b.mark(head);
        b.op(Instr::Ldi { d: 0, imm: 5 });
        b.mark(tail);
        b.op(Instr::Halt);
        let (_code, offsets) = b.link_with_offsets().expect("link");
        assert_eq!(offsets[head as usize], Some(0));
        assert_eq!(
            offsets[tail as usize],
            Some(Instr::Ldi { d: 0, imm: 5 }.encoded_len() as u32)
        );
    }
}
