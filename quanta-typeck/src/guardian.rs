// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::TypeError;
use crate::model::Model;
use quanta_ast::{AfterTarget, AssignOp, Clause, Expr, Stmt};
use std::collections::HashSet;

const GUARDIAN_SET: &str = "GuardianSet";

pub fn check(model: &Model) -> Result<(), TypeError> {
    let fields: HashSet<&str> = model
        .state
        .iter()
        .filter(|(_, f)| f.ty.name.text == GUARDIAN_SET)
        .map(|(name, _)| *name)
        .collect();
    for entry in &model.entries {
        let mut sets = fields.clone();
        for param in &entry.params {
            if param.ty.name.text == GUARDIAN_SET {
                sets.insert(param.name.text.as_str());
            }
        }
        if sets.is_empty() {
            continue;
        }
        for clause in &entry.clauses {
            match clause {
                Clause::Limits { expr, .. } | Clause::Denies { expr, .. } => refuse(expr, &sets)?,
                Clause::After { target, from, .. } => {
                    if let AfterTarget::Expr(expr) = target {
                        refuse(expr, &sets)?;
                    }
                    if let Some(expr) = from {
                        refuse(expr, &sets)?;
                    }
                }
                _ => {}
            }
        }
        for stmt in &entry.body {
            match stmt {
                Stmt::Assign {
                    target: Expr::Ident(target),
                    op: AssignOp::Set,
                    value: Expr::Ident(value),
                    ..
                } if fields.contains(target.text.as_str())
                    && sets.contains(value.text.as_str()) => {}
                Stmt::Guard { expr, .. } | Stmt::Expr { expr, .. } => refuse(expr, &sets)?,
                Stmt::Let { value, .. } => refuse(value, &sets)?,
                Stmt::Assign { target, value, .. } => {
                    refuse(target, &sets)?;
                    refuse(value, &sets)?;
                }
                Stmt::Emit { args, .. } => {
                    for arg in args {
                        refuse(arg, &sets)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn refuse(expr: &Expr, sets: &HashSet<&str>) -> Result<(), TypeError> {
    match expr {
        Expr::Ident(id) if sets.contains(id.text.as_str()) => Err(TypeError::new(
            format!(
                "the guardian set `{}` is used as a value; a guardian set is only named in a \
                 quorum type or assigned whole to a guardian set field",
                id.text
            ),
            id.span,
        )),
        Expr::Unary { expr, .. } | Expr::Checked { expr, .. } | Expr::Wrapping { expr, .. } => {
            refuse(expr, sets)
        }
        Expr::Binary { left, right, .. } => {
            refuse(left, sets)?;
            refuse(right, sets)
        }
        Expr::Field { base, .. } => refuse(base, sets),
        Expr::Call { callee, args, .. } => {
            refuse(callee, sets)?;
            for arg in args {
                refuse(arg, sets)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
