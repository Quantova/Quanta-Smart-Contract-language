// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn main() {
    println!("cargo:rerun-if-env-changed=QUANTA_BUILD_COMMIT");
    if std::env::var_os("QUANTA_BUILD_COMMIT").is_some() {
        return;
    }
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| text.len() == 40 && text.bytes().all(|c| c.is_ascii_hexdigit()));
    if let Some(commit) = commit {
        let clean = std::process::Command::new("git")
            .args(["status", "--porcelain", "--untracked-files=no"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .is_some_and(|out| out.stdout.is_empty());
        let id = if clean {
            commit
        } else {
            format!("{commit}-modified")
        };
        println!("cargo:rustc-env=QUANTA_BUILD_COMMIT={id}");
    }
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    let head = std::fs::read_to_string("../.git/HEAD").unwrap_or_default();
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        println!("cargo:rerun-if-changed=../.git/{reference}");
        println!("cargo:rerun-if-changed=../.git/packed-refs");
    }
}
