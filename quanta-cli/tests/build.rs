//! The build subcommand compiles a source file to its container on disk.

use std::path::PathBuf;
use std::process::Command;

const METER: &str = "contract Meter {\n\
  state { reading: u64; }\n\
  entry advance(step: u64) writes(reading) {\n\
    guard step > 0;\n\
    reading = checked(reading + step);\n\
    emit Advanced(reading);\n\
  }\n\
  event Advanced(value: u64);\n\
}\n";

#[test]
fn build_writes_a_container_beside_the_source() {
    let dir = std::env::temp_dir().join(format!("quanta-cli-build-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let source = dir.join("Meter.qs");
    std::fs::write(&source, METER).expect("write source");

    let output = Command::new(env!("CARGO_BIN_EXE_quanta-cli"))
        .arg("build")
        .arg(&source)
        .output()
        .expect("run quanta-cli");

    assert!(
        output.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("advance(u64)"), "stdout was: {stdout}");

    let container: PathBuf = dir.join("Meter.qbc");
    let bytes = std::fs::read(&container).expect("container written");
    assert!(!bytes.is_empty(), "container must not be empty");

    let _ = std::fs::remove_dir_all(&dir);
}
