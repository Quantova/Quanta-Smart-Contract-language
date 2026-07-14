fn main() {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| "quanta-cli".to_string());
    eprintln!("usage: {prog} parse <file>");
    std::process::exit(2);
}
