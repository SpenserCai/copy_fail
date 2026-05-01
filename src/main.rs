fn main() {
    if let Err(e) = copy_fail::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
