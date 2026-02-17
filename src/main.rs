fn main() {
    if let Err(e) = slient_layer::cli::run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

