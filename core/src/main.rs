mod cli;

fn main() {
    let code = match cli::commands::run(cli::args::parse().command) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    };

    std::process::exit(code);
}
