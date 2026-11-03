mod cli;

fn main() {
    let args = cli::args::parse();
    drop(args);
}
