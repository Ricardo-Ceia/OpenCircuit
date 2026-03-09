use std::env;

use opencircuit::parse_and_normalize_cidr;

fn run(args: &[String]) -> Result<String, String> {
    if args.len() != 3 || args[1] != "normalize" {
        return Err(String::from("Usage: opencircuit normalize <ipv4-cidr>"));
    }

    parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match run(&args) {
        Ok(normalized) => {
            println!("{normalized}");
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}
