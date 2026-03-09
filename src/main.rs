use std::env;

use opencircuit::{network_bounds, parse_and_normalize_cidr, parse_cidr, usable_host_range};

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>";

fn run(args: &[String]) -> Result<String, String> {
    if args.len() != 3 {
        return Err(String::from(USAGE));
    }

    match args[1].as_str() {
        "normalize" => {
            parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))
        }
        "info" => {
            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (network, broadcast) =
                network_bounds(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (first_usable, last_usable) =
                usable_host_range(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!(
                "cidr={normalized}\nnetwork={network}\nbroadcast={broadcast}\nfirst_usable={first_usable}\nlast_usable={last_usable}"
            ))
        }
        _ => Err(String::from(USAGE)),
    }
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
