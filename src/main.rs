use std::env;
use std::net::Ipv4Addr;

use opencircuit::{
    cidr_contains, network_bounds, parse_and_normalize_cidr, parse_cidr, usable_host_range,
};

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>";

fn run(args: &[String]) -> Result<String, String> {
    if args.len() < 2 {
        return Err(String::from(USAGE));
    }

    match args[1].as_str() {
        "normalize" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }
            parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))
        }
        "info" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }
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
        "contains" => {
            if args.len() != 4 {
                return Err(String::from(USAGE));
            }

            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let candidate = args[3]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;
            let contains = cidr_contains(ip, prefix, candidate)
                .map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(contains.to_string())
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
