use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrParseError {
    MissingSlash,
    InvalidIp,
    InvalidPrefix,
}

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSlash => write!(f, "CIDR must include '/' separator"),
            Self::InvalidIp => write!(f, "CIDR contains an invalid IPv4 address"),
            Self::InvalidPrefix => write!(f, "CIDR prefix must be an integer between 0 and 32"),
        }
    }
}

pub fn parse_cidr(input: &str) -> Result<(Ipv4Addr, u8), CidrParseError> {
    let (ip_part, prefix_part) = input.split_once('/').ok_or(CidrParseError::MissingSlash)?;

    let ip = ip_part
        .parse::<Ipv4Addr>()
        .map_err(|_| CidrParseError::InvalidIp)?;

    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| CidrParseError::InvalidPrefix)?;

    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::{parse_cidr, CidrParseError};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_valid_cidr() {
        let parsed = parse_cidr("192.168.1.0/24");
        assert_eq!(parsed, Ok((Ipv4Addr::new(192, 168, 1, 0), 24)));
    }

    #[test]
    fn parses_edge_prefix_values() {
        assert_eq!(
            parse_cidr("10.0.0.1/0"),
            Ok((Ipv4Addr::new(10, 0, 0, 1), 0))
        );
        assert_eq!(
            parse_cidr("10.0.0.1/32"),
            Ok((Ipv4Addr::new(10, 0, 0, 1), 32))
        );
    }

    #[test]
    fn fails_without_separator() {
        assert_eq!(parse_cidr("192.168.1.0"), Err(CidrParseError::MissingSlash));
    }

    #[test]
    fn fails_with_invalid_ipv4() {
        assert_eq!(parse_cidr("999.1.1.1/24"), Err(CidrParseError::InvalidIp));
    }

    #[test]
    fn fails_with_non_numeric_prefix() {
        assert_eq!(
            parse_cidr("192.168.1.0/x"),
            Err(CidrParseError::InvalidPrefix)
        );
    }

    #[test]
    fn fails_with_out_of_range_prefix() {
        assert_eq!(
            parse_cidr("192.168.1.0/33"),
            Err(CidrParseError::InvalidPrefix)
        );
    }
}
