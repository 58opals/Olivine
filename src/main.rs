mod client;
mod protocol;

use std::{env, io, process::ExitCode, time::Duration};

use client::{Checkpoint, Config};
use protocol::{display_hash, parse_hash};

const HELP: &str = "Olivine — trusted-peer Bitcoin Cash mainnet headers client

Usage:
  olivine --peer HOST:PORT --checkpoint-height HEIGHT --checkpoint-hash HASH
          [--timeout-seconds SECONDS]

Connect to one trusted peer, complete version/verack, and request one batch
of up to 2,000 headers extending the checkpoint. HASH is the 64-character
block hash in its usual displayed order. No peer or checkpoint is selected
automatically. The default timeout is 30 seconds per network phase.

This command checks message integrity and header linkage. It trusts the peer
for consensus and chain selection. It does not yet save headers or poll.

Options:
  --help, -h    Show this help
";

fn parse_args(args: impl Iterator<Item = String>) -> io::Result<Option<Config>> {
    let mut peer = None;
    let mut height = None;
    let mut hash = None;
    let mut timeout = None;
    let mut args = args.peekable();
    if args.peek().is_none() {
        return Err(input_error(
            "provide a peer and checkpoint; use --help for usage",
        ));
    }
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            return Ok(None);
        }
        if !matches!(
            flag.as_str(),
            "--peer" | "--checkpoint-height" | "--checkpoint-hash" | "--timeout-seconds"
        ) {
            return Err(input_error(format!("unknown option: {flag}")));
        }
        let value = args
            .next()
            .ok_or_else(|| input_error(format!("missing value for {flag}")))?;
        match flag.as_str() {
            "--peer" => {
                if peer.replace(value).is_some() {
                    return Err(input_error("--peer specified more than once"));
                }
            }
            "--checkpoint-height" => {
                let value: u32 = value
                    .parse()
                    .map_err(|_| input_error("invalid checkpoint height"))?;
                if value > i32::MAX as u32 {
                    return Err(input_error(
                        "checkpoint height exceeds the protocol's signed height range",
                    ));
                }
                if height.replace(value).is_some() {
                    return Err(input_error("--checkpoint-height specified more than once"));
                }
            }
            "--checkpoint-hash" => {
                if hash.replace(parse_hash(&value)?).is_some() {
                    return Err(input_error("--checkpoint-hash specified more than once"));
                }
            }
            "--timeout-seconds" => {
                let value: u64 = value.parse().map_err(|_| input_error("invalid timeout"))?;
                if !(1..=3600).contains(&value) {
                    return Err(input_error("timeout must be between 1 and 3600 seconds"));
                }
                if timeout.replace(Duration::from_secs(value)).is_some() {
                    return Err(input_error("--timeout-seconds specified more than once"));
                }
            }
            _ => unreachable!(),
        }
    }
    let peer = peer.ok_or_else(|| input_error("--peer is required"))?;
    if peer.trim().is_empty() {
        return Err(input_error("--peer must be a host:port endpoint"));
    }
    Ok(Some(Config {
        peer,
        checkpoint: Checkpoint {
            height: height.ok_or_else(|| input_error("--checkpoint-height is required"))?,
            hash: hash.ok_or_else(|| input_error("--checkpoint-hash is required"))?,
        },
        timeout: timeout.unwrap_or(Duration::from_secs(30)),
    }))
}

fn input_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn run() -> io::Result<()> {
    let Some(config) = parse_args(env::args().skip(1))? else {
        print!("{HELP}");
        return Ok(());
    };
    println!(
        "Connecting to {} from trusted checkpoint {} {}",
        config.peer,
        config.checkpoint.height,
        display_hash(&config.checkpoint.hash)
    );
    let download = client::download_first_headers(&config)?;
    println!(
        "Handshake complete with {} (protocol {}, services {:#x}, advertised height {})",
        download.peer,
        download.version.protocol,
        download.version.services,
        download.version.start_height
    );
    println!(
        "Received {} linked headers; height {} hash {}",
        download.headers.len(),
        download.tip.height,
        display_hash(&download.tip.hash)
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("olivine: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        [
            "--peer",
            "127.0.0.1:8333",
            "--checkpoint-height",
            "0",
            "--checkpoint-hash",
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        ]
        .iter()
        .chain(extra)
        .map(|value| (*value).to_owned())
        .collect()
    }

    #[test]
    fn explicit_inputs_and_defaults() {
        let config = parse_args(args(&[]).into_iter()).unwrap().unwrap();
        assert_eq!(config.peer, "127.0.0.1:8333");
        assert_eq!(config.checkpoint.height, 0);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(
            display_hash(&config.checkpoint.hash),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_inputs() {
        for values in [
            vec![],
            vec!["--peer"],
            vec!["--peer", "localhost:8333"],
            vec!["--unexpected"],
        ] {
            assert!(parse_args(values.into_iter().map(str::to_owned)).is_err());
        }
        for extra in [
            vec!["--peer", "other:8333"],
            vec!["--checkpoint-height", "1"],
            vec!["--timeout-seconds", "0"],
            vec!["--timeout-seconds", "3601"],
            vec!["--timeout-seconds", "invalid"],
            vec!["--checkpoint-height", "2147483648"],
        ] {
            assert!(parse_args(args(&extra).into_iter()).is_err());
        }
    }
}
