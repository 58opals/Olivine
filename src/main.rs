mod client;
mod protocol;
mod store;

use std::{env, io, path::PathBuf, process::ExitCode, time::Duration};

use client::{Checkpoint, Config};
use protocol::{display_hash, parse_hash};
use store::HeaderStore;

const HELP: &str = "Olivine — trusted-peer Bitcoin Cash mainnet headers client

Usage:
  olivine --peer HOST:PORT --checkpoint-height HEIGHT --checkpoint-hash HASH
          [--headers-file PATH] [--timeout-seconds SECONDS]

Connect to one trusted peer, complete version/verack, and request one batch
of up to 2,000 headers extending the checkpoint. HASH is the 64-character
block hash in its usual displayed order. No peer or checkpoint is selected
automatically. The default timeout is 30 seconds per network phase.

With --headers-file, validate saved progress before connecting, resume from
its tip, and durably save the downloaded batch. Keep supplying the original
checkpoint on later runs. The parent directory must already exist.

This command checks message integrity and header linkage. It trusts the peer
for consensus and chain selection. Each run downloads one batch; it does
not yet catch up automatically or poll.

Options:
  --help, -h    Show this help
";

struct Arguments {
    config: Config,
    headers_file: Option<PathBuf>,
}

fn parse_args(args: impl Iterator<Item = String>) -> io::Result<Option<Arguments>> {
    let mut peer = None;
    let mut height = None;
    let mut hash = None;
    let mut timeout = None;
    let mut headers_file = None;
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
            "--peer"
                | "--checkpoint-height"
                | "--checkpoint-hash"
                | "--timeout-seconds"
                | "--headers-file"
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
            "--headers-file" => {
                if value.is_empty() {
                    return Err(input_error("--headers-file must not be empty"));
                }
                if headers_file.replace(PathBuf::from(value)).is_some() {
                    return Err(input_error("--headers-file specified more than once"));
                }
            }
            _ => unreachable!(),
        }
    }
    let peer = peer.ok_or_else(|| input_error("--peer is required"))?;
    if peer.trim().is_empty() {
        return Err(input_error("--peer must be a host:port endpoint"));
    }
    Ok(Some(Arguments {
        config: Config {
            peer,
            checkpoint: Checkpoint {
                height: height.ok_or_else(|| input_error("--checkpoint-height is required"))?,
                hash: hash.ok_or_else(|| input_error("--checkpoint-hash is required"))?,
            },
            timeout: timeout.unwrap_or(Duration::from_secs(30)),
        },
        headers_file,
    }))
}

fn input_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn run() -> io::Result<()> {
    let Some(Arguments {
        mut config,
        headers_file,
    }) = parse_args(env::args().skip(1))?
    else {
        print!("{HELP}");
        return Ok(());
    };
    let mut store = headers_file
        .as_deref()
        .map(|path| HeaderStore::open(path, config.checkpoint).map_err(store_error))
        .transpose()?;
    if let Some(store) = &store {
        config.checkpoint = store.tip();
        println!(
            "Loaded {} stored headers; height {} hash {}",
            store.header_count(),
            config.checkpoint.height,
            display_hash(&config.checkpoint.hash)
        );
    }
    println!(
        "Connecting to {} from height {} hash {}",
        config.peer,
        config.checkpoint.height,
        display_hash(&config.checkpoint.hash)
    );
    let download = client::download_first_headers(&config)?;
    if let Some(store) = &mut store {
        store.append(&download.headers).map_err(store_error)?;
    }
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
    if let Some(store) = &store {
        let tip = store.tip();
        println!(
            "Stored {} headers; height {} hash {}",
            store.header_count(),
            tip.height,
            display_hash(&tip.hash)
        );
    }
    Ok(())
}

fn store_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("header store: {error}"))
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
        let arguments = parse_args(args(&[]).into_iter()).unwrap().unwrap();
        assert!(arguments.headers_file.is_none());
        let config = arguments.config;
        assert_eq!(config.peer, "127.0.0.1:8333");
        assert_eq!(config.checkpoint.height, 0);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(
            display_hash(&config.checkpoint.hash),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn accepts_an_explicit_headers_file() {
        let arguments = parse_args(args(&["--headers-file", "headers.dat"]).into_iter())
            .unwrap()
            .unwrap();
        assert_eq!(arguments.headers_file, Some(PathBuf::from("headers.dat")));
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
            vec!["--headers-file", ""],
            vec!["--headers-file", "a", "--headers-file", "b"],
        ] {
            assert!(parse_args(args(&extra).into_iter()).is_err());
        }
    }
}
