# Olivine

Olivine is a Bitcoin Cash mainnet headers client written in Rust. It connects to one explicitly selected trusted peer, starting from an explicitly supplied trusted checkpoint.

Olivine completes a `version`/`verack` handshake and downloads batches of up to 2,000 headers. It verifies BCH mainnet message magic, payload bounds, checksums, canonical length encodings, and header linkage through every batch. With `--headers-file`, it saves progress locally and resumes from the saved tip. `--sync` catches up automatically, while `--watch` continues polling for new headers. Without either mode, it downloads one batch and exits.

The peer supplies consensus and chain selection. Olivine does not independently validate proof of work, difficulty, timestamps, or accumulated chainwork. A response that does not extend the checkpoint or saved tip stops the download; there is no automatic fork selection or reorganisation recovery. Sync/watch modes retry recognized transient transport failures against the same configured endpoint. Protocol, checksum, local input and storage failures stop immediately; restart with the same file and original checkpoint to resume.

## Build and run

Use a stable Rust toolchain with Cargo. The executable currently targets Unix systems, using `/dev/urandom` for its connection nonce:

```sh
cargo build --locked
cargo run --locked -- --help
```

Supply a peer endpoint, checkpoint height, and the checkpoint's usual displayed 64-character block hash:

```sh
cargo run --locked -- \
  --peer YOUR_TRUSTED_PEER:8333 \
  --checkpoint-height YOUR_CHECKPOINT_HEIGHT \
  --checkpoint-hash YOUR_CHECKPOINT_HASH
```

These are placeholders. Select and verify the peer and checkpoint before making a live connection. There is no default peer, DNS seed discovery, automatic checkpoint, wallet, or transaction relay. Use `[IPv6_ADDRESS]:8333` for an IPv6 endpoint. Starting from height H with N returned headers reports height H+N.

`--timeout-seconds` accepts 1–3,600 seconds and defaults to 30. Connection attempts share one deadline after OS name resolution; the handshake and first download each have their own deadline. Partial frames and unrelated messages do not reset a deadline. All incoming messages are limited to 2 MiB before payload allocation. Errors exit with a nonzero status.

## Save and resume

Add `--headers-file PATH` to save progress. The parent directory must already exist. Run the same command again with the same original checkpoint height/hash and file path; Olivine validates the saved file before connecting and requests headers from its saved tip. Without a mode flag, each invocation downloads only one batch. Without a file option, that one-batch download remains in memory.

The file records the network, original checkpoint, and linked headers, with a checksum covering the complete snapshot. A mismatched checkpoint, malformed file, failed checksum, or broken link stops before any network connection or replacement of existing progress. A divergent response or interrupted download leaves saved progress unchanged.

Updates write a complete sibling temporary snapshot, sync it, rename it over the data file, and sync the parent directory before reporting stored progress. An empty response does not rewrite the file. After an interrupted write, the previous or newly committed snapshot is the source of truth; unrelated temporary files are ignored. If the final directory sync fails after replacement, Olivine reports uncertain durability and stops; restart to validate the file on disk.

A companion `PATH.lock` file prevents concurrent writers. It remains on disk; its operating-system lock is released when the process exits. Do not delete it while a client may be using the store. The data path must be a regular file rather than a symbolic link.

The initial storage format is `OLIVHDR1` (8 bytes), BCH mainnet magic (4), original checkpoint height (little-endian u32), checkpoint hash (32 wire-order bytes), header count (little-endian u64), raw 80-byte headers, then a 32-byte double-SHA256 checksum of all preceding bytes. Current height and hash are derived from the validated headers. Snapshot replacement favors simple recovery; its write cost will need reassessment for large multi-batch historical downloads.

## Catch up and watch

Add `--sync` and `--headers-file PATH` to catch up and exit. The client reuses one peer connection, saves each valid batch before advancing its locator, and continues until the peer returns no headers. A short nonempty batch does not end catch-up. The peer's advertised height is informational; an empty response means caught up with that peer at that moment.

Use `--watch` instead of `--sync` to catch up and keep polling. The default interval is 30 seconds; `--poll-seconds` accepts 1–3,600 seconds with `--watch`. For example, after replacing the placeholders:

```sh
cargo run --locked -- \
  --peer YOUR_TRUSTED_PEER:8333 \
  --checkpoint-height YOUR_CHECKPOINT_HEIGHT \
  --checkpoint-hash YOUR_CHECKPOINT_HASH \
  --headers-file /path/to/headers.dat \
  --watch --poll-seconds 30
```

`--sync` and `--watch` are mutually exclusive and both require a headers file. The client reports each saved batch's height/hash and reports when it catches up. Quiet polls do not repeat progress messages. Stop watching with Ctrl-C, then run the same command to resume. Keep using the original checkpoint rather than replacing it with the saved tip.

Each headers request receives a fresh response deadline. While waiting to poll, the client handles peer pings and finishes any started message under the normal network timeout before issuing its next request. A slow partial frame can therefore delay a poll by up to that timeout; it cannot reset the timeout indefinitely or be discarded between requests on a healthy connection.

## Reconnect after transport failures

`--sync` and `--watch` share a budget of three retries per invocation, after backoff delays of 1, 2 and 4 seconds. The initial connection plus three retries permits at most four connection attempts. Saving headers or catching up does not reset the budget, so a repeatedly disconnecting peer cannot keep the run retrying indefinitely. Normal network timeouts still apply to each attempt in addition to backoff delays. One-batch mode remains fail-fast.

Retries use the same configured endpoint, perform a new handshake and resume from the last durably saved height/hash. The file remains locked during backoff and reconnect. A partially received batch is discarded with the failed connection, and the next request starts from committed progress. Hostnames are resolved normally on each connection attempt; there is no seed discovery or automatic endpoint substitution.

Recognized connection refusals, disconnects, timeouts and other transport failures are retryable. A completely received malformed message, wrong network, checksum failure, divergent chain, local setup failure or storage failure is not. Unknown errors also stop rather than being retried blindly. After the retry budget is exhausted, the client exits with an error and leaves committed progress available for a later run.

## Verify

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use fixed protocol/storage fixtures and local scripted TCP peers. They do not contact a public peer. They cover framing, linkage, file integrity, restart/resume, automatic catch-up, idle ping handling, new-header polling, bounded reconnection, and preservation of saved progress on failed downloads. They do not establish independent BCH consensus validation or prove physical power-loss durability.

## Protocol references and dependencies

The wire implementation follows the [BCH network message reference](https://documentation.cash/protocol/network/messages.html) and [Bitcoin Cash Node](https://github.com/bitcoin-cash-node/bitcoin-cash-node), including its mainnet message magic and protocol version. The deprecated transaction-count field in each `headers` entry is decoded and ignored, as in BCHN.

Olivine is provided under the [MIT license](LICENSE), copyright 2026 Coda Beatrix. Double SHA-256 uses [`bitcoin_hashes`](https://github.com/rust-bitcoin/rust-bitcoin/tree/bitcoin_hashes-0.14.0/hashes), licensed under CC0-1.0, with default features disabled. The dependency graph contains Rust crates and needs no C/C++ library or FFI wrapper. [Third-party notices](THIRD_PARTY_NOTICES.md) identify the locked dependencies and their license texts. Cargo registry publication is disabled.
