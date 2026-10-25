# Olivine

Olivine is a Bitcoin Cash mainnet headers client written in Rust. It connects to one explicitly selected trusted peer, starting from an explicitly supplied trusted checkpoint.

The current executable completes a `version`/`verack` handshake and downloads one batch of up to 2,000 headers. It verifies BCH mainnet message magic, payload bounds, checksums, canonical length encodings, and header linkage through the entire batch. With `--headers-file`, it saves progress locally and resumes from the saved tip on the next run. It reports the resulting height and block hash, then exits. An empty response leaves progress unchanged.

The peer supplies consensus and chain selection. Olivine does not independently validate proof of work, difficulty, timestamps, or accumulated chainwork. A response that does not extend the checkpoint or saved tip stops the download; there is no automatic fork selection or reorganisation recovery. The current executable does not catch up across multiple batches or poll for new blocks automatically yet.

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

Add `--headers-file PATH` to save progress. The parent directory must already exist. Run the same command again with the same original checkpoint height/hash and file path; Olivine validates the saved file before connecting and requests the next batch from its saved tip. Each invocation still downloads only one batch. Without this option the download remains in memory.

The file records the network, original checkpoint, and linked headers, with a checksum covering the complete snapshot. A mismatched checkpoint, malformed file, failed checksum, or broken link stops before any network connection or replacement of existing progress. A divergent response or interrupted download leaves saved progress unchanged.

Updates write a complete sibling temporary snapshot, sync it, rename it over the data file, and sync the parent directory before reporting stored progress. An empty response does not rewrite the file. After an interrupted write, the previous or newly committed snapshot is the source of truth; unrelated temporary files are ignored. If the final directory sync fails after replacement, Olivine reports uncertain durability and stops; restart to validate the file on disk.

A companion `PATH.lock` file prevents concurrent writers. It remains on disk; its operating-system lock is released when the process exits. Do not delete it while a client may be using the store. The data path must be a regular file rather than a symbolic link.

The initial storage format is `OLIVHDR1` (8 bytes), BCH mainnet magic (4), original checkpoint height (little-endian u32), checkpoint hash (32 wire-order bytes), header count (little-endian u64), raw 80-byte headers, then a 32-byte double-SHA256 checksum of all preceding bytes. Current height and hash are derived from the validated headers. Snapshot replacement favors simple recovery; its write cost will need reassessment for large multi-batch historical downloads.

## Verify

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use fixed protocol/storage fixtures and local scripted TCP peers. They do not contact a public peer. They cover framing, linkage, file integrity, restart/resume, and preservation of saved progress on failed downloads. They do not establish independent BCH consensus validation or prove physical power-loss durability.

## Protocol references and dependencies

The wire implementation follows the [BCH network message reference](https://documentation.cash/protocol/network/messages.html) and [Bitcoin Cash Node](https://github.com/bitcoin-cash-node/bitcoin-cash-node), including its mainnet message magic and protocol version. The deprecated transaction-count field in each `headers` entry is decoded and ignored, as in BCHN.

Double SHA-256 uses [`bitcoin_hashes`](https://github.com/rust-bitcoin/rust-bitcoin/tree/bitcoin_hashes-0.14.0/hashes), licensed under CC0-1.0, with default features disabled. The dependency graph contains Rust crates and needs no C/C++ library or FFI wrapper. Project licensing has not yet been selected, and Cargo publication is disabled.
