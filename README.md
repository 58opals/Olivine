# Olivine

Olivine is a Bitcoin Cash mainnet headers client written in Rust. It connects to one explicitly selected trusted peer, starting from an explicitly supplied trusted checkpoint.

The current executable completes a `version`/`verack` handshake and downloads one batch of up to 2,000 headers. It verifies BCH mainnet message magic, payload bounds, checksums, canonical length encodings, and header linkage from the checkpoint through the entire batch. It reports the resulting height and block hash, then exits. An empty response leaves the checkpoint unchanged.

The peer supplies consensus and chain selection. Olivine does not independently validate proof of work, difficulty, timestamps, or accumulated chainwork. A response that does not extend the checkpoint stops the download; there is no automatic fork selection or reorganisation recovery. The current executable does not save headers, resume, catch up across multiple batches, or poll for new blocks yet.

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

## Verify

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use fixed protocol fixtures and a local scripted TCP peer. They do not contact a public peer. Passing them verifies framing, checkpoint linkage, and the first-download flow; it does not establish live-peer interoperability or independent BCH consensus validation.

## Protocol references and dependencies

The wire implementation follows the [BCH network message reference](https://documentation.cash/protocol/network/messages.html) and [Bitcoin Cash Node](https://github.com/bitcoin-cash-node/bitcoin-cash-node), including its mainnet message magic and protocol version. The deprecated transaction-count field in each `headers` entry is decoded and ignored, as in BCHN.

Double SHA-256 uses [`bitcoin_hashes`](https://github.com/rust-bitcoin/rust-bitcoin/tree/bitcoin_hashes-0.14.0/hashes), licensed under CC0-1.0, with default features disabled. The dependency graph contains Rust crates and needs no C/C++ library or FFI wrapper. Project licensing has not yet been selected, and Cargo publication is disabled.
