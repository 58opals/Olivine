# Changelog

## 0.1.0 - 2026-10-25

Initial trusted-peer Bitcoin Cash headers-client release.

- Add a pure Rust Bitcoin Cash mainnet headers client for one explicitly configured peer and trusted checkpoint.
- Complete the `version`/`verack` handshake and download batches of up to 2,000 headers, checking message integrity, bounded parsing and sequential header linkage.
- Save headers in a checksummed file bound to the original checkpoint, using atomic replacement and an exclusive companion lock. Validate saved progress and resume from its tip after restarting.
- Add `--sync` to download successive batches until the peer returns no headers, and `--watch` to poll for new headers and report the latest height and hash.
- Retry transient network failures in `--sync` and `--watch` against the same configured endpoint up to three times, waiting 1, 2 and 4 seconds. Reconnect from the committed tip without resetting saved progress. Single-batch mode fails immediately on a connection failure.
- Stop on chain divergence, malformed protocol data or storage corruption, preserving committed progress.
- Provide the project under the MIT license and include notices and license texts for the locked third-party dependencies.

The client trusts its selected peer for consensus and chain selection. It does not independently validate proof of work, difficulty, timestamps or chainwork, and it does not recover automatically from reorganisations. Full blocks, transaction and script validation, wallet features, a GUI, RPC, a mempool and Utreexo remain outside this milestone.
