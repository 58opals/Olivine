# Third-party notices

Olivine uses the following Rust crates. Their licenses apply to those crates independently of Olivine's own license.

| Crate | Version | License used | Upstream |
| --- | --- | --- | --- |
| `bitcoin_hashes` | 0.14.0 | CC0-1.0 | [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) |
| `hex-conservative` | 0.2.3 | CC0-1.0 | [hex-conservative](https://github.com/rust-bitcoin/hex-conservative) |
| `arrayvec` | 0.7.8 | MIT | [arrayvec](https://github.com/bluss/arrayvec) |

The full [CC0 1.0 Universal text](LICENSES/CC0-1.0.txt) is included for `bitcoin_hashes` and `hex-conservative`.

`arrayvec` is offered under `MIT OR Apache-2.0`. This distribution uses the MIT option. Its complete [MIT notice and license text](LICENSES/arrayvec-MIT.txt) includes this copyright notice:

> Copyright (c) Ulrik Sverdrup "bluss" 2015-2023

The `arrayvec` source file `src/char.rs` also carries the following notice, retained here together with the MIT license text:

> Copyright 2012-2016 The Rust Project Developers.

That file is also offered under the MIT or Apache-2.0 license, at the recipient's option. Its original authors are listed as `alexchrichton` and `bluss`.

BCH protocol documentation and Bitcoin Cash Node source are references for wire compatibility. They are not linked dependencies; Olivine does not include copied Bitcoin Cash Node implementation code.
