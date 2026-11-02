# Contributing to coqui-agentic-peer

## Licence

This project is distributed under the **Mozilla Public License 2.0** (`LICENSE`). Its copyleft is per file: using the
crates imposes nothing on your code, and a modified file must be published under the MPL 2.0.

## Contributor licence agreement

A first pull request needs a one-time signature. The bot will comment with the exact sentence to reply with; read
[`CLA.md`](CLA.md) first. You keep the copyright in everything you write.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
(cd bindings/dart/coqui_agentic_peer && dart analyze && dart test)
```

A change in how a client behaves on the wire changes `vectors/conversations.json`, which both suites run. Each crate's
`AGENTS.md` is its API header and ships in the package; keep it current in the same commit. Files are LF.
