# coqui-agentic-peer

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-agentic-peer/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-online-blue.svg)](https://boriken-dev.github.io/coqui-agentic-peer/)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-agentic-peer/test.yml)](https://github.com/Boriken-Dev/coqui-agentic-peer/actions/workflows/test.yml)

**Pair once with a peer, then run any agent protocol over that one connection.** ACP, A2A, MCP or a protocol of your own each run as a capability on one proven link, with no second pairing. It makes peers easier to find and connections easier to establish, and adds nothing to the protocols: a stream carries their own messages.

| Path | What it is |
| --- | --- |
| `crates/coqui-agentic-peer` | the Rust library |
| `bindings/dart/coqui_agentic_peer` | streams for Dart and Flutter |
| `bindings/js` | streams for a browser or Node |
| `vectors/mux.json` | the wire as data, which every language runs |
| `docs/link.md` | the wire |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
(cd bindings/dart/coqui_agentic_peer && dart analyze && dart test)
(cd bindings/js && npm test)
```

## License

MPL-2.0; see [LICENSE](https://github.com/Boriken-Dev/coqui-agentic-peer/blob/main/LICENSE).
