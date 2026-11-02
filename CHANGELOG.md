# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `mcp_offer`: `mcp-offer/1`, a peer serving its own MCP tools to a program here, through a stdio shim and a loopback port with a token that last as long as the stream.
- `forward`: `tcp/1`, one TCP connection per stream in either direction, with each target its own grant, refused before anything connects.
- `Services::with_admission` and `serve_with`, and `LinkStream` in `Handler`, so a service can half-close and say why a stream ended.

- `mux`: named streams inside one link, with credit per stream, metadata on open, a distinct cause for every end, and an optional heartbeat, in Rust, Dart and JavaScript, on one set of vectors.
- `home`: one identity and one trust store per user, shared by every program and capability, and only a default.
- `peers`: claims and grants per peer behind a `PeerStore` trait, with audit events. `link`: serving a link under them, failing closed, with a capability document saying what a peer may open and which process it is talking to.
- `auth`, `pairing`, `discovery` and `companion`, from `coqui-acp-bridge`.
