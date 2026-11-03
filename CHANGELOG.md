# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The Noise method (`coqui-peer-noise`) beside WebCrypto, chosen per endpoint and never negotiated: `auth::Method`, `auth::Identity`, `auth::Proof`, `auth::Trust` and `auth::Session` hold either, `Sealed` takes a session of either, and `pairing` pairs by PIN under the identity's method. A peer of the other method is refused with an error naming both.
- `Method::record_length`: the record a message becomes under each method, for sizing a channel's limit.
- `home::identity_path(method)`, `home::identity_file` and `home::methods`: each method's identity has its own file, `identity` for WebCrypto as before and `identity-noise` for Noise.
- `discovery`: a record and a descriptor name their `method`, and `Candidate::method` reads it; one that names none is WebCrypto's.
- `Proof::with_key_limit` and `Proof::with_rekey`, each method's own setting with its default, and `Proof::weakened`.

### Changed

- `home` records the method a home proves by in `method`: the one named last, or the first identity's. A program naming none uses it, so a home holding an identity of each method after moving to Noise keeps working.
- `Method::record_length` is the longest record at any key limit the sender runs, counting a change of key before each Noise part.
- `Proof::with_max_message` answers a `Result`, refusing under Noise, which has no such limit.
- `Advertisement` names `Method::DEFAULT` unless told otherwise.
- An identity file that cannot be written says why, with the system's error.
- A responder refusing a peer of the other method answers `Error::OtherMethod`, so a host can say so rather than offer to accept the key.
- A new identity is Noise's unless a method is named (`Method::DEFAULT`). An existing identity keeps its method: a WebCrypto home stays WebCrypto, and its paired peers keep working, until a person makes a Noise identity (`home::identity(None, Some(Method::Noise))`) and pairs again under it, since a key of one method is never the other's.
- `auth::read_identity` answers an `auth::Identity` of whichever method the file's key is, and `auth::create_identity` takes the method.
- `home::identity` takes the method: without one it keeps the identity this user has, and refuses to pick when they have one of each.
- `pairing::respond` and `pairing::join` take an `auth::Identity`. A pairing refusal says which: a wrong PIN, an expired one, a mode not offered.
- `prove` and `prove_out` take any `coqui_peer::Method`, and a refused first message that shows the other method says so.

### Removed

- `auth::RECORD_OVERHEAD`: a Noise record grows with its message, so `Method::record_length` replaces it.

- `Stream::finished_by_peer`, `LinkStream::finished_by_peer`, and `finishedByPeer` in JavaScript and Dart: whether the peer sent `finish`, since a receive answers `None` for a close in order as well.
- `mcp_offer`: `mcp-offer/1`, a peer serving its own MCP tools to a program here, through a stdio shim and a loopback port with a token that last as long as the stream.
- `forward`: `tcp/1`, one TCP connection per stream in either direction, with each target its own grant, refused before anything connects.
- `Services::with_admission` and `serve_with`, and `LinkStream` in `Handler`, so a service can half-close and say why a stream ended.

- `mux`: named streams inside one link, with credit per stream, metadata on open, a distinct cause for every end, and an optional heartbeat, in Rust, Dart and JavaScript, on one set of vectors.
- `home`: one identity and one trust store per user, shared by every program and capability, and only a default.
- `peers`: claims and grants per peer behind a `PeerStore` trait, with audit events. `link`: serving a link under them, failing closed, with a capability document saying what a peer may open and which process it is talking to.
- `auth`, `pairing`, `discovery` and `companion`, from `coqui-acp-bridge`.

### Fixed

- `mux`: streams opened at once from several threads are opened in id order, so a lower id no longer follows a higher one and ends the peer's link; the same in JavaScript and Dart. An `open` whose frame could not be sent leaves no stream behind.
- `mcp_offer`: the relay polls a non-blocking socket instead of using a read timeout, which can fail on Windows as data arrives and read as the connection ending; a partial write goes on where it stopped.
