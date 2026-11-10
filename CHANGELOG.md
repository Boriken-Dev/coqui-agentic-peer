# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Breaking:** the peer family is on `coqui-builder`. `NonDefault` is `coqui_builder::NonDefault` (the crate takes `coqui-builder` as a dependency), so a setting's `value` and `default` are `Shown` values that print as `bool(false)` or `Duration(5s)` rather than plain text.
- **Breaking:** `ProofBuilder` is no longer `Clone`; the builders of `coqui-peer-noise` and `coqui-peer-webcrypto` it holds are not, so a caller that cloned one builds again from its inputs.
- **Breaking: a weakened setting is a non-default setting.** `Proof::weakened` is `non_defaults`, returning coqui-builder's
  `NonDefault { setting, value, default }`; the old method is gone; nothing keeps an alias before a release without a pre-release tag.
- **Breaking:** `discovery::read_descriptors` returns `Descriptors { candidates, directory }`, where `directory` is a
  `DirectoryCheck` (`Private`, `SharedWithOthers`, `NotChecked`), instead of printing 'descriptors ignored' to standard
  error. `discover` prints nothing either; `discover_report` returns the same finding and the reason the link could not be
  searched. A library prints nothing: the application shows the finding.

### Added

- The Noise method (`coqui-peer-noise`) beside WebCrypto, chosen per endpoint and never negotiated: `auth::Method`, `auth::Identity`, `auth::Proof`, `auth::Trust` and `auth::Session` hold either, `Sealed` takes a session of either, and `pairing` pairs by PIN under the identity's method. A peer of the other method is refused with an error naming both.
- `Method::record_length`: the record a message becomes under each method, for sizing a channel's limit.
- `home::identity_path(method)`, `home::identity_file` and `home::methods`: each method's identity has its own file, `identity` for WebCrypto as before and `identity-noise` for Noise.
- `discovery`: a record and a descriptor name their `method`, and `Candidate::method` reads it; one that names none is WebCrypto's.
- `Proof::builder(identity)` with `responders`, `initiators`, `key_limit` and `rekey`, each method's own setting with its default, and `Proof::non_defaults`.

### Changed

- `home` records the method a home proves by in `method`: the one named last, or the first identity's. A program naming none uses it, so a home holding an identity of each method after moving to Noise keeps working.
- `Method::record_length` is the longest record at any key limit the sender runs, counting a change of key before each Noise part.
- `ProofBuilder::build` answers a `Result`: `max_message` is refused under Noise, which has no such limit, and `rekey(true)` under WebCrypto.
- `Advertisement` names `Method::DEFAULT` unless told otherwise.
- An identity file that cannot be written says why, with the system's error.
- A responder refusing a peer of the other method answers `Error::OtherMethod`, so a host can say so rather than offer to accept the key.
- The channel crate is `coqui-web-channel` (`coqui_web_channel::`), renamed from coqui-web, pinned at `0b5b05c`: coqui-web's `3b39c00` under its new name, the revision Guatiao's remote source pins, so a program using both has one `Channel` type.
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
