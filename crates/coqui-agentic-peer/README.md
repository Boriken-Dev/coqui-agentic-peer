# coqui-agentic-peer

A proven link between two peers, and what runs over it: pair once, then ACP, A2A, MCP or anything else, each as a capability on the same link, with no second pairing. What crosses a stream is that protocol's own messages.

## Features

- `mux`: named streams inside one link, each a `coqui_web_channel::Channel`, with credit per stream, so a reader that stops holds up only itself.
- `auth`: prove a peer before any byte reaches a program, and seal everything after, by the Noise or the WebCrypto method, chosen per endpoint and never negotiated.
- `pairing`: pair once with a PIN, over any channel, including through a reverse proxy.
- `home`: one identity and one trust store per user, shared by every program and capability, with each method's identity in a file of its own.
- `discovery`: DNS-SD records and per-user descriptors. What is found is a claim, and only the proof tests it.
- `companion`: answers a browser extension over native messaging.

## Installation

Not on crates.io yet:

```sh
cargo add --git https://github.com/Boriken-Dev/coqui-agentic-peer coqui-agentic-peer
```

## Quick start

```rust,ignore
use coqui_agentic_peer::mux::{Limits, Mux, Side};
use coqui_web_channel::Channel as _;

Mux::run(&sealed_link, Side::Dialed, Limits::default(), None, |mux| {
    let acp = mux.open("acp/1")?;
    let mcp = mux.open("mcp")?;
    acp.send(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}"#)?;
    let answer = acp.receive(None)?;
    Ok::<_, coqui_web_channel::Failure>(answer)
})?;
```

The wire is in [`docs/link.md`](https://boriken-dev.github.io/coqui-agentic-peer/link/).

## License

[MPL-2.0](../../LICENSE).
