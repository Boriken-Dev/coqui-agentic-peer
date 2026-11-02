# coqui-agentic-peer

**Pair once with a peer, then run any agent protocol over that one connection.** It makes peers easier to find and connections easier to establish, and adds nothing to the protocols themselves: a stream carries ACP's, A2A's or MCP's own messages.

- [The link](link.md): the wire, for any language.

The discovery record, the descriptor directory and the companion are specified with the browser contract, in [ACP in the browser](https://boriken-dev.github.io/coqui-acp/browser/#network-discovery).

Three rules hold the design together:

- **Standards stay standard.** A client with none of this code keeps working.
- **One pairing per peer.** A new capability is a grant on the same entry in the same trust store, never another pairing.
- **One implementation of each thing.** Proof, pairing, channels and discovery live here, and each protocol's library holds only that protocol.
