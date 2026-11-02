# The link

A link is one proven, sealed connection between two peers, carrying named streams. This page is the wire, so any language can implement it. `vectors/mux.json` holds the frames as data, and every implementation runs them.

## Layers

| Layer | What it does | Where |
| --- | --- | --- |
| Transport | WebTransport or WebSocket: a channel a browser can open | `coqui-web` |
| Proof | shows who holds a key, and seals every message after that with keys from the proof | a method of `coqui-peer` |
| Streams | this page | `coqui-agentic-peer` |
| Capabilities | ACP, A2A, MCP, or anything else: each protocol's own messages | each protocol's own library |

A stream carries a protocol's messages unchanged. The link adds finding and reaching a peer, never a dialect.

## Frames

Each message on the link is one frame:

| Bytes | Field |
| --- | --- |
| 1 | kind |
| 4 | stream id, little-endian |
| rest | body |

| Kind | Name | Body |
| --- | --- | --- |
| 0 | open | one byte, the token's length; a protocol token; metadata, the rest |
| 1 | data | the last or only part of a message, never empty |
| 2 | credit | a little-endian `u32`, never zero: bytes read |
| 3 | close | one byte: 0 done, 1 refused, 2 broken, 3 superseded, 4 revoked; then a reason in UTF-8, at most 256 bytes, possibly empty |
| 4 | ping | none, on stream 0 |
| 5 | pong | none, on stream 0 |
| 6 | more | a part of a message, with more to come, never empty |
| 7 | finish | none: this side will send nothing more on the stream, and still reads |

A receiver MUST treat anything else as a peer not speaking this, and end the link.

A **protocol token** is printable ASCII with no space, comma or equals sign, at most 64 bytes, so it can go in a DNS-SD record as it is: `acp/1`, `a2a/1`, `mcp`, `dev.boriken.ai6/tether`. Tokens are open: a program may use its own, under a domain it controls, and a client ignores one it does not know.

## Streams

The side that connected uses odd ids and the other even ones, so the two never choose the same id. Ids only go up, so a stream that has ended cannot be opened again. An `open` with an id from the wrong side's range, or one not above the last, ends the link.

Either side may open a stream, whoever connected. The other either serves it or answers `close` with `refused`, because nobody serves that protocol there or this peer may not open it. A proof admits a peer to the link, and being admitted to the link grants no protocol.

**Metadata** on an `open` is opaque to the link, and for the side accepting it: a token, a session key, a resume cursor. It goes with one stream and is kept nowhere, so what rotates or belongs to one conversation stays out of the link's credentials.

A message may be cut into `more` frames and a last `data`, 64 KiB each by default, so a long one cannot hold other streams up for as long as it takes, and an interrupt passes between two parts of someone else's message. The parts of one message arrive in order, and only a whole message is delivered.

`finish` is half a close: a request answered on the same stream sends it after the request. The peer's reader then sees the end after what was sent, which tells a finished message from a truncated one, and it may go on answering. `data` after `finish` breaks the stream. `close` ends both directions.

## Delivery

A stream delivers in order or fails, and never skips. Nothing is ordered across streams, so what needs one order shares a stream, and what must overtake a full stream, such as an interrupt, takes its own.

**The link replays nothing.** A bounded window would mean silent loss after a long drop. A host that needs to survive one reopens a stream with its own cursor in the metadata.

Each way a stream ends is its own, so a host can tell what to do next: closed in order, refused, broken, superseded, revoked, or the link lost. `superseded` means a newer stream took this one's place, so the holder must not simply reopen it, and it is sent before the old stream closes.

## Heartbeat

Optional, off unless set, at link level. A side sends `ping` every interval, and `pong` answers any `ping`. A side that has heard nothing at all for its interval times its allowed misses treats the link as lost. A stream silent for hours is not affected, since a link with live peers answers whatever its streams are doing. Set the interval under a reverse proxy's read timeout, which it also keeps from closing an idle link.

## Flow control

Each direction of each stream starts with a window of credit, 1 MiB by default. Sending a message costs its size in credit. A sender MAY start a message only while its credit is above zero, so a message larger than the window still passes, one at a time. A receiver returns credit as the application reads, not as the link delivers.

So a stream whose reader has stopped stalls only itself, and a receiver holds at most its window and one message for each stream. A peer that sends past that loses that stream, with `close` and `broken`, and keeps the link. Credit is what every other stream depends on, so a frame the mux owes the peer is not dropped when the link is momentarily full.

## Telling a link from plain ACP

After the proof, the side that connected speaks first. A first message whose first byte is 0 is an `open`, and the link has streams. JSON never starts with a zero byte, so anything else is a client speaking one protocol directly, which keeps working. Nothing has to be agreed first, so this works through any proxy, on either transport, with no path to configure.

## Limits

A peer can make a mux hold no more than: 32 streams, 16 of one protocol, 8 opens nobody has accepted, 4 KiB of metadata on each, 600 opens a minute, and on each stream its window and one message of at most 16 MiB, which an unfinished message counts against. These are defaults, and each is a setting. An `open` past them is refused, not queued.

A frame adds 5 bytes, so the link's own largest message has to be 5 bytes larger than the largest frame.
