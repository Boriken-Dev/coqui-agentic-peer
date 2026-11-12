# `coqui-agentic-peer` — API header

Header-file-style reference for the `coqui-agentic-peer` crate, so it can be used without reading the source. It ships inside the package and is self-contained.

No Cargo features. MSRV Rust 1.89. Version `0.0.0-alpha.0`, not published. It depends on `coqui-transport` (by revision, no default features; its `Channel` and `Failure` are what every link and stream is generic over), `coqui-builder`, `coqui-peer`, `coqui-peer-webcrypto` and `coqui-peer-noise` (each with `pin`), `mdns-sd`, `serde_json` and `url`. No `unsafe` code. Public modules: `auth`, `companion`, `discovery`, `forward`, `home`, `link`, `mcp_offer`, `mux`, `pairing`, `peers`.

## `coqui_agentic_peer::mux`

```rust
pub const MAX_PROTOCOL: usize = 64;
pub fn valid_protocol(protocol: &str) -> bool      // printable ASCII, no space, comma or equals; goes in a DNS-SD record as it is
pub fn starts_mux(first_message: &[u8]) -> bool    // true for a link with streams; JSON never starts with a zero byte
pub const MAX_REASON: usize = 256;
pub struct Limits { pub max_streams: usize, pub max_per_protocol: usize, pub window: u32, pub max_message: usize, pub max_frame: usize, pub max_metadata: usize, pub max_pending_opens: usize, pub max_opens_per_minute: u32, pub send_wait: Duration, pub heartbeat: Option<Heartbeat> }  // non_exhaustive, Default
pub struct Heartbeat { pub interval: Duration, pub misses: u32 }    // non_exhaustive; Heartbeat::new(interval, misses)
pub enum Side { Dialed, Answered }
pub enum Frame { Open { stream, protocol, metadata }, Data { stream, body }, More { stream, body }, Credit { stream, bytes }, Finish { stream }, Close { stream, reason, text }, Ping, Pong }  // non_exhaustive
pub enum CloseReason { Done, Refused, Broken, Superseded, Revoked }  // non_exhaustive
pub enum StreamEnd { PeerClosed, Refused(String), Broken, Superseded(String), Revoked(String), LinkLost(Failure) }  // non_exhaustive
pub enum LinkState { Up, Closed, Lost(Failure, SystemTime) }  // non_exhaustive
pub struct Incoming { pub protocol: String, pub metadata: Vec<u8>, pub stream: Stream<'c, C> }  // non_exhaustive
pub fn Frame::encode(&self) -> Vec<u8>
pub fn Frame::decode(bytes: &[u8]) -> Option<Frame>

pub fn Mux::run<R>(channel: &C, side: Side, limits: Limits, first: Option<Vec<u8>>, body: impl FnOnce(&Mux<'c, C>) -> R) -> R
pub fn Mux::open(&self, protocol: &str) -> Result<Stream<'c, C>, Failure>
pub fn Mux::open_with(&self, protocol: &str, metadata: &[u8]) -> Result<Stream<'c, C>, Failure>
pub fn Mux::accept(&self, timeout: Option<Duration>) -> Result<Option<Incoming<'c, C>>, Failure>
pub fn Mux::link_state(&self) -> LinkState
impl Channel for Stream<'_, C>   // send, receive, close; closes on drop
pub fn Stream::try_send(&self, message: &[u8]) -> Result<(), Failure>    // NoProgress at once when full, uncharged
pub fn Stream::finish(&self) -> Result<(), Failure>                      // sends nothing more, goes on reading; the peer's receive answers None
pub fn Stream::close_with(&self, reason: CloseReason, text: &str)        // refused, superseded or revoked, saying why
pub fn Stream::end(&self) -> Option<StreamEnd>
pub fn Stream::finished_by_peer(&self) -> bool                            // the peer sent `finish`; also on LinkStream (default false)
```

- `Mux::run` reads the link for as long as `body` runs, on a thread of its own, and does not close the channel. `first` is a message already read, as when `starts_mux` looked at it.
- `Stream::send` waits up to `send_wait` for credit, then answers `Failure::NoProgress`, uncharged, so a caller may try again. A stream refused, superseded or revoked answers `Failure::Permission`, one that broke its bounds `Failure::Protocol`, and a lost link the link's own failure; `Stream::end` says which.
- `receive` answers `None` for a peer that called `finish` and for a stream or link closed in order alike. `finished_by_peer` tells them apart: `false` after a `None` means what arrived may be part of what the peer meant to send. In JavaScript it is `stream.finishedByPeer`, in Dart `MuxStream.finishedByPeer`.
- Opens leave in id order whatever the thread count, and an open whose frame could not be sent leaves nothing in the stream table. In JavaScript and Dart `open` is one at a time for the same reason.
- A long message is cut into frames of `max_frame`, so another stream's message passes between its parts. Only the first part can be taken back: past that, a link that will not take the rest is lost.
- A stream delivers in order or fails, and never skips. Nothing is ordered across streams. Nothing replays: to survive a drop, reopen with your own cursor in `metadata`. Either side opens streams, whoever connected.
- `Limits::heartbeat` is off by default, and a zero interval or zero misses turns it off too. It loses a link only when nothing at all is heard, so a stream silent for hours is fine. `link_state` says when a link went; what that means is the host's to decide.
- What one stream does wrong ends that stream. What no peer may send ends the link.
- A proof admits a peer to the link and grants no protocol. Deciding who may open what is the caller's: `accept`, then serve, or `close_with(CloseReason::Refused, why)`. `metadata` is kept nowhere, and is not a credential of the link's.

## `coqui_agentic_peer::mcp_offer`

```rust
pub const OFFER_PROTOCOL: &str = "mcp-offer/1";
pub const ADDRESS_VARIABLE: &str = "COQUI_MCP_OFFER_ADDRESS";
pub const TOKEN_FILE_VARIABLE: &str = "COQUI_MCP_OFFER_TOKEN_FILE";
pub fn handler(command: PathBuf, args: Vec<String>, tokens: PathBuf) -> link::Handler      // what Services::with takes; command is absolute and starts shim; tokens is made private and holds one file per offer
pub fn shim(input: impl Read + Send + 'static, output: impl Write) -> Result<(), ShimError>   // the stdio server, from its environment
pub enum ShimError { Setting(&'static str), Io(io::Error) }  // non_exhaustive
```

- A peer opens the stream, with a server name in `metadata` or none, and its first message is a stdio `mcpServers` entry to declare to its agent. Lines the shim carries are then that stream's messages, both ways. The wire is in `docs/link.md`.
- The shim refuses an address off this machine, so the token goes nowhere else. It returns when either end stops; call it with standard input and output, and exit.
- The port, the token and its file last as long as the stream. The entry holds no secret, since an agent may pass its environment to a program in arguments another user can read. What it starts has to run as the user who can read that file.

## `coqui_agentic_peer::link`

```rust
pub const LINK_PROTOCOL: &str = "link/1";
pub fn instance() -> &'static str                // random per process
pub struct Accepted { pub peer: String, pub claims: BTreeMap<String, String>, pub protocol: String, pub metadata: Vec<u8> }  // non_exhaustive
pub type Handler = Box<dyn Fn(&dyn Channel, &Accepted) + Send + Sync>;
pub fn Services::with(self, protocol: &str, handler: Handler) -> Services   // Default
pub fn Services::offers(&self, protocol: &str) -> bool
pub fn Services::tokens(&self) -> impl Iterator<Item = &str>
pub struct Options { pub limits: Limits, pub recheck: Duration }  // non_exhaustive, Default: a second
pub type Admission = Box<dyn Fn(&PeerRecord, &[u8]) -> Result<(), &'static str> + Send + Sync>;   // asked at open and while running
Services::with_admission(self, protocol: &str, handler: Handler, admission: Admission) -> Self
pub fn serve_with<'c, C: Channel>(channel: &'c C, side: Side, options: Options, first: Option<Vec<u8>>, peer: &str, host: &Host<'_>, opener: impl FnOnce(&Mux<'c, C>) + Send)
pub struct Host<'a> { pub store: &'a dyn PeerStore, pub services: &'a Services, pub events: &'a dyn Events }
pub fn serve<C: Channel>(channel: &C, side: Side, options: Options, first: Option<Vec<u8>>, peer: &str, host: &Host<'_>)
pub struct Capabilities { pub instance: String, pub offers: Vec<String> }  // non_exhaustive
pub fn capabilities<C: Channel>(mux: &Mux<'_, C>, wait: Duration) -> Result<Capabilities, Failure>
pub struct Prefilled<'a, C>;  // impl Channel; Prefilled::new(channel, first)
```

`serve` runs one handler thread per stream, so a slow service holds up nothing, up to `Limits::max_streams`. Every open is decided against `PeerStore::get`, and every running stream again each `recheck`. A store error refuses, so nothing fails open. A taken-away grant closes the stream with `CloseReason::Revoked`, whose reason reaches the peer first. Call it after the proof, and close `channel` yourself afterwards.

## `coqui_agentic_peer::peers`

```rust
pub struct PeerRecord { pub peer: String, pub claims: BTreeMap<String, String>, pub grants: BTreeSet<String> }  // non_exhaustive, Default
pub fn PeerRecord::new(peer: &str) -> PeerRecord; pub fn PeerRecord::granting(self, protocol: &str) -> PeerRecord; pub fn PeerRecord::claiming(self, name: &str, value: &str) -> PeerRecord
pub trait PeerStore: Send + Sync { fn get(&self, peer: &str) -> Result<Option<PeerRecord>, Error>; fn put(&self, record: &PeerRecord) -> Result<(), Error>; fn remove(&self, peer: &str) -> Result<(), Error>; }
pub struct MemoryPeers;                              // Default; impl PeerStore
pub fn FilePeers::new(path: impl Into<PathBuf>) -> FilePeers   // impl PeerStore; read on every question, so a grant from another process counts at once
pub enum Event { LinkUp { peer }, LinkDown { peer }, Opened { peer, protocol }, Refused { peer, protocol }, Revoked { peer, protocol } }  // non_exhaustive; no payload, never a token or metadata
pub trait Events: Send + Sync { fn event(&self, event: &Event); }
pub struct NoEvents;                                 // impl Events
```

A host keeps peers in its own registry by implementing `PeerStore`, with no file, prompt or companion involved. `claims` are set by the host and never interpreted here: derive who is speaking from them, not from anything a peer says. Only keys, peers and grants need to survive a restart.

## `coqui_agentic_peer::home`

```rust
pub const HOME_ENV: &str = "COQUI_AGENTIC_PEER_HOME";
pub fn dir() -> Option<PathBuf>                        // $COQUI_AGENTIC_PEER_HOME, or coqui-agentic-peer under %LOCALAPPDATA%, $XDG_CONFIG_HOME or ~/.config
pub const fn identity_file(method: Method) -> &'static str          // "identity" (WebCrypto), "identity-noise" (Noise)
pub const METHOD_FILE: &str = "method";                             // the home's chosen method, one line: noise or webcrypto
pub fn chosen_method() -> Result<Option<Method>, Error>
pub fn identity_path(method: Method) -> Result<PathBuf, Error>
pub fn methods() -> Result<Vec<Method>, Error>                      // the methods this user has an identity of
pub fn store_path() -> Result<PathBuf, Error>
pub fn grants_path() -> Result<PathBuf, Error>
pub fn identity(path: Option<&Path>, method: Option<Method>) -> Result<Identity, Error>   // made the first time it is needed
pub fn store(path: Option<&Path>) -> Result<TrustStore, Error>     // this user's, or at path; keys of both methods
```

One identity per method and one trust store per user is what makes one pairing serve every program and capability. `identity`: with `path`, the key there, whose type is its method, or a new one of `method` (else `Method::DEFAULT`); without, this user's identity of `method`, which the home then records in `METHOD_FILE`; with no method, the one `METHOD_FILE` records, else the one identity this user has (then recorded), else a new `Method::DEFAULT` one (then recorded), and `Error::Identity` only for a home from before the record that holds both. So the method named last is the one every later program naming none uses. A key of another method than the one named is refused, never replaced. A file that cannot be written says why: the error carries the system's own.

## `coqui_agentic_peer::auth`

```rust
pub const MAX_PROOF_MESSAGE: usize = 3072;
pub enum Method { WebCrypto, Noise }   // Copy, Eq, Hash, Display, FromStr ("webcrypto" | "noise", exactly); non_exhaustive
pub const Method::DEFAULT: Method;     // Noise: what a new identity gets when nothing names a method
pub const Method::ALL: [Method; 2];
pub const fn Method::name(self) -> &'static str
pub const fn Method::record_length(self, message: usize) -> usize   // the longest record: WebCrypto message + 17; Noise message + 38 per 65,518 bytes or part
pub fn Method::of_key(material: &KeyMaterial) -> Option<Method>

pub enum Identity { WebCrypto(coqui_peer_webcrypto::Identity), Noise(coqui_peer_noise::Identity) }   // Clone, From both; Debug shows method and id; non_exhaustive
pub fn Identity::generate(method: Method) -> Result<Identity, Error>
pub fn Identity::read(path: &Path) -> Result<Option<Identity>, Error>      // the key's type is its method
pub fn Identity::write_new(&self, path: &Path) -> Result<(), Error>       // never replaces; 0600 on Unix
pub fn Identity::open_or_create(path: &Path, method: Method) -> Result<Identity, Error>   // a key of another method there is refused
pub fn Identity::of_method(self, method: Method) -> Result<Identity, Error>
pub const fn Identity::method(&self) -> Method
pub fn Identity::peer_id(&self) -> PeerId
pub fn Identity::key_material(&self) -> KeyMaterial
pub fn read_identity(path: &Path) -> Result<Identity, Error>
pub fn create_identity(path: &Path, method: Method) -> Result<PeerId, Error>

pub enum Trust { Pinned(BTreeSet<PeerId>), Store(TrustStore) }   // Clone; Trust::pinned(ids); non_exhaustive
pub enum Proof { WebCrypto(WebCrypto), Noise(Noise) }            // Clone, From both; impl coqui_peer::Method: Handshake = ProofHandshake, Output = Session, Error = ProofError
pub fn Proof::builder(identity: Identity) -> ProofBuilder        // identity's method, neither role yet
impl ProofBuilder {                                              // Debug, not Clone; must_use
    pub fn responders(self, trust: Trust) -> ProofBuilder          // whom prove_out admits
    pub fn initiators(self, trust: Trust) -> ProofBuilder          // whom prove admits
    pub fn key_limit(self, bytes: u64) -> ProofBuilder             // WebCrypto's session limit, Noise's key limit; 2^38 by default, no floor
    pub fn rekey(self, rekey: bool) -> ProofBuilder                // Noise: on by default; WebCrypto refuses true at build, having no key change
    pub fn max_message(self, bytes: usize) -> ProofBuilder         // WebCrypto's handshake message limit; refused at build under Noise, whose messages have fixed lengths
    pub fn build(self) -> Result<Proof, Error>                     // Error::Proof for a setting the method does not have
}
pub const fn Proof::method(&self) -> Method
pub fn Proof::peer_id(&self) -> PeerId
pub fn Proof::non_defaults(&self) -> Vec<NonDefault>             // coqui_builder::NonDefault: value and default are Shown (prints `bool(false)`, `Duration(5s)`)
pub enum Session { WebCrypto(..), Noise(..) }                    // From both; method(), id(), export(label, out)
pub enum ProofError { WebCrypto(..), Noise(..) }                 // the method's own error

pub fn prove<M: coqui_peer::Method, C: Channel>(method: &M, channel: &C, limit: Duration, max_message: usize) -> Result<Established<<M::Handshake as Handshake>::Output>, Error>
pub fn prove_out<M: coqui_peer::Method, C: Channel>(method: &M, channel: &C, limit: Duration, max_message: usize) -> Result<Established<<M::Handshake as Handshake>::Output>, Error>
pub struct Sealed<'a, C>;   // impl Channel
pub fn Sealed::new(channel: &'a C, session: impl Into<Session>) -> Sealed<'a, C>   // a session of either method
pub const fn Sealed::method(&self) -> Method
pub fn Sealed::with_check(self, allowed: impl Fn() -> bool + Send + Sync + 'a) -> Sealed<'a, C>   // a check that cannot tell must say no
pub const fn Sealed::with_check_every(self, recheck: Duration) -> Sealed<'a, C>                    // a second unless set
```

An endpoint proves by one method, chosen when it is built: nothing on the wire names it and nothing negotiates it. A peer of the other method fails the handshake; the responder's `Error::OtherMethod` names both methods, from the shape of the first message (WebCrypto's is JSON, Noise's 32 bytes), and the side that connected sees only the connection end, as `Error::Channel`. A peer id is the hash of a key of one type, so only its own method proves it: store the method with the id, and never fall back on a failure.

`create_identity` never replaces a file. `prove` answers and `prove_out` connects, within `limit`, refusing a message over 3072 bytes, and set the channel's limit to `max_message` before the proof's last message goes out: size it with `Method::record_length`. `Sealed::set_max_message(n)` sets the channel's to its method's `record_length(n)`. Under Noise that is the worst case at any key limit the sender runs: 19 bytes per part of 65,518 bytes, and 19 more per part for a change of key in front of it (9,766 at 16 MiB), since a receiver cannot know the sender's limit.

## `coqui_agentic_peer::pairing`

```rust
pub fn desk() -> Result<PairingDesk, Error>   // PIN runs only
pub fn respond<C: Channel>(channel: &C, identity: &Identity, store: &TrustStore, desk: &PairingDesk, source: Option<SocketAddr>, limit: Duration) -> Result<Paired, Error>
pub fn join<C: Channel>(channel: &C, identity: &Identity, pin: Pin, store: &TrustStore, limit: Duration) -> Result<Paired, Error>
```

PIN pairing over any channel in binary frames, with the PIN shown by the responder, by `identity`'s method: a joiner of the other method fails the handshake, and the responder's error names it. The key stored names its method, so the two then connect by it. A refusal's error says which: a wrong PIN, an expired one, a mode not offered. Under Noise, a joiner that proves itself and then says nothing is sent away as expired within `limit`, or Noise's own minute if that is sooner.

## `coqui_agentic_peer::discovery`

```rust
pub const SERVICE_TYPE: &str = "_acp-agent._tcp.local.";
pub const DEFAULT_PATH: &str = "/acp";
pub const DESCRIPTORS_ENV: &str = "COQUI_ACP_DESCRIPTORS";
pub const MAX_CANDIDATES: usize = 64;
pub struct Candidate { pub label: String, pub url: String, pub peer: Option<String>, pub method: Method, pub source: Source, pub webtransport: Option<u16>, pub webtransport_hash: Option<String>, pub acp_versions: Vec<u32>, pub offers: Vec<String> }  // non_exhaustive
pub enum Source { Network, ThisMachine }  // non_exhaustive
pub fn Candidate::to_json(&self) -> Value
pub fn Advertisement::new(label: &str, tls: bool) -> Result<Advertisement, Error>
pub fn Advertisement::with_peer(self, peer: Option<String>) -> Advertisement
pub const fn Advertisement::with_method(self, method: Method) -> Advertisement   // Method::DEFAULT unless set
pub const fn Advertisement::with_webtransport(self, port: Option<u16>) -> Advertisement
pub fn Advertisement::with_webtransport_hash(self, hash: Option<String>) -> Advertisement
pub fn Advertisement::with_host(self, host: Option<String>) -> Result<Advertisement, Error>
pub fn Advertisement::with_offers(self, offers: &[String]) -> Advertisement   // a hint, at most 16; the link's own document decides
pub fn advertise(advertisement: &Advertisement, bound: SocketAddr) -> Result<Advertised, Error>   // withdrawn on drop
pub fn discover(wait: Duration) -> Vec<Candidate>                 // descriptors, then the link; a failed mDNS start leaves the descriptors; prints nothing
pub fn discover_report(wait: Duration) -> Discovery               // the same, with the directory check and why the link could not be searched
pub struct Discovery { pub candidates: Vec<Candidate>, pub directory: Option<DirectoryCheck>, pub network_error: Option<String> }   // non_exhaustive
pub fn browse(wait: Duration) -> Result<Vec<Candidate>, Error>    // the link only
pub fn read_descriptors(dir: &Path) -> Descriptors
pub struct Descriptors { pub candidates: Vec<Candidate>, pub directory: DirectoryCheck }   // non_exhaustive
pub enum DirectoryCheck { Private, SharedWithOthers, NotChecked }   // non_exhaustive; NotChecked is every non-Unix platform, where the ACLs are not read
pub fn descriptors_dir() -> Option<PathBuf>
pub fn candidate_from(record: &Record<'_>) -> Option<Candidate>
```

A record and a descriptor carry `method`, and `to_json` gives it as `"method"`. One naming no method is WebCrypto's; one naming a method this version cannot run is skipped. `candidate_from` reads an answer anyone on the link can send: it refuses this machine in any spelling, a link-local or multicast address, anything plain, no or a malformed key, and an unknown `txtvers` or `proto`, and cuts the label down, removing control and format characters. A descriptor may name only loopback, and may have no key. `read_descriptors` takes only regular files, spends at most 5 seconds, and reads nothing from a directory others can write to on Unix: it returns no candidates and `DirectoryCheck::SharedWithOthers`, the finding the application shows (a directory nobody meant to loosen). It prints nothing. On Windows it returns `NotChecked` and reads the files.

## `coqui_agentic_peer::companion`

```rust
pub const HOST_NAME: &str = "dev.boriken.coqui_acp_bridge";
pub const MAX_REQUEST: usize = 65_536;
pub const MAX_REPLY: usize = 1_048_576;
pub fn started_by_browser(first_argument: &str) -> bool
pub fn read_message(input: &mut impl Read) -> io::Result<Option<Vec<u8>>>
pub fn write_message(output: &mut impl Write, message: &[u8]) -> io::Result<()>
pub fn run(input: &mut impl Read, output: &mut impl Write) -> io::Result<()>
pub fn install(extensions: &[String]) -> Result<Vec<String>, Error>
pub fn uninstall() -> Result<(), Error>
```

It answers `{ "op": "discover", "seconds": N }`, at most 10 seconds, and nothing else; it carries no agent traffic.

## Errors

`coqui_agentic_peer::Error` (`#[non_exhaustive]`): `Channel(Failure)`, `Proof(String)`, `Identity(String)`, `Discovery(String)`, `OtherMethod { peer: Method, ours: Method }` (a responder seeing the other method's first message: report it as a method mismatch, never as a key to accept). A message never quotes a key file.

## Gotchas

- A frame adds 5 bytes, so the link's own limit has to be at least `max_frame + 5`. `Mux` blocks a thread: on Tokio, run it on `spawn_blocking`.
- A browser takes a self-signed certificate only for WebTransport with `serverCertificateHashes`.
- mDNS stays on the link. `discover` does not check that an answer came from the link, so anyone who can reach UDP 5353 here can send a record. A record is a claim either way.
- On Windows, the first time a program listens or joins multicast the firewall may ask, and an answer of no leaves an inbound block rule for that path. `discover` then sees agents on this machine and none on others.
- A key file's permissions are set only on Unix; elsewhere it takes its directory's. Nothing checks them on reading.

## `forward`

`tcp/1`: one TCP connection per stream, in either direction. The widest capability there is, so a peer needs `tcp/1` and a grant naming the target exactly, with no wildcards. A refusal happens before anything connects, and removing either grant ends running streams within `Options::recheck`.

```rust
pub const TCP_PROTOCOL: &str = "tcp/1";
pub struct Target;                                    // FromStr, Display: HOST:PORT in one spelling; "localhost:80" is not "127.0.0.1:80"
Target::grant_token(&self) -> String                  // "tcp/1:HOST:PORT"
Target::from_grant_token(token: &str) -> Option<Target>
pub fn grant(record: PeerRecord, target: &Target) -> PeerRecord
pub fn serving(services: Services) -> Services        // adds tcp/1
pub fn connect<'c, C: Channel>(mux: &Mux<'c, C>, target: &Target) -> Result<Stream<'c, C>, Failure>
pub fn pump<S: LinkStream + ?Sized>(stream: &S, connection: &TcpStream)   // until both directions end; FIN maps to finish
pub fn listen<C: Channel>(mux: &Mux<'_, C>, listener: &TcpListener, target: &Target) -> io::Result<()>   // until the link ends
pub fn is_loopback(address: IpAddr) -> bool
```

A stream ended any way but in order resets the connection, so a cut-short transfer does not read as finished. `Sealed::send` answering `NoProgress` means that message was not taken: send it again.

Gotchas: whoever can connect to a `listen`er gets what this peer was granted, so bind it to loopback. `Limits::max_message` has to allow 16 KiB. A name is resolved by the side connecting, each time, so a grant on a name trusts that name's DNS.
