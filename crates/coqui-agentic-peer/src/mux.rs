//! Named channels inside one link, so ACP, A2A, MCP or anything else can share one proven connection. Each stream is a
//! [`Channel`] of its own, and a reader that stops holds up only its own stream.
//!
//! The wire is in `docs/link.md`, and `vectors/mux.json` holds it as data for every language to run. Nothing here replays: a stream
//! delivers in order or fails with why, and resuming is the host's, with its own cursor in the metadata of a new stream.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use coqui_transport::{Channel, Failure};

/// One frame's kind, the first byte of a message on the link.
const OPEN: u8 = 0;
const DATA: u8 = 1;
const CREDIT: u8 = 2;
const CLOSE: u8 = 3;
const PING: u8 = 4;
const PONG: u8 = 5;
const MORE: u8 = 6;
const FINISH: u8 = 7;
/// A kind, then a stream id.
const HEADER: usize = 5;
/// How often the reader looks up to see whether the mux has ended.
const POLL: Duration = Duration::from_millis(100);
/// How long a frame the mux itself owes the peer may wait on a full link. Credit that is never delivered would stall a stream
/// for good, so past this the link is treated as gone.
const CONTROL_WAIT: Duration = Duration::from_secs(30);
/// How long one part of a message already begun may wait on a full link, since the rest of it cannot be taken back.
const PART_WAIT: Duration = Duration::from_secs(30);
/// The longest protocol token, which an `OPEN` carries.
pub const MAX_PROTOCOL: usize = 64;
/// The longest reason a `CLOSE` carries, in bytes.
pub const MAX_REASON: usize = 256;

/// Whether to notice a link that has gone silent, and how soon. Silence on a stream never ends it: only a link that answers
/// nothing, not even this, is lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Heartbeat {
    /// How often to ask. Set this under a reverse proxy's read timeout, which it also keeps from closing an idle link.
    pub interval: Duration,
    /// Intervals with nothing heard after which the link is lost.
    pub misses: u32,
}

impl Heartbeat {
    /// A heartbeat with these settings.
    #[must_use]
    pub const fn new(interval: Duration, misses: u32) -> Self {
        Self { interval, misses }
    }
}

/// What a mux will hold for its peer, which the peer cannot make it exceed, and how it behaves. Every one is a setting.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Streams open at once, in both directions together.
    pub max_streams: usize,
    /// Streams open at once speaking one protocol.
    pub max_per_protocol: usize,
    /// Bytes a peer may send on a stream ahead of what has been read. A message may overrun by its own size, so a message
    /// larger than this can still pass one at a time.
    pub window: u32,
    /// The largest message on a stream.
    pub max_message: usize,
    /// The largest part of a message in one frame, so a long message cannot hold other streams up for as long as it takes. An
    /// interrupt gets through between two parts of someone else's message.
    pub max_frame: usize,
    /// The most metadata an `OPEN` carries.
    pub max_metadata: usize,
    /// Streams the peer may have opened and nobody has accepted yet.
    pub max_pending_opens: usize,
    /// Streams the peer may open in a minute.
    pub max_opens_per_minute: u32,
    /// How long a send waits for credit before answering [`Failure::NoProgress`].
    pub send_wait: Duration,
    /// None sends nothing and notices only what the transport notices.
    pub heartbeat: Option<Heartbeat>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_streams: 32,
            max_per_protocol: 16,
            window: 1024 * 1024,
            max_message: 16 * 1024 * 1024,
            max_frame: 64 * 1024,
            max_metadata: 4096,
            max_pending_opens: 8,
            max_opens_per_minute: 600,
            send_wait: Duration::from_millis(250),
            heartbeat: None,
        }
    }
}

/// Which side of the link this is, so the two never pick the same stream id. Either side may open streams, whoever connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The side that connected: odd stream ids.
    Dialed,
    /// The side that was connected to: even stream ids.
    Answered,
}

/// Why a stream was closed, on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// In order, by whoever opened or accepted it.
    Done,
    /// Refused: nobody serves that protocol here, or this peer may not open it.
    Refused,
    /// It broke its bounds, and only it pays for that.
    Broken,
    /// A newer stream took its place.
    Superseded,
    /// The grant it ran under was taken away.
    Revoked,
}

impl CloseReason {
    const fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::Refused => 1,
            Self::Broken => 2,
            Self::Superseded => 3,
            Self::Revoked => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Done),
            1 => Some(Self::Refused),
            2 => Some(Self::Broken),
            3 => Some(Self::Superseded),
            4 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// One frame on the link, as it goes over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// Starts a stream speaking this protocol.
    Open {
        /// The stream.
        stream: u32,
        /// Its protocol token.
        protocol: String,
        /// Opaque to the link, for the side accepting it: a token, a session key or a resume cursor.
        metadata: Vec<u8>,
    },
    /// The last or only part of a message on a stream.
    Data {
        /// The stream.
        stream: u32,
        /// This part, never empty.
        body: Vec<u8>,
    },
    /// A part of a message on a stream, with more to come.
    More {
        /// The stream.
        stream: u32,
        /// This part, never empty.
        body: Vec<u8>,
    },
    /// The receiver has read this many more bytes.
    Credit {
        /// The stream.
        stream: u32,
        /// How many, never zero.
        bytes: u32,
    },
    /// This side will send nothing more on the stream, and still reads.
    Finish {
        /// The stream.
        stream: u32,
    },
    /// Ends a stream.
    Close {
        /// The stream.
        stream: u32,
        /// Why.
        reason: CloseReason,
        /// In words, for a person or a log. Possibly empty.
        text: String,
    },
    /// Is the link there?
    Ping,
    /// It is.
    Pong,
}

impl Frame {
    /// The bytes of this frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, stream, body): (u8, u32, Vec<u8>) = match self {
            Self::Open {
                stream,
                protocol,
                metadata,
            } => {
                let mut body = Vec::with_capacity(1 + protocol.len() + metadata.len());
                body.push(u8::try_from(protocol.len()).unwrap_or(u8::MAX));
                body.extend_from_slice(protocol.as_bytes());
                body.extend_from_slice(metadata);
                (OPEN, *stream, body)
            }
            Self::Data { stream, body } => (DATA, *stream, body.clone()),
            Self::More { stream, body } => (MORE, *stream, body.clone()),
            Self::Credit { stream, bytes } => (CREDIT, *stream, bytes.to_le_bytes().to_vec()),
            Self::Finish { stream } => (FINISH, *stream, Vec::new()),
            Self::Close {
                stream,
                reason,
                text,
            } => {
                let mut body = Vec::with_capacity(1 + text.len());
                body.push(reason.code());
                body.extend_from_slice(text.as_bytes());
                (CLOSE, *stream, body)
            }
            Self::Ping => (PING, 0, Vec::new()),
            Self::Pong => (PONG, 0, Vec::new()),
        };
        let mut out = Vec::with_capacity(HEADER + body.len());
        out.push(kind);
        out.extend_from_slice(&stream.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Reads a frame. Anything else is `None`, whoever sent it.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        let id: [u8; 4] = rest.get(..4)?.try_into().ok()?;
        let stream = u32::from_le_bytes(id);
        let body = rest.get(4..)?;
        match kind {
            OPEN => {
                let (&length, body) = body.split_first()?;
                let token = body.get(..usize::from(length))?;
                let protocol = core::str::from_utf8(token).ok()?;
                valid_protocol(protocol).then(|| Self::Open {
                    stream,
                    protocol: protocol.to_owned(),
                    metadata: body[usize::from(length)..].to_vec(),
                })
            }
            DATA => (!body.is_empty()).then(|| Self::Data {
                stream,
                body: body.to_vec(),
            }),
            MORE => (!body.is_empty()).then(|| Self::More {
                stream,
                body: body.to_vec(),
            }),
            CREDIT => {
                let bytes = u32::from_le_bytes(body.try_into().ok()?);
                (bytes != 0).then_some(Self::Credit { stream, bytes })
            }
            FINISH => body.is_empty().then_some(Self::Finish { stream }),
            CLOSE => {
                let (&code, text) = body.split_first()?;
                if text.len() > MAX_REASON {
                    return None;
                }
                Some(Self::Close {
                    stream,
                    reason: CloseReason::from_code(code)?,
                    text: core::str::from_utf8(text).ok()?.to_owned(),
                })
            }
            PING => (stream == 0 && body.is_empty()).then_some(Self::Ping),
            PONG => (stream == 0 && body.is_empty()).then_some(Self::Pong),
            _ => None,
        }
    }
}

/// A protocol token: `acp/1`, `a2a/1`, `mcp`. Printable ASCII with no spaces, so it can go in a DNS-SD record as it is.
#[must_use]
pub fn valid_protocol(protocol: &str) -> bool {
    !protocol.is_empty()
        && protocol.len() <= MAX_PROTOCOL
        && protocol
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',' && byte != b'=')
}

/// Whether a link's first message opens a mux, rather than being plain ACP, whose JSON starts with `{` or whitespace. Lets one
/// listener serve both, with nothing to agree first, and so through any proxy.
#[must_use]
pub fn starts_mux(first_message: &[u8]) -> bool {
    first_message.first() == Some(&OPEN)
}

/// Why a stream ended, each cause its own, so a host can tell what to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEnd {
    /// The peer closed it in order. Everything it sent has been delivered.
    PeerClosed,
    /// The peer refused it, saying why.
    Refused(String),
    /// A side broke its bounds.
    Broken,
    /// A newer stream took its place, so this one must not be reopened automatically.
    Superseded(String),
    /// The grant it ran under was taken away.
    Revoked(String),
    /// The link went. What was on its way may be lost, which the host's own cursor answers.
    LinkLost(Failure),
}

impl StreamEnd {
    /// What [`Channel`] answers for it: nothing for an orderly end, otherwise a failure.
    const fn failure(&self) -> Option<Failure> {
        match self {
            Self::PeerClosed => None,
            Self::Refused(_) | Self::Superseded(_) | Self::Revoked(_) => Some(Failure::Permission),
            Self::Broken => Some(Failure::Protocol),
            // `NoProgress` from a stream means full, try again, and that will never again be true. `end` has the cause.
            Self::LinkLost(Failure::NoProgress) => Some(Failure::PathLost),
            Self::LinkLost(failure) => Some(*failure),
        }
    }
}

#[derive(Default)]
struct StreamState {
    protocol: String,
    incoming: VecDeque<Vec<u8>>,
    /// The parts so far of a message still arriving.
    partial: Vec<u8>,
    /// What the peer has sent and this side has not read.
    held: usize,
    /// What this side may still send.
    credit: i64,
    /// The peer will send nothing more, and may still read.
    peer_finished: bool,
    finished: bool,
    ended: Option<StreamEnd>,
}

struct Waiting {
    stream: u32,
    protocol: String,
    metadata: Vec<u8>,
}

struct State {
    streams: HashMap<u32, StreamState>,
    pending: VecDeque<Waiting>,
    next_stream: u32,
    /// The highest id the peer has used: ids only go up, so a stream that has ended cannot be opened again.
    peer_stream: u32,
    link: Option<Failure>,
    ended: bool,
    /// When the link went, for a host deciding what is lost.
    down_at: Option<SystemTime>,
    opens_this_minute: u32,
    minute_began: Instant,
    last_heard: Instant,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    /// Held from choosing a stream id until its `OPEN` is sent, so opens leave in id order: a lower id after a higher one ends the
    /// peer's link. Only `open_with` takes it, and never while waiting on the state, so the reader is never held up by it.
    opening: Mutex<()>,
    limits: Limits,
    stop: AtomicBool,
    side: Side,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn opened_by_peer(&self, stream: u32) -> bool {
        (stream % 2 == 1) == (self.side == Side::Answered)
    }

    fn lost(&self, failure: Failure) {
        let mut state = self.lock();
        if state.link.is_none() {
            state.link = Some(failure);
            state.down_at = Some(SystemTime::now());
        }
        for stream in state.streams.values_mut() {
            stream.ended.get_or_insert(StreamEnd::LinkLost(failure));
        }
        drop(state);
        self.changed.notify_all();
    }
}

/// Whether a link is up, as a host deciding what is lost wants to know it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkState {
    /// Still up.
    Up,
    /// Closed in order.
    Closed,
    /// Lost, why, and when.
    Lost(Failure, SystemTime),
}

/// Channels inside one link.
pub struct Mux<'c, C: Channel> {
    channel: &'c C,
    shared: Arc<Shared>,
}

impl<C: Channel> core::fmt::Debug for Mux<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mux")
    }
}

/// A stream the peer opened, which is not served until the host says so. See [`Mux::accept`].
#[non_exhaustive]
pub struct Incoming<'c, C: Channel> {
    /// Its protocol token.
    pub protocol: String,
    /// What the peer sent with it, opaque to the link: a token, a session key, a resume cursor. It is not a credential of the
    /// link's, and nothing here keeps it.
    pub metadata: Vec<u8>,
    /// The stream. Use it to serve, or [`Stream::close_with`] to refuse.
    pub stream: Stream<'c, C>,
}

impl<C: Channel> core::fmt::Debug for Incoming<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Incoming({})", self.protocol)
    }
}

impl<'c, C: Channel> Mux<'c, C> {
    /// Runs `body` with a mux over `channel`. The link is read for as long as `body` runs, and streams end when it returns.
    /// `first`, if given, is a message already read from the channel, as when [`starts_mux`] looked at it.
    pub fn run<R>(
        channel: &'c C,
        side: Side,
        limits: Limits,
        first: Option<Vec<u8>>,
        body: impl FnOnce(&Mux<'c, C>) -> R,
    ) -> R {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                streams: HashMap::new(),
                pending: VecDeque::new(),
                next_stream: if side == Side::Dialed { 1 } else { 2 },
                peer_stream: 0,
                link: None,
                ended: false,
                down_at: None,
                opens_this_minute: 0,
                minute_began: Instant::now(),
                last_heard: Instant::now(),
            }),
            changed: Condvar::new(),
            opening: Mutex::new(()),
            limits,
            stop: AtomicBool::new(false),
            side,
        });
        let mux = Mux {
            channel,
            shared: Arc::clone(&shared),
        };
        thread::scope(|scope| {
            let reader = Reader {
                channel,
                shared: &shared,
            };
            scope.spawn(move || reader.run(first));
            if let Some(heartbeat) = limits.heartbeat {
                let shared = &shared;
                scope.spawn(move || beat(channel, shared, heartbeat));
            }
            // Also when `body` panics: otherwise the reader goes on for ever, and the scope never ends.
            let _stop = StopOnDrop(&shared);
            body(&mux)
        })
    }

    /// Opens a stream. See [`Mux::open_with`].
    ///
    /// # Errors
    ///
    /// As [`Mux::open_with`].
    pub fn open(&self, protocol: &str) -> Result<Stream<'c, C>, Failure> {
        self.open_with(protocol, &[])
    }

    /// Opens a stream, carrying `metadata` for the side accepting it. The peer may still refuse: the stream's first receive then
    /// answers [`Failure::Permission`], and [`Stream::end`] why.
    ///
    /// # Errors
    ///
    /// [`Failure::Protocol`] for a malformed token or too much metadata, [`Failure::NoProgress`] past a limit on streams, and the
    /// link's own failure.
    pub fn open_with(&self, protocol: &str, metadata: &[u8]) -> Result<Stream<'c, C>, Failure> {
        let limits = &self.shared.limits;
        if !valid_protocol(protocol) || metadata.len() > limits.max_metadata {
            return Err(Failure::Protocol);
        }
        // The id and its `OPEN` go out together: two threads opening at once must not send the higher id first.
        let _opening = self
            .shared
            .opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stream = {
            let mut state = self.shared.lock();
            if let Some(failure) = state.link {
                return Err(failure);
            }
            let same = state
                .streams
                .values()
                .filter(|held| held.protocol == protocol)
                .count();
            if state.streams.len() >= limits.max_streams || same >= limits.max_per_protocol {
                return Err(Failure::NoProgress);
            }
            let stream = state.next_stream;
            state.next_stream = stream.checked_add(2).ok_or(Failure::NoProgress)?;
            state.streams.insert(
                stream,
                StreamState {
                    protocol: protocol.to_owned(),
                    credit: i64::from(limits.window),
                    ..StreamState::default()
                },
            );
            stream
        };
        let sent = control(
            self.channel,
            &Frame::Open {
                stream,
                protocol: protocol.to_owned(),
                metadata: metadata.to_vec(),
            },
        );
        if let Err(failure) = sent {
            // The peer never heard of it, so it must not count against the limits here. Its id is not reused, and ids may skip.
            self.shared.lock().streams.remove(&stream);
            return Err(failure);
        }
        Ok(self.handle(stream))
    }

    /// The next stream the peer opened, or `None` when the link has ended in order. It is the host's to serve or to refuse: a
    /// proof admits a peer to the link and grants it no protocol.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when none came within `timeout`, after which the mux is still usable, and the link's own failure.
    pub fn accept(&self, timeout: Option<Duration>) -> Result<Option<Incoming<'c, C>>, Failure> {
        let until = timeout.map(|limit| Instant::now() + limit);
        let mut state = self.shared.lock();
        loop {
            if let Some(waiting) = state.pending.pop_front() {
                return Ok(Some(Incoming {
                    protocol: waiting.protocol,
                    metadata: waiting.metadata,
                    stream: self.handle(waiting.stream),
                }));
            }
            if let Some(failure) = state.link {
                return Err(failure);
            }
            if state.ended {
                return Ok(None);
            }
            state = wait(&self.shared.changed, state, until).ok_or(Failure::Timeout)?;
        }
    }

    /// Whether the link is up, and if not since when.
    #[must_use]
    pub fn link_state(&self) -> LinkState {
        let state = self.shared.lock();
        match (state.link, state.down_at, state.ended) {
            (Some(failure), Some(at), _) => LinkState::Lost(failure, at),
            (_, _, true) => LinkState::Closed,
            _ => LinkState::Up,
        }
    }

    fn handle(&self, id: u32) -> Stream<'c, C> {
        Stream {
            id,
            channel: self.channel,
            shared: Arc::clone(&self.shared),
            closed: AtomicBool::new(false),
        }
    }
}

struct StopOnDrop<'a>(&'a Shared);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::SeqCst);
        self.0.changed.notify_all();
    }
}

/// Sends a frame the mux owes the peer, waiting out a full link, since there is no caller to hand that back to.
fn control<C: Channel>(channel: &C, frame: &Frame) -> Result<(), Failure> {
    send_within(channel, &frame.encode(), CONTROL_WAIT)
}

fn send_within<C: Channel>(channel: &C, message: &[u8], limit: Duration) -> Result<(), Failure> {
    let until = Instant::now() + limit;
    loop {
        match channel.send(message) {
            Err(Failure::NoProgress) if Instant::now() < until => {
                thread::sleep(Duration::from_millis(10))
            }
            other => return other,
        }
    }
}

fn wait<'a>(
    changed: &Condvar,
    state: MutexGuard<'a, State>,
    until: Option<Instant>,
) -> Option<MutexGuard<'a, State>> {
    match until {
        None => Some(changed.wait(state).unwrap_or_else(PoisonError::into_inner)),
        Some(until) => {
            let left = until.checked_duration_since(Instant::now())?;
            Some(
                changed
                    .wait_timeout(state, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0,
            )
        }
    }
}

/// Asks, and notices silence. Only a link with nothing at all heard for this long is lost: a stream silent for hours is fine, since
/// the other side answers this whatever its streams are doing.
fn beat<C: Channel>(channel: &C, shared: &Shared, heartbeat: Heartbeat) {
    if heartbeat.interval.is_zero() || heartbeat.misses == 0 {
        return;
    }
    let mut next = Instant::now() + heartbeat.interval;
    while !shared.stop.load(Ordering::SeqCst) {
        thread::sleep(POLL.min(heartbeat.interval));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + heartbeat.interval;
        let (heard, down) = {
            let state = shared.lock();
            (state.last_heard, state.link.is_some() || state.ended)
        };
        if down {
            return;
        }
        if heard.elapsed() >= heartbeat.interval.saturating_mul(heartbeat.misses) {
            return shared.lost(Failure::NoProgress);
        }
        // A full link is not silence, and the next beat asks again.
        let _ = channel.send(&Frame::Ping.encode());
    }
}

struct Reader<'a, 'c, C: Channel> {
    channel: &'c C,
    shared: &'a Shared,
}

impl<C: Channel> Reader<'_, '_, C> {
    fn run(&self, first: Option<Vec<u8>>) {
        if let Some(message) = first
            && !self.take(&message)
        {
            return self.shared.lost(Failure::Protocol);
        }
        while !self.shared.stop.load(Ordering::SeqCst) {
            match self.channel.receive(Some(POLL)) {
                Ok(Some(message)) => {
                    self.shared.lock().last_heard = Instant::now();
                    if !self.take(&message) {
                        return self.shared.lost(Failure::Protocol);
                    }
                }
                Ok(None) => return self.ended(),
                Err(Failure::Timeout) => {}
                Err(failure) => return self.shared.lost(failure),
            }
        }
    }

    fn ended(&self) {
        let mut state = self.shared.lock();
        state.ended = true;
        for stream in state.streams.values_mut() {
            stream.ended.get_or_insert(StreamEnd::PeerClosed);
        }
        drop(state);
        self.shared.changed.notify_all();
    }

    /// One frame. `false` for what breaks the link as a whole: a frame no peer may send. What one stream does wrong ends that
    /// stream only.
    fn take(&self, message: &[u8]) -> bool {
        let Some(frame) = Frame::decode(message) else {
            return false;
        };
        let mut reply = None;
        let fine = {
            let mut state = self.shared.lock();
            match frame {
                Frame::Open {
                    stream,
                    protocol,
                    metadata,
                } => self.opened(&mut state, stream, protocol, metadata, &mut reply),
                Frame::Data { stream, body } => {
                    Self::part(
                        &self.shared.limits,
                        &mut state,
                        stream,
                        &body,
                        true,
                        &mut reply,
                    );
                    true
                }
                Frame::More { stream, body } => {
                    Self::part(
                        &self.shared.limits,
                        &mut state,
                        stream,
                        &body,
                        false,
                        &mut reply,
                    );
                    true
                }
                Frame::Credit { stream, bytes } => {
                    if let Some(entry) = state.streams.get_mut(&stream) {
                        entry.credit = entry
                            .credit
                            .saturating_add(i64::from(bytes))
                            .min(i64::from(u32::MAX));
                    }
                    true
                }
                Frame::Finish { stream } => {
                    if let Some(entry) = state.streams.get_mut(&stream) {
                        entry.peer_finished = true;
                    }
                    true
                }
                Frame::Close {
                    stream,
                    reason,
                    text,
                } => {
                    if let Some(entry) = state.streams.get_mut(&stream) {
                        entry.ended.get_or_insert(match reason {
                            CloseReason::Done => StreamEnd::PeerClosed,
                            CloseReason::Refused => StreamEnd::Refused(text),
                            CloseReason::Broken => StreamEnd::Broken,
                            CloseReason::Superseded => StreamEnd::Superseded(text),
                            CloseReason::Revoked => StreamEnd::Revoked(text),
                        });
                    }
                    true
                }
                Frame::Ping => {
                    reply = Some(Frame::Pong);
                    true
                }
                Frame::Pong => true,
            }
        };
        self.shared.changed.notify_all();
        if let Some(frame) = reply {
            let _ = control(self.channel, &frame);
        }
        fine
    }

    fn opened(
        &self,
        state: &mut State,
        stream: u32,
        protocol: String,
        metadata: Vec<u8>,
        reply: &mut Option<Frame>,
    ) -> bool {
        // An id from the wrong side's range, or one already used, is a peer not speaking this at all.
        if !self.shared.opened_by_peer(stream) || stream <= state.peer_stream {
            return false;
        }
        state.peer_stream = stream;
        let limits = &self.shared.limits;
        if state.minute_began.elapsed() >= Duration::from_secs(60) {
            state.minute_began = Instant::now();
            state.opens_this_minute = 0;
        }
        state.opens_this_minute = state.opens_this_minute.saturating_add(1);
        let same = state
            .streams
            .values()
            .filter(|held| held.protocol == protocol)
            .count();
        if state.streams.len() >= limits.max_streams
            || same >= limits.max_per_protocol
            || state.pending.len() >= limits.max_pending_opens
            || state.opens_this_minute > limits.max_opens_per_minute
            || metadata.len() > limits.max_metadata
        {
            *reply = Some(Frame::Close {
                stream,
                reason: CloseReason::Refused,
                text: "over a limit".to_owned(),
            });
            return true;
        }
        state.streams.insert(
            stream,
            StreamState {
                protocol: protocol.clone(),
                credit: i64::from(limits.window),
                ..StreamState::default()
            },
        );
        state.pending.push_back(Waiting {
            stream,
            protocol,
            metadata,
        });
        true
    }

    fn part(
        limits: &Limits,
        state: &mut State,
        stream: u32,
        body: &[u8],
        last: bool,
        reply: &mut Option<Frame>,
    ) {
        // Data for a stream already over is what was on its way when it ended.
        let Some(entry) = state.streams.get_mut(&stream) else {
            return;
        };
        if entry.ended.is_some() {
            return;
        }
        // A sender may start a message only while it has credit, so what is held before a new message is under the window. More
        // than that is a peer ignoring credit, and it costs that stream only. So at most a window and one message are ever held.
        let window = usize::try_from(limits.window).unwrap_or(usize::MAX);
        let starting = entry.partial.is_empty();
        let whole = entry.partial.len().saturating_add(body.len());
        if whole > limits.max_message || (starting && entry.held >= window) || entry.peer_finished {
            entry.ended = Some(StreamEnd::Broken);
            entry.incoming.clear();
            entry.partial = Vec::new();
            entry.held = 0;
            *reply = Some(Frame::Close {
                stream,
                reason: CloseReason::Broken,
                text: String::new(),
            });
            return;
        }
        entry.held += body.len();
        entry.partial.extend_from_slice(body);
        if last {
            let message = core::mem::take(&mut entry.partial);
            entry.incoming.push_back(message);
        }
    }
}

/// One stream inside a link, as a [`Channel`] of its own.
pub struct Stream<'c, C: Channel> {
    id: u32,
    channel: &'c C,
    shared: Arc<Shared>,
    closed: AtomicBool,
}

impl<C: Channel> core::fmt::Debug for Stream<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Stream({})", self.id)
    }
}

/// How much of a stream is left, for a service that has to notice while it waits on something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLife {
    /// Running.
    Open,
    /// The other side closed it in order. What it sent can still be read.
    Draining,
    /// Ended any other way, here or there, or its link went. Stop at once.
    Gone,
}

/// A stream as a service sees it, whatever carries the link: it can stop sending and go on reading, and say why it ended.
pub trait LinkStream: Channel {
    /// How much of it is left.
    fn life(&self) -> StreamLife;
    /// See [`Stream::finish`].
    ///
    /// # Errors
    ///
    /// The link's own failure.
    fn finish(&self) -> Result<(), Failure>;

    /// See [`Stream::finished_by_peer`]. A carrier that cannot tell answers `false`, which is what this says unless it is
    /// overridden.
    fn finished_by_peer(&self) -> bool {
        false
    }

    /// See [`Stream::close_with`].
    fn close_with(&self, reason: CloseReason, text: &str);
}

impl<C: Channel> LinkStream for Stream<'_, C> {
    fn life(&self) -> StreamLife {
        let state = self.shared.lock();
        if state.link.is_some() {
            return StreamLife::Gone;
        }
        match state
            .streams
            .get(&self.id)
            .map(|entry| entry.ended.as_ref())
        {
            Some(None) => StreamLife::Open,
            Some(Some(StreamEnd::PeerClosed)) => StreamLife::Draining,
            _ => StreamLife::Gone,
        }
    }
    fn finish(&self) -> Result<(), Failure> {
        Stream::finish(self)
    }

    fn finished_by_peer(&self) -> bool {
        Stream::finished_by_peer(self)
    }

    fn close_with(&self, reason: CloseReason, text: &str) {
        Stream::close_with(self, reason, text);
    }
}

impl<C: Channel> Stream<'_, C> {
    /// Why it ended, once it has.
    #[must_use]
    pub fn end(&self) -> Option<StreamEnd> {
        self.shared
            .lock()
            .streams
            .get(&self.id)
            .and_then(|entry| entry.ended.clone())
    }

    /// Whether the peer said it was done sending with [`Stream::finish`]. A receive answers `None` both for that and for a stream
    /// or link closed in order, and this tells them apart: `false` after `None` means what the peer sent may be a part of what it
    /// meant to. It stays `true` once the peer's `finish` has arrived, however the stream ends after.
    #[must_use]
    pub fn finished_by_peer(&self) -> bool {
        self.shared
            .lock()
            .streams
            .get(&self.id)
            .is_some_and(|entry| entry.peer_finished)
    }

    /// Sends now or says it cannot: [`Failure::NoProgress`] means full, for a host that would rather drop a slow reader than wait.
    /// Nothing is charged.
    ///
    /// # Errors
    ///
    /// [`Failure::NoProgress`] when full, and otherwise as [`Channel::send`].
    pub fn try_send(&self, message: &[u8]) -> Result<(), Failure> {
        self.send_by(message, None)
    }

    /// Says this side will send nothing more, and goes on reading: a request answered on the same stream. The peer's receive
    /// answers `None` after what was sent, which tells a finished message from a truncated one.
    ///
    /// # Errors
    ///
    /// The link's own failure.
    pub fn finish(&self) -> Result<(), Failure> {
        {
            let mut state = self.shared.lock();
            let entry = state.streams.get_mut(&self.id).ok_or(Failure::Protocol)?;
            if let Some(end) = &entry.ended {
                return Err(end.failure().unwrap_or(Failure::PathLost));
            }
            entry.finished = true;
        }
        control(self.channel, &Frame::Finish { stream: self.id })
    }

    /// Ends it from this side, saying why: refused, superseded or revoked, so the other side knows not to simply try again.
    pub fn close_with(&self, reason: CloseReason, text: &str) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut end = text.len().min(MAX_REASON);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let tell_peer = {
            let mut state = self.shared.lock();
            let told = state
                .streams
                .get(&self.id)
                .is_some_and(|entry| entry.ended.is_none());
            state.streams.remove(&self.id);
            told
        };
        // Before telling the other side, which on a full link can take as long as the link allows.
        self.shared.changed.notify_all();
        if tell_peer {
            let _ = control(
                self.channel,
                &Frame::Close {
                    stream: self.id,
                    reason,
                    text: text[..end].to_owned(),
                },
            );
        }
    }

    fn send_by(&self, message: &[u8], until: Option<Instant>) -> Result<(), Failure> {
        if message.is_empty() || message.len() > self.shared.limits.max_message {
            return Err(Failure::Protocol);
        }
        let mut state = self.shared.lock();
        loop {
            let entry = state.streams.get_mut(&self.id).ok_or(Failure::Protocol)?;
            if let Some(end) = &entry.ended {
                return Err(end.failure().unwrap_or(Failure::PathLost));
            }
            if entry.finished {
                return Err(Failure::Protocol);
            }
            if entry.credit > 0 {
                entry.credit -= i64::try_from(message.len()).unwrap_or(i64::MAX);
                break;
            }
            let Some(until) = until else {
                return Err(Failure::NoProgress);
            };
            state = wait(&self.shared.changed, state, Some(until)).ok_or(Failure::NoProgress)?;
        }
        drop(state);
        let max_frame = self.shared.limits.max_frame.max(1);
        let mut parts = message.chunks(max_frame).peekable();
        let mut first = true;
        while let Some(part) = parts.next() {
            let frame = if parts.peek().is_some() {
                Frame::More {
                    stream: self.id,
                    body: part.to_vec(),
                }
            } else {
                Frame::Data {
                    stream: self.id,
                    body: part.to_vec(),
                }
            };
            // Only the first part can be taken back. Once a message has begun, the link has to take the rest or be lost.
            let sent = if first {
                self.channel.send(&frame.encode())
            } else {
                send_within(self.channel, &frame.encode(), PART_WAIT)
            };
            if let Err(failure) = sent {
                if first && let Some(entry) = self.shared.lock().streams.get_mut(&self.id) {
                    // Not sent, so a caller who tries again is not charged twice.
                    entry.credit = entry
                        .credit
                        .saturating_add(i64::try_from(message.len()).unwrap_or(i64::MAX));
                }
                if !first {
                    self.shared.lost(failure);
                }
                return Err(failure);
            }
            first = false;
        }
        Ok(())
    }
}

impl<C: Channel> Channel for Stream<'_, C> {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        self.send_by(message, Some(Instant::now() + self.shared.limits.send_wait))
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        let until = timeout.map(|limit| Instant::now() + limit);
        let mut state = self.shared.lock();
        loop {
            let entry = state.streams.get_mut(&self.id).ok_or(Failure::Protocol)?;
            if let Some(message) = entry.incoming.pop_front() {
                entry.held = entry.held.saturating_sub(message.len());
                drop(state);
                let bytes = u32::try_from(message.len()).unwrap_or(u32::MAX);
                // Reading frees room, so this is where credit goes back. A link that has gone reports that on the next call.
                let _ = control(
                    self.channel,
                    &Frame::Credit {
                        stream: self.id,
                        bytes,
                    },
                );
                return Ok(Some(message));
            }
            if let Some(end) = &entry.ended {
                return end.failure().map_or(Ok(None), Err);
            }
            if entry.peer_finished {
                return Ok(None);
            }
            state = wait(&self.shared.changed, state, until).ok_or(Failure::Timeout)?;
        }
    }

    fn close(&self) {
        self.close_with(CloseReason::Done, "");
    }
}

impl<C: Channel> Drop for Stream<'_, C> {
    fn drop(&mut self) {
        Channel::close(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{Receiver, Sender, channel as queue};

    /// Two ends of a link in memory, which can be told to refuse to carry anything for a while.
    struct Wire {
        out: Sender<Vec<u8>>,
        incoming: Mutex<Receiver<Vec<u8>>>,
        full: AtomicBool,
    }

    fn wires() -> (Wire, Wire) {
        let (a_out, b_in) = queue();
        let (b_out, a_in) = queue();
        let wire = |out, incoming| Wire {
            out,
            incoming: Mutex::new(incoming),
            full: AtomicBool::new(false),
        };
        (wire(a_out, a_in), wire(b_out, b_in))
    }

    impl Channel for Wire {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            if self.full.load(Ordering::SeqCst) {
                return Err(Failure::NoProgress);
            }
            self.out
                .send(message.to_vec())
                .map_err(|_| Failure::PathLost)
        }

        fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            let incoming = self.incoming.lock().unwrap();
            match incoming.recv_timeout(timeout.unwrap_or(Duration::from_secs(5))) {
                Ok(message) => Ok(Some(message)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Failure::Timeout),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            }
        }

        fn close(&self) {}
    }

    const WAIT: Option<Duration> = Some(Duration::from_secs(5));

    /// Runs both ends at once.
    fn both(
        limits: Limits,
        dialed: impl FnOnce(&Mux<'_, Wire>) + Send,
        answered: impl FnOnce(&Mux<'_, Wire>) + Send,
    ) {
        let (a, b) = wires();
        thread::scope(|scope| {
            scope.spawn(|| Mux::run(&a, Side::Dialed, limits, None, dialed));
            Mux::run(&b, Side::Answered, limits, None, answered);
        });
    }

    fn accepted<'c>(mux: &Mux<'c, Wire>) -> Incoming<'c, Wire> {
        mux.accept(WAIT).unwrap().unwrap()
    }

    #[test]
    fn two_protocols_run_at_once_each_on_its_own_stream() {
        both(
            Limits::default(),
            |mux| {
                let acp = mux.open("acp/1").unwrap();
                let mcp = mux.open("mcp").unwrap();
                acp.send(b"to acp").unwrap();
                mcp.send(b"to mcp").unwrap();
                assert_eq!(acp.receive(WAIT).unwrap().unwrap(), b"acp says");
                assert_eq!(mcp.receive(WAIT).unwrap().unwrap(), b"mcp says");
            },
            |mux| {
                let mut kept = Vec::new();
                for _ in 0..2 {
                    let incoming = accepted(mux);
                    let (expected, answer): (&[u8], &[u8]) = if incoming.protocol == "acp/1" {
                        (b"to acp", b"acp says")
                    } else {
                        (b"to mcp", b"mcp says")
                    };
                    assert_eq!(incoming.stream.receive(WAIT).unwrap().unwrap(), expected);
                    incoming.stream.send(answer).unwrap();
                    kept.push(incoming.stream);
                }
                thread::sleep(Duration::from_millis(100));
            },
        );
    }

    #[test]
    fn either_side_opens_streams_whoever_connected() {
        both(
            Limits::default(),
            |mux| {
                let incoming = accepted(mux);
                assert_eq!(incoming.protocol, "dev.boriken.ai6/tether");
                assert_eq!(
                    incoming.stream.receive(WAIT).unwrap().unwrap(),
                    b"from the side that answered"
                );
                thread::sleep(Duration::from_millis(50));
            },
            |mux| {
                let stream = mux.open("dev.boriken.ai6/tether").unwrap();
                stream.send(b"from the side that answered").unwrap();
                thread::sleep(Duration::from_millis(50));
            },
        );
    }

    #[test]
    fn metadata_reaches_the_side_accepting_and_a_refusal_says_why() {
        both(
            Limits::default(),
            |mux| {
                let stream = mux.open_with("a2a/1", b"cursor=42").unwrap();
                assert_eq!(stream.receive(WAIT), Err(Failure::Permission));
                assert_eq!(
                    stream.end(),
                    Some(StreamEnd::Refused("not for this Station".to_owned()))
                );
                assert_eq!(stream.send(b"x"), Err(Failure::Permission));
                let other = mux.open("acp/1").unwrap();
                assert_eq!(other.receive(WAIT).unwrap().unwrap(), b"still here");
            },
            |mux| {
                let incoming = accepted(mux);
                assert_eq!(incoming.metadata, b"cursor=42");
                incoming
                    .stream
                    .close_with(CloseReason::Refused, "not for this Station");
                let other = accepted(mux);
                other.stream.send(b"still here").unwrap();
                thread::sleep(Duration::from_millis(100));
            },
        );
    }

    #[test]
    fn each_end_says_its_own_cause() {
        for (reason, expected) in [
            (
                CloseReason::Superseded,
                StreamEnd::Superseded("detached".to_owned()),
            ),
            (
                CloseReason::Revoked,
                StreamEnd::Revoked("detached".to_owned()),
            ),
            (CloseReason::Broken, StreamEnd::Broken),
            (CloseReason::Done, StreamEnd::PeerClosed),
        ] {
            let wanted = expected.clone();
            both(
                Limits::default(),
                move |mux| {
                    let stream = mux.open("x").unwrap();
                    let _ = stream.receive(WAIT);
                    assert_eq!(stream.end(), Some(wanted));
                },
                move |mux| {
                    accepted(mux).stream.close_with(reason, "detached");
                    thread::sleep(Duration::from_millis(100));
                },
            );
        }
    }

    #[test]
    fn finishing_ends_one_direction_and_the_answer_still_comes_back() {
        both(
            Limits::default(),
            |mux| {
                let stream = mux.open("a2a/1").unwrap();
                stream.send(b"request").unwrap();
                stream.finish().unwrap();
                assert_eq!(
                    stream.send(b"more"),
                    Err(Failure::Protocol),
                    "this side said it was done"
                );
                assert_eq!(stream.receive(WAIT).unwrap().unwrap(), b"answer");
                assert_eq!(stream.receive(WAIT).unwrap(), None);
            },
            |mux| {
                let incoming = accepted(mux);
                assert_eq!(incoming.stream.receive(WAIT).unwrap().unwrap(), b"request");
                assert_eq!(
                    incoming.stream.receive(WAIT).unwrap(),
                    None,
                    "finished, not truncated"
                );
                incoming.stream.send(b"answer").unwrap();
                drop(incoming);
                thread::sleep(Duration::from_millis(100));
            },
        );
    }

    #[test]
    fn a_receive_ending_in_none_says_whether_the_peer_finished() {
        // Finished, then closed: the whole of what it meant to send.
        both(
            Limits::default(),
            |mux| {
                let stream = mux.open("a2a/1").unwrap();
                assert!(!stream.finished_by_peer());
                stream.send(b"request").unwrap();
                stream.finish().unwrap();
                assert_eq!(stream.receive(WAIT).unwrap().unwrap(), b"answer");
                assert_eq!(stream.receive(WAIT).unwrap(), None);
                assert!(stream.finished_by_peer());
                assert!(LinkStream::finished_by_peer(&stream));
            },
            |mux| {
                let incoming = accepted(mux);
                incoming.stream.receive(WAIT).unwrap().unwrap();
                incoming.stream.send(b"answer").unwrap();
                incoming.stream.finish().unwrap();
                thread::sleep(Duration::from_millis(100));
                drop(incoming);
                thread::sleep(Duration::from_millis(100));
            },
        );
        // Closed in order with no finish: the same `None`, and not finished.
        both(
            Limits::default(),
            |mux| {
                let stream = mux.open("a2a/1").unwrap();
                stream.send(b"request").unwrap();
                assert_eq!(stream.receive(WAIT).unwrap().unwrap(), b"partial");
                assert_eq!(stream.receive(WAIT).unwrap(), None);
                assert_eq!(stream.end(), Some(StreamEnd::PeerClosed));
                assert!(!stream.finished_by_peer());
                assert!(!LinkStream::finished_by_peer(&stream));
            },
            |mux| {
                let incoming = accepted(mux);
                incoming.stream.receive(WAIT).unwrap().unwrap();
                incoming.stream.send(b"partial").unwrap();
                drop(incoming);
                thread::sleep(Duration::from_millis(100));
            },
        );
    }

    #[test]
    fn a_link_ended_in_order_without_a_finish_is_not_finished() {
        let (a, b) = wires();
        thread::scope(|scope| {
            scope.spawn(move || {
                Mux::run(&b, Side::Answered, Limits::default(), None, |mux| {
                    let incoming = accepted(mux);
                    incoming.stream.receive(WAIT).unwrap().unwrap();
                    // Only the link ends, with no frame for the stream.
                    std::mem::forget(incoming);
                });
                drop(b);
            });
            Mux::run(&a, Side::Dialed, Limits::default(), None, |mux| {
                let stream = mux.open("a2a/1").unwrap();
                stream.send(b"request").unwrap();
                assert_eq!(stream.receive(WAIT).unwrap(), None);
                assert_eq!(stream.end(), Some(StreamEnd::PeerClosed));
                assert!(!stream.finished_by_peer());
            });
        });
    }

    /// A link whose sends take a different time each, as a busy one does, so frames sent at once can leave in any order.
    struct Jittery<'a> {
        wire: &'a Wire,
        sends: std::sync::atomic::AtomicU32,
    }

    impl Channel for Jittery<'_> {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            let turn = self.sends.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_micros(u64::from(turn * 7 % 5) * 400));
            self.wire.send(message)
        }

        fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            self.wire.receive(timeout)
        }

        fn close(&self) {
            self.wire.close();
        }
    }

    #[test]
    fn streams_opened_at_once_from_many_threads_are_opened_in_order() {
        const THREADS: usize = 12;
        for _ in 0..20 {
            let (a, b) = wires();
            let jittery = Jittery {
                wire: &a,
                sends: std::sync::atomic::AtomicU32::new(0),
            };
            let limits = Limits {
                max_pending_opens: THREADS,
                ..Limits::default()
            };
            thread::scope(|scope| {
                scope.spawn(|| {
                    Mux::run(&jittery, Side::Dialed, limits, None, |mux| {
                        let barrier = std::sync::Barrier::new(THREADS);
                        thread::scope(|opening| {
                            for _ in 0..THREADS {
                                opening.spawn(|| {
                                    barrier.wait();
                                    let stream = mux.open("a2a/1").unwrap();
                                    stream.send(b"hello").unwrap();
                                    thread::sleep(Duration::from_millis(300));
                                });
                            }
                        });
                    });
                });
                Mux::run(&b, Side::Answered, limits, None, |mux| {
                    for _ in 0..THREADS {
                        let incoming = accepted(mux);
                        assert_eq!(incoming.stream.receive(WAIT).unwrap().unwrap(), b"hello");
                    }
                    assert_eq!(mux.link_state(), LinkState::Up);
                });
            });
        }
    }

    #[test]
    fn an_open_that_cannot_be_sent_leaves_no_stream_behind() {
        let (ours, theirs) = wires();
        drop(theirs);
        Mux::run(&ours, Side::Dialed, Limits::default(), None, |mux| {
            assert_eq!(mux.open("a2a/1").err(), Some(Failure::PathLost));
            assert!(mux.shared.lock().streams.is_empty());
        });
    }

    #[test]
    fn a_long_message_arrives_whole_with_another_stream_passing_between_its_parts() {
        let limits = Limits {
            max_frame: 1024,
            window: 1024 * 1024,
            ..Limits::default()
        };
        let (a, b) = wires();
        thread::scope(|scope| {
            scope.spawn(|| {
                Mux::run(&a, Side::Dialed, limits, None, |mux| {
                    let long = mux.open("long").unwrap();
                    let interrupt = mux.open("interrupt").unwrap();
                    thread::scope(|inner| {
                        inner.spawn(|| long.send(&vec![9; 512 * 1024]).unwrap());
                        interrupt.send(b"stop").unwrap();
                    });
                    thread::sleep(Duration::from_millis(100));
                });
            });
            Mux::run(&b, Side::Answered, limits, None, |mux| {
                let first = accepted(mux);
                let second = accepted(mux);
                let (long, interrupt) = if first.protocol == "long" {
                    (first, second)
                } else {
                    (second, first)
                };
                assert_eq!(interrupt.stream.receive(WAIT).unwrap().unwrap(), b"stop");
                let message = long.stream.receive(WAIT).unwrap().unwrap();
                assert_eq!(message.len(), 512 * 1024);
                assert!(message.iter().all(|byte| *byte == 9));
            });
        });
    }

    #[test]
    fn parts_past_the_largest_message_end_the_stream_before_they_are_held() {
        let limits = Limits {
            max_message: 8,
            ..Limits::default()
        };
        let more = |size| Frame::More {
            stream: 1,
            body: vec![1; size],
        };
        against(limits, &[open(1), more(5), more(5)], |mux, _| {
            assert_eq!(accepted(mux).stream.receive(WAIT), Err(Failure::Protocol));
        });
    }

    #[test]
    fn a_stream_that_stops_reading_holds_up_only_itself() {
        let limits = Limits {
            window: 16,
            send_wait: Duration::from_millis(50),
            ..Limits::default()
        };
        both(
            limits,
            |mux| {
                let stuck = mux.open("stuck").unwrap();
                let live = mux.open("live").unwrap();
                // One message past the window goes, then the sender has no credit left.
                stuck.send(&[1; 32]).unwrap();
                assert_eq!(stuck.send(&[2; 8]), Err(Failure::NoProgress));
                assert_eq!(stuck.try_send(&[2; 8]), Err(Failure::NoProgress));
                for round in 0..100_u8 {
                    live.send(&[round; 8]).unwrap();
                    assert_eq!(live.receive(WAIT).unwrap().unwrap(), [round; 8]);
                }
            },
            |mux| {
                let stuck = accepted(mux);
                let live = accepted(mux);
                for _ in 0..100 {
                    let message = live.stream.receive(WAIT).unwrap().unwrap();
                    live.stream.send(&message).unwrap();
                }
                drop(stuck);
                thread::sleep(Duration::from_millis(100));
            },
        );
    }

    #[test]
    fn reading_gives_credit_back_and_a_retried_send_is_not_charged_twice() {
        let limits = Limits {
            window: 8,
            send_wait: Duration::from_millis(20),
            ..Limits::default()
        };
        let (a, b) = wires();
        thread::scope(|scope| {
            scope.spawn(|| {
                Mux::run(&b, Side::Answered, limits, None, |mux| {
                    let incoming = accepted(mux);
                    for _ in 0..20 {
                        assert_eq!(incoming.stream.receive(WAIT).unwrap().unwrap().len(), 8);
                    }
                    assert_eq!(incoming.stream.receive(WAIT).unwrap(), None);
                });
            });
            Mux::run(&a, Side::Dialed, limits, None, |mux| {
                let stream = mux.open("x").unwrap();
                a.full.store(true, Ordering::SeqCst);
                assert_eq!(stream.send(&[0; 8]), Err(Failure::NoProgress));
                assert_eq!(stream.send(&[0; 8]), Err(Failure::NoProgress));
                a.full.store(false, Ordering::SeqCst);
                for _ in 0..20 {
                    loop {
                        match stream.send(&[0; 8]) {
                            Ok(()) => break,
                            Err(Failure::NoProgress) => {}
                            Err(failure) => panic!("{failure:?}"),
                        }
                    }
                }
            });
        });
    }

    /// A hostile peer, by frames, against a real mux.
    fn against(limits: Limits, frames: &[Frame], check: impl FnOnce(&Mux<'_, Wire>, &Wire)) {
        let (ours, theirs) = wires();
        for frame in frames {
            theirs.out.send(frame.encode()).unwrap();
        }
        Mux::run(&ours, Side::Answered, limits, None, |mux| {
            check(mux, &theirs)
        });
    }

    fn data(stream: u32, size: usize) -> Frame {
        Frame::Data {
            stream,
            body: vec![7; size],
        }
    }

    fn open(stream: u32) -> Frame {
        Frame::Open {
            stream,
            protocol: "x".to_owned(),
            metadata: Vec::new(),
        }
    }

    fn told(theirs: &Wire) -> Frame {
        Frame::decode(
            &theirs
                .incoming
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_peer_ignoring_credit_loses_that_stream_and_not_the_link() {
        let limits = Limits {
            window: 8,
            ..Limits::default()
        };
        against(
            limits,
            &[open(1), open(3), data(1, 8), data(1, 8), data(3, 1)],
            |mux, theirs| {
                let first = accepted(mux);
                let second = accepted(mux);
                assert_eq!(second.stream.receive(WAIT).unwrap().unwrap(), [7]);
                assert_eq!(first.stream.receive(WAIT), Err(Failure::Protocol));
                assert_eq!(
                    told(theirs),
                    Frame::Close {
                        stream: 1,
                        reason: CloseReason::Broken,
                        text: String::new()
                    }
                );
            },
        );
    }

    #[test]
    fn data_after_finish_is_a_broken_stream() {
        against(
            Limits::default(),
            &[open(1), Frame::Finish { stream: 1 }, data(1, 1)],
            |mux, _| {
                let incoming = accepted(mux);
                // Read too soon, the stream has only finished, so wait for what came after that.
                let until = Instant::now() + Duration::from_secs(5);
                while incoming.stream.end().is_none() {
                    assert!(Instant::now() < until);
                    thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(incoming.stream.end(), Some(StreamEnd::Broken));
            },
        );
    }

    #[test]
    fn a_message_over_the_limit_ends_its_stream() {
        let limits = Limits {
            max_message: 8,
            ..Limits::default()
        };
        against(limits, &[open(1), data(1, 9)], |mux, _| {
            assert_eq!(accepted(mux).stream.receive(WAIT), Err(Failure::Protocol));
        });
    }

    fn refused_with(stream: u32) -> Frame {
        Frame::Close {
            stream,
            reason: CloseReason::Refused,
            text: "over a limit".to_owned(),
        }
    }

    #[test]
    fn opens_past_the_limits_are_refused_and_held_for_nobody() {
        let limits = Limits {
            max_pending_opens: 2,
            ..Limits::default()
        };
        against(limits, &[open(1), open(3), open(5)], |mux, theirs| {
            assert_eq!(told(theirs), refused_with(5));
            let _first = accepted(mux);
            let _second = accepted(mux);
            assert_eq!(
                mux.accept(Some(Duration::from_millis(50))).err(),
                Some(Failure::Timeout)
            );
        });
    }

    #[test]
    fn too_much_metadata_a_protocol_at_its_limit_and_too_many_opens_are_each_refused() {
        let heavy = Frame::Open {
            stream: 1,
            protocol: "x".to_owned(),
            metadata: vec![0; 9],
        };
        against(
            Limits {
                max_metadata: 8,
                ..Limits::default()
            },
            &[heavy],
            |_, theirs| {
                assert_eq!(told(theirs), refused_with(1));
            },
        );
        let limits = Limits {
            max_per_protocol: 1,
            ..Limits::default()
        };
        let other = Frame::Open {
            stream: 5,
            protocol: "y".to_owned(),
            metadata: Vec::new(),
        };
        against(limits, &[open(1), open(3), other], |mux, theirs| {
            assert_eq!(told(theirs), refused_with(3));
            assert_eq!(accepted(mux).protocol, "x");
            assert_eq!(accepted(mux).protocol, "y");
        });
        let limits = Limits {
            max_opens_per_minute: 1,
            ..Limits::default()
        };
        against(limits, &[open(1), open(3)], |_, theirs| {
            assert_eq!(told(theirs), refused_with(3));
        });
    }

    #[test]
    fn a_frame_no_peer_may_send_ends_the_link() {
        for frames in [
            vec![open(2)],
            vec![open(1), open(1)],
            vec![open(3), open(1)],
        ] {
            against(Limits::default(), &frames, |mux, _| {
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    match mux.accept(Some(Duration::from_millis(50))) {
                        Err(Failure::Protocol) => break,
                        Ok(Some(_)) | Err(Failure::Timeout) => {
                            assert!(Instant::now() < until, "{frames:?}")
                        }
                        other => panic!("{other:?}"),
                    }
                }
                assert!(matches!(
                    mux.link_state(),
                    LinkState::Lost(Failure::Protocol, _)
                ));
            });
        }
        let (ours, theirs) = wires();
        theirs.out.send(vec![9, 0, 0, 0, 0]).unwrap();
        Mux::run(&ours, Side::Answered, Limits::default(), None, |mux| {
            let until = Instant::now() + Duration::from_secs(5);
            while !matches!(
                mux.accept(Some(Duration::from_millis(50))),
                Err(Failure::Protocol)
            ) {
                assert!(Instant::now() < until);
            }
        });
    }

    #[test]
    fn a_closed_link_ends_the_mux_in_order() {
        let (ours, theirs) = wires();
        drop(theirs);
        Mux::run(&ours, Side::Dialed, Limits::default(), None, |mux| {
            let until = Instant::now() + Duration::from_secs(5);
            while !matches!(mux.accept(Some(Duration::from_millis(50))), Ok(None)) {
                assert!(Instant::now() < until);
            }
            assert_eq!(mux.link_state(), LinkState::Closed);
        });
    }

    #[test]
    fn a_silent_link_is_lost_by_the_heartbeat_and_a_silent_stream_is_not() {
        let limits = Limits {
            heartbeat: Some(Heartbeat::new(Duration::from_millis(200), 5)),
            ..Limits::default()
        };
        // A peer that answers: a stream silent for many intervals stays open.
        both(
            limits,
            |mux| {
                let stream = mux.open("quiet").unwrap();
                assert_eq!(
                    stream.receive(Some(Duration::from_millis(2000))),
                    Err(Failure::Timeout)
                );
                assert_eq!(stream.end(), None);
                assert_eq!(mux.link_state(), LinkState::Up);
            },
            |mux| {
                let _kept = accepted(mux);
                thread::sleep(Duration::from_millis(2200));
            },
        );
        // A peer that has gone quiet altogether: the link is lost, and every stream hears why.
        let (ours, theirs) = wires();
        Mux::run(&ours, Side::Dialed, limits, None, |mux| {
            let stream = mux.open("quiet").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            while stream.end().is_none() {
                assert!(Instant::now() < until);
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(stream.end(), Some(StreamEnd::LinkLost(Failure::NoProgress)));
            assert!(matches!(
                mux.link_state(),
                LinkState::Lost(Failure::NoProgress, _)
            ));
        });
        drop(theirs);
    }

    #[test]
    fn no_heartbeat_sends_nothing_and_a_zero_interval_turns_it_off() {
        for limits in [
            Limits::default(),
            Limits {
                heartbeat: Some(Heartbeat::new(Duration::ZERO, 3)),
                ..Limits::default()
            },
        ] {
            let (ours, theirs) = wires();
            Mux::run(&ours, Side::Dialed, limits, None, |mux| {
                thread::sleep(Duration::from_millis(200));
                assert_eq!(mux.link_state(), LinkState::Up);
            });
            assert!(theirs.incoming.lock().unwrap().try_recv().is_err());
        }
    }

    #[test]
    fn a_body_that_panics_does_not_hang_the_link() {
        let (ours, _theirs) = wires();
        let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            Mux::run(&ours, Side::Dialed, Limits::default(), None, |_| {
                panic!("the host's own bug")
            });
        }));
        assert!(result.is_err());
    }

    #[test]
    fn a_first_message_already_read_is_not_lost() {
        let (ours, theirs) = wires();
        let first = open(1).encode();
        assert!(starts_mux(&first));
        assert!(!starts_mux(b"{\"jsonrpc\":\"2.0\"}"));
        assert!(!starts_mux(b""));
        theirs.out.send(data(1, 1).encode()).unwrap();
        Mux::run(
            &ours,
            Side::Answered,
            Limits::default(),
            Some(first),
            |mux| {
                assert_eq!(accepted(mux).stream.receive(WAIT).unwrap().unwrap(), [7]);
            },
        );
    }

    #[test]
    fn the_vectors_are_the_wire() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/mux.json")).unwrap();
        let hex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        };
        for vector in vectors["frames"].as_array().unwrap() {
            let bytes = hex(vector["hex"].as_str().unwrap());
            let stream = u32::try_from(vector["stream"].as_u64().unwrap_or(0)).unwrap();
            let expected = match vector["kind"].as_str().unwrap() {
                "open" => Frame::Open {
                    stream,
                    protocol: vector["protocol"].as_str().unwrap().to_owned(),
                    metadata: hex(vector["metadata"].as_str().unwrap_or("")),
                },
                "data" => Frame::Data {
                    stream,
                    body: hex(vector["body"].as_str().unwrap()),
                },
                "more" => Frame::More {
                    stream,
                    body: hex(vector["body"].as_str().unwrap()),
                },
                "credit" => Frame::Credit {
                    stream,
                    bytes: u32::try_from(vector["bytes"].as_u64().unwrap()).unwrap(),
                },
                "finish" => Frame::Finish { stream },
                "close" => Frame::Close {
                    stream,
                    reason: match vector["reason"].as_str().unwrap() {
                        "done" => CloseReason::Done,
                        "refused" => CloseReason::Refused,
                        "superseded" => CloseReason::Superseded,
                        "revoked" => CloseReason::Revoked,
                        _ => CloseReason::Broken,
                    },
                    text: vector["text"].as_str().unwrap_or("").to_owned(),
                },
                "ping" => Frame::Ping,
                "pong" => Frame::Pong,
                other => panic!("{other}"),
            };
            assert_eq!(Frame::decode(&bytes).as_ref(), Some(&expected), "{vector}");
            assert_eq!(expected.encode(), bytes, "{vector}");
        }
        for vector in vectors["invalid"].as_array().unwrap() {
            assert_eq!(
                Frame::decode(&hex(vector["hex"].as_str().unwrap())),
                None,
                "{vector}"
            );
        }
    }

    #[test]
    fn a_protocol_token_can_go_in_a_record_as_it_is() {
        for good in ["acp/1", "a2a/1", "mcp", "tcp/1", "dev.boriken.ai6/tether"] {
            assert!(valid_protocol(good), "{good}");
        }
        for bad in ["", "a b", "a,b", "a=b", "\u{e9}", &"x".repeat(65)] {
            assert!(!valid_protocol(bad), "{bad}");
        }
    }

    proptest::proptest! {
        /// Whatever arrives, the decoder answers, and what it takes is exactly what it would send.
        #[test]
        fn the_decoder_takes_any_bytes_and_what_it_takes_encodes_back(bytes in proptest::collection::vec(0_u8..8, 0..24)) {
            if let Some(frame) = Frame::decode(&bytes) {
                proptest::prop_assert_eq!(frame.encode(), bytes);
            }
        }

        #[test]
        fn the_decoder_takes_any_bytes_at_all(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = Frame::decode(&bytes);
        }
    }
}
