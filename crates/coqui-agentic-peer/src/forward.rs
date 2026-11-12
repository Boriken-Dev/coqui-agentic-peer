//! TCP over a link, one `tcp/1` stream per connection, in either direction since either side opens streams.
//!
//! This is the widest capability a peer can be given, so it is refused by default twice over: a peer needs the `tcp/1` grant and
//! a grant naming the target, compared exactly. A target is decided before anything connects, so a peer learns nothing about
//! what it was not granted, and again while the stream runs, so taking one away ends its connections.

use std::io::{self, Read as _, Write as _};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _,
};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use coqui_transport::{Channel, Failure};
use socket2::SockRef;

use crate::link::{Accepted, Services};
use crate::mux::{CloseReason, LinkState, LinkStream, Mux, Stream, StreamLife};
use crate::peers::PeerRecord;

/// The protocol token.
pub const TCP_PROTOCOL: &str = "tcp/1";
const GRANT_PREFIX: &str = "tcp/1:";
const MAX_HOST: usize = 253;
/// Well under a mux's default message size, which is what a host with smaller limits has to allow for.
const CHUNK: usize = 16 * 1024;
const CONNECT: Duration = Duration::from_secs(10);
const LISTEN_POLL: Duration = Duration::from_millis(50);
/// How often each direction looks at the stream, while its connection has nothing for it.
const IDLE_MIN: Duration = Duration::from_millis(1);
const IDLE_MAX: Duration = Duration::from_millis(10);
const WATCH: Duration = Duration::from_millis(50);
/// How long a connection that has stopped reading may hold what a stream that has ended in order sent.
const STALLED: Duration = Duration::from_secs(30);
const FAILED: &str = "the connection to the target failed";

/// Where a stream goes: a host and a port, in one spelling, since a grant compares exactly. `localhost:80` and `127.0.0.1:80` are
/// different targets, and a name is resolved by the side that connects, whenever it connects.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Target {
    host: String,
    port: u16,
}

/// Text that does not name a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadTarget;

impl core::fmt::Display for BadTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a target is HOST:PORT, with an IPv6 address in brackets")
    }
}

impl std::error::Error for BadTarget {}

impl FromStr for Target {
    type Err = BadTarget;

    fn from_str(text: &str) -> Result<Self, BadTarget> {
        let (host, port) = text.rsplit_once(':').ok_or(BadTarget)?;
        if !host.is_ascii() {
            return Err(BadTarget);
        }
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(BadTarget);
        }
        let port: u16 = port.parse().map_err(|_| BadTarget)?;
        if port == 0 {
            return Err(BadTarget);
        }
        let host = if let Some(inner) = host.strip_prefix('[') {
            let inner = inner.strip_suffix(']').ok_or(BadTarget)?;
            let address = inner.parse::<Ipv6Addr>().map_err(|_| BadTarget)?;
            if address.is_unspecified() {
                return Err(BadTarget);
            }
            address.to_string()
        } else {
            let allowed =
                |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_');
            if host.is_empty() || host.len() > MAX_HOST || !host.bytes().all(allowed) {
                return Err(BadTarget);
            }
            // A resolver reads `010.0.0.1`, `2130706433` and `0x7f.1` as addresses other than they look, so a grant on one could
            // reach something the person did not mean. A name is not numeric at its end, and an address is a plain dotted quad.
            let last = host.rsplit('.').next().unwrap_or(host);
            let numeric = last.bytes().all(|byte| byte.is_ascii_digit())
                || last.to_ascii_lowercase().starts_with("0x");
            if numeric {
                let address = host.parse::<Ipv4Addr>().map_err(|_| BadTarget)?;
                if address.is_unspecified() {
                    return Err(BadTarget);
                }
            }
            host.to_ascii_lowercase()
        };
        Ok(Self { host, port })
    }
}

impl core::fmt::Display for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl Target {
    /// What goes in a peer's grants so it may reach this, beside [`TCP_PROTOCOL`] itself. See [`grant`].
    #[must_use]
    pub fn grant_token(&self) -> String {
        format!("{GRANT_PREFIX}{self}")
    }

    /// The target a grant token names, if it names one.
    #[must_use]
    pub fn from_grant_token(token: &str) -> Option<Self> {
        token.strip_prefix(GRANT_PREFIX)?.parse().ok()
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        let addresses: Vec<SocketAddr> =
            (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        for address in addresses {
            match TcpStream::connect_timeout(&address, CONNECT) {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

/// `record`, now allowed to reach `target`.
#[must_use]
pub fn grant(record: PeerRecord, target: &Target) -> PeerRecord {
    record
        .granting(TCP_PROTOCOL)
        .granting(&target.grant_token())
}

fn target_of(metadata: &[u8]) -> Option<Target> {
    core::str::from_utf8(metadata).ok()?.parse().ok()
}

fn admit(record: &PeerRecord, metadata: &[u8]) -> Result<(), &'static str> {
    let target = target_of(metadata).ok_or("that is not a target")?;
    if record.grants.contains(&target.grant_token()) {
        Ok(())
    } else {
        Err("this peer may not reach that")
    }
}

fn handle(stream: &dyn LinkStream, accepted: &Accepted) {
    let Some(target) = target_of(&accepted.metadata) else {
        return;
    };
    match target.connect() {
        Ok(connection) => pump(stream, &connection),
        Err(_) => stream.close_with(CloseReason::Refused, "that target cannot be reached"),
    }
}

/// `services`, also serving `tcp/1` to the targets each peer is granted.
#[must_use]
pub fn serving(services: Services) -> Services {
    services.with_admission(TCP_PROTOCOL, Box::new(handle), Box::new(admit))
}

/// Moves bytes both ways until both have ended, then ends the connection. Each direction ends by itself, so a client that stops
/// sending still gets its answer. A stream that ends any way but in order ends the connection at once, even if the far end of the
/// connection never reads or never closes, and ends it with a reset, so what was cut short does not read as finished.
///
/// The socket is non-blocking so each direction can always notice the stream's end: Windows does not wake a blocked receive when the
/// socket is shut down, and warns that a send timeout leaves a socket in an undefined state.
pub fn pump<S: LinkStream + ?Sized>(stream: &S, connection: &TcpStream) {
    if connection.set_nonblocking(true).is_err() {
        stream.close_with(CloseReason::Refused, FAILED);
        return;
    }
    let stop = AtomicBool::new(false);
    let cut_short = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| connection_to_stream(stream, connection, &stop, &cut_short));
        stream_to_connection(stream, connection, &stop, &cut_short);
    });
    if cut_short.load(Ordering::SeqCst) {
        // What follows when this is dropped is a reset rather than a close. Without the option the worst is a clean end.
        let _ = SockRef::from(connection).set_linger(Some(Duration::ZERO));
    } else {
        let _ = connection.shutdown(Shutdown::Both);
    }
}

fn connection_to_stream<S: LinkStream + ?Sized>(
    stream: &S,
    connection: &TcpStream,
    stop: &AtomicBool,
    cut_short: &AtomicBool,
) {
    let mut reader = connection;
    let mut buffer = vec![0_u8; CHUNK];
    let mut idle = IDLE_MIN;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match stream.life() {
            StreamLife::Open => {}
            // Nothing more can be sent. The other direction is what is left.
            StreamLife::Draining => return,
            StreamLife::Gone => {
                cut_short.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
                return;
            }
        }
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = stream.finish();
                return;
            }
            Ok(read) => {
                idle = IDLE_MIN;
                if !send_all(stream, &buffer[..read], stop) {
                    cut_short.store(true, Ordering::SeqCst);
                    stop.store(true, Ordering::SeqCst);
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(idle);
                idle = (idle * 2).min(IDLE_MAX);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                stream.close_with(CloseReason::Refused, FAILED);
                cut_short.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
                return;
            }
        }
    }
}

/// `false` when it could not all go. A full window is only a wait, for as long as the stream is alive.
fn send_all<S: LinkStream + ?Sized>(stream: &S, bytes: &[u8], stop: &AtomicBool) -> bool {
    loop {
        match stream.send(bytes) {
            Ok(()) => return true,
            Err(Failure::NoProgress)
                if !stop.load(Ordering::SeqCst) && stream.life() == StreamLife::Open =>
            {
                thread::sleep(IDLE_MIN);
            }
            Err(_) => return false,
        }
    }
}

fn stream_to_connection<S: LinkStream + ?Sized>(
    stream: &S,
    connection: &TcpStream,
    stop: &AtomicBool,
    cut_short: &AtomicBool,
) {
    let mut writer = connection;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match stream.receive(Some(WATCH)) {
            Ok(Some(message)) => {
                if !write_all(stream, &mut writer, &message, stop) {
                    Channel::close(stream);
                    cut_short.store(true, Ordering::SeqCst);
                    stop.store(true, Ordering::SeqCst);
                    return;
                }
            }
            Ok(None) => {
                let _ = connection.shutdown(Shutdown::Write);
                return;
            }
            Err(Failure::Timeout) => {}
            Err(_) => {
                cut_short.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
                return;
            }
        }
    }
}

/// `false` when it could not all go. A connection that stops reading holds this only for as long as the stream is alive, and for
/// [`STALLED`] once the other side has closed in order and nothing more is coming.
fn write_all<S: LinkStream + ?Sized>(
    stream: &S,
    writer: &mut &TcpStream,
    mut bytes: &[u8],
    stop: &AtomicBool,
) -> bool {
    let mut idle = IDLE_MIN;
    let mut moved = Instant::now();
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return false,
            Ok(written) => {
                bytes = &bytes[written..];
                idle = IDLE_MIN;
                moved = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                match stream.life() {
                    StreamLife::Open => {}
                    StreamLife::Draining if moved.elapsed() < STALLED => {}
                    _ => return false,
                }
                thread::sleep(idle);
                idle = (idle * 2).min(IDLE_MAX);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Opens a stream to `target`.
///
/// # Errors
///
/// As [`Mux::open_with`]. The other side's refusal arrives on the stream, as [`crate::mux::StreamEnd::Refused`].
pub fn connect<'c, C: Channel>(
    mux: &Mux<'c, C>,
    target: &Target,
) -> Result<Stream<'c, C>, Failure> {
    mux.open_with(TCP_PROTOCOL, target.to_string().as_bytes())
}

/// Whether binding here reaches only this machine. Any other address gives everyone who can reach it what this peer was granted.
#[must_use]
pub fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

/// Maps each connection to `listener` onto a stream to `target`, until the link ends. Whoever can connect to `listener` gets what
/// this peer was granted, so it belongs on loopback; see [`is_loopback`].
///
/// # Errors
///
/// When `listener` cannot be polled.
pub fn listen<C: Channel>(
    mux: &Mux<'_, C>,
    listener: &TcpListener,
    target: &Target,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    thread::scope(|scope| {
        loop {
            if mux.link_state() != LinkState::Up {
                return Ok(());
            }
            match listener.accept() {
                Ok((connection, _)) => {
                    scope.spawn(move || {
                        if connection.set_nonblocking(false).is_err() {
                            return;
                        }
                        if let Ok(stream) = connect(mux, target) {
                            pump(&stream, &connection);
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(LISTEN_POLL)
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
                Err(error) => return Err(error),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    use super::*;
    use crate::link::{Host, Options, serve, serve_with};
    use crate::mux::{Limits, Side, StreamEnd};
    use crate::peers::{MemoryPeers, NoEvents, PeerStore as _};

    const WAIT: Duration = Duration::from_secs(10);

    /// One direction of a link in memory, which can be cut, so whichever side serves it sees the link end.
    struct Wire {
        out: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
        incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl Wire {
        fn cut(&self) {
            self.out.lock().unwrap().take();
        }
    }

    impl Channel for Wire {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            let out = self.out.lock().unwrap();
            let out = out.as_ref().ok_or(Failure::PathLost)?;
            out.send(message.to_vec()).map_err(|_| Failure::PathLost)
        }

        fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            let incoming = self.incoming.lock().unwrap();
            match incoming.recv_timeout(timeout.unwrap_or(Duration::from_secs(5))) {
                Ok(message) => Ok(Some(message)),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(Failure::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            }
        }

        fn close(&self) {}
    }

    struct CutOnDrop<'a>(&'a Wire, &'a Wire);

    impl Drop for CutOnDrop<'_> {
        fn drop(&mut self) {
            self.0.cut();
            self.1.cut();
        }
    }

    fn wires() -> (Wire, Wire) {
        let (a_out, b_in) = mpsc::channel();
        let (b_out, a_in) = mpsc::channel();
        let wire = |out, incoming| Wire {
            out: Mutex::new(Some(out)),
            incoming: Mutex::new(incoming),
        };
        (wire(a_out, a_in), wire(b_out, b_in))
    }

    /// Answers each connection with what it sent, once it stops sending, so half-close is what gets the answer.
    fn answering_server() -> (Target, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target: Target = listener.local_addr().unwrap().to_string().parse().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(mut connection) = connection else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    let mut asked = Vec::new();
                    if connection.read_to_end(&mut asked).is_ok() {
                        let _ = connection.write_all(b"you said: ");
                        let _ = connection.write_all(&asked);
                    }
                });
            }
        });
        (target, connections)
    }

    /// `body` on the dialing side of a link whose answering side serves `tcp/1` from `store`.
    fn with_link(store: &MemoryPeers, body: impl FnOnce(&Mux<'_, Wire>) + Send) {
        let (ours, theirs) = wires();
        let services = serving(Services::default());
        let options = Options {
            recheck: Duration::from_millis(20),
            ..Options::default()
        };
        thread::scope(|scope| {
            let host = Host {
                store,
                services: &services,
                events: &NoEvents,
            };
            let answered = &theirs;
            // Also when `body` panics: otherwise the scope waits on `serve` and the failure is never reported.
            let cut = CutOnDrop(&ours, &theirs);
            let serving =
                scope.spawn(move || serve(answered, Side::Answered, options, None, "peer", &host));
            Mux::run(&ours, Side::Dialed, Limits::default(), None, body);
            drop(cut);
            serving.join().unwrap();
        });
    }

    fn through(mux: &Mux<'_, Wire>, target: &Target, asked: &[u8]) -> Vec<u8> {
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = local.local_addr().unwrap();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (connection, _) = local.accept().unwrap();
                let stream = connect(mux, target).unwrap();
                pump(&stream, &connection);
            });
            let mut client = TcpStream::connect(address).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            client.write_all(asked).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            answer
        })
    }

    #[test]
    fn a_target_has_one_spelling_and_bad_ones_are_refused() {
        for (text, spelled) in [
            ("LocalHost:80", "localhost:80"),
            ("127.0.0.1:65535", "127.0.0.1:65535"),
            ("[::1]:80", "[::1]:80"),
            ("[0:0:0:0:0:0:0:1]:80", "[::1]:80"),
            ("my_host.lan:1", "my_host.lan:1"),
        ] {
            assert_eq!(text.parse::<Target>().unwrap().to_string(), spelled);
        }
        for bad in [
            "",
            "host",
            "host:",
            ":80",
            "host:0",
            "host:65536",
            "host:+80",
            "host:8 0",
            "::1:80",
            "[::1]",
            "[::1:80",
            "[nope]:80",
            "0.0.0.0:80",
            "[::]:80",
            "010.0.0.1:80",
            "0177.0.0.1:80",
            "2130706433:80",
            "0x7f.1:80",
            "127.1:80",
            "1.2.3:80",
            "a b:80",
            "a/b:80",
            "a@b:80",
            "user:pw@host:80",
            "host:80\n",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad:?}");
        }
        assert!(
            format!("{}:1", "a".repeat(MAX_HOST + 1))
                .parse::<Target>()
                .is_err()
        );
        let token = "db:5432".parse::<Target>().unwrap().grant_token();
        assert_eq!(token, "tcp/1:db:5432");
        assert_eq!(
            Target::from_grant_token(&token).unwrap().to_string(),
            "db:5432"
        );
        assert_eq!(Target::from_grant_token("acp/1"), None);
    }

    #[test]
    fn a_granted_target_is_reached_and_half_close_gets_the_answer() {
        let (target, _) = answering_server();
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        with_link(&store, |mux| {
            assert_eq!(through(mux, &target, b"hello"), b"you said: hello");
            let large = vec![7_u8; 3 * 1024 * 1024];
            let answer = through(mux, &target, &large);
            assert_eq!(
                answer.len(),
                large.len() + 10,
                "more than the window and more than a chunk"
            );
        });
    }

    #[test]
    fn nothing_connects_for_a_target_or_a_peer_without_a_grant() {
        let (target, connections) = answering_server();
        let (other, _) = answering_server();
        let refused = |stream: &Stream<'_, Wire>| {
            assert_eq!(stream.receive(Some(WAIT)), Err(Failure::Permission));
            assert!(matches!(stream.end(), Some(StreamEnd::Refused(_))));
        };
        // No record at all.
        let store = MemoryPeers::default();
        with_link(&store, |mux| refused(&connect(mux, &target).unwrap()));
        // The protocol alone reaches nothing.
        store
            .put(&PeerRecord::new("peer").granting(TCP_PROTOCOL))
            .unwrap();
        with_link(&store, |mux| refused(&connect(mux, &target).unwrap()));
        // A target's own grant without the protocol reaches nothing.
        store
            .put(&PeerRecord::new("peer").granting(&target.grant_token()))
            .unwrap();
        with_link(&store, |mux| refused(&connect(mux, &target).unwrap()));
        // Another target's grant does not cover this one, and a target it cannot read is not a target.
        store.put(&grant(PeerRecord::new("peer"), &other)).unwrap();
        with_link(&store, |mux| {
            refused(&connect(mux, &target).unwrap());
            refused(&mux.open(TCP_PROTOCOL).unwrap());
            refused(&mux.open_with(TCP_PROTOCOL, b"\xff\xfe").unwrap());
        });
        assert_eq!(
            connections.load(Ordering::SeqCst),
            0,
            "a refusal happens before anything connects"
        );
    }

    #[test]
    fn a_granted_target_that_is_not_there_says_so() {
        let free = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let target: Target = free.to_string().parse().unwrap();
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        with_link(&store, |mux| {
            let stream = connect(mux, &target).unwrap();
            assert_eq!(stream.receive(Some(WAIT)), Err(Failure::Permission));
            assert!(
                matches!(stream.end(), Some(StreamEnd::Refused(why)) if why.contains("reached"))
            );
        });
    }

    #[test]
    fn taking_a_target_away_ends_only_its_connections() {
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let held: Target = holder.local_addr().unwrap().to_string().parse().unwrap();
        let (kept, _) = answering_server();
        let store = MemoryPeers::default();
        store
            .put(&grant(grant(PeerRecord::new("peer"), &held), &kept))
            .unwrap();
        let (seen, ended) = mpsc::channel();
        let ended = Mutex::new(ended);
        let (arrived, connected) = mpsc::channel();
        let connected = Mutex::new(connected);
        thread::spawn(move || {
            let (mut connection, _) = holder.accept().unwrap();
            let _ = arrived.send(());
            connection
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            // It ends with a reset now, which is what a cut-short connection is, and well before this read's own limit.
            let mut asked = Vec::new();
            let began = Instant::now();
            let _ = connection.read_to_end(&mut asked);
            let _ = seen.send(began.elapsed() < Duration::from_secs(15));
        });
        with_link(&store, |mux| {
            let stream = connect(mux, &held).unwrap();
            stream.send(b"waiting").unwrap();
            // Taken away before this, it would be a refusal rather than a revocation.
            connected.lock().unwrap().recv_timeout(WAIT).unwrap();
            store.put(&grant(PeerRecord::new("peer"), &kept)).unwrap();
            assert_eq!(stream.receive(Some(WAIT)), Err(Failure::Permission));
            assert!(matches!(stream.end(), Some(StreamEnd::Revoked(_))));
            assert!(
                ended.lock().unwrap().recv_timeout(WAIT) == Ok(true),
                "the connection on the far side goes too"
            );
            assert_eq!(through(mux, &kept, b"still"), b"you said: still");
        });
    }

    #[test]
    fn the_side_that_answered_the_link_can_be_the_one_that_listens() {
        // It opens the stream, and the side that dialed decides, from its own store.
        let (target, _) = answering_server();
        let (dialed, answered) = wires();
        let dialers = MemoryPeers::default();
        dialers
            .put(&grant(PeerRecord::new("host"), &target))
            .unwrap();
        let answerers = MemoryPeers::default();
        let services = serving(Services::default());
        let nothing = Services::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let options = Options::default();
        thread::scope(|scope| {
            let near = Host {
                store: &dialers,
                services: &services,
                events: &NoEvents,
            };
            let far = Host {
                store: &answerers,
                services: &nothing,
                events: &NoEvents,
            };
            let (dialed, answered, listener, target) = (&dialed, &answered, &listener, &target);
            let one =
                scope.spawn(move || serve(dialed, Side::Dialed, options, None, "host", &near));
            let other = scope.spawn(move || {
                serve_with(
                    answered,
                    Side::Answered,
                    options,
                    None,
                    "dialer",
                    &far,
                    |mux| {
                        listen(mux, listener, target).unwrap();
                    },
                );
            });
            let mut client = TcpStream::connect(address).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            client.write_all(b"from the far side").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            assert_eq!(answer, b"you said: from the far side");
            dialed.cut();
            answered.cut();
            one.join().unwrap();
            other.join().unwrap();
        });
    }

    #[test]
    fn a_listener_with_no_grant_on_the_far_side_drops_the_connection() {
        let (target, connections) = answering_server();
        let store = MemoryPeers::default();
        with_link(&store, |mux| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            thread::scope(|scope| {
                scope.spawn(|| {
                    let (connection, _) = listener.accept().unwrap();
                    let stream = connect(mux, &target).unwrap();
                    pump(&stream, &connection);
                });
                let mut client = TcpStream::connect(address).unwrap();
                client.set_read_timeout(Some(WAIT)).unwrap();
                let mut answer = Vec::new();
                let _ = client.read_to_end(&mut answer);
                assert!(answer.is_empty());
            });
        });
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_reader_slower_than_a_send_can_wait_loses_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target: Target = listener.local_addr().unwrap().to_string().parse().unwrap();
        let size = 4 * 1024 * 1024;
        thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let _ = connection.write_all(&vec![1_u8; size]);
        });
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        let (ours, theirs) = wires();
        let services = serving(Services::default());
        let limits = Limits {
            send_wait: Duration::from_millis(20),
            ..Limits::default()
        };
        let options = Options {
            limits,
            ..Options::default()
        };
        thread::scope(|scope| {
            let host = Host {
                store: &store,
                services: &services,
                events: &NoEvents,
            };
            let answered = &theirs;
            let serving =
                scope.spawn(move || serve(answered, Side::Answered, options, None, "peer", &host));
            Mux::run(&ours, Side::Dialed, Limits::default(), None, |mux| {
                let stream = connect(mux, &target).unwrap();
                let mut got = 0;
                while let Ok(Some(message)) = stream.receive(Some(WAIT)) {
                    got += message.len();
                    thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(got, size);
            });
            ours.cut();
            theirs.cut();
            serving.join().unwrap();
        });
    }

    /// A target that accepts, then neither reads nor closes, as a machine gone quiet would.
    fn quiet_target() -> (Target, mpsc::Receiver<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target: Target = listener.local_addr().unwrap().to_string().parse().unwrap();
        let (holding, held) = mpsc::channel();
        thread::spawn(move || {
            if let Ok((connection, _)) = listener.accept() {
                let _ = holding.send(connection);
            }
        });
        (target, held)
    }

    /// `body` on a link it can end at will, returning how long the serving side took to come back after that.
    fn with_serving(store: &MemoryPeers, body: impl FnOnce(&Mux<'_, Wire>) + Send) -> Duration {
        let (ours, theirs) = wires();
        let services = serving(Services::default());
        let options = Options {
            recheck: Duration::from_millis(20),
            ..Options::default()
        };
        thread::scope(|scope| {
            let host = Host {
                store,
                services: &services,
                events: &NoEvents,
            };
            let answered = &theirs;
            let cut = CutOnDrop(&ours, &theirs);
            let serving =
                scope.spawn(move || serve(answered, Side::Answered, options, None, "peer", &host));
            Mux::run(&ours, Side::Dialed, Limits::default(), None, body);
            drop(cut);
            let began = Instant::now();
            serving.join().unwrap();
            began.elapsed()
        })
    }

    const PROMPTLY: Duration = Duration::from_secs(5);

    #[test]
    fn revoking_ends_a_connection_whose_target_never_closes() {
        let (target, held) = quiet_target();
        let held = Mutex::new(held);
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        let took = with_serving(&store, |mux| {
            let stream = connect(mux, &target).unwrap();
            let mut connection = held.lock().unwrap().recv_timeout(WAIT).unwrap();
            store
                .put(&PeerRecord::new("peer").granting(TCP_PROTOCOL))
                .unwrap();
            assert_eq!(stream.receive(Some(WAIT)), Err(Failure::Permission));
            connection.set_read_timeout(Some(WAIT)).unwrap();
            let mut rest = Vec::new();
            // Reset or closed: either way it ends, and well before the target gives up.
            let began = Instant::now();
            let _ = connection.read_to_end(&mut rest);
            assert!(began.elapsed() < PROMPTLY, "the connection stayed open");
        });
        assert!(took < PROMPTLY, "serve did not come back: {took:?}");
    }

    #[test]
    fn revoking_ends_a_connection_whose_target_has_stopped_reading() {
        let (target, held) = quiet_target();
        let held = Mutex::new(held);
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        let took = with_serving(&store, |mux| {
            let stream = connect(mux, &target).unwrap();
            let _connection = held.lock().unwrap().recv_timeout(WAIT).unwrap();
            // Far more than the socket buffers hold, so the writing side is stuck when the grant goes.
            let chunk = vec![1_u8; 512 * 1024];
            for _ in 0..64 {
                match stream.try_send(&chunk) {
                    Ok(()) => {}
                    Err(_) => break,
                }
                thread::sleep(Duration::from_millis(2));
            }
            store
                .put(&PeerRecord::new("peer").granting(TCP_PROTOCOL))
                .unwrap();
            let began = Instant::now();
            while stream.life() != StreamLife::Gone {
                assert!(began.elapsed() < PROMPTLY, "the revocation did not arrive");
                thread::sleep(Duration::from_millis(10));
            }
        });
        assert!(took < PROMPTLY, "serve did not come back: {took:?}");
    }

    #[test]
    fn a_link_ending_ends_a_connection_whose_target_stays_quiet() {
        let (target, held) = quiet_target();
        let held = Mutex::new(held);
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        let took = with_serving(&store, |mux| {
            let _stream = connect(mux, &target).unwrap();
            let _connection = held.lock().unwrap().recv_timeout(WAIT).unwrap();
        });
        assert!(took < PROMPTLY, "serve did not come back: {took:?}");
    }

    #[test]
    fn a_peer_closing_in_order_ends_a_connection_whose_target_stays_quiet() {
        let (target, held) = quiet_target();
        let held = Mutex::new(held);
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        with_serving(&store, |mux| {
            let stream = connect(mux, &target).unwrap();
            let mut connection = held.lock().unwrap().recv_timeout(WAIT).unwrap();
            stream.send(b"last words").unwrap();
            Channel::close(&stream);
            connection.set_read_timeout(Some(WAIT)).unwrap();
            let mut heard = Vec::new();
            let began = Instant::now();
            connection.read_to_end(&mut heard).unwrap();
            assert_eq!(heard, b"last words", "what it sent still arrives");
            assert!(began.elapsed() < PROMPTLY);
        });
    }

    #[test]
    fn a_silent_link_does_not_leave_a_connection_spinning() {
        let (target, held) = quiet_target();
        let held = Mutex::new(held);
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        let (ours, theirs) = wires();
        let services = serving(Services::default());
        let options = Options {
            limits: Limits {
                heartbeat: Some(crate::mux::Heartbeat::new(Duration::from_millis(20), 5)),
                ..Limits::default()
            },
            ..Options::default()
        };
        thread::scope(|scope| {
            let host = Host {
                store: &store,
                services: &services,
                events: &NoEvents,
            };
            let answered = &theirs;
            let cut = CutOnDrop(&ours, &theirs);
            let serving =
                scope.spawn(move || serve(answered, Side::Answered, options, None, "peer", &host));
            // Opens one stream and goes silent, with its side of the wire still connected: no pongs, nothing read.
            ours.send(
                &crate::mux::Frame::Open {
                    stream: 1,
                    protocol: TCP_PROTOCOL.to_owned(),
                    metadata: target.to_string().into_bytes(),
                }
                .encode(),
            )
            .unwrap();
            let connection = held.lock().unwrap().recv_timeout(WAIT).unwrap();
            let began = Instant::now();
            while !serving.is_finished() {
                assert!(
                    began.elapsed() < Duration::from_secs(20),
                    "serve did not come back after the link went silent"
                );
                thread::sleep(Duration::from_millis(20));
            }
            drop(connection);
            drop(cut);
        });
    }

    #[test]
    fn a_target_that_fails_midway_does_not_read_as_finished() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target: Target = listener.local_addr().unwrap().to_string().parse().unwrap();
        thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection.write_all(b"partial").unwrap();
            thread::sleep(Duration::from_millis(100));
            // A reset, as a crash or a dropped route looks.
            SockRef::from(&connection)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        });
        let store = MemoryPeers::default();
        store.put(&grant(PeerRecord::new("peer"), &target)).unwrap();
        with_link(&store, |mux| {
            let local = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = local.local_addr().unwrap();
            thread::scope(|scope| {
                scope.spawn(|| {
                    let (connection, _) = local.accept().unwrap();
                    let stream = connect(mux, &target).unwrap();
                    pump(&stream, &connection);
                });
                let mut client = TcpStream::connect(address).unwrap();
                client.set_read_timeout(Some(WAIT)).unwrap();
                let mut answer = Vec::new();
                let read = client.read_to_end(&mut answer);
                assert!(
                    read.is_err(),
                    "ended as if finished, after {:?}",
                    String::from_utf8_lossy(&answer)
                );
            });
        });
    }
}
