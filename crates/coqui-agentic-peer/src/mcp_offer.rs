//! A peer serving its own MCP tools to a program on this machine, which starts a stdio server because every agent can: `mcp-offer/1`.
//!
//! The peer opens a stream and is answered with one stdio `mcpServers` entry, which runs [`shim`]. The shim shows the token it was
//! given, and from then on the lines it carries are MCP's own, relayed to that stream. No HTTP server exists for a web page to reach,
//! and the port and its token last as long as the stream.

use std::env;
use std::io::{self, BufRead as _, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use coqui_web::Failure;
use serde_json::json;

use crate::link::{Accepted, Handler};
use crate::mux::{CloseReason, LinkStream, StreamLife};

/// The stream that offers a stdio server.
pub const OFFER_PROTOCOL: &str = "mcp-offer/1";
/// Where the shim connects.
pub const ADDRESS_VARIABLE: &str = "COQUI_MCP_OFFER_ADDRESS";
/// What the shim shows. In the environment, since another user can read a process's arguments.
pub const TOKEN_VARIABLE: &str = "COQUI_MCP_OFFER_TOKEN";
/// The server's name when the peer opens with none.
const DEFAULT_NAME: &str = "peer-tools";
const MAX_NAME: usize = 64;
/// As long as a line may be: the mux's own default for a message.
const MAX_LINE: usize = 16 * 1024 * 1024;
const TOKEN_BYTES: usize = 32;
const POLL: Duration = Duration::from_millis(50);
/// How long something that connected may take to show the token, during which nothing else is served.
const TOKEN_WAIT: Duration = Duration::from_secs(2);
/// How long a line may wait on an agent that stopped reading, or on a peer whose stream is full.
const STUCK: Duration = Duration::from_secs(30);

/// Serves `mcp-offer/1`. `command` and `args` start [`shim`], and `command` has to be absolute, as ACP says of a stdio server.
pub fn handler(command: PathBuf, args: Vec<String>) -> Handler {
    Box::new(move |stream: &dyn LinkStream, accepted: &Accepted| {
        if let Err(why) = offer(stream, &command, &args, &accepted.metadata) {
            stream.close_with(CloseReason::Refused, why);
        }
    })
}

/// A name the agent can put in front of a tool's: a peer picks it, and it goes into what the agent shows and what its model reads.
fn server_name(metadata: &[u8]) -> Result<&str, &'static str> {
    if metadata.is_empty() {
        return Ok(DEFAULT_NAME);
    }
    let valid = metadata.len() <= MAX_NAME
        && metadata
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        core::str::from_utf8(metadata).map_err(|_| "that is no name for a server")
    } else {
        Err("that is no name for a server")
    }
}

fn new_token() -> Result<String, &'static str> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    // A guessable token lets anyone on this machine in, so no randomness means no offer.
    coqui_peer_webcrypto::random()
        .fill(&mut bytes)
        .map_err(|_| "this machine has no randomness to offer that with")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn offer(
    stream: &dyn LinkStream,
    command: &std::path::Path,
    args: &[String],
    metadata: &[u8],
) -> Result<(), &'static str> {
    let name = server_name(metadata)?;
    let command = command.to_str().ok_or("this program's path is not text")?;
    let token = new_token()?;
    let refused = |_| "no local port could be opened";
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(refused)?;
    listener.set_nonblocking(true).map_err(refused)?;
    let address = listener.local_addr().map_err(refused)?;
    let entry = json!({
        "name": name,
        "command": command,
        "args": args,
        "env": [
            { "name": ADDRESS_VARIABLE, "value": address.to_string() },
            { "name": TOKEN_VARIABLE, "value": token },
        ],
    });
    if stream.send(entry.to_string().as_bytes()).is_err() {
        return Ok(());
    }
    while stream.life() == StreamLife::Open {
        match listener.accept() {
            Ok((connection, _)) => {
                if showed_token(&connection, &token) {
                    // Over when the agent ends its server, which it may start again, and the stream is still there for that.
                    relay(&connection, stream);
                }
            }
            // Nothing waiting, or a connection that failed before it was taken: either way, look again.
            Err(_) => thread::sleep(POLL),
        }
    }
    Ok(())
}

/// Reads only as far as the first line, which is all anything without the token gets to send.
fn showed_token(connection: &TcpStream, token: &str) -> bool {
    if connection.set_nonblocking(false).is_err()
        || connection.set_read_timeout(Some(TOKEN_WAIT)).is_err()
    {
        return false;
    }
    let mut shown = Vec::with_capacity(token.len() + 1);
    let mut limited = connection.take((token.len() + 1) as u64);
    if limited.read_to_end(&mut shown).is_err() {
        return false;
    }
    shown.len() == token.len() + 1
        && shown.pop() == Some(b'\n')
        && shown
            .iter()
            .zip(token.as_bytes())
            .fold(0, |differs, (a, b)| differs | (a ^ b))
            == 0
}

/// One line at a time from something that may time out between its parts, keeping what it has read.
struct Lines<R> {
    source: BufReader<R>,
    line: Vec<u8>,
}

enum NextLine {
    Line(Vec<u8>),
    Nothing,
    Ended,
    TooLong,
}

impl<R: Read> Lines<R> {
    fn new(source: R) -> Self {
        Self {
            source: BufReader::new(source),
            line: Vec::new(),
        }
    }

    fn next(&mut self) -> NextLine {
        loop {
            let available = match self.source.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return NextLine::Nothing;
                }
                Err(_) => return NextLine::Ended,
            };
            if available.is_empty() {
                return NextLine::Ended;
            }
            let (taken, complete) = match available.iter().position(|byte| *byte == b'\n') {
                Some(at) => (at + 1, true),
                None => (available.len(), false),
            };
            let room = MAX_LINE + 2;
            if self.line.len() + taken > room {
                return NextLine::TooLong;
            }
            self.line.extend_from_slice(&available[..taken]);
            self.source.consume(taken);
            if complete {
                let mut line = core::mem::take(&mut self.line);
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > MAX_LINE {
                    return NextLine::TooLong;
                }
                return NextLine::Line(line);
            }
        }
    }
}

/// Lines both ways until the connection or the stream ends. A message is one line, so one with a line break in it would forge another.
fn relay(connection: &TcpStream, stream: &dyn LinkStream) {
    if connection.set_read_timeout(Some(POLL)).is_err()
        || connection.set_write_timeout(Some(STUCK)).is_err()
    {
        return;
    }
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let stop = &stop;
        scope.spawn(move || {
            let mut lines = Lines::new(connection);
            while !stop.load(Ordering::SeqCst) {
                match lines.next() {
                    NextLine::Line(line) if line.is_empty() => {}
                    NextLine::Line(line) => {
                        if !deliver(stream, &line, stop) {
                            break;
                        }
                    }
                    NextLine::Nothing => {}
                    NextLine::Ended | NextLine::TooLong => break,
                }
            }
            stop.store(true, Ordering::SeqCst);
        });
        let mut writer = connection;
        while !stop.load(Ordering::SeqCst) {
            match stream.receive(Some(POLL)) {
                Ok(Some(message)) => {
                    let written = !message.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
                        && writer.write_all(&message).is_ok()
                        && writer.write_all(b"\n").is_ok();
                    if !written {
                        break;
                    }
                }
                Err(Failure::Timeout) => {}
                Ok(None) | Err(_) => break,
            }
        }
        stop.store(true, Ordering::SeqCst);
    });
    let _ = connection.shutdown(std::net::Shutdown::Both);
}

fn deliver(stream: &dyn LinkStream, line: &[u8], stop: &AtomicBool) -> bool {
    let until = Instant::now() + STUCK;
    loop {
        match stream.send(line) {
            Ok(()) => return true,
            Err(Failure::NoProgress) if Instant::now() < until && !stop.load(Ordering::SeqCst) => {
                thread::sleep(POLL);
            }
            Err(_) => return false,
        }
    }
}

/// Why the shim could not run.
#[derive(Debug)]
#[non_exhaustive]
pub enum ShimError {
    /// A variable was missing, or named somewhere other than this machine.
    Setting(&'static str),
    /// The offer could not be reached, or it ended before the shim did.
    Io(io::Error),
}

impl core::fmt::Display for ShimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Setting(why) => f.write_str(why),
            Self::Io(error) => write!(f, "the offer could not be reached: {error}"),
        }
    }
}

impl std::error::Error for ShimError {}

/// The stdio server: connects as its environment says, then carries lines between `input` and `output` until either end stops. A
/// program calls this with its standard streams, and exits when it returns.
///
/// # Errors
///
/// [`ShimError`] when the variables are missing or wrong, or the offer cannot be reached.
pub fn shim(input: impl Read + Send + 'static, output: impl Write) -> Result<(), ShimError> {
    let address = env::var(ADDRESS_VARIABLE)
        .map_err(|_| ShimError::Setting("no address in the environment"))?;
    let token =
        env::var(TOKEN_VARIABLE).map_err(|_| ShimError::Setting("no token in the environment"))?;
    shim_to(&address, &token, input, output)
}

fn shim_to(
    address: &str,
    token: &str,
    input: impl Read + Send + 'static,
    mut output: impl Write,
) -> Result<(), ShimError> {
    let address: SocketAddr = address
        .parse()
        .map_err(|_| ShimError::Setting("that is no address"))?;
    // The token would go to whoever is there, so it goes nowhere but this machine.
    if !address.ip().is_loopback() {
        return Err(ShimError::Setting("the address is not on this machine"));
    }
    let mut connection = TcpStream::connect(address).map_err(ShimError::Io)?;
    connection
        .write_all(format!("{token}\n").as_bytes())
        .map_err(ShimError::Io)?;
    let mut upstream = connection.try_clone().map_err(ShimError::Io)?;
    // On its own thread, and left behind: a read of standard input cannot be interrupted, and returning ends the program.
    thread::spawn(move || {
        let mut lines = Lines::new(input);
        loop {
            match lines.next() {
                NextLine::Line(line) => {
                    if upstream.write_all(&line).is_err() || upstream.write_all(b"\n").is_err() {
                        break;
                    }
                }
                NextLine::Nothing => {}
                NextLine::Ended | NextLine::TooLong => break,
            }
        }
        let _ = upstream.shutdown(std::net::Shutdown::Write);
    });
    let mut lines = Lines::new(&connection);
    loop {
        match lines.next() {
            NextLine::Line(line) => {
                let written = output
                    .write_all(&line)
                    .and_then(|()| output.write_all(b"\n"))
                    .and_then(|()| output.flush());
                if written.is_err() {
                    return Ok(());
                }
            }
            NextLine::Nothing => {}
            NextLine::Ended | NextLine::TooLong => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex, mpsc};

    use coqui_web::Channel;
    use serde_json::Value;

    use super::*;
    use crate::link::{Host, Options, Services, serve_with};
    use crate::mux::{Limits, Mux, Side};
    use crate::peers::{MemoryPeers, NoEvents, PeerRecord, PeerStore as _};

    const WAIT: Duration = Duration::from_secs(10);
    const PEER: &str = "sha256:peer";

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

    /// A served link, with the far side's mux handed to `body`.
    fn with_link(body: impl FnOnce(&Mux<'_, Wire>, &MemoryPeers) + Send) {
        let (near, far) = wires();
        let store = MemoryPeers::default();
        store
            .put(&PeerRecord::new(PEER).granting(OFFER_PROTOCOL))
            .unwrap();
        let services = Services::default().with(
            OFFER_PROTOCOL,
            handler(PathBuf::from("/abs/program"), vec!["mcp-shim".to_owned()]),
        );
        thread::scope(|scope| {
            let (near, store_ref, services) = (&near, &store, &services);
            scope.spawn(move || {
                let host = Host {
                    store: store_ref,
                    services,
                    events: &NoEvents,
                };
                serve_with(
                    near,
                    Side::Answered,
                    Options::default(),
                    None,
                    PEER,
                    &host,
                    |_| {},
                );
            });
            // Also when `body` panics, or the side serving would wait for ever and hide the failure.
            let _cut = CutOnDrop(near, &far);
            Mux::run(&far, Side::Dialed, Limits::default(), None, |mux| {
                body(mux, &store);
            });
        });
    }

    struct Offered {
        address: String,
        token: String,
        entry: Value,
    }

    fn read_entry<C: Channel>(stream: &crate::mux::Stream<'_, C>) -> Offered {
        let first = stream.receive(Some(WAIT)).unwrap().unwrap();
        let entry: Value = serde_json::from_slice(&first).unwrap();
        let env = entry["env"].as_array().unwrap();
        let value = |name: &str| {
            env.iter().find(|item| item["name"] == name).unwrap()["value"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        Offered {
            address: value(ADDRESS_VARIABLE),
            token: value(TOKEN_VARIABLE),
            entry,
        }
    }

    /// The next line, empty once the other side has closed. Closing with something unread can arrive as a reset.
    fn line_from(connection: &TcpStream) -> String {
        connection.set_read_timeout(Some(WAIT)).unwrap();
        let mut line = String::new();
        if let Err(error) = BufReader::new(connection).read_line(&mut line) {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ),
                "{error}"
            );
        }
        line
    }

    #[test]
    fn an_entry_is_a_stdio_server_whose_token_is_not_in_its_arguments() {
        with_link(|mux, _| {
            let stream = mux.open_with(OFFER_PROTOCOL, b"canoa-browser").unwrap();
            let offered = read_entry(&stream);
            assert_eq!(offered.entry["name"], "canoa-browser");
            assert_eq!(offered.entry["command"], "/abs/program");
            assert_eq!(offered.entry["args"], json!(["mcp-shim"]));
            assert_eq!(offered.token.len(), TOKEN_BYTES * 2);
            assert!(!offered.entry["args"].to_string().contains(&offered.token));
            let address: SocketAddr = offered.address.parse().unwrap();
            assert!(address.ip().is_loopback());
        });
    }

    #[test]
    fn lines_cross_both_ways_once_the_token_is_shown() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            assert_eq!(offered.entry["name"], DEFAULT_NAME);
            let mut shim = TcpStream::connect(&offered.address).unwrap();
            writeln!(shim, "{}", offered.token).unwrap();
            shim.write_all(b"{\"id\":1}\r\n").unwrap();
            assert_eq!(stream.receive(Some(WAIT)).unwrap().unwrap(), b"{\"id\":1}");
            stream.send(b"{\"result\":2}").unwrap();
            assert_eq!(line_from(&shim), "{\"result\":2}\n");
        });
    }

    #[test]
    fn a_wrong_token_or_an_http_request_reaches_nothing() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let mut wrong = TcpStream::connect(&offered.address).unwrap();
            writeln!(wrong, "{}", "0".repeat(TOKEN_BYTES * 2)).unwrap();
            wrong.write_all(b"{\"id\":\"wrong\"}\n").unwrap();
            assert_eq!(line_from(&wrong), "");
            let mut web = TcpStream::connect(&offered.address).unwrap();
            write!(web, "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://a.example\r\nContent-Length: 2\r\n\r\n{{}}{}", " ".repeat(TOKEN_BYTES * 2)).unwrap();
            assert_eq!(line_from(&web), "");
            let mut short = TcpStream::connect(&offered.address).unwrap();
            short.write_all(b"\n").unwrap();
            short.shutdown(std::net::Shutdown::Write).unwrap();
            assert_eq!(line_from(&short), "");
            assert!(matches!(
                stream.receive(Some(Duration::from_millis(300))),
                Err(Failure::Timeout)
            ));
            // The offer itself is unharmed.
            let mut shim = TcpStream::connect(&offered.address).unwrap();
            writeln!(shim, "{}", offered.token).unwrap();
            shim.write_all(b"{\"id\":\"right\"}\n").unwrap();
            assert_eq!(
                stream.receive(Some(WAIT)).unwrap().unwrap(),
                b"{\"id\":\"right\"}"
            );
        });
    }

    #[test]
    fn an_agent_may_start_its_server_again() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            for round in 0..2 {
                let mut shim = TcpStream::connect(&offered.address).unwrap();
                writeln!(shim, "{}", offered.token).unwrap();
                writeln!(shim, "{{\"round\":{round}}}").unwrap();
                assert_eq!(
                    stream.receive(Some(WAIT)).unwrap().unwrap(),
                    format!("{{\"round\":{round}}}").as_bytes()
                );
                drop(shim);
            }
        });
    }

    #[test]
    fn a_message_with_a_line_break_cannot_forge_a_second_line() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let mut shim = TcpStream::connect(&offered.address).unwrap();
            writeln!(shim, "{}", offered.token).unwrap();
            shim.write_all(b"{}\n").unwrap();
            stream.receive(Some(WAIT)).unwrap();
            stream.send(b"{\"a\":1}\n{\"forged\":true}").unwrap();
            assert_eq!(line_from(&shim), "");
        });
    }

    #[test]
    fn the_port_goes_with_the_stream() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let mut shim = TcpStream::connect(&offered.address).unwrap();
            writeln!(shim, "{}", offered.token).unwrap();
            shim.write_all(b"{}\n").unwrap();
            stream.receive(Some(WAIT)).unwrap();
            stream.close();
            assert_eq!(line_from(&shim), "");
            let until = Instant::now() + WAIT;
            while TcpStream::connect(&offered.address).is_ok() {
                assert!(Instant::now() < until, "the port stayed open");
                thread::sleep(POLL);
            }
        });
    }

    #[test]
    fn taking_the_grant_away_closes_the_port() {
        with_link(|mux, store| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            store.remove(PEER).unwrap();
            let until = Instant::now() + WAIT;
            while TcpStream::connect(&offered.address).is_ok() {
                assert!(Instant::now() < until, "the port stayed open");
                thread::sleep(POLL);
            }
        });
    }

    #[test]
    fn a_peer_cannot_name_a_server_anything_it_likes() {
        with_link(|mux, _| {
            for name in [
                b"two words".as_slice(),
                b"new\nline",
                &[b'a'; MAX_NAME + 1],
                b"\xff",
            ] {
                let stream = mux.open_with(OFFER_PROTOCOL, name).unwrap();
                assert!(stream.receive(Some(WAIT)).is_err());
            }
        });
    }

    /// Stands in for standard input: nothing until a test has what it needs.
    struct Held(Arc<Mutex<Cursor<Vec<u8>>>>, mpsc::Receiver<()>);

    impl Read for Held {
        fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
            let _ = self.1.recv();
            self.0.lock().unwrap().read(into)
        }
    }

    #[test]
    fn the_shim_carries_lines_and_stops_when_the_offer_ends() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let (release, wait) = mpsc::channel();
            let input = Held(
                Arc::new(Mutex::new(Cursor::new(b"{\"id\":7}\n".to_vec()))),
                wait,
            );
            release.send(()).unwrap();
            let shared = Arc::new(Mutex::new(Vec::new()));
            let output = SharedOutput(Arc::clone(&shared));
            let (address, token) = (offered.address.clone(), offered.token.clone());
            let running = thread::spawn(move || shim_to(&address, &token, input, output));
            assert_eq!(stream.receive(Some(WAIT)).unwrap().unwrap(), b"{\"id\":7}");
            stream.send(b"{\"id\":8}").unwrap();
            let until = Instant::now() + WAIT;
            while shared.lock().unwrap().is_empty() {
                assert!(Instant::now() < until, "nothing came out");
                thread::sleep(POLL);
            }
            assert_eq!(*shared.lock().unwrap(), b"{\"id\":8}\n");
            stream.close();
            let until = Instant::now() + WAIT;
            while !running.is_finished() {
                assert!(Instant::now() < until, "the shim went on");
                thread::sleep(POLL);
            }
            running.join().unwrap().unwrap();
        });
    }

    struct SharedOutput(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_shim_shows_its_token_only_to_this_machine() {
        for address in ["10.0.0.1:80", "[2001:db8::1]:80", "example.com:80", ""] {
            let failed = shim_to(address, "secret", Cursor::new(Vec::new()), Vec::new());
            assert!(matches!(failed, Err(ShimError::Setting(_))), "{address}");
        }
    }

    #[test]
    fn a_line_over_the_limit_ends_it() {
        let mut lines = Lines::new(Cursor::new(vec![b'a'; MAX_LINE + 8]));
        assert!(matches!(lines.next(), NextLine::TooLong));
        let mut lines = Lines::new(Cursor::new(b"one\r\ntwo\n".to_vec()));
        assert!(matches!(lines.next(), NextLine::Line(line) if line == b"one"));
        assert!(matches!(lines.next(), NextLine::Line(line) if line == b"two"));
        assert!(matches!(lines.next(), NextLine::Ended));
    }
}
