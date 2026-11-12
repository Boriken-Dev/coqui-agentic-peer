//! A peer serving its own MCP tools to a program on this machine, which starts a stdio server because every agent can: `mcp-offer/1`.
//!
//! The peer opens a stream and is answered with one stdio `mcpServers` entry, which runs [`shim`]. The shim shows the token in a file
//! only this user can read, and from then on the lines it carries are MCP's own, relayed to that stream. No HTTP server exists for a
//! web page to reach, and the port and its token last as long as the stream.

use std::env;
use std::fs;
use std::io::{self, BufRead as _, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use coqui_transport::Failure;
use serde_json::json;

use crate::link::{Accepted, Handler};
use crate::mux::{CloseReason, LinkStream, StreamLife};

/// The stream that offers a stdio server.
pub const OFFER_PROTOCOL: &str = "mcp-offer/1";
/// Where the shim connects.
pub const ADDRESS_VARIABLE: &str = "COQUI_MCP_OFFER_ADDRESS";
/// The file holding what the shim shows. The entry names it and never holds the token: an agent may pass an entry's environment to
/// a program in its arguments, which another user on the machine can read.
pub const TOKEN_FILE_VARIABLE: &str = "COQUI_MCP_OFFER_TOKEN_FILE";
/// The server's name when the peer opens with none.
const DEFAULT_NAME: &str = "peer-tools";
const MAX_NAME: usize = 64;
/// As long as a line may be: the mux's own default for a message.
const MAX_LINE: usize = 16 * 1024 * 1024;
const TOKEN_BYTES: usize = 32;
const POLL: Duration = Duration::from_millis(50);
/// How long [`relay`] waits between looks at a socket with nothing to read or no room to write. The socket is non-blocking and has no
/// timeout of its own: a receive timeout can fail on Windows just as data arrives, which reads as the connection ending.
const RELAY_POLL: Duration = Duration::from_millis(5);
/// How long something that connected has to show the token, in all.
const TOKEN_WAIT: Duration = Duration::from_secs(2);
/// As many waiting to show one: past this the longest waiting goes, so nothing local can keep a real shim out by connecting.
const MAX_KNOCKING: usize = 16;
/// A token file a crash left behind goes after this, and by then its port has long gone.
const STALE: Duration = Duration::from_secs(24 * 60 * 60);
const TOKEN_SUFFIX: &str = "token";
/// How long a line may wait on an agent that stopped reading, or on a peer whose stream is full.
const STUCK: Duration = Duration::from_secs(30);

/// Serves `mcp-offer/1`. `command` and `args` start [`shim`], and `command` has to be absolute, as ACP says of a stdio server. Token
/// files go in `tokens`, which is made private to this user, so whatever the entry starts has to run as this user too.
pub fn handler(command: PathBuf, args: Vec<String>, tokens: PathBuf) -> Handler {
    Box::new(move |stream: &dyn LinkStream, accepted: &Accepted| {
        if let Err(why) = offer(stream, &command, &args, &tokens, &accepted.metadata) {
            stream.close_with(CloseReason::Refused, why);
        }
    })
}

/// A token on disk, for as long as the offer it opens.
struct TokenFile(PathBuf);

impl TokenFile {
    fn create(dir: &Path, token: &str) -> Result<Self, &'static str> {
        let refused = |_| "the token could not be stored";
        crate::discovery::create_private_dir(dir).map_err(refused)?;
        forget_stale(dir);
        let path = dir.join(format!("{}.{TOKEN_SUFFIX}", new_token()?));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(refused)?;
        let kept = Self(path);
        file.write_all(token.as_bytes()).map_err(refused)?;
        Ok(kept)
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn forget_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > STALE);
        if old
            && path
                .extension()
                .is_some_and(|extension| extension == TOKEN_SUFFIX)
        {
            let _ = fs::remove_file(path);
        }
    }
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
    command: &Path,
    args: &[String],
    tokens: &Path,
    metadata: &[u8],
) -> Result<(), &'static str> {
    let name = server_name(metadata)?;
    let command = command.to_str().ok_or("this program's path is not text")?;
    let token = new_token()?;
    let refused = |_| "no local port could be opened";
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(refused)?;
    listener.set_nonblocking(true).map_err(refused)?;
    let address = listener.local_addr().map_err(refused)?;
    let file = TokenFile::create(tokens, &token)?;
    let path = file.0.to_str().ok_or("the token's path is not text")?;
    // ACP v2 needs the type, and v1 takes it.
    let entry = json!({
        "type": "stdio",
        "name": name,
        "command": command,
        "args": args,
        "env": [
            { "name": ADDRESS_VARIABLE, "value": address.to_string() },
            { "name": TOKEN_FILE_VARIABLE, "value": path },
        ],
    });
    if stream.send(entry.to_string().as_bytes()).is_err() {
        return Ok(());
    }
    let mut knocking: Vec<Knock> = Vec::new();
    while stream.life() == StreamLife::Open {
        // All that are waiting, so however many connected first cannot put off the real one by a turn each.
        while let Ok((connection, _)) = listener.accept() {
            if connection.set_nonblocking(true).is_err() {
                continue;
            }
            if knocking.len() >= MAX_KNOCKING {
                knocking.remove(0);
            }
            knocking.push(Knock {
                connection,
                shown: Vec::with_capacity(token.len() + 1),
                since: Instant::now(),
            });
        }
        let mut shown = None;
        knocking.retain_mut(|knock| match knock.read(&token) {
            Knocked::Waiting => true,
            Knocked::Wrong => false,
            Knocked::Right => {
                if shown.is_none() {
                    shown = Some(knock.connection.try_clone());
                }
                false
            }
        });
        // Over when the agent ends its server, which it may start again, and the stream is still there for that.
        if let Some(Ok(connection)) = shown {
            relay(&connection, stream);
        }
        thread::sleep(POLL);
    }
    Ok(())
}

/// Something that connected and has not yet shown the token. One slow connection holds up nobody: each is read without waiting, and
/// has [`TOKEN_WAIT`] in all.
struct Knock {
    connection: TcpStream,
    shown: Vec<u8>,
    since: Instant,
}

enum Knocked {
    Waiting,
    Wrong,
    Right,
}

impl Knock {
    /// Reads only as far as the first line, which is all anything without the token gets to send.
    fn read(&mut self, token: &str) -> Knocked {
        let wanted = token.len() + 1;
        let mut buffer = [0_u8; 128];
        while self.shown.len() < wanted {
            let room = (wanted - self.shown.len()).min(buffer.len());
            match (&self.connection).read(&mut buffer[..room]) {
                Ok(0) => return Knocked::Wrong,
                Ok(count) => self.shown.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    return if self.since.elapsed() < TOKEN_WAIT {
                        Knocked::Waiting
                    } else {
                        Knocked::Wrong
                    };
                }
                Err(_) => return Knocked::Wrong,
            }
        }
        let same = self.shown.pop() == Some(b'\n')
            && self
                .shown
                .iter()
                .zip(token.as_bytes())
                .fold(0, |differs, (a, b)| differs | (a ^ b))
                == 0;
        if same { Knocked::Right } else { Knocked::Wrong }
    }
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
    if connection.set_nonblocking(true).is_err() {
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
                    NextLine::Nothing => thread::sleep(RELAY_POLL),
                    NextLine::Ended | NextLine::TooLong => break,
                }
            }
            stop.store(true, Ordering::SeqCst);
        });
        while !stop.load(Ordering::SeqCst) {
            match stream.receive(Some(POLL)) {
                Ok(Some(message)) => {
                    let written = !message.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
                        && write_line(connection, &message, stop);
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

/// One line to a non-blocking socket, all of it or `false`: a partial write goes on from where it stopped, and an agent that takes
/// nothing for [`STUCK`] has stopped reading.
fn write_line(mut connection: &TcpStream, message: &[u8], stop: &AtomicBool) -> bool {
    let mut line = Vec::with_capacity(message.len() + 1);
    line.extend_from_slice(message);
    line.push(b'\n');
    let mut done = 0;
    let mut moved = Instant::now();
    while done < line.len() {
        match connection.write(&line[done..]) {
            Ok(0) => return false,
            Ok(count) => {
                done += count;
                moved = Instant::now();
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if moved.elapsed() >= STUCK || stop.load(Ordering::SeqCst) {
                    return false;
                }
                thread::sleep(RELAY_POLL);
            }
            Err(_) => return false,
        }
    }
    true
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
    let file = env::var_os(TOKEN_FILE_VARIABLE)
        .ok_or(ShimError::Setting("no token file in the environment"))?;
    let token = fs::read_to_string(file).map_err(ShimError::Io)?;
    shim_to(&address, token.trim(), input, output)
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

    use coqui_transport::Channel;
    use serde_json::Value;

    use super::*;
    use crate::link::{Host, Options, Services, serve_with};
    use crate::mux::{Limits, Mux, Side};
    use crate::peers::{MemoryPeers, NoEvents, PeerRecord, PeerStore as _};

    const WAIT: Duration = Duration::from_secs(10);
    const PEER: &str = "sha256:peer";

    /// A directory of a test's own, removed with it.
    struct Tokens(PathBuf);

    impl Tokens {
        fn new() -> Self {
            static NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
            let name = format!(
                "coqui-mcp-offer-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            );
            Self(env::temp_dir().join(name))
        }
    }

    impl Drop for Tokens {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
        let tokens = Tokens::new();
        let services = Services::default().with(
            OFFER_PROTOCOL,
            handler(
                PathBuf::from("/abs/program"),
                vec!["mcp-shim".to_owned()],
                tokens.0.clone(),
            ),
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
        file: PathBuf,
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
            token: fs::read_to_string(value(TOKEN_FILE_VARIABLE)).unwrap(),
            file: PathBuf::from(value(TOKEN_FILE_VARIABLE)),
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
    fn an_entry_is_a_stdio_server_that_holds_no_token_anywhere() {
        with_link(|mux, _| {
            let stream = mux.open_with(OFFER_PROTOCOL, b"canoa-browser").unwrap();
            let offered = read_entry(&stream);
            assert_eq!(offered.entry["type"], "stdio");
            assert_eq!(offered.entry["name"], "canoa-browser");
            assert_eq!(offered.entry["command"], "/abs/program");
            assert_eq!(offered.entry["args"], json!(["mcp-shim"]));
            assert_eq!(offered.token.len(), TOKEN_BYTES * 2);
            assert!(!offered.entry.to_string().contains(&offered.token));
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
    fn a_connection_dripping_bytes_or_saying_nothing_keeps_nobody_out() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let silent: Vec<TcpStream> = (0..MAX_KNOCKING + 4)
                .map(|_| TcpStream::connect(&offered.address).unwrap())
                .collect();
            let mut dripping = TcpStream::connect(&offered.address).unwrap();
            dripping.write_all(b"0").unwrap();
            let started = Instant::now();
            let mut shim = TcpStream::connect(&offered.address).unwrap();
            writeln!(shim, "{}", offered.token).unwrap();
            shim.write_all(b"{\"id\":1}\n").unwrap();
            assert_eq!(stream.receive(Some(WAIT)).unwrap().unwrap(), b"{\"id\":1}");
            assert!(started.elapsed() < TOKEN_WAIT, "{:?}", started.elapsed());
            drop(silent);
        });
    }

    #[test]
    fn showing_it_slowly_has_a_limit_in_all() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            let mut slow = TcpStream::connect(&offered.address).unwrap();
            for byte in offered.token.as_bytes() {
                if slow.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = writeln!(slow);
            let _ = slow.write_all(b"{\"late\":true}\n");
            assert!(matches!(
                stream.receive(Some(Duration::from_millis(300))),
                Err(Failure::Timeout)
            ));
        });
    }

    #[test]
    fn the_token_file_goes_with_the_stream_and_only_this_user_can_read_it() {
        with_link(|mux, _| {
            let stream = mux.open(OFFER_PROTOCOL).unwrap();
            let offered = read_entry(&stream);
            assert!(offered.file.is_file());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = fs::metadata(&offered.file).unwrap().permissions().mode();
                assert_eq!(mode & 0o077, 0, "{mode:o}");
                let dir = fs::metadata(offered.file.parent().unwrap()).unwrap();
                assert_eq!(dir.permissions().mode() & 0o077, 0);
            }
            stream.close();
            let until = Instant::now() + WAIT;
            while offered.file.exists() {
                assert!(Instant::now() < until, "the file stayed");
                thread::sleep(POLL);
            }
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

    /// A stream with nothing behind it but two queues, to run [`relay`] alone.
    struct Queues {
        to_agent: Mutex<mpsc::Receiver<Vec<u8>>>,
        from_agent: Mutex<mpsc::Sender<Vec<u8>>>,
    }

    impl Channel for Queues {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            self.from_agent
                .lock()
                .unwrap()
                .send(message.to_vec())
                .map_err(|_| Failure::PathLost)
        }

        fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            match self
                .to_agent
                .lock()
                .unwrap()
                .recv_timeout(timeout.unwrap_or(WAIT))
            {
                Ok(message) => Ok(Some(message)),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(Failure::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            }
        }

        fn close(&self) {}
    }

    impl LinkStream for Queues {
        fn life(&self) -> StreamLife {
            StreamLife::Open
        }

        fn finish(&self) -> Result<(), Failure> {
            Ok(())
        }

        fn close_with(&self, _: CloseReason, _: &str) {}
    }

    /// `relay` on one end of a loopback connection, `body` given the other end, the queues' ends and the relay's own socket.
    fn relaying(
        body: impl FnOnce(&TcpStream, &mpsc::Sender<Vec<u8>>, &mpsc::Receiver<Vec<u8>>, &TcpStream),
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (served, _) = listener.accept().unwrap();
        let (to_agent, agent_in) = mpsc::channel();
        let (agent_out, from_agent) = mpsc::channel();
        let queues = Queues {
            to_agent: Mutex::new(agent_in),
            from_agent: Mutex::new(agent_out),
        };
        thread::scope(|scope| {
            scope.spawn(|| relay(&served, &queues));
            body(&client, &to_agent, &from_agent, &served);
            // Ends the relay, which looks at the connection and at its stream.
            let _ = client.shutdown(std::net::Shutdown::Both);
            drop(to_agent);
        });
    }

    #[test]
    fn the_relay_polls_by_looking_and_not_by_a_socket_timeout() {
        relaying(|client, _, from_agent, served| {
            (&*client).write_all(b"{\"id\":1}\n").unwrap();
            assert_eq!(from_agent.recv_timeout(WAIT).unwrap(), b"{\"id\":1}");
            // A receive timeout can fail with an error that reads as the end of the connection.
            assert_eq!(served.read_timeout().unwrap(), None);
            assert_eq!(served.write_timeout().unwrap(), None);
        });
    }

    #[test]
    fn a_line_arriving_in_pieces_with_gaps_is_one_line() {
        relaying(|client, _, from_agent, _| {
            let mut client = client;
            for piece in [&b"{\"a\":"[..], b"\"b", b"c\"", b"}\r", b"\n"] {
                client.write_all(piece).unwrap();
                client.flush().unwrap();
                thread::sleep(Duration::from_millis(120));
            }
            assert_eq!(from_agent.recv_timeout(WAIT).unwrap(), b"{\"a\":\"bc\"}");
        });
    }

    #[test]
    fn a_line_bigger_than_the_socket_takes_arrives_whole_whatever_the_reader_does() {
        relaying(|client, to_agent, _, _| {
            let message: Vec<u8> = (0..6_000_000_u32)
                .map(|at| b'a' + u8::try_from(at % 26).unwrap())
                .collect();
            to_agent.send(message.clone()).unwrap();
            to_agent.send(b"next".to_vec()).unwrap();
            // The reader starts late and takes it in small bites, so the writer meets a full socket again and again.
            thread::sleep(Duration::from_millis(300));
            client.set_read_timeout(Some(WAIT)).unwrap();
            let mut lines = BufReader::with_capacity(4096, client);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            assert_eq!(line.pop(), Some(b'\n'));
            assert!(line == message, "the line arrived whole");
            line.clear();
            lines.read_until(b'\n', &mut line).unwrap();
            assert_eq!(line, b"next\n");
        });
    }
}
