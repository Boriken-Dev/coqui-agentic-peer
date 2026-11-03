//! PIN pairing under each method, between two Rust sides and with coqui-peer-noise's JavaScript module as the joiner, and a
//! joiner of the other method refused.
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel as queue};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use coqui_agentic_peer::Error;
use coqui_agentic_peer::auth::{Identity, Method, Proof, Sealed, Trust, prove, prove_out};
use coqui_agentic_peer::pairing;
use coqui_peer::TrustStore;
use coqui_web::{Channel, Failure};

const SHORT: Duration = Duration::from_secs(20);

/// A link in memory.
struct Wire {
    out: Sender<Vec<u8>>,
    incoming: Mutex<Receiver<Vec<u8>>>,
}

impl Channel for Wire {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        self.out
            .send(message.to_vec())
            .map_err(|_| Failure::PathLost)
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        let incoming = self.incoming.lock().unwrap();
        match incoming.recv_timeout(timeout.unwrap_or(SHORT)) {
            Ok(message) => Ok(Some(message)),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
            Err(RecvTimeoutError::Timeout) => Err(Failure::Timeout),
        }
    }

    fn close(&self) {}
}

fn wires() -> (Wire, Wire) {
    let (a_out, b_in) = queue();
    let (b_out, a_in) = queue();
    (
        Wire {
            out: a_out,
            incoming: Mutex::new(a_in),
        },
        Wire {
            out: b_out,
            incoming: Mutex::new(b_in),
        },
    )
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "coqui-agentic-peer-pairing-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn store(&self, name: &str) -> TrustStore {
        TrustStore::open(&self.0.join(name)).unwrap()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn accepted_methods(store: &TrustStore) -> Vec<String> {
    store
        .accepted()
        .unwrap()
        .iter()
        .map(|id| store.accepted_key(id).unwrap().method)
        .collect()
}

#[test]
fn a_pin_pairs_under_each_method_and_the_pinned_link_then_proves_by_it() {
    for method in Method::ALL {
        let dir = Dir::new(method.name());
        let (server, client) = (
            Identity::generate(method).unwrap(),
            Identity::generate(method).unwrap(),
        );
        let (server_store, client_store) = (dir.store("server"), dir.store("client"));
        let desk = pairing::desk().unwrap();
        let pin = desk.show_pin().unwrap().pin;
        let (near, far) = wires();
        let (joined, responded) = thread::scope(|scope| {
            let responding =
                scope.spawn(|| pairing::respond(&far, &server, &server_store, &desk, None, SHORT));
            let joined = pairing::join(&near, &client, pin, &client_store, SHORT);
            (joined, responding.join().unwrap())
        });
        let (joined, responded) = (joined.unwrap(), responded.unwrap());
        assert_eq!(coqui_peer::KeyMaterial::id(&joined.peer), server.peer_id());
        assert_eq!(
            coqui_peer::KeyMaterial::id(&responded.peer),
            client.peer_id()
        );
        assert_eq!(accepted_methods(&server_store), [method.name()]);
        assert_eq!(accepted_methods(&client_store), [method.name()]);

        // Connecting again, each side trusts the other through its store, by the method it paired with.
        let dialing =
            Proof::new(client.clone()).with_responders(Trust::Store(client_store.clone()));
        let answering =
            Proof::new(server.clone()).with_initiators(Trust::Store(server_store.clone()));
        let (near, far) = wires();
        thread::scope(|scope| {
            let answer = scope.spawn(|| {
                let done = prove(&answering, &far, SHORT, 1 << 16).unwrap();
                let sealed = Sealed::new(&far, done.session);
                assert_eq!(sealed.receive(None).unwrap().unwrap(), b"over the link");
                done.peer
            });
            let done = prove_out(&dialing, &near, SHORT, 1 << 16).unwrap();
            assert_eq!(done.session.method(), method);
            Sealed::new(&near, done.session)
                .send(b"over the link")
                .unwrap();
            assert_eq!(answer.join().unwrap(), client.peer_id());
        });
    }
}

#[test]
fn a_joiner_of_the_other_method_is_refused_and_nobody_is_stored() {
    for (joining, responding) in [
        (Method::WebCrypto, Method::Noise),
        (Method::Noise, Method::WebCrypto),
    ] {
        let dir = Dir::new(&format!("{joining}-{responding}"));
        let (server, client) = (
            Identity::generate(responding).unwrap(),
            Identity::generate(joining).unwrap(),
        );
        let (server_store, client_store) = (dir.store("server"), dir.store("client"));
        let desk = pairing::desk().unwrap();
        let pin = desk.show_pin().unwrap().pin;
        let (near, far) = wires();
        let (joined, responded) = thread::scope(|scope| {
            let responding = scope.spawn(move || {
                let responded = pairing::respond(&far, &server, &server_store, &desk, None, SHORT);
                drop(far);
                (responded, server_store)
            });
            let joined = pairing::join(&near, &client, pin, &client_store, SHORT);
            (joined, responding.join().unwrap())
        });
        let (responded, server_store) = responded;
        let Err(Error::Proof(why)) = responded else {
            panic!("{responding} paired with {joining}: {responded:?}");
        };
        assert!(
            why.contains(&format!("the peer proves by {joining}")),
            "{why}"
        );
        assert!(joined.is_err());
        assert!(accepted_methods(&server_store).is_empty());
        assert!(accepted_methods(&client_store).is_empty());
    }
}

#[test]
fn a_silent_noise_joiner_is_sent_away_within_the_responders_limit() {
    let dir = Dir::new("silent");
    let server = Identity::generate(Method::Noise).unwrap();
    let client = Identity::generate(Method::Noise).unwrap();
    let store = dir.store("server");
    let desk = pairing::desk().unwrap();
    let _shown = desk.show_pin().unwrap();
    let (near, far) = wires();
    // The joiner proves itself, then says nothing: the responder's limit, not Noise's own minute, ends the wait.
    let limit = Duration::from_secs(2);
    let started = Instant::now();
    let responded = thread::scope(|scope| {
        let responding =
            scope.spawn(|| pairing::respond(&far, &server, &store, &desk, None, limit));
        let method = coqui_peer_noise::PairingMethod::new(match client {
            Identity::Noise(identity) => identity,
            _ => unreachable!(),
        });
        let joined = prove_out(&method, &near, SHORT, 4096).unwrap();
        let answered = responding.join().unwrap();
        drop(joined);
        answered
    });
    let took = started.elapsed();
    let Err(Error::Proof(why)) = responded else {
        panic!("a silent joiner paired: {responded:?}");
    };
    assert!(why.contains("expired"), "{why}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    // It was told: the refusal is the one record waiting on the joiner's side.
    assert!(near.incoming.lock().unwrap().try_recv().is_ok());
}

/// A child process speaking frames on its standard streams, each with a connection number, as `noise_joiner.mjs` does.
struct Frames {
    input: Mutex<ChildStdin>,
    incoming: [Mutex<Receiver<Vec<u8>>>; 2],
}

struct Connection<'a> {
    stdio: &'a Frames,
    number: u8,
}

impl Channel for Connection<'_> {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        let mut framed = u32::try_from(message.len() + 1)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        framed.push(self.number);
        framed.extend_from_slice(message);
        let mut input = self.stdio.input.lock().unwrap();
        input
            .write_all(&framed)
            .and_then(|()| input.flush())
            .map_err(|_| Failure::PathLost)
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        let incoming = self.stdio.incoming[usize::from(self.number)]
            .lock()
            .unwrap();
        match incoming.recv_timeout(timeout.unwrap_or(SHORT)) {
            Ok(message) => Ok(Some(message)),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
            Err(RecvTimeoutError::Timeout) => Err(Failure::Timeout),
        }
    }

    fn close(&self) {}
}

fn start_joiner(node: &Path, module: &Path, mode: &str) -> (Child, Arc<Frames>) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("noise_joiner.mjs");
    let mut child = Command::new(node)
        .arg(script)
        .arg(module)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    let (zero_out, zero_in) = queue();
    let (one_out, one_in) = queue();
    thread::spawn(move || {
        let outs = [zero_out, one_out];
        loop {
            let mut length = [0; 4];
            if output.read_exact(&mut length).is_err() {
                return;
            }
            let mut body = vec![0; u32::from_le_bytes(length) as usize];
            if output.read_exact(&mut body).is_err() || body.is_empty() {
                return;
            }
            let number = usize::from(body.remove(0));
            if outs.get(number).is_none_or(|out| out.send(body).is_err()) {
                return;
            }
        }
    });
    let stdio = Arc::new(Frames {
        input: Mutex::new(child.stdin.take().unwrap()),
        incoming: [Mutex::new(zero_in), Mutex::new(one_in)],
    });
    (child, stdio)
}

fn node() -> Option<PathBuf> {
    let found = std::env::var_os("COQUI_AGENTIC_PEER_TEST_NODE")
        .map_or_else(|| PathBuf::from("node"), PathBuf::from);
    let version = Command::new(&found).arg("--version").output().ok()?;
    let text = String::from_utf8(version.stdout).ok()?;
    let major: u32 = text
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()?;
    (major >= 22).then_some(found)
}

fn noise_module() -> Option<(PathBuf, PathBuf)> {
    let module = std::env::var_os("COQUI_AGENTIC_PEER_TEST_NOISE").map(PathBuf::from);
    match (node(), module) {
        (Some(node), Some(module)) if module.exists() => Some((node, module)),
        (_, module) => {
            assert!(module.is_none(), "a module was named and could not be used");
            eprintln!(
                "SKIPPED: needs Node 22 or later and COQUI_AGENTIC_PEER_TEST_NOISE naming coqui-peer-noise's bindings/js/coqui-peer-noise/src/index.mjs"
            );
            None
        }
    }
}

#[test]
fn the_javascript_module_pairs_by_pin_with_a_rust_responder_then_proves_by_noise() {
    let Some((node, module)) = noise_module() else {
        return;
    };
    let dir = Dir::new("js");
    let server = Identity::generate(Method::Noise).unwrap();
    let store = dir.store("server");
    let desk = pairing::desk().unwrap();
    let pin = desk.show_pin().unwrap().pin;
    let (mut child, stdio) = start_joiner(&node, &module, "right");
    let first = Connection {
        stdio: &stdio,
        number: 0,
    };
    first.send(pin.as_str().as_bytes()).unwrap();
    let paired = pairing::respond(&first, &server, &store, &desk, None, SHORT).unwrap();
    let joiner = coqui_peer::KeyMaterial::id(&paired.peer);
    assert_eq!(accepted_methods(&store), ["noise"]);

    let second = Connection {
        stdio: &stdio,
        number: 1,
    };
    let answering = Proof::new(server).with_initiators(Trust::Store(store));
    let done = prove(&answering, &second, SHORT, 1 << 16).unwrap();
    assert_eq!(done.peer, joiner);
    let sealed = Sealed::new(&second, done.session);
    assert_eq!(
        sealed.receive(None).unwrap().unwrap(),
        format!("hello from {joiner}").as_bytes()
    );
    sealed.send(b"hello from rust").unwrap();
    // The module's close record: the stream ended in order.
    assert_eq!(sealed.receive(None).unwrap(), None);
    assert!(child.wait().unwrap().success());
}

#[test]
fn the_javascript_module_with_a_wrong_pin_pairs_nobody() {
    let Some((node, module)) = noise_module() else {
        return;
    };
    let dir = Dir::new("js-wrong");
    let server = Identity::generate(Method::Noise).unwrap();
    let store = dir.store("server");
    let desk = pairing::desk().unwrap();
    let pin = desk.show_pin().unwrap().pin;
    let (mut child, stdio) = start_joiner(&node, &module, "wrong");
    let first = Connection {
        stdio: &stdio,
        number: 0,
    };
    first.send(pin.as_str().as_bytes()).unwrap();
    let responded = pairing::respond(&first, &server, &store, &desk, None, SHORT);
    let Err(Error::Proof(why)) = responded else {
        panic!("a wrong PIN paired: {responded:?}");
    };
    assert!(why.contains("wrong"), "{why}");
    assert!(accepted_methods(&store).is_empty());
    assert!(child.wait().unwrap().success());
}
