//! Proving a peer before any byte reaches the agent, and keeping everything after it inside the session the proof made.
//! A plain message after the handshake comes from whoever carries the connection, so none is ever taken.

use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use coqui_peer::{Established, Handshake, Method};
use coqui_peer_webcrypto::{Identity, Opener, PeerId, Sealer, Session};
use coqui_web::{Channel, Failure};

use crate::Error;

/// A proof fits in a few short messages; this also bounds what an unproven peer can make us hold.
pub const MAX_PROOF_MESSAGE: usize = 3072;
/// What a session adds to each message.
pub const RECORD_OVERHEAD: usize = 17;
/// How often a live session asks whether its peer is still allowed.
const RECHECK: Duration = Duration::from_secs(1);

/// Reads an identity.
///
/// # Errors
///
/// [`Error::Identity`] when the file cannot be read or is not a key. The message never quotes the file.
pub fn read_identity(path: &Path) -> Result<Identity, Error> {
    Identity::read(path)
        .map_err(|error| Error::Identity(error.to_string()))?
        .ok_or_else(|| Error::Identity("the identity file does not exist".to_owned()))
}

/// Creates an identity file and answers its peer id. It never replaces a file. On Unix only this user can read it; elsewhere
/// it takes its directory's permissions.
///
/// # Errors
///
/// [`Error::Identity`] when the file exists or cannot be written.
pub fn create_identity(path: &Path) -> Result<PeerId, Error> {
    let identity = Identity::generate().map_err(|error| Error::Identity(error.to_string()))?;
    identity
        .write_new(path)
        .map_err(|error| Error::Identity(error.to_string()))?;
    Ok(identity.peer_id())
}

/// Runs the responder's side of the proof on `channel`, within `limit`, and gives a peer that proved itself `max_message`
/// from before the last message of the proof goes out, so the peer's first message after that meets the new limit.
///
/// # Errors
///
/// [`Error::Proof`] for a refused or malformed proof, and [`Error::Channel`] for silence or a failed channel.
pub fn prove<M: Method, C: Channel>(
    method: &M,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<<M::Handshake as Handshake>::Output>, Error> {
    let proof = method.respond(None).map_err(proof_failed)?;
    drive(proof, channel, limit, max_message)
}

/// [`prove`], as the side that connected.
///
/// # Errors
///
/// As [`prove`].
pub fn prove_out<M: Method, C: Channel>(
    method: &M,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<<M::Handshake as Handshake>::Output>, Error> {
    let proof = method.initiate().map_err(proof_failed)?;
    drive(proof, channel, limit, max_message)
}

fn proof_failed(error: impl core::fmt::Display) -> Error {
    Error::Proof(error.to_string())
}

/// The next message, within `deadline`.
pub(crate) fn next<C: Channel>(channel: &C, deadline: Instant) -> Result<Vec<u8>, Error> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Channel(Failure::Timeout));
    }
    match channel.receive(Some(left)) {
        Ok(Some(message)) => Ok(message),
        Ok(None) => Err(Error::Channel(Failure::PathLost)),
        Err(failure) => Err(failure.into()),
    }
}

fn drive<H: Handshake, C: Channel>(
    mut proof: H,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<H::Output>, Error> {
    let deadline = Instant::now() + limit;
    loop {
        let mut outgoing = Vec::new();
        while let Some(out) = proof.transmit().map_err(proof_failed)? {
            outgoing.push(out);
        }
        let complete = proof.is_complete();
        if complete {
            channel.set_max_message(max_message);
        }
        for out in &outgoing {
            channel.send(out)?;
        }
        if complete {
            return proof.finish().map_err(proof_failed);
        }
        let message = next(channel, deadline)?;
        if message.len() > MAX_PROOF_MESSAGE {
            return Err(Error::Proof("a proof message is over its limit".to_owned()));
        }
        proof.receive(&message).map_err(proof_failed)?;
    }
}
/// How often a kept record is tried again while waiting to receive.
const FLUSH_POLL: Duration = Duration::from_millis(20);

struct SealerState {
    sealer: Sealer,
    /// A record the channel had no room for. Sealing takes the next sequence number, so it is sent as it is, or the
    /// peer would meet a gap.
    waiting: Option<Vec<u8>>,
}

/// A channel whose every message is inside a session. Anything that does not open ends it, and so does a connection cut before
/// the peer's close record, which is how a relay would hide what it held back.
pub struct Sealed<'a, C: Channel> {
    channel: &'a C,
    sealer: Mutex<SealerState>,
    opener: Mutex<Opener>,
    allowed: Option<Box<dyn Fn() -> bool + Send + Sync + 'a>>,
    checked: Mutex<Instant>,
    recheck: Duration,
}

impl<C: Channel> core::fmt::Debug for Sealed<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed").finish_non_exhaustive()
    }
}

impl<'a, C: Channel> Sealed<'a, C> {
    /// Protects `channel` with `session`.
    #[must_use]
    pub fn new(channel: &'a C, session: Session) -> Self {
        let (sealer, opener) = session.split();
        Self {
            channel,
            sealer: Mutex::new(SealerState {
                sealer,
                waiting: None,
            }),
            opener: Mutex::new(opener),
            allowed: None,
            checked: Mutex::new(Instant::now()),
            recheck: RECHECK,
        }
    }

    /// Ends the link within about a second once `allowed` says no, for a peer removed from a store while connected. A check that
    /// cannot tell has to say no: a store that cannot be read must not keep a link alive.
    #[must_use]
    pub fn with_check(mut self, allowed: impl Fn() -> bool + Send + Sync + 'a) -> Self {
        self.allowed = Some(Box::new(allowed));
        self
    }

    /// How often [`Sealed::with_check`] asks: a second unless set.
    #[must_use]
    pub const fn with_check_every(mut self, recheck: Duration) -> Self {
        self.recheck = recheck;
        self
    }

    /// Sends a kept record, if there is one. [`Failure::NoProgress`] means it is still kept.
    fn flush(&self, state: &mut SealerState) -> Result<(), Failure> {
        let Some(record) = state.waiting.take() else {
            return Ok(());
        };
        let sent = self.channel.send(&record);
        if sent == Err(Failure::NoProgress) {
            state.waiting = Some(record);
        }
        sent
    }

    fn still_allowed(&self) -> bool {
        let Some(allowed) = &self.allowed else {
            return true;
        };
        let mut checked = self.checked.lock().unwrap_or_else(PoisonError::into_inner);
        if checked.elapsed() < self.recheck {
            return true;
        }
        *checked = Instant::now();
        allowed()
    }
}

impl<C: Channel> Channel for Sealed<'_, C> {
    /// [`Failure::NoProgress`] means this message was not taken, so send it again. A record has to go in the order it was sealed, so
    /// one the link cannot take yet is kept and goes before anything else: it is already this channel's to deliver, and is never sent
    /// as if it were another caller's message.
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        let mut state = self.sealer.lock().unwrap_or_else(PoisonError::into_inner);
        self.flush(&mut state)?;
        let record = state.sealer.seal(message).map_err(|_| Failure::Protocol)?;
        match self.channel.send(&record) {
            Err(Failure::NoProgress) => {
                state.waiting = Some(record);
                Ok(())
            }
            other => other,
        }
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        if !self.still_allowed() {
            self.channel.close();
            return Err(Failure::Permission);
        }
        let mut opener = self.opener.lock().unwrap_or_else(PoisonError::into_inner);
        let until = timeout.map(|limit| Instant::now() + limit);
        let incoming = loop {
            // With nothing more to send, this is what delivers a kept record.
            let waiting = {
                let mut state = self.sealer.lock().unwrap_or_else(PoisonError::into_inner);
                match self.flush(&mut state) {
                    Ok(()) => false,
                    Err(Failure::NoProgress) => true,
                    Err(failure) => return Err(failure),
                }
            };
            if !waiting {
                break self
                    .channel
                    .receive(until.map(|at| at.saturating_duration_since(Instant::now())))?;
            }
            let left = until.map_or(FLUSH_POLL, |at| {
                at.saturating_duration_since(Instant::now())
            });
            match self.channel.receive(Some(left.min(FLUSH_POLL))) {
                Err(Failure::Timeout) if until.is_none_or(|at| Instant::now() < at) => {}
                other => break other?,
            }
        };
        let Some(record) = incoming else {
            return match opener.verify_end() {
                Ok(()) => Ok(None),
                Err(_) => Err(Failure::PathLost),
            };
        };
        match opener.open(&record) {
            Ok(opened) => Ok(opened),
            Err(_) => {
                self.channel.close();
                Err(Failure::Protocol)
            }
        }
    }

    /// Sends this side's close record, then ends the channel. Safe to call more than once.
    fn close(&self) {
        let mut state = self.sealer.lock().unwrap_or_else(PoisonError::into_inner);
        // Out of order, the close record would read as tampering, so a link that cannot take what comes before it ends without one.
        if self.flush(&mut state).is_ok()
            && let Ok(record) = state.sealer.close()
        {
            let _ = self.channel.send(&record);
        }
        drop(state);
        self.channel.close();
    }

    fn set_max_message(&self, bytes: usize) {
        self.channel
            .set_max_message(bytes.saturating_add(RECORD_OVERHEAD));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, Sender, channel as queue};
    use std::thread;

    use coqui_peer_webcrypto::{Trust, WebCrypto};

    use super::*;

    /// A link in memory, for two real handshakes to run over.
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
            incoming
                .recv_timeout(timeout.unwrap_or(Duration::from_secs(5)))
                .map(Some)
                .map_err(|_| Failure::Timeout)
        }

        fn close(&self) {}
    }

    /// A link that can be told it is full, recording what it was given, as a queue that has filled would.
    #[derive(Default)]
    struct Fills {
        full: AtomicBool,
        taken: Mutex<Vec<Vec<u8>>>,
    }

    impl Channel for Fills {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            if self.full.load(Ordering::SeqCst) {
                return Err(Failure::NoProgress);
            }
            self.taken.lock().unwrap().push(message.to_vec());
            Ok(())
        }

        fn receive(&self, _timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            Err(Failure::Timeout)
        }

        fn close(&self) {}
    }

    fn sealed_pair() -> (Session, Session) {
        let dialer = Identity::generate().unwrap();
        let answerer = Identity::generate().unwrap();
        let (dialer_id, answerer_id) = (dialer.peer_id(), answerer.peer_id());
        let dialing = WebCrypto::new(dialer).with_responders(Trust::pinned([answerer_id]));
        let answering = WebCrypto::new(answerer).with_initiators(Trust::pinned([dialer_id]));
        let (a_out, b_in) = queue();
        let (b_out, a_in) = queue();
        let ours = Wire {
            out: a_out,
            incoming: Mutex::new(a_in),
        };
        let theirs = Wire {
            out: b_out,
            incoming: Mutex::new(b_in),
        };
        const LIMIT: Duration = Duration::from_secs(10);
        thread::scope(|scope| {
            let answer =
                scope.spawn(|| prove(&answering, &theirs, LIMIT, 1 << 20).unwrap().session);
            let dialed = prove_out(&dialing, &ours, LIMIT, 1 << 20).unwrap().session;
            (dialed, answer.join().unwrap())
        })
    }

    fn opened(session: Session, records: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let (_, mut opener) = session.split();
        records
            .iter()
            .map(|record| opener.open(record).unwrap().unwrap())
            .collect()
    }

    #[test]
    fn a_full_link_never_loses_one_callers_message_or_sends_it_twice() {
        let (ours, theirs) = sealed_pair();
        let link = Fills::default();
        let sealed = Sealed::new(&link, ours);
        sealed.send(b"first").unwrap();
        link.full.store(true, Ordering::SeqCst);
        // Taken, and kept: it goes first once the link has room.
        sealed.send(b"second").unwrap();
        // Not taken, and it says so, since the one before it is still waiting.
        assert_eq!(sealed.send(b"third"), Err(Failure::NoProgress));
        assert_eq!(sealed.send(b"other caller"), Err(Failure::NoProgress));
        link.full.store(false, Ordering::SeqCst);
        sealed.send(b"third").unwrap();
        sealed.send(b"other caller").unwrap();
        let taken = link.taken.lock().unwrap().clone();
        assert_eq!(
            opened(theirs, &taken),
            [&b"first"[..], b"second", b"third", b"other caller"]
        );
    }

    #[test]
    fn a_kept_record_goes_while_only_receiving() {
        let (ours, theirs) = sealed_pair();
        let link = Fills::default();
        let sealed = Sealed::new(&link, ours);
        link.full.store(true, Ordering::SeqCst);
        sealed.send(b"last").unwrap();
        assert_eq!(
            sealed.receive(Some(Duration::from_millis(1))),
            Err(Failure::Timeout)
        );
        assert!(link.taken.lock().unwrap().is_empty());
        link.full.store(false, Ordering::SeqCst);
        assert_eq!(
            sealed.receive(Some(Duration::from_millis(1))),
            Err(Failure::Timeout)
        );
        let taken = link.taken.lock().unwrap().clone();
        assert_eq!(opened(theirs, &taken), [&b"last"[..]]);
    }
}
