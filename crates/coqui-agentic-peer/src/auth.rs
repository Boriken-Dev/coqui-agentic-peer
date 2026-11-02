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
        }
    }

    /// Ends the link within about a second once `allowed` says no, for a peer removed from a store while connected.
    #[must_use]
    pub fn with_check(mut self, allowed: impl Fn() -> bool + Send + Sync + 'a) -> Self {
        self.allowed = Some(Box::new(allowed));
        self
    }

    fn still_allowed(&self) -> bool {
        let Some(allowed) = &self.allowed else {
            return true;
        };
        let mut checked = self.checked.lock().unwrap_or_else(PoisonError::into_inner);
        if checked.elapsed() < RECHECK {
            return true;
        }
        *checked = Instant::now();
        allowed()
    }
}

impl<C: Channel> Channel for Sealed<'_, C> {
    /// After [`Failure::NoProgress`], send the same message again: its record is waiting.
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        let mut state = self.sealer.lock().unwrap_or_else(PoisonError::into_inner);
        let record = match state.waiting.take() {
            Some(record) => record,
            None => state.sealer.seal(message).map_err(|_| Failure::Protocol)?,
        };
        let sent = self.channel.send(&record);
        if sent == Err(Failure::NoProgress) {
            state.waiting = Some(record);
        }
        sent
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        if !self.still_allowed() {
            self.channel.close();
            return Err(Failure::Permission);
        }
        let mut opener = self.opener.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record) = self.channel.receive(timeout)? else {
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
        if let Ok(record) = state.sealer.close() {
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
