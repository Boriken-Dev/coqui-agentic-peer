//! PIN pairing over any channel, so it works through a reverse proxy that ends TLS.
//!
//! Two strangers run the handshake admitting anyone who proves a key, which yields a pairing session: it runs one exchange and
//! can carry nothing else, so a connection like this can never reach an agent. Inside it the PIN confirms both keys, both PAKE
//! messages and a secret export of the session, so a relay that swaps a key or changes a message fails on both sides. A peer then
//! connects again, pinned. Only PIN mode is offered, with the PIN this side shows.
//!
//! Both sides pair by their identity's method, and a joiner of the other method fails the handshake. The key a joiner stores is
//! the one its method proved, so the pairing names the method the two then connect by.

use core::cell::Cell;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use coqui_peer::pair::{Paired, Pairing, PairingDesk, PairingOptions, Pin, PinRole};
use coqui_peer::{MessageTransport, ReadTimeout, TrustStore};
use coqui_peer_noise as noise;
use coqui_peer_webcrypto as webcrypto;
use coqui_transport::{Channel, Failure};

use crate::Error;
use crate::auth::{Identity, MAX_PROOF_MESSAGE, prove, prove_out};

/// The error and each cause beneath it, so a refusal says which: a wrong PIN, an expired one, a disabled mode.
fn failed(error: impl core::error::Error) -> Error {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let more = next.to_string();
        if !text.ends_with(&more) {
            text = format!("{text}: {more}");
        }
        cause = next.source();
    }
    Error::Proof(text)
}

/// A channel as the messages a pairing exchange expects, never waiting past `deadline`.
struct OverChannel<'a, C> {
    channel: &'a C,
    wait: Cell<Option<Duration>>,
    deadline: Instant,
}

impl<C: Channel> OverChannel<'_, C> {
    /// What the next receive waits at most: the timeout set, within what is left of the deadline.
    fn waiting(&self) -> Duration {
        let left = self.deadline.saturating_duration_since(Instant::now());
        self.wait.get().map_or(left, |wait| wait.min(left))
    }
}

impl<C: Channel> MessageTransport for OverChannel<'_, C> {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.channel.send(message).map_err(io_error)
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        match self.channel.receive(Some(self.waiting())) {
            Ok(Some(message)) => Ok(message),
            Ok(None) => Err(io::ErrorKind::UnexpectedEof.into()),
            Err(failure) => Err(io_error(failure)),
        }
    }
}

impl<C: Channel> ReadTimeout for OverChannel<'_, C> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.wait.set(timeout);
        Ok(())
    }
}

/// Noise's responder bounds a stranger's first message by the smaller of this and its own setting, so this is the wait a
/// receive would really take: never past the deadline.
impl<C: Channel> noise::CurrentReadTimeout for OverChannel<'_, C> {
    fn current_read_timeout(&self) -> Option<Duration> {
        Some(self.waiting())
    }
}

fn io_error(failure: Failure) -> io::Error {
    match failure {
        Failure::Timeout => io::ErrorKind::TimedOut.into(),
        other => io::Error::other(other.to_string()),
    }
}

/// A desk that takes only PIN runs, as [`respond`] needs: a joiner asking for another mode is told it is disabled.
///
/// # Errors
///
/// [`Error::Proof`] when the options are refused.
pub fn desk() -> Result<PairingDesk, Error> {
    let mut options = PairingOptions::default();
    options.invitation = false;
    options.device = false;
    // Nobody is at a desk here to enter a PIN the joiner shows, so such a run must not wait for one.
    options.pin_shown = false;
    PairingDesk::builder()
        .random(coqui_peer_webcrypto::random())
        .options(options)
        .build()
        .map_err(failed)
}

/// The side that shows the PIN, on a [`desk`], pairing by `identity`'s method. A joiner it pairs with is accepted in `store`
/// before the joiner is told.
///
/// # Errors
///
/// [`Error::Proof`] for a wrong PIN, a changed message, a failed proof or a joiner of the other method; [`Error::Channel`] for
/// silence or a failed channel.
pub fn respond<C: Channel>(
    channel: &C,
    identity: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    source: Option<SocketAddr>,
    limit: Duration,
) -> Result<Paired, Error> {
    let deadline = Instant::now() + limit;
    let mut transport = OverChannel {
        channel,
        wait: Cell::new(None),
        deadline,
    };
    match identity {
        Identity::WebCrypto(identity) => {
            let method = webcrypto::PairingMethod::builder()
                .identity(identity.clone())
                .build()
                .map_err(failed)?;
            let established = prove(&method, channel, limit, MAX_PROOF_MESSAGE)?;
            established
                .session
                .respond(store, desk, source, &mut transport)
                .map_err(failed)
        }
        Identity::Noise(identity) => {
            let method = noise::PairingMethod::builder()
                .identity(identity.clone())
                .build()
                .map_err(failed)?;
            let established = prove(&method, channel, limit, MAX_PROOF_MESSAGE)?;
            established
                .session
                .respond(store, desk, source, &mut transport)
                .map_err(failed)
        }
    }
}

/// The side that was given the PIN, pairing by `identity`'s method. The responder's key is accepted in `store` once it is
/// confirmed.
///
/// # Errors
///
/// As [`respond`].
pub fn join<C: Channel>(
    channel: &C,
    identity: &Identity,
    pin: Pin,
    store: &TrustStore,
    limit: Duration,
) -> Result<Paired, Error> {
    join_as(
        channel,
        identity,
        Pairing::pin(pin, PinRole::Typed),
        store,
        limit,
    )
}

/// [`join`] asking for any mode, to show what a responder refuses.
#[doc(hidden)]
pub fn join_as<C: Channel>(
    channel: &C,
    identity: &Identity,
    pairing: Pairing,
    store: &TrustStore,
    limit: Duration,
) -> Result<Paired, Error> {
    let deadline = Instant::now() + limit;
    let mut transport = OverChannel {
        channel,
        wait: Cell::new(None),
        deadline,
    };
    let paired = match identity {
        Identity::WebCrypto(identity) => {
            let method = webcrypto::PairingMethod::builder()
                .identity(identity.clone())
                .build()
                .map_err(failed)?;
            let established = prove_out(&method, channel, limit, MAX_PROOF_MESSAGE)?;
            established
                .session
                .join(pairing, &mut transport)
                .map_err(failed)?
                .finish()
                .map_err(failed)?
        }
        Identity::Noise(identity) => {
            let method = noise::PairingMethod::builder()
                .identity(identity.clone())
                .build()
                .map_err(failed)?;
            let established = prove_out(&method, channel, limit, MAX_PROOF_MESSAGE)?;
            established
                .session
                .join(pairing, &mut transport)
                .map_err(failed)?
                .finish()
                .map_err(failed)?
        }
    };
    match store.accept_key(&paired.peer) {
        Ok(_) | Err(coqui_peer::Error::AlreadyAccepted) => Ok(paired),
        Err(error) => Err(failed(error)),
    }
}
