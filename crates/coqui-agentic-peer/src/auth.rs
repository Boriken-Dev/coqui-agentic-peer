//! Proving a peer before any byte reaches the agent, and keeping everything after it inside the session the proof made.
//! A plain message after the handshake comes from whoever carries the connection, so none is ever taken.
//!
//! An endpoint proves by one [`Method`], chosen when it is built and never negotiated on a connection: a peer of the other method
//! fails the proof, and nothing falls back.

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use coqui_builder::NonDefault;
use coqui_peer::{Established, Framing, Handshake, KeyMaterial, PeerId, TrustStore};
use coqui_peer_noise as noise;
use coqui_peer_webcrypto as webcrypto;
use coqui_transport::{Channel, Failure};

use crate::Error;

/// A proof fits in a few short messages; this also bounds what an unproven peer can make us hold.
pub const MAX_PROOF_MESSAGE: usize = 3072;
/// What a WebCrypto record adds to a message: the type byte and the tag.
const WEBCRYPTO_OVERHEAD: usize = 17;
/// The most of a message one Noise part holds: 65535 bytes less the tag and the type byte.
const NOISE_PART: usize = 65_518;
/// A Noise key change: its length field, type byte and tag.
const NOISE_KEY_CHANGE: usize = 19;
/// How often a live session asks whether its peer is still allowed.
const RECHECK: Duration = Duration::from_secs(1);
/// How every WebCrypto handshake message starts, which a Noise message of 32 bytes never does.
const WEBCRYPTO_START: &[u8] = b"{\"profile\":\"dev.boriken.coqui.peer-webcrypto/";

/// The proof an endpoint runs. A key belongs to one method: a peer id names a key of one type, so it can be proved only by its own
/// method, and an endpoint never holds keys of both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `coqui-peer-webcrypto`: P-256 signatures and ECDH, for browsers whose WebCrypto has no X25519.
    WebCrypto,
    /// `coqui-peer-noise`: `Noise_XX_25519_AESGCM_SHA256`, with PIN pairing in the browser as well.
    Noise,
}

impl Method {
    /// The method a new identity gets when nothing names one. An existing identity keeps its own.
    pub const DEFAULT: Self = Self::Noise;

    /// Every method, in no order of preference.
    pub const ALL: [Self; 2] = [Self::WebCrypto, Self::Noise];

    /// The name a key of this method is stored under, as in [`KeyMaterial::method`]: `webcrypto` or `noise`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WebCrypto => webcrypto::METHOD,
            Self::Noise => noise::METHOD,
        }
    }

    /// The longest record a message of `message` bytes can become in this method's session, whatever key limit its sender
    /// runs. A channel's limit for sealed messages is set from it, never from the message length. Under Noise a sender may
    /// change keys before any part of a record, each change 19 bytes, so this is `noise::record_length` and 19 more per part.
    #[must_use]
    pub const fn record_length(self, message: usize) -> usize {
        match self {
            Self::WebCrypto => message.saturating_add(WEBCRYPTO_OVERHEAD),
            Self::Noise => {
                let parts = message.div_ceil(NOISE_PART);
                let parts = if parts == 0 { 1 } else { parts };
                noise::record_length(message).saturating_add(parts.saturating_mul(NOISE_KEY_CHANGE))
            }
        }
    }

    /// The method a stored key belongs to, if it is one of these.
    #[must_use]
    pub fn of_key(material: &KeyMaterial) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|method| method.name() == material.method)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Method {
    type Err = Error;

    /// `webcrypto` or `noise`, exactly.
    fn from_str(text: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|method| method.name() == text)
            .ok_or_else(|| Error::Identity("the method is webcrypto or noise".to_owned()))
    }
}

/// A private key, of one method.
#[derive(Clone)]
#[non_exhaustive]
pub enum Identity {
    /// A P-256 key.
    WebCrypto(webcrypto::Identity),
    /// An X25519 key.
    Noise(noise::Identity),
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("method", &self.method())
            .field("peer", &self.peer_id())
            .finish()
    }
}

impl From<webcrypto::Identity> for Identity {
    fn from(identity: webcrypto::Identity) -> Self {
        Self::WebCrypto(identity)
    }
}

impl From<noise::Identity> for Identity {
    fn from(identity: noise::Identity) -> Self {
        Self::Noise(identity)
    }
}

/// The error and each cause beneath it, so a file that cannot be written says why.
fn identity_failed(error: impl std::error::Error) -> Error {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text = format!("{text}: {next}");
        cause = next.source();
    }
    Error::Identity(text)
}

impl Identity {
    /// A new key of `method`, from the operating system's generator.
    ///
    /// # Errors
    ///
    /// [`Error::Identity`] when the generator fails.
    pub fn generate(method: Method) -> Result<Self, Error> {
        match method {
            Method::WebCrypto => webcrypto::Identity::generate()
                .map(Self::WebCrypto)
                .map_err(identity_failed),
            Method::Noise => noise::Identity::generate()
                .map(Self::Noise)
                .map_err(identity_failed),
        }
    }

    /// The key at `path`, of whichever method its type is; `None` when there is no file.
    ///
    /// # Errors
    ///
    /// [`Error::Identity`] when it cannot be read or is a key of no method here. The message never quotes the file.
    pub fn read(path: &Path) -> Result<Option<Self>, Error> {
        match noise::Identity::read(path) {
            Ok(found) => return Ok(found.map(Self::Noise)),
            Err(noise::Error::Key) => {}
            Err(error) => return Err(identity_failed(error)),
        }
        match webcrypto::Identity::read(path) {
            Ok(found) => Ok(found.map(Self::WebCrypto)),
            Err(webcrypto::Error::Key) => Err(Error::Identity(
                "the file holds no private key of either method".to_owned(),
            )),
            Err(error) => Err(identity_failed(error)),
        }
    }

    /// Writes this key to `path`, which must not exist. On Unix only this user can read it; elsewhere it takes its directory's
    /// permissions. Parent directories are created.
    ///
    /// # Errors
    ///
    /// [`Error::Identity`] when the file exists or cannot be written.
    pub fn write_new(&self, path: &Path) -> Result<(), Error> {
        match self {
            Self::WebCrypto(identity) => identity.write_new(path).map_err(identity_failed),
            Self::Noise(identity) => identity.write_new(path).map_err(identity_failed),
        }
    }

    /// The key at `path`, or a new one of `method` written there. A key already there keeps its own method: one of another
    /// method than `method` is refused, never replaced.
    ///
    /// # Errors
    ///
    /// [`Error::Identity`] when it cannot be read or written, or holds a key of another method.
    pub fn open_or_create(path: &Path, method: Method) -> Result<Self, Error> {
        if let Some(found) = Self::read(path)? {
            return found.of_method(method);
        }
        let identity = Self::generate(method)?;
        match identity.write_new(path) {
            Ok(()) => Ok(identity),
            // Another process made it first: theirs is the identity. Otherwise the write's own error says why.
            Err(error) => match Self::read(path) {
                Ok(Some(found)) => found.of_method(method),
                _ => Err(error),
            },
        }
    }

    /// This identity, if it is of `method`.
    ///
    /// # Errors
    ///
    /// [`Error::Identity`] naming both methods when it is not.
    pub fn of_method(self, method: Method) -> Result<Self, Error> {
        if self.method() == method {
            Ok(self)
        } else {
            Err(Error::Identity(format!(
                "this identity proves by {}, not {method}; a key belongs to one method, so {method} needs an identity of its own",
                self.method()
            )))
        }
    }

    /// Its method.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::WebCrypto(_) => Method::WebCrypto,
            Self::Noise(_) => Method::Noise,
        }
    }

    /// Its peer id: the SHA-256 of its public key's SubjectPublicKeyInfo.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        match self {
            Self::WebCrypto(identity) => identity.peer_id(),
            Self::Noise(identity) => identity.peer_id(),
        }
    }

    /// Its public key as a trust store keeps it, naming its method.
    #[must_use]
    pub fn key_material(&self) -> KeyMaterial {
        match self {
            Self::WebCrypto(identity) => identity.key_material(),
            Self::Noise(identity) => identity.key_material(),
        }
    }
}

/// Reads an identity, of whichever method its key is.
///
/// # Errors
///
/// [`Error::Identity`] when the file cannot be read or is not a key. The message never quotes the file.
pub fn read_identity(path: &Path) -> Result<Identity, Error> {
    Identity::read(path)?
        .ok_or_else(|| Error::Identity("the identity file does not exist".to_owned()))
}

/// Creates an identity file of `method` and answers its peer id. It never replaces a file. On Unix only this user can read it;
/// elsewhere it takes its directory's permissions.
///
/// # Errors
///
/// [`Error::Identity`] when the file exists or cannot be written.
pub fn create_identity(path: &Path, method: Method) -> Result<PeerId, Error> {
    let identity = Identity::generate(method)?;
    identity.write_new(path)?;
    Ok(identity.peer_id())
}

/// Whom a proof admits, decided after the peer proved its key and never before.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Trust {
    /// These ids, fixed when the proof is built. An empty set admits nobody.
    Pinned(BTreeSet<PeerId>),
    /// The keys a store accepts, of the proof's own method, read at each handshake. A responder records a proved stranger as
    /// waiting.
    Store(TrustStore),
}

impl Trust {
    /// Admits exactly these ids.
    pub fn pinned(ids: impl IntoIterator<Item = PeerId>) -> Self {
        Self::Pinned(ids.into_iter().collect())
    }

    fn webcrypto(self) -> webcrypto::Trust {
        match self {
            Self::Pinned(ids) => webcrypto::Trust::Pinned(ids),
            Self::Store(store) => webcrypto::Trust::Store(store),
        }
    }

    fn noise(self) -> noise::Trust {
        match self {
            Self::Pinned(ids) => noise::Trust::Pinned(ids),
            Self::Store(store) => noise::Trust::Store(store),
        }
    }
}

/// An endpoint's proof: its identity's method, with whom it admits in each role. It is a [`coqui_peer::Method`], so [`prove`] and
/// [`prove_out`] run it, and its handshake ends in a [`Session`] of that method.
#[derive(Clone)]
#[non_exhaustive]
pub enum Proof {
    /// The WebCrypto method.
    WebCrypto(webcrypto::WebCrypto),
    /// The Noise method.
    Noise(noise::Noise),
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proof")
            .field("method", &self.method())
            .finish_non_exhaustive()
    }
}

impl From<webcrypto::WebCrypto> for Proof {
    fn from(method: webcrypto::WebCrypto) -> Self {
        Self::WebCrypto(method)
    }
}

impl From<noise::Noise> for Proof {
    fn from(method: noise::Noise) -> Self {
        Self::Noise(method)
    }
}

/// Builds a [`Proof`]: [`Proof::builder`], the settings by name, then [`build`](Self::build).
#[derive(Debug)]
#[must_use]
pub struct ProofBuilder {
    inner: Inner,
    refusal: Option<&'static str>,
}

#[derive(Debug)]
enum Inner {
    WebCrypto(webcrypto::WebCryptoBuilder),
    Noise(noise::NoiseBuilder),
}

impl ProofBuilder {
    /// Whom [`prove_out`] admits.
    pub fn responders(mut self, trust: Trust) -> Self {
        self.inner = match self.inner {
            Inner::WebCrypto(builder) => Inner::WebCrypto(builder.responders(trust.webcrypto())),
            Inner::Noise(builder) => Inner::Noise(builder.responders(trust.noise())),
        };
        self
    }

    /// Whom [`prove`] admits.
    pub fn initiators(mut self, trust: Trust) -> Self {
        self.inner = match self.inner {
            Inner::WebCrypto(builder) => Inner::WebCrypto(builder.initiators(trust.webcrypto())),
            Inner::Noise(builder) => Inner::Noise(builder.initiators(trust.noise())),
        };
        self
    }

    /// What one key may carry in each direction: WebCrypto's session limit, Noise's key limit. The default is each method's
    /// (2^38 bytes for both), with no floor; any other, [`Proof::non_defaults`] says so.
    pub fn key_limit(mut self, bytes: u64) -> Self {
        self.inner = match self.inner {
            Inner::WebCrypto(builder) => Inner::WebCrypto(builder.session_limit(bytes)),
            Inner::Noise(builder) => Inner::Noise(builder.key_limit(bytes)),
        };
        self
    }

    /// Whether a sender changes its key at the limit by itself, which Noise does unless told not to. WebCrypto has no key
    /// change, so it takes only `false`: [`build`](Self::build) refuses `true` there.
    pub fn rekey(mut self, rekey: bool) -> Self {
        match self.inner {
            Inner::WebCrypto(_) if rekey => {
                self.refusal = Some("webcrypto has no key change: a session ends at its limit");
            }
            Inner::WebCrypto(_) => {}
            Inner::Noise(builder) => self.inner = Inner::Noise(builder.rekey(rekey)),
        }
        self
    }

    /// The longest handshake message WebCrypto takes; [`build`](Self::build) refuses it under Noise, whose handshake messages
    /// have fixed lengths and no such setting.
    pub fn max_message(mut self, bytes: usize) -> Self {
        match self.inner {
            Inner::WebCrypto(builder) => self.inner = Inner::WebCrypto(builder.max_message(bytes)),
            Inner::Noise(_) => {
                self.refusal = Some(
                    "noise has no handshake message limit: its messages are 32, 96 and 64 bytes",
                );
            }
        }
        self
    }

    /// The proof.
    ///
    /// # Errors
    ///
    /// [`Error::Proof`] when a setting the identity's method does not have was given.
    pub fn build(self) -> Result<Proof, Error> {
        if let Some(reason) = self.refusal {
            return Err(Error::Proof(reason.to_owned()));
        }
        Ok(match self.inner {
            Inner::WebCrypto(builder) => Proof::WebCrypto(builder.build().map_err(proof_failed)?),
            Inner::Noise(builder) => Proof::Noise(builder.build().map_err(proof_failed)?),
        })
    }
}

impl Proof {
    /// A builder for the proof of `identity`'s method, in neither role until
    /// [`responders`](ProofBuilder::responders) or [`initiators`](ProofBuilder::initiators).
    pub fn builder(identity: Identity) -> ProofBuilder {
        let inner = match identity {
            Identity::WebCrypto(identity) => {
                Inner::WebCrypto(webcrypto::WebCrypto::builder().identity(identity))
            }
            Identity::Noise(identity) => Inner::Noise(noise::Noise::builder().identity(identity)),
        };
        ProofBuilder {
            inner,
            refusal: None,
        }
    }

    /// Its method.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::WebCrypto(_) => Method::WebCrypto,
            Self::Noise(_) => Method::Noise,
        }
    }

    /// Its identity's peer id.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        match self {
            Self::WebCrypto(method) => method.identity().peer_id(),
            Self::Noise(method) => method.identity().peer_id(),
        }
    }

    /// Every setting looser than its method's default, for the host to show.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        match self {
            Self::WebCrypto(method) => method.non_defaults(),
            Self::Noise(method) => method.non_defaults(),
        }
    }
}

/// A proof that failed, in its method's own words.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofError {
    /// WebCrypto's.
    WebCrypto(webcrypto::Error),
    /// Noise's.
    Noise(noise::Error),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebCrypto(error) => error.fmt(f),
            Self::Noise(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WebCrypto(error) => Some(error),
            Self::Noise(error) => Some(error),
        }
    }
}

/// A [`Proof`]'s handshake in progress.
#[non_exhaustive]
pub enum ProofHandshake {
    /// WebCrypto's.
    WebCrypto(webcrypto::WebCryptoHandshake),
    /// Noise's.
    Noise(noise::NoiseHandshake),
}

impl fmt::Debug for ProofHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofHandshake").finish_non_exhaustive()
    }
}

impl Handshake for ProofHandshake {
    type Output = Session;
    type Error = ProofError;

    fn framing(&self) -> Framing {
        match self {
            Self::WebCrypto(handshake) => handshake.framing(),
            Self::Noise(handshake) => handshake.framing(),
        }
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), ProofError> {
        match self {
            Self::WebCrypto(handshake) => handshake.receive(input).map_err(ProofError::WebCrypto),
            Self::Noise(handshake) => handshake.receive(input).map_err(ProofError::Noise),
        }
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, ProofError> {
        match self {
            Self::WebCrypto(handshake) => handshake.transmit().map_err(ProofError::WebCrypto),
            Self::Noise(handshake) => handshake.transmit().map_err(ProofError::Noise),
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::WebCrypto(handshake) => handshake.is_complete(),
            Self::Noise(handshake) => handshake.is_complete(),
        }
    }

    fn finish(self) -> Result<Established<Session>, ProofError> {
        match self {
            Self::WebCrypto(handshake) => handshake
                .finish()
                .map(|done| Established {
                    peer: done.peer,
                    key: done.key,
                    session: Session::WebCrypto(done.session),
                })
                .map_err(ProofError::WebCrypto),
            Self::Noise(handshake) => handshake
                .finish()
                .map(|done| Established {
                    peer: done.peer,
                    key: done.key,
                    session: Session::Noise(done.session),
                })
                .map_err(ProofError::Noise),
        }
    }
}

impl coqui_peer::Method for Proof {
    type Handshake = ProofHandshake;

    fn name(&self) -> &'static str {
        self.method().name()
    }

    fn initiate(&self) -> Result<ProofHandshake, ProofError> {
        match self {
            Self::WebCrypto(method) => method
                .initiate()
                .map(ProofHandshake::WebCrypto)
                .map_err(ProofError::WebCrypto),
            Self::Noise(method) => method
                .initiate()
                .map(ProofHandshake::Noise)
                .map_err(ProofError::Noise),
        }
    }

    fn respond(&self, source: Option<SocketAddr>) -> Result<ProofHandshake, ProofError> {
        match self {
            Self::WebCrypto(method) => method
                .respond(source)
                .map(ProofHandshake::WebCrypto)
                .map_err(ProofError::WebCrypto),
            Self::Noise(method) => method
                .respond(source)
                .map(ProofHandshake::Noise)
                .map_err(ProofError::Noise),
        }
    }
}

/// The session a proof ended in, of its method.
#[non_exhaustive]
pub enum Session {
    /// WebCrypto's.
    WebCrypto(webcrypto::Session),
    /// Noise's.
    Noise(noise::Session),
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("method", &self.method())
            .finish_non_exhaustive()
    }
}

impl From<webcrypto::Session> for Session {
    fn from(session: webcrypto::Session) -> Self {
        Self::WebCrypto(session)
    }
}

impl From<noise::Session> for Session {
    fn from(session: noise::Session) -> Self {
        Self::Noise(session)
    }
}

impl Session {
    /// Its method.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::WebCrypto(_) => Method::WebCrypto,
            Self::Noise(_) => Method::Noise,
        }
    }

    /// The session id both ends agree on. It is not secret.
    #[must_use]
    pub fn id(&self) -> &[u8; 32] {
        match self {
            Self::WebCrypto(session) => session.id(),
            Self::Noise(session) => session.id(),
        }
    }

    /// Bytes secret to the two peers and bound to this run, under `label`; another label or length gives unrelated bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Proof`] when the method refuses the length.
    pub fn export(&self, label: &str, out: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::WebCrypto(session) => session.export(label, out).map_err(proof_failed),
            Self::Noise(session) => session.export(label, out).map_err(proof_failed),
        }
    }

    fn split(self) -> (Sealer, Opener) {
        match self {
            Self::WebCrypto(session) => {
                let (sealer, opener) = session.split();
                (Sealer::WebCrypto(sealer), Opener::WebCrypto(opener))
            }
            Self::Noise(session) => {
                let (sealer, opener) = session.split();
                (Sealer::Noise(sealer), Opener::Noise(opener))
            }
        }
    }
}

enum Sealer {
    WebCrypto(webcrypto::Sealer),
    Noise(noise::Sealer),
}

impl Sealer {
    fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::WebCrypto(sealer) => sealer.seal(message).map_err(drop),
            Self::Noise(sealer) => sealer.seal(message).map_err(drop),
        }
    }

    fn close(&mut self) -> Result<Vec<u8>, ()> {
        match self {
            Self::WebCrypto(sealer) => sealer.close().map_err(drop),
            Self::Noise(sealer) => sealer.close().map_err(drop),
        }
    }
}

enum Opener {
    WebCrypto(webcrypto::Opener),
    Noise(noise::Opener),
}

impl Opener {
    fn open(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        match self {
            Self::WebCrypto(opener) => opener.open(record).map_err(drop),
            Self::Noise(opener) => opener.open(record).map_err(drop),
        }
    }

    fn verify_end(&self) -> Result<(), ()> {
        match self {
            Self::WebCrypto(opener) => opener.verify_end().map_err(drop),
            Self::Noise(opener) => opener.verify_end().map_err(drop),
        }
    }
}

/// Runs the responder's side of the proof on `channel`, within `limit`, and gives a peer that proved itself `max_message`
/// from before the last message of the proof goes out, so the peer's first message after that meets the new limit. Size
/// `max_message` with [`Method::record_length`].
///
/// # Errors
///
/// [`Error::Proof`] for a refused or malformed proof, naming the peer's method when its first message shows it proves by
/// another; [`Error::Channel`] for silence or a failed channel.
pub fn prove<M: coqui_peer::Method, C: Channel>(
    method: &M,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<<M::Handshake as Handshake>::Output>, Error> {
    let proof = method.respond(None).map_err(proof_failed)?;
    drive(proof, method.name(), channel, limit, max_message)
}

/// [`prove`], as the side that connected. A peer that proves by another method ends the connection, which this reports as the
/// channel failing.
///
/// # Errors
///
/// As [`prove`].
pub fn prove_out<M: coqui_peer::Method, C: Channel>(
    method: &M,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<<M::Handshake as Handshake>::Output>, Error> {
    let proof = method.initiate().map_err(proof_failed)?;
    drive(proof, method.name(), channel, limit, max_message)
}

fn proof_failed(error: impl fmt::Display) -> Error {
    Error::Proof(error.to_string())
}

/// The method a refused first message shows its sender proves by, when that is not `ours`. Only a responder's first message can
/// show this: an initiator of another method gets no answer at all.
fn other_method(ours: &str, message: &[u8]) -> Option<Method> {
    if message.starts_with(WEBCRYPTO_START) {
        (ours != webcrypto::METHOD).then_some(Method::WebCrypto)
    } else if message.len() == 32 && message.first() != Some(&b'{') {
        (ours != noise::METHOD).then_some(Method::Noise)
    } else {
        None
    }
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
    ours: &str,
    channel: &C,
    limit: Duration,
    max_message: usize,
) -> Result<Established<H::Output>, Error> {
    let deadline = Instant::now() + limit;
    let mut first = true;
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
        let answering = first && outgoing.is_empty();
        first = false;
        if let Err(error) =
            check_size(&message).and_then(|()| proof.receive(&message).map_err(proof_failed))
        {
            return Err(match other_method(ours, &message).filter(|_| answering) {
                Some(theirs) => match ours.parse() {
                    Ok(ours) => Error::OtherMethod { peer: theirs, ours },
                    Err(_) => error,
                },
                None => error,
            });
        }
    }
}

fn check_size(message: &[u8]) -> Result<(), Error> {
    if message.len() > MAX_PROOF_MESSAGE {
        return Err(Error::Proof("a proof message is over its limit".to_owned()));
    }
    Ok(())
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
    method: Method,
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
    /// Protects `channel` with `session`, of either method.
    #[must_use]
    pub fn new(channel: &'a C, session: impl Into<Session>) -> Self {
        let session = session.into();
        let method = session.method();
        let (sealer, opener) = session.split();
        Self {
            channel,
            sealer: Mutex::new(SealerState {
                sealer,
                waiting: None,
            }),
            opener: Mutex::new(opener),
            method,
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

    /// The method of the session it was given.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
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
            .set_max_message(self.method.record_length(bytes));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, Sender, channel as queue};
    use std::thread;

    use super::*;

    /// A link in memory, for two real handshakes to run over.
    struct Wire {
        out: Sender<Vec<u8>>,
        incoming: Mutex<Receiver<Vec<u8>>>,
        limit: AtomicUsize,
    }

    impl Channel for Wire {
        fn send(&self, message: &[u8]) -> Result<(), Failure> {
            self.out
                .send(message.to_vec())
                .map_err(|_| Failure::PathLost)
        }

        fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            let incoming = self.incoming.lock().unwrap();
            match incoming.recv_timeout(timeout.unwrap_or(Duration::from_secs(5))) {
                Ok(message) => Ok(Some(message)),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Failure::Timeout),
            }
        }

        fn close(&self) {}

        fn set_max_message(&self, bytes: usize) {
            self.limit.store(bytes, Ordering::SeqCst);
        }
    }

    fn wires() -> (Wire, Wire) {
        let (a_out, b_in) = queue();
        let (b_out, a_in) = queue();
        let wire = |out, incoming| Wire {
            out,
            incoming: Mutex::new(incoming),
            limit: AtomicUsize::new(0),
        };
        (wire(a_out, a_in), wire(b_out, b_in))
    }

    /// A link that can be told it is full, recording what it was given, as a queue that has filled would.
    #[derive(Default)]
    struct Fills {
        full: AtomicBool,
        taken: Mutex<Vec<Vec<u8>>>,
        limit: AtomicUsize,
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

        fn set_max_message(&self, bytes: usize) {
            self.limit.store(bytes, Ordering::SeqCst);
        }
    }

    const LIMIT: Duration = Duration::from_secs(10);

    fn sealed_pair(method: Method) -> (Session, Session) {
        let dialer = Identity::generate(method).unwrap();
        let answerer = Identity::generate(method).unwrap();
        let (dialer_id, answerer_id) = (dialer.peer_id(), answerer.peer_id());
        let dialing = Proof::builder(dialer)
            .responders(Trust::pinned([answerer_id]))
            .build()
            .unwrap();
        let answering = Proof::builder(answerer)
            .initiators(Trust::pinned([dialer_id]))
            .build()
            .unwrap();
        let (ours, theirs) = wires();
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
        for method in Method::ALL {
            let (ours, theirs) = sealed_pair(method);
            assert_eq!((ours.method(), theirs.method()), (method, method));
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
    }

    #[test]
    fn a_kept_record_goes_while_only_receiving() {
        for method in Method::ALL {
            let (ours, theirs) = sealed_pair(method);
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

    #[test]
    fn a_limit_is_the_record_a_message_of_that_length_becomes_in_its_method() {
        const MESSAGE: usize = 16 * 1024 * 1024;
        for method in Method::ALL {
            let (ours, theirs) = sealed_pair(method);
            let link = Fills::default();
            let sealed = Sealed::new(&link, ours);
            sealed.set_max_message(MESSAGE);
            assert_eq!(
                link.limit.load(Ordering::SeqCst),
                method.record_length(MESSAGE)
            );
            // The largest message under the limit seals to a record the limit just takes.
            sealed.send(&vec![7; MESSAGE]).unwrap();
            let taken = link.taken.lock().unwrap().clone();
            // At the default key limit no change of key comes into one record this size: what it holds is the plain length.
            assert!(taken[0].len() <= method.record_length(MESSAGE));
            if method == Method::Noise {
                assert_eq!(taken[0].len(), coqui_peer_noise::record_length(MESSAGE));
            }
            assert_eq!(opened(theirs, &taken)[0].len(), MESSAGE);
        }
        assert_eq!(Method::WebCrypto.record_length(10), 27);
        // Noise adds 19 bytes per 65,518, and as much again for key changes: 9,766 at 16 MiB.
        assert_eq!(Method::Noise.record_length(MESSAGE), MESSAGE + 9_766);
    }

    #[test]
    fn records_of_one_method_are_refused_by_a_session_of_the_other() {
        let (webcrypto_ours, _) = sealed_pair(Method::WebCrypto);
        let (_, noise_theirs) = sealed_pair(Method::Noise);
        let link = Fills::default();
        Sealed::new(&link, webcrypto_ours).send(b"hello").unwrap();
        let taken = link.taken.lock().unwrap().clone();
        let (_, mut opener) = noise_theirs.split();
        assert!(opener.open(&taken[0]).is_err());
    }

    /// Runs a dialer of `dialing` against an answerer of `answering`, each admitting the other's key, and gives both results.
    fn across(
        dialing: Method,
        answering: Method,
    ) -> (Result<PeerId, Error>, Result<PeerId, Error>) {
        let dialer = Identity::generate(dialing).unwrap();
        let answerer = Identity::generate(answering).unwrap();
        let (dialer_id, answerer_id) = (dialer.peer_id(), answerer.peer_id());
        let dialing = Proof::builder(dialer)
            .responders(Trust::pinned([answerer_id]))
            .build()
            .unwrap();
        let answering = Proof::builder(answerer)
            .initiators(Trust::pinned([dialer_id]))
            .build()
            .unwrap();
        let (ours, theirs) = wires();
        thread::scope(|scope| {
            let answer = scope.spawn(move || {
                let answered = prove(&answering, &theirs, Duration::from_secs(2), 1 << 20)
                    .map(|done| done.peer);
                // The connection ends with the answerer.
                drop(theirs);
                answered
            });
            let dialed =
                prove_out(&dialing, &ours, Duration::from_secs(2), 1 << 20).map(|done| done.peer);
            (dialed, answer.join().unwrap())
        })
    }

    #[test]
    fn a_peer_of_the_other_method_is_refused_by_an_error_naming_both() {
        for (dialing, answering) in [
            (Method::WebCrypto, Method::Noise),
            (Method::Noise, Method::WebCrypto),
        ] {
            let (dialed, answered) = across(dialing, answering);
            let Err(Error::OtherMethod { peer, ours }) = answered else {
                panic!("{answering} answered {dialing}: {answered:?}");
            };
            assert_eq!((peer, ours), (dialing, answering));
            let why = Error::OtherMethod { peer, ours }.to_string();
            assert!(
                why.contains(&format!("the peer proves by {dialing}"))
                    && why.contains(&format!("only by {answering}")),
                "{why}"
            );
            // Nothing answers it, so the side that connected sees the connection end.
            assert!(matches!(dialed, Err(Error::Channel(_))), "{dialed:?}");
        }
        for method in Method::ALL {
            let (dialed, answered) = across(method, method);
            assert!(dialed.is_ok() && answered.is_ok(), "{method}");
        }
    }

    #[test]
    fn a_message_of_neither_method_is_not_named_as_either() {
        assert_eq!(other_method("noise", b"{\"x\":1}"), None);
        assert_eq!(other_method("webcrypto", &[b'{'; 32]), None);
        assert_eq!(other_method("noise", &[0; 32]), None);
        assert_eq!(other_method("webcrypto", &[0; 33]), None);
        assert_eq!(other_method("webcrypto", &[0; 32]), Some(Method::Noise));
        assert_eq!(
            other_method(
                "noise",
                b"{\"profile\":\"dev.boriken.coqui.peer-webcrypto/v1\"}"
            ),
            Some(Method::WebCrypto)
        );
    }

    #[test]
    fn an_identity_file_is_read_as_its_keys_method_and_never_used_for_the_other() {
        let dir = std::env::temp_dir().join(format!(
            "coqui-agentic-peer-auth-{}-{:?}",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for method in Method::ALL {
            let path = dir.join(method.name());
            let id = create_identity(&path, method).unwrap();
            let read = read_identity(&path).unwrap();
            assert_eq!((read.method(), read.peer_id()), (method, id));
            assert_eq!(Method::of_key(&read.key_material()), Some(method));
            assert!(create_identity(&path, method).is_err(), "replaced");
            let other = Method::ALL.into_iter().find(|m| *m != method).unwrap();
            let Err(Error::Identity(why)) = Identity::open_or_create(&path, other) else {
                panic!("a {method} key served {other}");
            };
            assert!(
                why.contains(&format!("proves by {method}, not {other}")),
                "{why}"
            );
            assert_eq!(
                Identity::open_or_create(&path, method).unwrap().peer_id(),
                id
            );
        }
        let made = dir.join("made");
        let identity = Identity::open_or_create(&made, Method::Noise).unwrap();
        assert_eq!(read_identity(&made).unwrap().peer_id(), identity.peer_id());
        std::fs::write(
            dir.join("junk"),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(matches!(
            read_identity(&dir.join("junk")),
            Err(Error::Identity(_))
        ));
        assert!(matches!(Identity::read(&dir.join("absent")), Ok(None)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_method_reads_only_its_own_name() {
        assert_eq!("noise".parse::<Method>().unwrap(), Method::Noise);
        assert_eq!("webcrypto".parse::<Method>().unwrap(), Method::WebCrypto);
        for wrong in ["", "Noise", "p256-spki", "noise "] {
            assert!(wrong.parse::<Method>().is_err(), "{wrong}");
        }
    }

    #[test]
    fn settings_are_each_methods_and_non_defaults_show() {
        for method in Method::ALL {
            let proof = || Proof::builder(Identity::generate(method).unwrap());
            assert!(
                proof().build().unwrap().non_defaults().is_empty(),
                "{method}"
            );
            assert!(
                !proof()
                    .key_limit(u64::MAX)
                    .build()
                    .unwrap()
                    .non_defaults()
                    .is_empty(),
                "{method}"
            );
            assert!(
                proof()
                    .rekey(false)
                    .build()
                    .map_or(true, |proof| proof.non_defaults().len() <= 1)
            );
        }
        let webcrypto = Proof::builder(Identity::generate(Method::WebCrypto).unwrap());
        assert!(matches!(
            webcrypto.rekey(true).build(),
            Err(Error::Proof(_))
        ));
        let noise = Proof::builder(Identity::generate(Method::Noise).unwrap());
        assert_eq!(noise.rekey(false).build().unwrap().non_defaults().len(), 1);
    }

    #[test]
    fn a_record_fits_the_limit_whatever_key_limit_its_sender_runs() {
        const MESSAGE: usize = 16 * 1024 * 1024;
        let dialer = Identity::generate(Method::Noise).unwrap();
        let answerer = Identity::generate(Method::Noise).unwrap();
        let (dialer_id, answerer_id) = (dialer.peer_id(), answerer.peer_id());
        // A sender changing keys every MiB puts a key change in front of many parts of one record.
        let dialing = Proof::builder(dialer)
            .key_limit(1 << 20)
            .responders(Trust::pinned([answerer_id]))
            .build()
            .unwrap();
        let answering = Proof::builder(answerer)
            .initiators(Trust::pinned([dialer_id]))
            .build()
            .unwrap();
        let (ours, theirs) = wires();
        let ours = thread::scope(|scope| {
            let answer = scope.spawn(|| prove(&answering, &theirs, LIMIT, 1 << 20).unwrap());
            let dialed = prove_out(&dialing, &ours, LIMIT, 1 << 20).unwrap().session;
            drop(answer.join().unwrap());
            dialed
        });
        let link = Fills::default();
        let sealed = Sealed::new(&link, ours);
        sealed.send(&vec![7; MESSAGE]).unwrap();
        let taken = link.taken.lock().unwrap().clone();
        assert!(
            taken[0].len() <= Method::Noise.record_length(MESSAGE),
            "{} over",
            taken[0].len() - Method::Noise.record_length(MESSAGE)
        );
    }

    #[test]
    fn an_identity_that_cannot_be_written_says_why() {
        let dir = std::env::temp_dir().join(format!(
            "coqui-agentic-peer-unwritable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A file where the parent directory should be.
        std::fs::write(dir.join("parent"), b"").unwrap();
        let path = dir.join("parent").join("identity");
        let Err(Error::Identity(why)) = Identity::open_or_create(&path, Method::Noise) else {
            panic!("an identity was made under a file");
        };
        assert!(!why.contains("could not be written"), "{why}");
        // The system's own words, which differ by platform: Windows cannot find the path, Linux finds no directory.
        assert!(why.contains("(os error "), "{why} gives no system error");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_handshake_limit_noise_cannot_apply_is_refused() {
        let noise = Proof::builder(Identity::generate(Method::Noise).unwrap());
        assert!(matches!(
            noise.max_message(4096).build(),
            Err(Error::Proof(_))
        ));
        let webcrypto = Proof::builder(Identity::generate(Method::WebCrypto).unwrap());
        assert!(webcrypto.max_message(4096).build().is_ok());
    }
}
