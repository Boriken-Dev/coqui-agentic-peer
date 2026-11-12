//! A proven link between two peers, and what runs over it: pair once, then Agent Client Protocol, A2A, MCP or anything else, each
//! as a capability on the same link, with no second pairing. It adds finding and reaching a peer, never a dialect: what crosses a
//! stream is that protocol's own messages.
//!
//! Each language's capability libraries sit on this one, which holds the proof, the pairing, the channels and discovery once.
#![forbid(unsafe_code)]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

pub mod auth;
pub mod companion;
pub mod discovery;
pub mod forward;
pub mod home;
pub mod link;
pub mod mcp_offer;
pub mod mux;
pub mod pairing;
pub mod peers;

use core::fmt;

/// What went wrong on a link.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The network channel failed.
    Channel(coqui_transport::Failure),
    /// A peer failed its identity proof, or its proof could not be completed.
    Proof(String),
    /// A key, identity file or trust store could not be used.
    Identity(String),
    /// A peer could not be advertised or searched for, or the companion could not be installed.
    Discovery(String),
    /// The peer's first message shows it proves by another method than this endpoint, which never tries that one.
    OtherMethod {
        /// The method the peer's message shows.
        peer: auth::Method,
        /// This endpoint's.
        ours: auth::Method,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(failure) => write!(f, "the channel failed: {failure}"),
            Self::Proof(why) => write!(f, "the peer was not proven: {why}"),
            Self::Identity(why) => write!(f, "the identity could not be used: {why}"),
            Self::Discovery(why) => write!(f, "discovery failed: {why}"),
            Self::OtherMethod { peer, ours } => write!(
                f,
                "the peer was not proven: the peer proves by {peer}, and this endpoint only by {ours}: a method is chosen per endpoint, never per connection"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<coqui_transport::Failure> for Error {
    fn from(failure: coqui_transport::Failure) -> Self {
        Self::Channel(failure)
    }
}
