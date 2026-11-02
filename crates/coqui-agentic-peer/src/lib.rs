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
pub mod home;
pub mod link;
pub mod mux;
pub mod pairing;
pub mod peers;

use core::fmt;

/// What went wrong on a link.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The network channel failed.
    Channel(coqui_web::Failure),
    /// A peer failed its identity proof, or its proof could not be completed.
    Proof(String),
    /// A key, identity file or trust store could not be used.
    Identity(String),
    /// A peer could not be advertised or searched for, or the companion could not be installed.
    Discovery(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(failure) => write!(f, "the channel failed: {failure}"),
            Self::Proof(why) => write!(f, "the peer was not proven: {why}"),
            Self::Identity(why) => write!(f, "the identity could not be used: {why}"),
            Self::Discovery(why) => write!(f, "discovery failed: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<coqui_web::Failure> for Error {
    fn from(failure: coqui_web::Failure) -> Self {
        Self::Channel(failure)
    }
}
