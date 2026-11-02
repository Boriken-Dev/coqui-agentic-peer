//! Where this user's identity and trust store live, so one pairing serves every program and every capability. Anything can name
//! other paths, and a program that does has a pairing of its own.

use std::path::{Path, PathBuf};

use coqui_peer_webcrypto::{Identity, TrustStore};

use crate::Error;

/// Overrides the whole directory, for a second identity on one account, and for tests.
pub const HOME_ENV: &str = "COQUI_AGENTIC_PEER_HOME";

fn var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// This user's directory: `$COQUI_AGENTIC_PEER_HOME`, or `coqui-agentic-peer` under `%LOCALAPPDATA%`, `$XDG_CONFIG_HOME` or
/// `~/.config`, the first that is set.
#[must_use]
pub fn dir() -> Option<PathBuf> {
    var(HOME_ENV).or_else(|| {
        let base = var("LOCALAPPDATA")
            .or_else(|| var("XDG_CONFIG_HOME"))
            .or_else(|| var("HOME").map(|home| home.join(".config")))?;
        Some(base.join("coqui-agentic-peer"))
    })
}

fn inside(name: &str) -> Result<PathBuf, Error> {
    dir()
        .map(|dir| dir.join(name))
        .ok_or_else(|| Error::Identity("no home directory for this user".to_owned()))
}

/// The path of this user's identity.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn identity_path() -> Result<PathBuf, Error> {
    inside("identity")
}

/// The directory of this user's trust store.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn store_path() -> Result<PathBuf, Error> {
    inside("peers")
}

/// The identity at `path`, or this user's, made the first time it is needed. Parent directories are created.
///
/// # Errors
///
/// [`Error::Identity`] when it cannot be read or written. The message never quotes the file.
pub fn identity(path: Option<&Path>) -> Result<Identity, Error> {
    let path = path.map_or_else(identity_path, |path| Ok(path.to_owned()))?;
    Identity::open_or_create(&path).map_err(|error| Error::Identity(error.to_string()))
}

/// The trust store at `path`, or this user's.
///
/// # Errors
///
/// [`Error::Identity`] when it cannot be opened.
pub fn store(path: Option<&Path>) -> Result<TrustStore, Error> {
    let path = path.map_or_else(store_path, |path| Ok(path.to_owned()))?;
    TrustStore::open(&path).map_err(|error| Error::Identity(error.to_string()))
}
