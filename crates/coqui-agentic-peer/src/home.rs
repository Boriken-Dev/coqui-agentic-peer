//! Where this user's identity and trust store live, so one pairing serves every program and every capability. Anything can name
//! other paths, and a program that does has a pairing of its own.
//!
//! Each method's identity has its own file, so one key is never used by both, and the trust store holds keys of either, each
//! under its method. A program that names no method gets the identity this user already has; a user with none gets
//! [`Method::DEFAULT`]'s, and one with both has to choose.

use std::path::{Path, PathBuf};

use coqui_peer_webcrypto::TrustStore;

use crate::Error;
use crate::auth::{Identity, Method};

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

/// The file name of a method's identity in this user's directory: `identity` for WebCrypto, where it has always been, and
/// `identity-noise` for Noise.
#[must_use]
pub const fn identity_file(method: Method) -> &'static str {
    match method {
        Method::WebCrypto => "identity",
        Method::Noise => "identity-noise",
    }
}

/// The path of this user's identity of `method`.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn identity_path(method: Method) -> Result<PathBuf, Error> {
    inside(identity_file(method))
}

/// The directory of this user's trust store.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn store_path() -> Result<PathBuf, Error> {
    inside("peers")
}

/// The file of this user's grants, which [`crate::peers::FilePeers`] reads.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn grants_path() -> Result<PathBuf, Error> {
    inside("grants.json")
}

/// The methods this user has an identity of, without reading the keys.
///
/// # Errors
///
/// [`Error::Identity`] when no directory can be worked out for this user.
pub fn methods() -> Result<Vec<Method>, Error> {
    let mut found = Vec::new();
    for method in Method::ALL {
        if identity_path(method)?.exists() {
            found.push(method);
        }
    }
    Ok(found)
}

/// An identity, made the first time it is needed, with parent directories.
///
/// - With `path`: the key there, whose type is its method; a new one of `method`, or [`Method::DEFAULT`], when there is none.
/// - Without: this user's identity of `method`. With no method either, the one this user has, or a new one of
///   [`Method::DEFAULT`] when they have none.
///
/// An identity never changes method: a key of another method than the one named is refused.
///
/// # Errors
///
/// [`Error::Identity`] when it cannot be read or written, when it is of another method than `method`, or when no method is
/// named and this user has identities of both. The message never quotes the file.
pub fn identity(path: Option<&Path>, method: Option<Method>) -> Result<Identity, Error> {
    if let Some(path) = path {
        return match (Identity::read(path)?, method) {
            (Some(found), Some(method)) => found.of_method(method),
            (Some(found), None) => Ok(found),
            (None, method) => Identity::open_or_create(path, method.unwrap_or(Method::DEFAULT)),
        };
    }
    let home =
        dir().ok_or_else(|| Error::Identity("no home directory for this user".to_owned()))?;
    in_home(&home, method)
}

fn in_home(home: &Path, method: Option<Method>) -> Result<Identity, Error> {
    let method = match method {
        Some(method) => method,
        None => {
            let held: Vec<Method> = Method::ALL
                .into_iter()
                .filter(|method| home.join(identity_file(*method)).exists())
                .collect();
            match held.as_slice() {
                [] => Method::DEFAULT,
                [only] => *only,
                _ => {
                    return Err(Error::Identity(
                        "this user has an identity of each method: name the one to use".to_owned(),
                    ));
                }
            }
        }
    };
    Identity::open_or_create(&home.join(identity_file(method)), method)
}

/// The trust store at `path`, or this user's. It holds keys of both methods, each under its own.
///
/// # Errors
///
/// [`Error::Identity`] when it cannot be opened.
pub fn store(path: Option<&Path>) -> Result<TrustStore, Error> {
    let path = path.map_or_else(store_path, |path| Ok(path.to_owned()))?;
    TrustStore::open(&path).map_err(|error| Error::Identity(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coqui-agentic-peer-home-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn each_method_has_its_own_file() {
        assert_eq!(identity_file(Method::WebCrypto), "identity");
        assert_eq!(identity_file(Method::Noise), "identity-noise");
    }

    #[test]
    fn a_named_path_keeps_its_keys_method() {
        let dir = fresh("path");
        let path = dir.join("key");
        let made = identity(Some(&path), Some(Method::Noise)).unwrap();
        assert_eq!(made.method(), Method::Noise);
        assert_eq!(
            identity(Some(&path), None).unwrap().peer_id(),
            made.peer_id()
        );
        assert!(identity(Some(&path), Some(Method::WebCrypto)).is_err());
        let default = identity(Some(&dir.join("other")), None).unwrap();
        assert_eq!(default.method(), Method::DEFAULT);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_user_keeps_the_method_they_have_and_chooses_when_they_have_both() {
        let home = fresh("user");
        // Nothing yet: the default.
        let first = in_home(&home, None).unwrap();
        assert_eq!(first.method(), Method::DEFAULT);
        assert_eq!(in_home(&home, None).unwrap().peer_id(), first.peer_id());
        // An existing WebCrypto identity is kept whatever the default is.
        let old = fresh("user-old");
        let kept = in_home(&old, Some(Method::WebCrypto)).unwrap();
        assert_eq!(in_home(&old, None).unwrap().peer_id(), kept.peer_id());
        // Naming the other method makes its own file and leaves the first alone.
        let moved = in_home(&old, Some(Method::Noise)).unwrap();
        assert_eq!(moved.method(), Method::Noise);
        assert_ne!(moved.peer_id(), kept.peer_id());
        assert_eq!(
            in_home(&old, Some(Method::WebCrypto)).unwrap().peer_id(),
            kept.peer_id()
        );
        // With both, nothing picks one.
        let Err(Error::Identity(why)) = in_home(&old, None) else {
            panic!("a method was picked for a user holding both");
        };
        assert!(why.contains("each method"), "{why}");
        std::fs::remove_dir_all(&home).unwrap();
        std::fs::remove_dir_all(&old).unwrap();
    }
}
