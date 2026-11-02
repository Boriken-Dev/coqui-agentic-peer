//! Who a peer is to this host, beyond a key: what it may open, and what the host says about it. A key is one entry, so a new
//! capability is a grant on that entry and never another pairing.
//!
//! [`PeerStore`] is a trait so a host can keep this in its own registry, such as several gateways sharing state, with no file, no
//! prompt and no per-user directory involved. [`FilePeers`] and [`MemoryPeers`] are for the rest.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value, json};

use crate::Error;

/// A file larger than this is not one this wrote.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// What this host knows about one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerRecord {
    /// The peer id.
    pub peer: String,
    /// What the host set at enrolment, such as a Station id or a role. The link never interprets these, and hands them to each
    /// service, so a host derives who is speaking from the pairing rather than from what a peer says.
    pub claims: BTreeMap<String, String>,
    /// The protocol tokens this peer may open.
    pub grants: BTreeSet<String>,
}

impl PeerRecord {
    /// A record with no claims and no grants.
    #[must_use]
    pub fn new(peer: &str) -> Self {
        Self {
            peer: peer.to_owned(),
            ..Self::default()
        }
    }

    /// With this protocol granted.
    #[must_use]
    pub fn granting(mut self, protocol: &str) -> Self {
        self.grants.insert(protocol.to_owned());
        self
    }

    /// With this claim.
    #[must_use]
    pub fn claiming(mut self, name: &str, value: &str) -> Self {
        self.claims.insert(name.to_owned(), value.to_owned());
        self
    }
}

/// Where a host keeps its peers. Only this needs to survive a restart: nothing about a live link does.
pub trait PeerStore: Send + Sync {
    /// The record of a peer. An error is treated as a refusal, since a store that cannot be read must not keep a link alive.
    ///
    /// # Errors
    ///
    /// When the store cannot say.
    fn get(&self, peer: &str) -> Result<Option<PeerRecord>, Error>;

    /// Writes a record, replacing any before it.
    ///
    /// # Errors
    ///
    /// When it cannot be kept.
    fn put(&self, record: &PeerRecord) -> Result<(), Error>;

    /// Removes a record. One that is not there is not a failure.
    ///
    /// # Errors
    ///
    /// When it cannot be removed.
    fn remove(&self, peer: &str) -> Result<(), Error>;
}

/// What happened, with no payload, for a host's audit log. Never a token, a message or metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A peer proved itself and the link came up.
    LinkUp {
        /// The peer.
        peer: String,
    },
    /// A link ended.
    LinkDown {
        /// The peer.
        peer: String,
    },
    /// A protocol was opened and served.
    Opened {
        /// The peer.
        peer: String,
        /// The protocol.
        protocol: String,
    },
    /// A protocol was refused.
    Refused {
        /// The peer.
        peer: String,
        /// The protocol.
        protocol: String,
    },
    /// A protocol being served was taken away.
    Revoked {
        /// The peer.
        peer: String,
        /// The protocol.
        protocol: String,
    },
}

/// Receives [`Event`]s. It runs on the link's own thread, so it must not wait on anything slow.
pub trait Events: Send + Sync {
    /// One event.
    fn event(&self, event: &Event);
}

/// For a host with no audit log.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl Events for NoEvents {
    fn event(&self, _event: &Event) {}
}

/// Peers in memory, for a host that fills them from somewhere else, and for tests.
#[derive(Debug, Default)]
pub struct MemoryPeers(Mutex<BTreeMap<String, PeerRecord>>);

impl PeerStore for MemoryPeers {
    fn get(&self, peer: &str) -> Result<Option<PeerRecord>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(peer)
            .cloned())
    }

    fn put(&self, record: &PeerRecord) -> Result<(), Error> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(record.peer.clone(), record.clone());
        Ok(())
    }

    fn remove(&self, peer: &str) -> Result<(), Error> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(peer);
        Ok(())
    }
}

/// Peers in one JSON file, read on every question, so a grant made by another process counts at once. Writes within a process take
/// turns; two processes writing at the same moment can lose one of them, which a person granting by hand does not do.
#[derive(Debug)]
pub struct FilePeers {
    path: PathBuf,
    writing: Mutex<()>,
}

impl FilePeers {
    /// The file at `path`, which need not exist yet.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writing: Mutex::new(()),
        }
    }

    fn read_all(&self) -> Result<BTreeMap<String, PeerRecord>, Error> {
        let fail =
            |why: String| Error::Identity(format!("the peers file could not be read: {why}"));
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) => return Err(fail(error.to_string())),
        };
        let mut text = String::new();
        file.take(MAX_FILE)
            .read_to_string(&mut text)
            .map_err(|error| fail(error.to_string()))?;
        let value: Value =
            serde_json::from_str(&text).map_err(|_| fail("it is not JSON".to_owned()))?;
        let peers = value
            .get("peers")
            .and_then(Value::as_object)
            .ok_or_else(|| fail("it has no peers".to_owned()))?;
        Ok(peers
            .iter()
            .map(|(peer, entry)| (peer.clone(), record_from(peer, entry)))
            .collect())
    }

    fn write_all(&self, all: &BTreeMap<String, PeerRecord>) -> Result<(), Error> {
        let fail = |error: io::Error| {
            Error::Identity(format!("the peers file could not be written: {error}"))
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        let peers: Map<String, Value> = all
            .iter()
            .map(|(peer, record)| {
                (
                    peer.clone(),
                    json!({ "claims": record.claims, "grants": record.grants }),
                )
            })
            .collect();
        let unfinished = unfinished_path(&self.path);
        let _ = std::fs::remove_file(&unfinished);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(&unfinished)
            .and_then(|mut file| file.write_all(json!({ "peers": peers }).to_string().as_bytes()))
            .map_err(fail)?;
        std::fs::rename(&unfinished, &self.path).map_err(fail)
    }
}

fn unfinished_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn record_from(peer: &str, entry: &Value) -> PeerRecord {
    let claims = entry
        .get("claims")
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .iter()
                .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let grants = entry
        .get("grants")
        .and_then(Value::as_array)
        .map(|grants| {
            grants
                .iter()
                .filter_map(|grant| grant.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    PeerRecord {
        peer: peer.to_owned(),
        claims,
        grants,
    }
}

impl PeerStore for FilePeers {
    fn get(&self, peer: &str) -> Result<Option<PeerRecord>, Error> {
        Ok(self.read_all()?.remove(peer))
    }

    fn put(&self, record: &PeerRecord) -> Result<(), Error> {
        let _turn = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut all = self.read_all()?;
        all.insert(record.peer.clone(), record.clone());
        self.write_all(&all)
    }

    fn remove(&self, peer: &str) -> Result<(), Error> {
        let _turn = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut all = self.read_all()?;
        if all.remove(peer).is_some() {
            self.write_all(&all)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(store: &dyn PeerStore) {
        assert_eq!(store.get("a").unwrap(), None);
        let record = PeerRecord::new("a")
            .granting("acp/1")
            .claiming("station_id", "s1");
        store.put(&record).unwrap();
        assert_eq!(store.get("a").unwrap(), Some(record.clone()));
        store.put(&record.clone().granting("mcp")).unwrap();
        assert!(store.get("a").unwrap().unwrap().grants.contains("mcp"));
        store.remove("a").unwrap();
        store.remove("a").unwrap();
        assert_eq!(store.get("a").unwrap(), None);
    }

    #[test]
    fn memory_and_file_keep_the_same_promises() {
        exercise(&MemoryPeers::default());
        let dir =
            std::env::temp_dir().join(format!("coqui-agentic-peer-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        exercise(&FilePeers::new(dir.join("deep/peers.json")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_grant_made_by_another_process_counts_at_once() {
        let dir =
            std::env::temp_dir().join(format!("coqui-agentic-peer-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("peers.json");
        let reading = FilePeers::new(&path);
        assert_eq!(reading.get("a").unwrap(), None);
        FilePeers::new(&path)
            .put(&PeerRecord::new("a").granting("mcp"))
            .unwrap();
        assert!(reading.get("a").unwrap().unwrap().grants.contains("mcp"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_it_cannot_read_is_an_error_not_an_empty_store() {
        let dir =
            std::env::temp_dir().join(format!("coqui-agentic-peer-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(FilePeers::new(&path).get("a").is_err());
        assert!(
            FilePeers::new(&path).put(&PeerRecord::new("a")).is_err(),
            "and nothing is overwritten"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
