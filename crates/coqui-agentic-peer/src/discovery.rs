//! Finding agents: DNS-SD records on the link, and descriptor files for agents on this machine, which no multicast answer can
//! name for others. Everything found here is a hint from whoever could send it: [`Candidate::peer`] says what a key is claimed to
//! be, and only a proof at connect shows who holds it.
//!
//! The record is specified in the page contract, `docs/browser.md`.

use core::fmt;
use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde_json::{Value, json};
use url::{Host, Url};

use crate::Error;
use crate::auth::Method;

/// The DNS-SD service type, provisional until `acp-agent` is registered with IANA.
pub const SERVICE_TYPE: &str = "_acp-agent._tcp.local.";
/// A path nothing was said about in a record.
pub const DEFAULT_PATH: &str = "/acp";
/// Overrides where descriptors are kept.
pub const DESCRIPTORS_ENV: &str = "COQUI_ACP_DESCRIPTORS";
/// Candidates one search reports: anyone on the link can send records, and a native message is limited to 1 MB.
pub const MAX_CANDIDATES: usize = 64;

/// The longest instance name DNS can carry, in bytes.
const MAX_LABEL: usize = 63;
const MAX_PATH: usize = 128;
const MAX_HOST: usize = 253;
/// A URL once parsing has percent-encoded it, which can triple a path.
const MAX_URL: usize = 512;
const MAX_VERSIONS: usize = 8;
const MAX_OFFERS: usize = 16;
/// Directory entries looked at in one search, whatever else is in the directory.
const MAX_DESCRIPTOR_FILES: usize = 256;
const MAX_DESCRIPTOR_BYTES: u64 = 8 * 1024;
/// What one search may spend on descriptors, whatever is in the directory: each dead one can cost [`LIVENESS`].
const DESCRIPTORS_BUDGET: Duration = Duration::from_secs(5);
/// Longer than Windows takes to report a refused loopback port, about 2 s, so a dead agent is told from a slow answer.
const LIVENESS: Duration = Duration::from_secs(3);

/// Where a candidate was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// A DNS-SD record on the link, which anyone there can send.
    Network,
    /// A descriptor in this user's own directory.
    ThisMachine,
}

impl Source {
    const fn name(self) -> &'static str {
        match self {
            Self::Network => "dns-sd",
            Self::ThisMachine => "local",
        }
    }
}

/// An agent somebody claims is there.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// What it calls itself, with control characters removed. Trust it no further than any other text from a stranger.
    pub label: String,
    /// Where to connect: `wss://`, or `ws://` on loopback.
    pub url: String,
    /// The peer id it claims, if it claimed a well-formed one.
    pub peer: Option<String>,
    /// The method that key proves by, as the record says: a record that names none is WebCrypto's, the only method before
    /// records named one. A false method only fails the proof, since a peer id names a key of one type.
    pub method: Method,
    /// Where it was found.
    pub source: Source,
    /// A UDP port claimed to serve WebTransport on the same host.
    pub webtransport: Option<u16>,
    /// The hash of its short-lived certificate, for a browser to open that WebTransport. A hint like the rest: the proof at
    /// connect is what authenticates, so a false one only fails to open.
    pub webtransport_hash: Option<String>,
    /// ACP versions it claims.
    pub acp_versions: Vec<u32>,
    /// Protocol tokens it says it serves over one link. A hint: what a peer may open is what the link's own document says.
    pub offers: Vec<String>,
}

impl Candidate {
    /// The form `discover` prints and the companion sends.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "label": self.label,
            "url": self.url,
            "peer": self.peer,
            "method": self.method.name(),
            "source": self.source.name(),
            "webtransport": self.webtransport,
            "webtransportHash": self.webtransport_hash,
            "acpVersions": self.acp_versions,
            "offers": self.offers,
        })
    }
}

/// What a `serve` says about itself.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Advertisement {
    /// The name people see.
    pub label: String,
    /// Whether the listener speaks TLS.
    pub tls: bool,
    /// The peer id its proof shows, when it has one.
    pub peer: Option<String>,
    /// The method its proof runs: [`Method::DEFAULT`] unless set.
    pub method: Method,
    /// A UDP port serving WebTransport.
    pub webtransport: Option<u16>,
    /// The hash of the certificate it serves, when a browser can pin that.
    pub webtransport_hash: Option<String>,
    /// A host name to publish, for a certificate a browser accepts. Without it, clients get an address.
    pub host: Option<String>,
    /// Protocol tokens served over one link. It tells the link what runs here, so list only what the operator means to say.
    pub offers: Vec<String>,
}

impl Advertisement {
    /// A checked advertisement.
    ///
    /// # Errors
    /// [`Error::Discovery`] when the label cannot be carried, or the host is not a host name.
    pub fn new(label: &str, tls: bool) -> Result<Self, Error> {
        if label.is_empty() || label.len() > MAX_LABEL || label.chars().any(hidden) {
            return Err(Error::Discovery(format!(
                "a label is 1 to {MAX_LABEL} bytes with no control or format characters"
            )));
        }
        Ok(Self {
            label: label.to_owned(),
            tls,
            peer: None,
            method: Method::DEFAULT,
            webtransport: None,
            webtransport_hash: None,
            host: None,
            offers: Vec::new(),
        })
    }

    /// The peer id its proof shows.
    #[must_use]
    pub fn with_peer(mut self, peer: Option<String>) -> Self {
        self.peer = peer;
        self
    }

    /// The method its proof runs, which a client connects by.
    #[must_use]
    pub const fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// The UDP port serving WebTransport.
    #[must_use]
    pub const fn with_webtransport(mut self, port: Option<u16>) -> Self {
        self.webtransport = port;
        self
    }

    /// The protocol tokens to say this serves, leaving out what could not go in a record.
    #[must_use]
    pub fn with_offers(mut self, offers: &[String]) -> Self {
        self.offers = offers
            .iter()
            .filter(|offer| crate::mux::valid_protocol(offer))
            .take(MAX_OFFERS)
            .cloned()
            .collect();
        self
    }

    /// The hash of the certificate it serves.
    #[must_use]
    pub fn with_webtransport_hash(mut self, hash: Option<String>) -> Self {
        self.webtransport_hash = hash;
        self
    }

    /// A host name to publish.
    ///
    /// # Errors
    /// [`Error::Discovery`] when it is not a host name.
    pub fn with_host(mut self, host: Option<String>) -> Result<Self, Error> {
        if let Some(name) = &host
            && !valid_host(name)
        {
            return Err(Error::Discovery("that is not a host name".to_owned()));
        }
        self.host = host;
        Ok(self)
    }

    fn txt(&self) -> HashMap<String, String> {
        let mut txt = HashMap::from([
            ("txtvers".to_owned(), "1".to_owned()),
            ("proto".to_owned(), "acp".to_owned()),
            ("path".to_owned(), DEFAULT_PATH.to_owned()),
            ("method".to_owned(), self.method.name().to_owned()),
        ]);
        if self.tls {
            txt.insert("tls".to_owned(), "1".to_owned());
        }
        if let Some(port) = self.webtransport {
            txt.insert("wt".to_owned(), port.to_string());
        }
        if let Some(hash) = &self.webtransport_hash {
            txt.insert("wth".to_owned(), hash.clone());
        }
        if let Some(peer) = &self.peer {
            txt.insert("peer".to_owned(), peer.clone());
        }
        if !self.offers.is_empty() {
            txt.insert("offers".to_owned(), self.offers.join(","));
        }
        txt
    }
}

fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// Control characters, and the format characters that hide part of a name or reorder what is shown around it.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{ad}' | '\u{61c}' | '\u{180e}' | '\u{feff}'
            | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{fff9}'..='\u{fffb}')
}

fn clean_label(raw: &str) -> Option<String> {
    let label: String = raw.chars().filter(|c| !hidden(*c)).collect();
    let label = label.trim();
    if label.is_empty() {
        return None;
    }
    let mut end = label.len().min(MAX_LABEL);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    Some(label[..end].to_owned())
}

fn clean_peer(raw: Option<&str>) -> Option<String> {
    let text = raw?;
    text.parse::<coqui_peer_webcrypto::PeerId>()
        .ok()
        .map(|_| text.to_owned())
}

fn clean_path(raw: Option<&str>) -> Option<String> {
    let path = raw.unwrap_or(DEFAULT_PATH);
    let fine = path.starts_with('/')
        && path.len() <= MAX_PATH
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#');
    fine.then(|| path.to_owned())
}

/// A record's method: none named is WebCrypto's; one this version does not know makes the record unusable.
fn clean_method(raw: Option<&str>) -> Option<Method> {
    raw.map_or(Some(Method::WebCrypto), |name| name.parse().ok())
}

fn clean_offers(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(',')
        .filter(|offer| crate::mux::valid_protocol(offer))
        .take(MAX_OFFERS)
        .map(str::to_owned)
        .collect()
}

fn clean_versions(raw: Option<&str>) -> Vec<u32> {
    raw.unwrap_or("")
        .split(',')
        .filter_map(|text| text.trim().parse().ok())
        .take(MAX_VERSIONS)
        .collect()
}

fn usable_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.octets()[0] == 0)
}

/// An address worth giving a client. A record naming this machine would point a person at a service of their own, a link-local
/// one needs a scope no URL carries, and an IPv4 address inside an IPv6 one reaches the same place, so it answers the same.
fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => usable_v4(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if octets[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
                return usable_v4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ));
            }
            if let Some(v4) = v6.to_ipv4() {
                return usable_v4(v4);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local())
        }
    }
}

/// Whether a URL's host, as URL parsing normalized it, is one a record may name. A single label is a name on this machine's own
/// network, not something a certificate for the record's agent would be issued for.
fn usable_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => usable(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => usable(IpAddr::V6(ip)),
        Some(Host::Domain(name)) => {
            let name = name.to_ascii_lowercase();
            name.contains('.') && !name.ends_with(".localhost") && name != "localhost"
        }
        None => false,
    }
}

/// One DNS-SD answer, as it came off the wire.
#[derive(Debug)]
pub struct Record<'a> {
    /// The instance name.
    pub instance: &'a str,
    /// The SRV target.
    pub host: &'a str,
    /// The addresses given for it.
    pub addresses: Vec<IpAddr>,
    /// The SRV port.
    pub port: u16,
    /// The TXT keys, in lower case, since DNS-SD ignores their case.
    pub txt: &'a HashMap<String, String>,
}

/// Reads an answer, which anyone on the link can send. `None` for one this version does not understand, for one that says it
/// is plain beyond loopback, which no client may use, for one naming no key, which nothing could then prove, and for one naming
/// nothing usable.
#[must_use]
pub fn candidate_from(record: &Record<'_>) -> Option<Candidate> {
    let txt = |key: &str| record.txt.get(key).map(String::as_str);
    if txt("txtvers") != Some("1") || txt("proto") != Some("acp") || record.port == 0 {
        return None;
    }
    if txt("tls") != Some("1") {
        return None;
    }
    let label = clean_label(record.instance)?;
    let peer = clean_peer(txt("peer"))?;
    let method = clean_method(txt("method"))?;
    let path = clean_path(txt("path"))?;
    let host = record.host.trim_end_matches('.');
    let authority = if host.to_ascii_lowercase().ends_with(".local") || !valid_host(host) {
        let mut addresses: Vec<IpAddr> = record
            .addresses
            .iter()
            .copied()
            .filter(|ip| usable(*ip))
            .collect();
        // The same answer gives the same address, and IPv4 first since a client is likelier to reach it.
        addresses.sort_by_key(|ip| (ip.is_ipv6(), *ip));
        SocketAddr::new(*addresses.first()?, record.port).to_string()
    } else {
        format!("{host}:{}", record.port)
    };
    let url = Url::parse(&format!("wss://{authority}{path}")).ok()?;
    if !usable_host(&url) || url.as_str().len() > MAX_URL {
        return None;
    }
    Some(Candidate {
        label,
        url: url.to_string(),
        peer: Some(peer),
        method,
        source: Source::Network,
        webtransport: txt("wt")
            .and_then(|port| port.parse().ok())
            .filter(|port| *port != 0),
        webtransport_hash: clean_peer(txt("wth")),
        acp_versions: clean_versions(txt("acpv")),
        offers: clean_offers(txt("offers")),
    })
}

/// This user's descriptor directory: only they can write there, so a descriptor is as good as anything else they run.
#[must_use]
pub fn descriptors_dir() -> Option<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    if let Some(dir) = var(DESCRIPTORS_ENV) {
        return Some(dir);
    }
    let base = var("LOCALAPPDATA")
        .or_else(|| var("XDG_RUNTIME_DIR"))
        .or_else(|| var("HOME").map(|home| home.join(".local").join("state")))?;
    Some(base.join("coqui-acp").join("agents"))
}

pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// What reading a descriptor directory found about who can write to it.
///
/// A descriptor is believed only because nobody else can write one, so a directory others can write to, which an override
/// can name, loses that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectoryCheck {
    /// Nobody but the owner can write to it.
    Private,
    /// Others can write to it (Unix: group or other write permission). Its descriptors were not read.
    SharedWithOthers,
    /// This platform's check was not made: on Windows `%LOCALAPPDATA%` belongs to its owner by default, and the ACLs are
    /// not read. Its descriptors were read.
    NotChecked,
}

/// The descriptors of a directory, and what was found about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Descriptors {
    /// Agents on this machine that are still there; empty when the directory is [`DirectoryCheck::SharedWithOthers`].
    pub candidates: Vec<Candidate>,
    /// Who can write to the directory. Nothing is printed: the application decides what this means.
    pub directory: DirectoryCheck,
}

fn check_directory(dir: &Path) -> DirectoryCheck {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(metadata) = std::fs::metadata(dir) {
            return if metadata.permissions().mode() & 0o022 == 0 {
                DirectoryCheck::Private
            } else {
                DirectoryCheck::SharedWithOthers
            };
        }
        DirectoryCheck::Private
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        DirectoryCheck::NotChecked
    }
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name == "localhost",
        None => false,
    }
}

fn candidate_from_descriptor(text: &str) -> Option<Candidate> {
    let value: Value = serde_json::from_str(text).ok()?;
    if value.get("txtvers").and_then(Value::as_u64) != Some(1)
        || value.get("proto").and_then(Value::as_str) != Some("acp")
    {
        return None;
    }
    let url = Url::parse(value.get("url")?.as_str()?).ok()?;
    // A user name in a URL shows one host and connects to another.
    if !matches!(url.scheme(), "ws" | "wss")
        || !is_loopback_host(&url)
        || url.as_str().len() > MAX_URL
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(Candidate {
        label: clean_label(value.get("label")?.as_str()?)?,
        url: url.to_string(),
        peer: clean_peer(value.get("peer").and_then(Value::as_str)),
        method: match value.get("method") {
            None | Some(Value::Null) => Method::WebCrypto,
            Some(name) => name.as_str()?.parse().ok()?,
        },
        source: Source::ThisMachine,
        webtransport: value
            .get("wt")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0),
        webtransport_hash: clean_peer(value.get("wth").and_then(Value::as_str)),
        acp_versions: clean_versions(value.get("acpv").and_then(Value::as_str)),
        offers: clean_offers(value.get("offers").and_then(Value::as_str)),
    })
}

fn listening(url: &str) -> bool {
    Url::parse(url)
        .and_then(|url| {
            url.socket_addrs(|| None)
                .map_err(|_| url::ParseError::InvalidPort)
        })
        .is_ok_and(|addresses| {
            addresses
                .iter()
                .any(|address| TcpStream::connect_timeout(address, LIVENESS).is_ok())
        })
}

/// Agents on this machine that are still there, and what was found about the directory. A descriptor nothing answers at is
/// left over from a `serve` that was killed, and is removed. A directory others can write to is not read.
#[must_use]
pub fn read_descriptors(dir: &Path) -> Descriptors {
    let directory = check_directory(dir);
    let mut found = Vec::new();
    if directory == DirectoryCheck::SharedWithOthers {
        return Descriptors {
            candidates: found,
            directory,
        };
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Descriptors {
            candidates: found,
            directory,
        };
    };
    let until = Instant::now() + DESCRIPTORS_BUDGET;
    let named = entries.flatten().filter(|entry| {
        entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
    });
    for entry in named.take(MAX_DESCRIPTOR_FILES) {
        if found.len() >= MAX_CANDIDATES || Instant::now() >= until {
            break;
        }
        // A regular file only: opening a FIFO would wait for a writer, and a link could name anything.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let path = entry.path();
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut text = String::new();
        if file
            .take(MAX_DESCRIPTOR_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }
        let Some(candidate) = candidate_from_descriptor(&text) else {
            continue;
        };
        if listening(&candidate.url) {
            found.push(candidate);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    Descriptors {
        candidates: found,
        directory,
    }
}

/// What one search found, and what it could not do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {
    /// The agents found, descriptors first.
    pub candidates: Vec<Candidate>,
    /// Who can write to the descriptor directory; `None` when no directory could be named.
    pub directory: Option<DirectoryCheck>,
    /// Why the link could not be searched, when it could not; the descriptors are still read.
    pub network_error: Option<String>,
}

/// Searches the link for `wait`, and reads this user's descriptors. An mDNS service that cannot start leaves the descriptors.
/// It prints nothing and says nothing of what it could not do; [`discover_report`] does.
#[must_use]
pub fn discover(wait: Duration) -> Vec<Candidate> {
    discover_report(wait).candidates
}

/// [`discover`], with what it found about the descriptor directory and why the link could not be searched.
#[must_use]
pub fn discover_report(wait: Duration) -> Discovery {
    let read = descriptors_dir().map(|dir| read_descriptors(&dir));
    let directory = read.as_ref().map(|read| read.directory);
    let mut found = read.map_or_else(Vec::new, |read| read.candidates);
    let mut network_error = None;
    match browse(wait) {
        Ok(network) => {
            for candidate in network {
                if found.len() >= MAX_CANDIDATES {
                    break;
                }
                if !found
                    .iter()
                    .any(|known| known.label == candidate.label && known.url == candidate.url)
                {
                    found.push(candidate);
                }
            }
        }
        Err(error) => network_error = Some(error.to_string()),
    }
    Discovery {
        candidates: found,
        directory,
        network_error,
    }
}

/// Searches the link for `wait`.
///
/// # Errors
/// [`Error::Discovery`] when the mDNS service cannot start.
pub fn browse(wait: Duration) -> Result<Vec<Candidate>, Error> {
    let daemon = ServiceDaemon::new().map_err(|error| Error::Discovery(error.to_string()))?;
    let events = daemon
        .browse(SERVICE_TYPE)
        .map_err(|error| Error::Discovery(error.to_string()))?;
    let suffix = format!(".{SERVICE_TYPE}");
    let until = Instant::now() + wait;
    // By instance, since one record arrives more than once, and an answer replaces the one before it.
    let mut found: HashMap<String, Candidate> = HashMap::new();
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        match events.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                let fullname = service.get_fullname();
                let instance = fullname
                    .strip_suffix(&suffix)
                    .unwrap_or(fullname)
                    .to_owned();
                if found.len() >= MAX_CANDIDATES && !found.contains_key(&instance) {
                    continue;
                }
                // The first of a repeated key counts, as RFC 6763 says.
                let mut txt = HashMap::new();
                for property in service.get_properties().iter() {
                    txt.entry(property.key().to_ascii_lowercase())
                        .or_insert_with(|| property.val_str().to_owned());
                }
                let record = Record {
                    instance: &instance,
                    host: service.get_hostname(),
                    addresses: service
                        .get_addresses()
                        .iter()
                        .map(mdns_sd::ScopedIp::to_ip_addr)
                        .collect(),
                    port: service.get_port(),
                    txt: &txt,
                };
                match candidate_from(&record) {
                    Some(candidate) => {
                        found.insert(instance, candidate);
                    }
                    None => {
                        found.remove(&instance);
                    }
                }
            }
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                found.remove(fullname.strip_suffix(&suffix).unwrap_or(&fullname));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    let mut list: Vec<Candidate> = found.into_values().collect();
    list.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.url.cmp(&b.url)));
    Ok(list)
}

/// A `serve`'s advertisement, for as long as this lasts.
pub struct Advertised(Published);

enum Published {
    Network(ServiceDaemon),
    Descriptor(PathBuf),
}

impl fmt::Debug for Advertised {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Published::Network(_) => "Advertised(network)",
            Published::Descriptor(_) => "Advertised(descriptor)",
        })
    }
}

impl Drop for Advertised {
    fn drop(&mut self) {
        match &self.0 {
            Published::Network(daemon) => {
                let _ = daemon.shutdown();
            }
            Published::Descriptor(path) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Says that a listener at `bound` exists: a DNS-SD record, or a descriptor when it is on loopback, which nothing on the link
/// could reach. Off unless asked for, since it tells everyone on the link that an agent exists.
///
/// # Errors
/// [`Error::Discovery`] when it could not be published.
pub fn advertise(advertisement: &Advertisement, bound: SocketAddr) -> Result<Advertised, Error> {
    if bound.ip().is_loopback() {
        return write_descriptor(advertisement, bound);
    }
    let fail = |error: mdns_sd::Error| Error::Discovery(error.to_string());
    let daemon = ServiceDaemon::new().map_err(fail)?;
    // Not the machine's name: nothing here needs it known, and it would tell the link more than the agent's label does.
    let host = advertisement.host.as_ref().map_or_else(
        || format!("acp-{}-{}.local.", std::process::id(), bound.port()),
        |name| format!("{}.", name.trim_end_matches('.')),
    );
    let txt = advertisement.txt();
    let info = if bound.ip().is_unspecified() {
        ServiceInfo::new(
            SERVICE_TYPE,
            &advertisement.label,
            &host,
            "",
            bound.port(),
            txt,
        )
        .map_err(fail)?
        .enable_addr_auto()
    } else {
        ServiceInfo::new(
            SERVICE_TYPE,
            &advertisement.label,
            &host,
            bound.ip(),
            bound.port(),
            txt,
        )
        .map_err(fail)?
    };
    daemon.register(info).map_err(fail)?;
    Ok(Advertised(Published::Network(daemon)))
}

fn write_descriptor(advertisement: &Advertisement, bound: SocketAddr) -> Result<Advertised, Error> {
    let fail = |error: io::Error| {
        Error::Discovery(format!("the descriptor could not be written: {error}"))
    };
    let dir = descriptors_dir()
        .ok_or_else(|| Error::Discovery("no directory for descriptors".to_owned()))?;
    create_private_dir(&dir).map_err(fail)?;
    if check_directory(&dir) == DirectoryCheck::SharedWithOthers {
        return Err(Error::Discovery(
            "others can write to the descriptor directory".to_owned(),
        ));
    }
    let scheme = if advertisement.tls { "wss" } else { "ws" };
    let text = json!({
        "txtvers": 1,
        "proto": "acp",
        "label": advertisement.label,
        "url": format!("{scheme}://{bound}{DEFAULT_PATH}"),
        "peer": advertisement.peer,
        "method": advertisement.method.name(),
        "wt": advertisement.webtransport,
        "wth": advertisement.webtransport_hash,
        "offers": (!advertisement.offers.is_empty()).then(|| advertisement.offers.join(",")),
    })
    .to_string();
    let name = format!("{}-{}", std::process::id(), bound.port());
    let unfinished = dir.join(format!("{name}.tmp"));
    let path = dir.join(format!("{name}.json"));
    // Never through a link or over something already there, in a directory someone may have named for us.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(&unfinished)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(fail)?;
    std::fs::rename(&unfinished, &path).map_err(fail)?;
    Ok(Advertised(Published::Descriptor(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn read(
        instance: &str,
        host: &str,
        addresses: &[&str],
        port: u16,
        keys: &[(&str, &str)],
    ) -> Option<Candidate> {
        let txt: HashMap<String, String> = keys
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        candidate_from(&Record {
            instance,
            host,
            addresses: addresses.iter().map(|text| text.parse().unwrap()).collect(),
            port,
            txt: &txt,
        })
    }

    const GOOD: &[(&str, &str)] = &[
        ("txtvers", "1"),
        ("proto", "acp"),
        ("tls", "1"),
        ("peer", PEER),
    ];

    #[test]
    fn a_plain_record_gives_a_wss_url_and_the_default_path() {
        let found = read("Mine", "acp-1.local.", &["10.0.0.5"], 8765, GOOD).unwrap();
        assert_eq!(found.url, "wss://10.0.0.5:8765/acp");
        assert_eq!(found.label, "Mine");
        assert_eq!(found.source, Source::Network);
        assert_eq!(found.peer.as_deref(), Some(PEER));
    }

    #[test]
    fn a_published_host_name_is_used_for_a_certificate_to_match() {
        let found = read("Mine", "agent.example.com.", &["10.0.0.5"], 443, GOOD).unwrap();
        assert_eq!(found.url, "wss://agent.example.com/acp");
    }

    #[test]
    fn it_ignores_what_it_does_not_understand() {
        assert!(
            read(
                "x",
                "h.local.",
                &["10.0.0.5"],
                1,
                &[("proto", "acp"), ("tls", "1")]
            )
            .is_none()
        );
        assert!(
            read(
                "x",
                "h.local.",
                &["10.0.0.5"],
                1,
                &[("txtvers", "2"), ("proto", "acp"), ("tls", "1")]
            )
            .is_none()
        );
        assert!(
            read(
                "x",
                "h.local.",
                &["10.0.0.5"],
                1,
                &[("txtvers", "1"), ("proto", "a2a"), ("tls", "1")]
            )
            .is_none()
        );
        assert!(read("x", "h.local.", &["10.0.0.5"], 0, GOOD).is_none());
    }

    #[test]
    fn a_record_cannot_point_a_person_at_their_own_machine_or_at_plain_text() {
        for address in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
        ] {
            assert!(
                read("x", "h.local.", &[address], 1, GOOD).is_none(),
                "{address}"
            );
        }
        assert!(
            read(
                "x",
                "h.local.",
                &["10.0.0.5"],
                1,
                &[("txtvers", "1"), ("proto", "acp"), ("peer", PEER)]
            )
            .is_none()
        );
        // A usable address beside it is still taken, and the loopback one is not.
        let found = read("x", "h.local.", &["127.0.0.1", "10.0.0.5"], 1, GOOD).unwrap();
        assert_eq!(found.url, "wss://10.0.0.5:1/acp");
    }

    #[test]
    fn hostile_text_is_cut_down() {
        let long = "é".repeat(100);
        let found = read(
            &format!("a\u{7}\n{long}"),
            "h.local.",
            &["10.0.0.5"],
            1,
            GOOD,
        )
        .unwrap();
        assert!(found.label.len() <= MAX_LABEL);
        assert!(!found.label.chars().any(char::is_control));
        assert!(read("\u{7}", "h.local.", &["10.0.0.5"], 1, GOOD).is_none());
        let good_peer = [
            ("txtvers", "1"),
            ("proto", "acp"),
            ("tls", "1"),
            ("peer", PEER),
            ("wt", "99999"),
            ("acpv", "2, 1, x"),
        ];
        let found = read("x", "h.local.", &["10.0.0.5"], 1, &good_peer).unwrap();
        assert_eq!(found.peer.as_deref(), Some(PEER));
        assert_eq!(found.webtransport, None);
        assert_eq!(found.acp_versions, [2, 1]);
    }

    #[test]
    fn a_path_cannot_smuggle_anything_into_the_url() {
        for path in ["acp", "/a b", "/a#b", "/\u{e9}"] {
            let keys = [
                ("txtvers", "1"),
                ("proto", "acp"),
                ("tls", "1"),
                ("path", path),
            ];
            assert!(
                read("x", "h.local.", &["10.0.0.5"], 1, &keys).is_none(),
                "{path}"
            );
        }
    }

    #[test]
    fn offers_are_read_as_a_stranger_wrote_them() {
        let many = (0..100)
            .map(|n| format!("p{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let hostile = format!("acp/1,a b,,{}", "x".repeat(65));
        let good = |offers: &str| {
            let keys = [
                ("txtvers", "1"),
                ("proto", "acp"),
                ("tls", "1"),
                ("peer", PEER),
                ("offers", offers),
            ];
            read("x", "h.local.", &["10.0.0.5"], 1, &keys)
                .unwrap()
                .offers
        };
        assert_eq!(good("acp/1,a2a/1,mcp"), ["acp/1", "a2a/1", "mcp"]);
        assert_eq!(good(&hostile), ["acp/1"]);
        assert_eq!(good(&many).len(), MAX_OFFERS);
        assert_eq!(
            read("x", "h.local.", &["10.0.0.5"], 1, GOOD)
                .unwrap()
                .offers,
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_descriptor_may_only_name_this_machine() {
        let descriptor =
            |url: &str| format!(r#"{{"txtvers":1,"proto":"acp","label":"x","url":"{url}"}}"#);
        assert!(candidate_from_descriptor(&descriptor("ws://127.0.0.1:1/acp")).is_some());
        assert!(candidate_from_descriptor(&descriptor("ws://[::1]:1/acp")).is_some());
        assert!(candidate_from_descriptor(&descriptor("ws://10.0.0.5:1/acp")).is_none());
        assert!(candidate_from_descriptor(&descriptor("http://127.0.0.1:1/")).is_none());
        assert!(candidate_from_descriptor("not json").is_none());
    }

    #[test]
    fn a_record_names_its_method_and_one_naming_none_is_webcrypto() {
        let found = read("Mine", "acp-1.local.", &["10.0.0.5"], 8765, GOOD).unwrap();
        assert_eq!(found.method, Method::WebCrypto);
        assert_eq!(found.to_json()["method"], "webcrypto");
        for (name, method) in [("noise", Method::Noise), ("webcrypto", Method::WebCrypto)] {
            let keys = [GOOD, &[("method", name)]].concat();
            let found = read("Mine", "acp-1.local.", &["10.0.0.5"], 8765, &keys).unwrap();
            assert_eq!(found.method, method);
            assert_eq!(found.to_json()["method"], name);
        }
        // A method this version cannot run is a record it cannot use.
        for name in ["", "Noise", "tls", "noise,webcrypto"] {
            let keys = [GOOD, &[("method", name)]].concat();
            assert!(
                read("Mine", "acp-1.local.", &["10.0.0.5"], 8765, &keys).is_none(),
                "{name}"
            );
        }
        let advertised = Advertisement::new("Mine", true).unwrap();
        assert_eq!(advertised.txt()["method"], Method::DEFAULT.name());
        let advertised = advertised.with_method(Method::Noise);
        assert_eq!(advertised.txt()["method"], "noise");
        let descriptor = |method: &str| {
            format!(
                r#"{{"txtvers":1,"proto":"acp","label":"x","url":"ws://127.0.0.1:1/acp"{method}}}"#
            )
        };
        assert_eq!(
            candidate_from_descriptor(&descriptor("")).unwrap().method,
            Method::WebCrypto
        );
        assert_eq!(
            candidate_from_descriptor(&descriptor(r#","method":null"#))
                .unwrap()
                .method,
            Method::WebCrypto
        );
        assert_eq!(
            candidate_from_descriptor(&descriptor(r#","method":"noise""#))
                .unwrap()
                .method,
            Method::Noise
        );
        assert!(candidate_from_descriptor(&descriptor(r#","method":"other""#)).is_none());
        assert!(candidate_from_descriptor(&descriptor(r#","method":1"#)).is_none());
    }

    #[test]
    fn an_advertisement_refuses_what_a_record_cannot_carry() {
        assert!(Advertisement::new("", false).is_err());
        assert!(Advertisement::new(&"x".repeat(64), false).is_err());
        assert!(Advertisement::new("a\nb", false).is_err());
        assert!(
            Advertisement::new("Mine", false)
                .unwrap()
                .with_host(Some("a b".to_owned()))
                .is_err()
        );
    }

    #[test]
    fn a_record_cannot_point_a_person_at_their_own_machine_by_any_spelling() {
        for host in [
            "localhost.",
            "LOCALHOST.",
            "foo.localhost.",
            "127.1.",
            "2130706433.",
            "0x7f.0.0.1.",
            "0.",
            "0.0.0.0.",
            "169.254.169.254.",
            "intranet.",
        ] {
            assert!(read("x", host, &["10.0.0.5"], 1, GOOD).is_none(), "{host}");
        }
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "0.1.2.3",
            "255.255.255.255",
        ] {
            assert!(
                read("x", "h.local.", &[address], 1, GOOD).is_none(),
                "{address}"
            );
        }
        assert!(
            read("x", "h.local.", &["2001:db8::5"], 1, GOOD).is_some(),
            "a real address still works"
        );
        assert!(
            read("x", "h.local.", &["::ffff:10.0.0.5"], 1, GOOD).is_some(),
            "and in the form that wraps it"
        );
    }

    #[test]
    fn a_record_naming_no_key_is_not_offered() {
        let no_peer = [("txtvers", "1"), ("proto", "acp"), ("tls", "1")];
        assert!(read("x", "h.local.", &["10.0.0.5"], 1, &no_peer).is_none());
        let bad_peer = [
            ("txtvers", "1"),
            ("proto", "acp"),
            ("tls", "1"),
            ("peer", "sha256:zz"),
        ];
        assert!(read("x", "h.local.", &["10.0.0.5"], 1, &bad_peer).is_none());
    }

    #[test]
    fn a_label_cannot_hide_part_of_itself_or_reorder_what_is_around_it() {
        let found = read(
            "a\u{202e}b\u{200b}c\u{ad}d",
            "h.local.",
            &["10.0.0.5"],
            1,
            GOOD,
        )
        .unwrap();
        assert_eq!(found.label, "abcd");
        assert!(read("\u{202e}\u{200b}", "h.local.", &["10.0.0.5"], 1, GOOD).is_none());
        assert!(Advertisement::new("a\u{202e}b", false).is_err());
    }

    #[test]
    fn a_descriptor_url_is_bounded_and_cannot_show_a_false_host() {
        let descriptor =
            |url: &str| format!(r#"{{"txtvers":1,"proto":"acp","label":"x","url":"{url}"}}"#);
        assert!(
            candidate_from_descriptor(&descriptor("ws://agent.example.com:443@127.0.0.1:1/acp"))
                .is_none()
        );
        let long = format!("ws://127.0.0.1:1/{}", "\u{e9}".repeat(200));
        assert!(candidate_from_descriptor(&descriptor(&long)).is_none());
    }

    #[test]
    fn an_advertisement_names_the_default_method_unless_told() {
        assert_eq!(
            Advertisement::new("Mine", true).unwrap().method,
            Method::DEFAULT
        );
    }

    fn scratch_directory(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("coqui-descriptors-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_others_can_write_is_reported_and_not_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_directory("shared");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let read = read_descriptors(&dir);
        assert_eq!(read.directory, DirectoryCheck::SharedWithOthers);
        assert!(read.candidates.is_empty());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(read_descriptors(&dir).directory, DirectoryCheck::Private);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn a_platform_that_cannot_check_the_directory_says_so() {
        let dir = scratch_directory("unchecked");
        assert_eq!(read_descriptors(&dir).directory, DirectoryCheck::NotChecked);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
