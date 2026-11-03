//! The native companion: what a browser extension cannot do itself, over native messaging. It answers one question, who is
//! around, and carries no agent traffic. The browser checks which extensions may start it, against the manifest
//! [`install`] writes. See <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging>.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::Error;
use crate::discovery::{self, Candidate};

/// The name an extension passes to `connectNative` or `sendNativeMessage`.
pub const HOST_NAME: &str = "dev.boriken.coqui_acp_bridge";
/// A message from the browser. All it ever says is short, so anything longer is not a browser speaking this.
pub const MAX_REQUEST: usize = 64 * 1024;
/// The browser's limit on one message to it.
pub const MAX_REPLY: usize = 1024 * 1024;
/// How long a search may be asked to take.
const MAX_SEARCH: Duration = Duration::from_secs(10);
const DEFAULT_SEARCH: Duration = Duration::from_secs(3);

/// How a browser starts a native host: its first argument is the caller's origin, so the host cannot be given a subcommand.
#[must_use]
pub fn started_by_browser(first_argument: &str) -> bool {
    first_argument.starts_with("chrome-extension://")
}

/// One message: a 32-bit length in native byte order, then that much JSON. `None` when the browser has gone.
///
/// # Errors
/// When it is longer than [`MAX_REQUEST`], or the stream fails or ends inside it.
pub fn read_message(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::try_from(u32::from_ne_bytes(length)).unwrap_or(usize::MAX);
    if length > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a message is too long",
        ));
    }
    let mut message = vec![0; length];
    input.read_exact(&mut message)?;
    Ok(Some(message))
}

/// One message, framed.
///
/// # Errors
/// When it is longer than [`MAX_REPLY`], or the stream fails.
pub fn write_message(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    if message.len() > MAX_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a message is too long",
        ));
    }
    let length = u32::try_from(message.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    output.write_all(&length.to_ne_bytes())?;
    output.write_all(message)?;
    output.flush()
}

/// Each field of a candidate is bounded, so [`discovery::MAX_CANDIDATES`] of them fit in one message.
fn reply_with(candidates: &[Candidate]) -> Vec<u8> {
    let list: Vec<Value> = candidates
        .iter()
        .take(discovery::MAX_CANDIDATES)
        .map(Candidate::to_json)
        .collect();
    json!({ "candidates": list }).to_string().into_bytes()
}

fn answer(request: &[u8], search: &dyn Fn(Duration) -> Vec<Candidate>) -> Vec<u8> {
    let Ok(request) = serde_json::from_slice::<Value>(request) else {
        return json!({ "error": "not JSON" }).to_string().into_bytes();
    };
    if request.get("op").and_then(Value::as_str) != Some("discover") {
        return json!({ "error": "unknown op" }).to_string().into_bytes();
    }
    let wait = request
        .get("seconds")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_SEARCH, Duration::from_secs)
        .min(MAX_SEARCH);
    reply_with(&search(wait))
}

/// Serves until the browser closes the stream.
///
/// # Errors
/// When a stream fails or a message is too long, which ends the host: the browser reports that to the extension.
pub fn run(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    while let Some(request) = read_message(input)? {
        write_message(output, &answer(&request, &discovery::discover))?;
    }
    Ok(())
}

fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

fn manifest(program: &Path, extensions: &[String]) -> Value {
    let origins: Vec<String> = extensions
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    json!({
        "name": HOST_NAME,
        "description": "Finds Agent Client Protocol agents on this machine and the local network",
        "path": program,
        "type": "stdio",
        "allowed_origins": origins,
    })
}

/// The registry keys Chromium browsers read a native host from on Windows.
const WINDOWS_KEYS: [&str; 3] = [
    r"HKCU\Software\Google\Chrome\NativeMessagingHosts",
    r"HKCU\Software\Chromium\NativeMessagingHosts",
    r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts",
];

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// The per-user directories native host manifests go in, for the browsers that have a profile here.
fn unix_directories() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let browsers: &[&str] = if cfg!(target_os = "macos") {
        &[
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Chromium",
            "Library/Application Support/Microsoft Edge",
        ]
    } else {
        &[
            ".config/google-chrome",
            ".config/chromium",
            ".config/microsoft-edge",
        ]
    };
    browsers
        .iter()
        .map(|browser| home.join(browser))
        .filter(|profile| profile.is_dir())
        .map(|profile| profile.join("NativeMessagingHosts"))
        .collect()
}

fn windows_manifest() -> Result<PathBuf, Error> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Discovery("LOCALAPPDATA is not set".to_owned()))?;
    Ok(PathBuf::from(base)
        .join("coqui-acp")
        .join("native")
        .join(format!("{HOST_NAME}.json")))
}

fn reg(arguments: &[&str]) -> Result<bool, Error> {
    let output = Command::new("reg")
        .args(arguments)
        .output()
        .map_err(|error| Error::Discovery(format!("reg could not run: {error}")))?;
    Ok(output.status.success())
}

/// Lets `extensions` start this program as a native host, for this user. Returns what it wrote.
///
/// # Errors
/// [`Error::Discovery`] for a malformed extension id, no browser profile to install into, or a file or the registry refusing.
pub fn install(extensions: &[String]) -> Result<Vec<String>, Error> {
    if extensions.is_empty() || !extensions.iter().all(|id| valid_extension_id(id)) {
        return Err(Error::Discovery(
            "an extension id is 32 letters from a to p".to_owned(),
        ));
    }
    let fail =
        |error: io::Error| Error::Discovery(format!("the manifest could not be written: {error}"));
    let program = std::env::current_exe().map_err(fail)?;
    let text = serde_json::to_string_pretty(&manifest(&program, extensions))
        .map_err(|error| Error::Discovery(error.to_string()))?;
    let mut wrote = Vec::new();
    if cfg!(windows) {
        let path = windows_manifest()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        std::fs::write(&path, &text).map_err(fail)?;
        let value = path.to_string_lossy().into_owned();
        wrote.push(value.clone());
        for key in WINDOWS_KEYS {
            let key = format!(r"{key}\{HOST_NAME}");
            if !reg(&["add", &key, "/ve", "/t", "REG_SZ", "/d", &value, "/f"])? {
                return Err(Error::Discovery(format!("the registry refused {key}")));
            }
            wrote.push(key);
        }
    } else {
        let directories = unix_directories();
        if directories.is_empty() {
            return Err(Error::Discovery(
                "no Chrome, Chromium or Edge profile for this user".to_owned(),
            ));
        }
        for directory in directories {
            std::fs::create_dir_all(&directory).map_err(fail)?;
            let path = directory.join(format!("{HOST_NAME}.json"));
            std::fs::write(&path, &text).map_err(fail)?;
            wrote.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(wrote)
}

/// Removes what [`install`] wrote. What is already gone is not a failure.
///
/// # Errors
/// [`Error::Discovery`] when a file exists and cannot be removed, or `reg` cannot run.
pub fn uninstall() -> Result<(), Error> {
    let remove = |path: &Path| match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(Error::Discovery(format!(
            "the manifest could not be removed: {error}"
        ))),
        _ => Ok(()),
    };
    if cfg!(windows) {
        for key in WINDOWS_KEYS {
            let key = format!(r"{key}\{HOST_NAME}");
            let _ = reg(&["delete", &key, "/f"])?;
        }
        remove(&windows_manifest()?)
    } else {
        for directory in unix_directories() {
            remove(&directory.join(format!("{HOST_NAME}.json")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn framed(message: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, message).unwrap();
        out
    }

    #[test]
    fn messages_round_trip_and_the_end_is_no_message() {
        let mut input = Cursor::new(framed(b"{}"));
        assert_eq!(read_message(&mut input).unwrap().unwrap(), b"{}");
        assert!(read_message(&mut input).unwrap().is_none());
    }

    #[test]
    fn a_length_past_the_limit_is_refused_before_anything_is_allocated() {
        let mut input = Cursor::new(u32::MAX.to_ne_bytes().to_vec());
        assert!(read_message(&mut input).is_err());
        let over = u32::try_from(MAX_REQUEST + 1).unwrap();
        let mut input = Cursor::new(over.to_ne_bytes().to_vec());
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn a_message_cut_short_is_an_error_not_a_message() {
        let mut bytes = framed(b"{\"op\":\"discover\"}");
        bytes.truncate(8);
        assert!(read_message(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn it_answers_only_discover_and_bounds_the_wait() {
        let asked = std::cell::Cell::new(Duration::ZERO);
        let search = |wait: Duration| {
            asked.set(wait);
            Vec::new()
        };
        let reply: Value =
            serde_json::from_slice(&answer(br#"{"op":"discover","seconds":3600}"#, &search))
                .unwrap();
        assert_eq!(reply["candidates"], json!([]));
        assert_eq!(asked.get(), MAX_SEARCH);
        let reply: Value =
            serde_json::from_slice(&answer(br#"{"op":"run","program":"x"}"#, &search)).unwrap();
        assert_eq!(reply["error"], "unknown op");
        let reply: Value = serde_json::from_slice(&answer(b"nope", &search)).unwrap();
        assert_eq!(reply["error"], "not JSON");
    }

    #[test]
    fn a_reply_always_fits_what_the_browser_takes() {
        // The longest of each field a record can give, in the characters JSON writes longest.
        let big = Candidate {
            label: "\"".repeat(63),
            url: format!("wss://{}:65535/{}", "h".repeat(253), "%".repeat(127)),
            peer: Some(format!("sha256:{}", "0".repeat(64))),
            method: crate::auth::Method::WebCrypto,
            source: discovery::Source::Network,
            webtransport: Some(65535),
            webtransport_hash: Some(format!("sha256:{}", "0".repeat(64))),
            acp_versions: vec![u32::MAX; 8],
            offers: vec!["x".repeat(64); 16],
        };
        let reply = reply_with(&vec![big; discovery::MAX_CANDIDATES + 1]);
        assert!(reply.len() <= MAX_REPLY, "{}", reply.len());
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(
            reply["candidates"].as_array().unwrap().len(),
            discovery::MAX_CANDIDATES
        );
    }

    #[test]
    fn extension_ids_are_checked_and_the_browser_is_recognised() {
        assert!(valid_extension_id(&"a".repeat(32)));
        assert!(!valid_extension_id(&"z".repeat(32)));
        assert!(!valid_extension_id("abc"));
        assert!(install(&["../../x".to_owned()]).is_err());
        assert!(install(&[]).is_err());
        assert!(started_by_browser("chrome-extension://abc/"));
        assert!(!started_by_browser("serve"));
    }
}
