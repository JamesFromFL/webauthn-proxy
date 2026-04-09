// service.rs — org.freedesktop.Secret.Service D-Bus interface implementation.
//
// This is the top-level object of the Secret Service API, served at
// /org/freedesktop/secrets on the session bus.

use std::collections::HashMap;
use std::sync::Mutex;
use log::info;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::interface;

use crate::session::SessionStore;

// ---------------------------------------------------------------------------
// SecretStruct — the (session, parameters, value, content_type) tuple used
// throughout the Secret Service API.
// ---------------------------------------------------------------------------

/// The Secret Service wire format for a secret value.
#[derive(Debug, Clone, zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
pub struct SecretStruct {
    /// Object path of the session used to encrypt this secret.
    pub session: OwnedObjectPath,
    /// Algorithm-specific parameters (empty for "plain").
    pub parameters: Vec<u8>,
    /// The secret value bytes.
    pub value: Vec<u8>,
    /// MIME type of the secret (e.g. "text/plain; charset=utf8").
    pub content_type: String,
}

// ---------------------------------------------------------------------------
// ServiceInterface
// ---------------------------------------------------------------------------

/// Implements org.freedesktop.Secret.Service.
pub struct ServiceInterface {
    sessions: Mutex<SessionStore>,
}

impl ServiceInterface {
    pub fn new() -> Self {
        ServiceInterface {
            sessions: Mutex::new(SessionStore::new()),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceInterface {
    // ── OpenSession ──────────────────────────────────────────────────────────

    /// Open a new session.  Only the "plain" algorithm is supported.
    ///
    /// Returns `(output, session_path)`.  For "plain", output is an empty
    /// variant.
    async fn open_session(
        &self,
        algorithm: String,
        input: Value<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath), zbus::fdo::Error> {
        info!("[service] OpenSession algorithm={algorithm}");
        let _ = input;

        if algorithm != "plain" {
            return Err(zbus::fdo::Error::NotSupported(format!(
                "Algorithm '{algorithm}' is not supported; use 'plain'"
            )));
        }

        let session_id = self
            .sessions
            .lock()
            .unwrap()
            .create(algorithm);

        let session_path = OwnedObjectPath::try_from(
            format!("/org/freedesktop/secrets/sessions/{session_id}")
        )
        .map_err(|e| zbus::fdo::Error::Failed(format!("Bad session path: {e}")))?;

        // For "plain", the output is an empty string variant.
        let output = OwnedValue::try_from(Value::new(""))
            .map_err(|e| zbus::fdo::Error::Failed(format!("OwnedValue: {e}")))?;

        info!("[service] OpenSession created session_id={session_id}");
        Ok((output, session_path))
    }

    // ── SearchItems ──────────────────────────────────────────────────────────

    /// Search all collections for items whose attributes match `attributes`.
    ///
    /// Returns `(unlocked_paths, locked_paths)`.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let _ = attributes;
        info!("[service] SearchItems (stub)");
        (Vec::new(), Vec::new())
    }

    // ── GetSecrets ───────────────────────────────────────────────────────────

    /// Retrieve secrets for the given item paths in a single call.
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> HashMap<OwnedObjectPath, SecretStruct> {
        let _ = (items, session);
        info!("[service] GetSecrets (stub)");
        HashMap::new()
    }

    // ── CreateCollection ─────────────────────────────────────────────────────

    /// Create a new collection.
    ///
    /// Returns `(collection_path, prompt_path)`.  Prompt path is "/" (no
    /// interactive prompt required).
    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        let _ = (properties, alias);
        info!("[service] CreateCollection (stub)");
        let col_path = OwnedObjectPath::try_from(
            "/org/freedesktop/secrets/collection/default"
        )
        .map_err(|e| zbus::fdo::Error::Failed(format!("Bad path: {e}")))?;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((col_path, prompt_path))
    }

    // ── GetDefaultCollection (convenience, not in spec but widely expected) ──

    /// Return the path of the default collection.
    async fn get_default_collection(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap()
    }
}
