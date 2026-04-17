// service.rs — org.freedesktop.Secret.Service D-Bus interface implementation.
//
// This is the top-level object of the Secret Service API, served at
// /org/freedesktop/secrets on the session bus.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use log::{info, warn};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::interface;

use crate::daemon_client::DaemonClient;
use crate::session::{SessionInterface, SessionStore};
use crate::storage;

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
    /// Active sessions keyed by UUID.  Arc so SessionInterface instances can
    /// call remove() when Close() is invoked by the client.
    sessions: Arc<Mutex<SessionStore>>,
    /// Object paths of all registered collections.
    collections: Vec<OwnedObjectPath>,
    /// Named alias mappings (e.g. "default" → collection path).
    aliases: HashMap<String, OwnedObjectPath>,
    /// Shared connection, populated after startup.  Used to register
    /// SessionInterface and CollectionInterface objects at runtime.
    pub conn: Arc<OnceLock<zbus::Connection>>,
}

impl ServiceInterface {
    pub fn new(
        collections: Vec<OwnedObjectPath>,
        aliases: HashMap<String, OwnedObjectPath>,
        conn: Arc<OnceLock<zbus::Connection>>,
    ) -> Self {
        ServiceInterface {
            sessions: Arc::new(Mutex::new(SessionStore::new())),
            collections,
            aliases,
            conn,
        }
    }
}

/// Convert a human-readable label into a D-Bus-path-safe collection identifier.
///
/// Rules: lowercase; spaces become underscores; characters that are neither
/// alphanumeric nor underscores are stripped.  Falls back to a UUID if the
/// result would be empty.
fn slugify(label: &str) -> String {
    let slug: String = label
        .to_lowercase()
        .chars()
        .map(|c| if c == ' ' { '_' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if slug.is_empty() {
        uuid::Uuid::new_v4().to_string().replace('-', "_")
    } else {
        slug
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceInterface {
    // ── Properties ───────────────────────────────────────────────────────────

    /// All collections currently registered with this service.
    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections.clone()
    }

    // ── Signals ──────────────────────────────────────────────────────────────

    /// Emitted when a new collection is created.
    #[zbus(signal)]
    pub async fn collection_created(
        ctxt: &zbus::SignalContext<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Emitted when a collection is deleted.
    #[zbus(signal)]
    pub async fn collection_deleted(
        ctxt: &zbus::SignalContext<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

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

        let safe_session_id = session_id.replace('-', "_");
        // Spec uses singular /session/ (not /sessions/).
        let session_path_str = format!(
            "/org/freedesktop/secrets/session/{safe_session_id}"
        );
        let session_path = OwnedObjectPath::try_from(session_path_str.clone())
            .map_err(|e| zbus::fdo::Error::Failed(format!("Bad session path: {e}")))?;

        // Register a SessionInterface object so clients can call Close() on it.
        // Pass a clone of the sessions Arc so Close() can remove the entry.
        let conn = self.conn.get().ok_or_else(|| {
            zbus::fdo::Error::Failed("D-Bus connection not yet available".into())
        })?;
        conn.object_server()
            .at(session_path_str, SessionInterface {
                session_id: session_id.clone(),
                sessions: Arc::clone(&self.sessions),
            })
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Register session on D-Bus: {e}")))?;

        // For "plain", the output is an empty string variant.
        let output = OwnedValue::try_from(Value::new(""))
            .map_err(|e| zbus::fdo::Error::Failed(format!("OwnedValue: {e}")))?;

        info!("[service] OpenSession created session_id={session_id}");
        Ok((output, session_path))
    }

    // ── SearchItems ──────────────────────────────────────────────────────────

    /// Search all collections for items whose attributes match `attributes`.
    ///
    /// Returns `(unlocked_paths, locked_paths)`.  All items are unlocked.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        info!("[service] SearchItems {:?}", attributes);
        let mut unlocked: Vec<OwnedObjectPath> = Vec::new();
        for col in storage::load_collections() {
            for item in storage::load_items(&col.id) {
                let matches = attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v));
                if matches {
                    // UUIDs contain hyphens which are invalid in D-Bus object paths.
                    let safe_id = item.id.replace('-', "_");
                    match OwnedObjectPath::try_from(format!(
                        "/org/freedesktop/secrets/collection/{}/{}",
                        col.id, safe_id
                    )) {
                        Ok(path) => unlocked.push(path),
                        Err(e) => warn!("[service] SearchItems: bad path: {e}"),
                    }
                }
            }
        }
        info!("[service] SearchItems found {} item(s)", unlocked.len());
        (unlocked, Vec::new())
    }

    // ── Unlock ───────────────────────────────────────────────────────────────

    /// Unlock a list of objects (collections or items).
    ///
    /// All MyKey items are always accessible — no unlock step is needed.
    /// Returns `(unlocked, prompt)` where prompt is "/" (no prompt required).
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        info!("[service] Unlock {} object(s)", objects.len());
        let prompt = OwnedObjectPath::try_from("/").unwrap();
        (objects, prompt)
    }

    // ── Lock ─────────────────────────────────────────────────────────────────

    /// Lock a list of objects (no-op — MyKey secrets are always accessible).
    ///
    /// Returns `(locked, prompt)` where locked is empty and prompt is "/".
    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        info!("[service] Lock {} object(s) (no-op)", objects.len());
        let _ = objects;
        let prompt = OwnedObjectPath::try_from("/").unwrap();
        (Vec::new(), prompt)
    }

    // ── GetSecrets ───────────────────────────────────────────────────────────

    /// Retrieve secrets for the given item paths in a single call.
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> HashMap<OwnedObjectPath, SecretStruct> {
        info!("[service] GetSecrets for {} item(s)", items.len());
        if items.is_empty() {
            return HashMap::new();
        }

        let client = match DaemonClient::connect().await {
            Ok(c) => c,
            Err(e) => {
                warn!("[service] GetSecrets: daemon connect failed: {e}");
                return HashMap::new();
            }
        };

        let mut result = HashMap::new();
        for path in items {
            // Path format: /org/freedesktop/secrets/collection/{col_id}/{item_id}
            // item_id in the path has underscores (D-Bus safe); on-disk UUIDs use hyphens.
            let parts: Vec<&str> = path.as_str().split('/').collect();
            if parts.len() < 7 {
                warn!("[service] GetSecrets: unexpected path format: {path}");
                continue;
            }
            let col_id = parts[5];
            let item_id = parts[6].replace('_', "-");

            let stored = storage::load_items(col_id)
                .into_iter()
                .find(|i| i.id == item_id);
            let stored = match stored {
                Some(s) => s,
                None => {
                    warn!("[service] GetSecrets: item not found in storage: {path}");
                    continue;
                }
            };

            match client.unseal_secret(&stored.sealed_value).await {
                Ok(plaintext) => {
                    result.insert(
                        path,
                        SecretStruct {
                            session: session.clone(),
                            parameters: Vec::new(),
                            value: plaintext,
                            content_type: stored.content_type,
                        },
                    );
                }
                Err(e) => warn!("[service] GetSecrets: unseal failed for {item_id}: {e}"),
            }
        }
        result
    }

    // ── CreateCollection ─────────────────────────────────────────────────────

    /// Create a new collection.
    ///
    /// Generates a slug from the label, persists collection metadata to disk,
    /// registers a CollectionInterface on the object server, and emits
    /// CollectionCreated.  Returns `(collection_path, prompt_path)`.
    async fn create_collection(
        &mut self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        // Extract label from properties.
        let label: String = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| {
                if let Value::Str(s) = &**v {
                    Some(s.as_str().to_owned())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Generate a D-Bus-path-safe collection ID.
        let col_id = if label.is_empty() {
            uuid::Uuid::new_v4().to_string().replace('-', "_")
        } else {
            slugify(&label)
        };

        info!("[service] CreateCollection label={label:?} id={col_id} alias={alias:?}");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Persist collection metadata to disk.
        let stored = storage::StoredCollection {
            id: col_id.clone(),
            label: label.clone(),
            created: now,
            modified: now,
        };
        storage::save_collection(&stored)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Save collection: {e}")))?;

        let col_path_str = format!("/org/freedesktop/secrets/collection/{col_id}");
        let col_path = OwnedObjectPath::try_from(col_path_str.clone())
            .map_err(|e| zbus::fdo::Error::Failed(format!("Bad collection path: {e}")))?;

        // Build and register the CollectionInterface.
        let col_iface = crate::collection::CollectionInterface {
            id: col_id.clone(),
            label,
            created: now,
            modified: now,
            item_paths: Vec::new(),
            conn: Arc::clone(&self.conn),
        };

        let conn = self.conn.get().ok_or_else(|| {
            zbus::fdo::Error::Failed("D-Bus connection not yet available".into())
        })?;
        conn.object_server()
            .at(col_path_str, col_iface)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Register collection on D-Bus: {e}")))?;

        self.collections.push(col_path.clone());

        // Handle alias if provided.
        if !alias.is_empty() {
            self.aliases.insert(alias.clone(), col_path.clone());
            let raw: HashMap<String, String> = self.aliases
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                .collect();
            if let Err(e) = storage::save_aliases(&raw) {
                warn!("[service] CreateCollection: failed to persist alias {alias:?}: {e}");
            }
        }

        // Emit CollectionCreated signal (best effort).
        match zbus::SignalContext::new(conn, "/org/freedesktop/secrets") {
            Ok(signal_ctxt) => {
                if let Err(e) = ServiceInterface::collection_created(&signal_ctxt, col_path.clone()).await {
                    warn!("[service] CollectionCreated signal failed: {e}");
                }
            }
            Err(e) => warn!("[service] Could not build signal context for CollectionCreated: {e}"),
        }

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((col_path, prompt_path))
    }

    // ── ReadAlias ────────────────────────────────────────────────────────────

    /// Return the collection path that a named alias resolves to.
    ///
    /// Looks up the alias in the in-memory map (loaded from disk at startup
    /// and kept up-to-date by SetAlias).  Returns "/" if not found.
    async fn read_alias(&self, name: String) -> OwnedObjectPath {
        info!("[service] ReadAlias name={name}");
        self.aliases
            .get(&name)
            .cloned()
            .unwrap_or_else(|| OwnedObjectPath::try_from("/").unwrap())
    }

    /// Persist a named alias for a collection.
    ///
    /// Updates the in-memory map and writes the full alias table to
    /// /etc/mykey/provider/aliases.json.
    async fn set_alias(
        &mut self,
        name: String,
        collection: OwnedObjectPath,
    ) -> Result<(), zbus::fdo::Error> {
        info!("[service] SetAlias name={name} collection={}", collection.as_str());
        self.aliases.insert(name, collection);
        let raw: HashMap<String, String> = self.aliases
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
            .collect();
        if let Err(e) = storage::save_aliases(&raw) {
            warn!("[service] set_alias: failed to persist aliases: {e}");
        }
        Ok(())
    }
}
