// collection.rs — org.freedesktop.Secret.Collection D-Bus interface.
//
// A collection groups related secret items.  The default collection is served
// at /org/freedesktop/secrets/collection/default.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, warn};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::item::ItemInterface;
use crate::service::SecretStruct;
use crate::storage::{self, StoredItem};

/// Implements org.freedesktop.Secret.Collection for a single collection.
pub struct CollectionInterface {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    /// Object paths of items belonging to this collection.
    pub item_paths: Vec<OwnedObjectPath>,
    /// Shared connection, populated after startup, used to register new items.
    pub conn: Arc<OnceLock<zbus::Connection>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionInterface {
    // ── Properties ───────────────────────────────────────────────────────────

    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        self.item_paths.clone()
    }

    #[zbus(property)]
    fn label(&self) -> &str {
        &self.label
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        self.created
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.modified
    }

    // ── Methods ──────────────────────────────────────────────────────────────

    /// Delete the collection.  Returns empty prompt path (no prompt required).
    async fn delete(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        info!("[collection] Delete called for collection={}", self.id);
        // Stub: deletion of whole collections is not yet implemented.
        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    /// Search for items whose attributes are a superset of `attributes`.
    /// Returns matching item paths (all items in this collection are unlocked).
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Vec<OwnedObjectPath> {
        info!("[collection:{}] SearchItems {:?}", self.id, attributes);
        let results: Vec<OwnedObjectPath> = storage::load_items(&self.id)
            .into_iter()
            .filter(|item| {
                attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            })
            .filter_map(|item| {
                // UUIDs contain hyphens which are invalid in D-Bus object paths.
                let safe_id = item.id.replace('-', "_");
                match OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}/{}",
                    self.id, safe_id
                )) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        warn!("[collection:{}] SearchItems: bad path for {}: {e}", self.id, item.id);
                        None
                    }
                }
            })
            .collect();
        info!("[collection:{}] SearchItems found {} item(s)", self.id, results.len());
        results
    }

    /// Create a new item in this collection.
    ///
    /// Seals the secret via the TPM2 daemon, persists it to disk, registers
    /// a new `ItemInterface` on the D-Bus object server, and returns
    /// `(item_path, prompt_path)`.  Prompt path is "/" (no prompt needed).
    async fn create_item(
        &mut self,
        mut properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        let _ = replace; // replace semantics not yet implemented
        info!("[collection] CreateItem called for collection={}", self.id);

        let item_id = uuid::Uuid::new_v4().to_string();
        // D-Bus object paths cannot contain hyphens; replace with underscores for the path.
        // The on-disk file continues to use the raw UUID (item_id) with hyphens.
        let safe_item_id = item_id.replace('-', "_");
        let item_path_str = format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.id, safe_item_id
        );

        // Extract label from properties (consumes the entry), defaulting to "Unnamed".
        let label = match properties.remove("org.freedesktop.Secret.Item.Label") {
            Some(Value::Str(s)) => s.to_string(),
            _ => "Unnamed".to_string(),
        };

        // Extract attributes dict from properties (consumes the entry), defaulting to empty.
        let attributes: HashMap<String, String> = properties
            .remove("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| HashMap::<String, String>::try_from(v).ok())
            .unwrap_or_default();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Seal the plaintext secret via the TPM2 daemon.
        let client = crate::daemon_client::DaemonClient::connect()
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Daemon connect: {e}")))?;
        let sealed = client
            .seal_secret(&secret.value)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("SealSecret: {e}")))?;

        // Persist to disk.
        let stored = StoredItem {
            id: item_id.clone(),
            collection_id: self.id.clone(),
            label: label.clone(),
            attributes: attributes.clone(),
            sealed_value: sealed.clone(),
            content_type: secret.content_type.clone(),
            created: now,
            modified: now,
        };
        storage::save_item(&stored)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Save item: {e}")))?;

        // Build the in-memory interface.
        let item_iface = ItemInterface {
            id: item_id.clone(),
            collection_id: self.id.clone(),
            label,
            attributes,
            content_type: secret.content_type,
            created: now,
            modified: now,
            sealed_value: sealed,
        };

        // Register the new item on the D-Bus object server.
        // Clone the Arc so the borrow on self ends before the await point.
        let conn_arc = Arc::clone(&self.conn);
        let conn = conn_arc.get().ok_or_else(|| {
            zbus::fdo::Error::Failed("D-Bus connection not yet available".into())
        })?;
        conn.object_server()
            .at(item_path_str.clone(), item_iface)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Register item on D-Bus: {e}")))?;

        let item_path = OwnedObjectPath::try_from(item_path_str)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Bad item path: {e}")))?;
        self.item_paths.push(item_path.clone());

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((item_path, prompt_path))
    }
}
