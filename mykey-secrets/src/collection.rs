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
use crate::storage::{self, StoredCollection, StoredItem};

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

    // ── Signals ──────────────────────────────────────────────────────────────

    /// Emitted when a new item is created in this collection.
    #[zbus(signal)]
    pub async fn item_created(ctxt: &zbus::SignalContext<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    /// Emitted when an existing item's secret is updated.
    #[zbus(signal)]
    pub async fn item_changed(ctxt: &zbus::SignalContext<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    /// Emitted when an item is deleted from this collection.
    #[zbus(signal)]
    pub async fn item_deleted(ctxt: &zbus::SignalContext<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    // ── Methods ──────────────────────────────────────────────────────────────

    /// Delete the collection and all of its items.
    ///
    /// Deletes every item from disk and unregisters its D-Bus object, removes
    /// the collection directory, unregisters this collection's D-Bus object,
    /// and emits CollectionDeleted on the Service interface.
    /// Returns "/" (no prompt required).
    async fn delete(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        info!("[collection] Delete called for collection={}", self.id);

        let conn = self.conn.get().ok_or_else(|| {
            zbus::fdo::Error::Failed("D-Bus connection not yet available".into())
        })?;

        // Delete all items from disk and unregister their D-Bus objects.
        let items = storage::load_items(&self.id);
        for item in &items {
            if let Err(e) = storage::delete_item(&self.id, &item.id) {
                warn!("[collection] Delete: failed to remove item={} from disk: {e}", item.id);
            }
            let safe_id = item.id.replace('-', "_");
            let item_path = format!(
                "/org/freedesktop/secrets/collection/{}/{}",
                self.id, safe_id
            );
            match conn.object_server()
                .remove::<crate::item::ItemInterface, _>(item_path.as_str())
                .await
            {
                Ok(true) => info!("[collection] Unregistered item D-Bus object at {item_path}"),
                Ok(false) => warn!("[collection] Item D-Bus object not found at {item_path}"),
                Err(e) => warn!("[collection] Failed to unregister item at {item_path}: {e}"),
            }
        }

        // Delete the collection directory from disk.
        if let Err(e) = storage::delete_collection_dir(&self.id) {
            warn!("[collection] Delete: failed to remove collection dir: {e}");
        }

        // Build the collection path before unregistering (needed for the signal).
        let col_path_str = format!("/org/freedesktop/secrets/collection/{}", self.id);
        let col_path = OwnedObjectPath::try_from(col_path_str.as_str())
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());

        // Unregister this collection's D-Bus object.
        match conn.object_server()
            .remove::<CollectionInterface, _>(col_path_str.as_str())
            .await
        {
            Ok(true) => info!("[collection] Unregistered collection D-Bus object at {col_path_str}"),
            Ok(false) => warn!("[collection] Collection D-Bus object not found at {col_path_str}"),
            Err(e) => warn!("[collection] Failed to unregister collection at {col_path_str}: {e}"),
        }

        // Emit CollectionDeleted on the Service interface (best effort).
        match zbus::SignalContext::new(conn, "/org/freedesktop/secrets") {
            Ok(signal_ctxt) => {
                if let Err(e) = crate::service::ServiceInterface::collection_deleted(
                    &signal_ctxt,
                    col_path,
                ).await {
                    warn!("[collection] CollectionDeleted signal failed: {e}");
                }
            }
            Err(e) => warn!("[collection] Could not build signal context for CollectionDeleted: {e}"),
        }

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
    /// When `replace` is true and an existing item whose attributes are a
    /// superset of the new item's attributes is found, that item is updated
    /// in place (same UUID / path) rather than creating a duplicate.
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
        info!("[collection] CreateItem called for collection={} replace={replace}", self.id);

        // Extract label and attributes first so they are available for both
        // the replace-search path and the new-item path below.
        let label = match properties.remove("org.freedesktop.Secret.Item.Label") {
            Some(Value::Str(s)) => s.to_string(),
            _ => "Unnamed".to_string(),
        };
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

        // Clone the Arc early so it is available to both paths below without
        // needing to borrow self across await points.
        let conn_arc = Arc::clone(&self.conn);

        // ── Replace path ─────────────────────────────────────────────────────
        // When replace=true, find any existing item whose stored attributes
        // contain all of the new item's attributes.  Update it in place so
        // clients receive the same item path they already know about.
        if replace {
            let existing = storage::load_items(&self.id)
                .into_iter()
                .find(|stored| {
                    attributes
                        .iter()
                        .all(|(k, v)| stored.attributes.get(k) == Some(v))
                });

            if let Some(mut existing_item) = existing {
                info!(
                    "[collection] CreateItem replacing existing item={} in collection={}",
                    existing_item.id, self.id
                );
                existing_item.sealed_value = sealed;
                existing_item.content_type = secret.content_type;
                existing_item.modified = now;
                storage::save_item(&existing_item)
                    .map_err(|e| zbus::fdo::Error::Failed(format!("Save item: {e}")))?;

                // Update the collection's modified timestamp on disk.
                self.modified = now;
                if let Err(e) = storage::save_collection(&StoredCollection {
                    id: self.id.clone(),
                    label: self.label.clone(),
                    created: self.created,
                    modified: now,
                }) {
                    warn!("[collection] Failed to update collection modified time: {e}");
                }

                // D-Bus path uses underscores; on-disk UUID uses hyphens.
                let safe_id = existing_item.id.replace('-', "_");
                let item_path = OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}/{}",
                    self.id, safe_id
                ))
                .map_err(|e| zbus::fdo::Error::Failed(format!("Bad item path: {e}")))?;

                let prompt_path = OwnedObjectPath::try_from("/").unwrap();
                return Ok((item_path, prompt_path));
            }
        }

        // ── New item path ────────────────────────────────────────────────────
        let item_id = uuid::Uuid::new_v4().to_string();
        // D-Bus object paths cannot contain hyphens; replace with underscores for the path.
        // The on-disk file continues to use the raw UUID (item_id) with hyphens.
        let safe_item_id = item_id.replace('-', "_");
        let item_path_str = format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.id, safe_item_id
        );

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

        // Update the collection's modified timestamp on disk.
        self.modified = now;
        if let Err(e) = storage::save_collection(&StoredCollection {
            id: self.id.clone(),
            label: self.label.clone(),
            created: self.created,
            modified: now,
        }) {
            warn!("[collection] Failed to update collection modified time: {e}");
        }

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
            conn: Arc::clone(&conn_arc),
        };

        // Register the new item on the D-Bus object server.
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

        // Emit ItemCreated signal so clients with subscriptions are notified.
        let col_path = format!("/org/freedesktop/secrets/collection/{}", self.id);
        match zbus::SignalContext::new(conn, col_path.as_str()) {
            Ok(signal_ctxt) => {
                if let Err(e) = CollectionInterface::item_created(&signal_ctxt, item_path.clone()).await {
                    warn!("[collection] ItemCreated signal failed: {e}");
                }
            }
            Err(e) => warn!("[collection] Could not build signal context for ItemCreated: {e}"),
        }

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((item_path, prompt_path))
    }
}
