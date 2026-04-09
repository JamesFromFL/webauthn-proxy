// collection.rs — org.freedesktop.Secret.Collection D-Bus interface.
//
// A collection groups related secret items.  The default collection is served
// at /org/freedesktop/secrets/collection/default.

use std::collections::HashMap;
use log::info;
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::service::SecretStruct;

/// Implements org.freedesktop.Secret.Collection for a single collection.
pub struct CollectionInterface {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    /// Object paths of items belonging to this collection.
    pub item_paths: Vec<OwnedObjectPath>,
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
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Vec<OwnedObjectPath> {
        // Return all item paths whose stored attributes contain every key=value
        // pair from the query.  Full implementation requires access to item
        // attribute data; for now return the full item list as a stub.
        let _ = attributes;
        self.item_paths.clone()
    }

    /// Create a new item in this collection.
    ///
    /// Returns `(item_path, prompt_path)`.  Prompt path is "/" (no prompt).
    async fn create_item(
        &self,
        properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        let _ = (properties, secret, replace);
        info!("[collection] CreateItem called for collection={} (stub)", self.id);
        // Stub: full implementation registers the item on the object path and
        // persists via storage::save_item.
        let item_path = OwnedObjectPath::try_from(
            format!("/org/freedesktop/secrets/collection/{}/stub", self.id)
        ).map_err(|e| zbus::fdo::Error::Failed(format!("Bad path: {e}")))?;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((item_path, prompt_path))
    }
}
