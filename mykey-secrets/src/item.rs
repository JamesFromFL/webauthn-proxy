// item.rs — org.freedesktop.Secret.Item D-Bus interface implementation.
//
// Represents a single stored secret.  Properties reflect the stored item
// metadata; GetSecret/SetSecret delegate to the daemon for TPM2 sealing.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use log::{debug, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::service::SecretStruct;

/// Implements the org.freedesktop.Secret.Item interface for a single secret.
pub struct ItemInterface {
    pub id: String,
    pub collection_id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
    /// TPM2-sealed secret bytes (empty until a secret is stored).
    pub sealed_value: Vec<u8>,
    /// Shared connection, used to unregister this D-Bus object on Delete().
    pub conn: Arc<OnceLock<zbus::Connection>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl ItemInterface {
    // ── Properties ───────────────────────────────────────────────────────────

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        self.attributes.clone()
    }

    #[zbus(property)]
    fn label(&self) -> &str {
        &self.label
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

    /// Delete this item.  Returns an empty prompt path (no prompt required).
    async fn delete(&self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        info!("[item] Delete called for item={}", self.id);
        crate::storage::delete_item(&self.collection_id, &self.id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Delete failed: {e}")))?;

        // Unregister the D-Bus object so the path no longer responds after deletion.
        let safe_id = self.id.replace('-', "_");
        let item_path_str = format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.collection_id, safe_id
        );
        let item_path = OwnedObjectPath::try_from(item_path_str.as_str())
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());

        if let Some(conn) = self.conn.get() {
            match conn.object_server().remove::<ItemInterface, _>(item_path_str.as_str()).await {
                Ok(true) => info!("[item] Unregistered D-Bus object at {item_path_str}"),
                Ok(false) => warn!("[item] D-Bus object not found at {item_path_str}"),
                Err(e) => warn!("[item] Failed to unregister D-Bus object at {item_path_str}: {e}"),
            }

            // Emit ItemDeleted signal on the parent collection (best effort).
            let col_path = format!("/org/freedesktop/secrets/collection/{}", self.collection_id);
            match zbus::SignalContext::new(conn, col_path.as_str()) {
                Ok(signal_ctxt) => {
                    if let Err(e) = crate::collection::CollectionInterface::item_deleted(
                        &signal_ctxt,
                        item_path,
                    ).await {
                        warn!("[item] ItemDeleted signal failed: {e}");
                    }
                }
                Err(e) => warn!("[item] Could not build signal context for ItemDeleted: {e}"),
            }
        }

        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    /// Return the secret value for this item, decrypted via the daemon.
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<SecretStruct, zbus::fdo::Error> {
        debug!("[item] GetSecret called for item={}", self.id);
        let client = crate::daemon_client::DaemonClient::connect()
            .await
            .map_err(|e| {
                warn!("[item] GetSecret: daemon connect failed for item={}: {e}", self.id);
                zbus::fdo::Error::Failed(format!("Daemon connect: {e}"))
            })?;
        let plaintext = client
            .unseal_secret(&self.sealed_value)
            .await
            .map_err(|e| {
                warn!("[item] GetSecret: unseal failed for item={}: {e}", self.id);
                zbus::fdo::Error::Failed(format!("UnsealSecret: {e}"))
            })?;
        Ok(SecretStruct {
            session,
            parameters: Vec::new(),
            value: plaintext,
            content_type: self.content_type.clone(),
        })
    }

    /// Store a new secret value for this item, sealing it via the daemon.
    async fn set_secret(&mut self, secret: SecretStruct) -> Result<(), zbus::fdo::Error> {
        debug!("[item] SetSecret called for item={}", self.id);
        let client = crate::daemon_client::DaemonClient::connect()
            .await
            .map_err(|e| {
                warn!("[item] SetSecret: daemon connect failed for item={}: {e}", self.id);
                zbus::fdo::Error::Failed(format!("Daemon connect: {e}"))
            })?;
        let sealed = client
            .seal_secret(&secret.value)
            .await
            .map_err(|e| {
                warn!("[item] SetSecret: seal failed for item={}: {e}", self.id);
                zbus::fdo::Error::Failed(format!("SealSecret: {e}"))
            })?;
        self.sealed_value = sealed.clone();
        self.content_type = secret.content_type.clone();
        self.modified = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = crate::storage::StoredItem {
            id: self.id.clone(),
            collection_id: self.collection_id.clone(),
            label: self.label.clone(),
            attributes: self.attributes.clone(),
            sealed_value: sealed,
            content_type: secret.content_type,
            created: self.created,
            modified: self.modified,
        };
        crate::storage::save_item(&stored)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Save item: {e}")))?;

        // Emit ItemChanged signal on the parent collection (best effort).
        let safe_id = self.id.replace('-', "_");
        let item_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.collection_id, safe_id
        ))
        .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());
        let col_path = format!("/org/freedesktop/secrets/collection/{}", self.collection_id);
        if let Some(conn) = self.conn.get() {
            match zbus::SignalContext::new(conn, col_path.as_str()) {
                Ok(signal_ctxt) => {
                    if let Err(e) = crate::collection::CollectionInterface::item_changed(
                        &signal_ctxt,
                        item_path,
                    ).await {
                        warn!("[item] ItemChanged signal failed: {e}");
                    }
                }
                Err(e) => warn!("[item] Could not build signal context for ItemChanged: {e}"),
            }
        }

        Ok(())
    }
}
