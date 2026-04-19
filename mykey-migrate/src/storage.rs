// storage.rs — On-disk storage for Secret Service collections and items.
//
// Secrets are stored as TPM2-sealed blobs under /etc/mykey/secrets/.
// Layout:
//   /etc/mykey/secrets/<collection_id>/collection.json
//   /etc/mykey/secrets/<collection_id>/<item_id>.json

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

const BASE_DIR: &str = "/etc/mykey/secrets";

fn save_collection_in(base_dir: &Path, c: &StoredCollection) -> Result<(), String> {
    let dir = base_dir.join(&c.id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create collection dir {}: {e}", dir.display()))?;
    let path = dir.join("collection.json");
    let data = serde_json::to_vec_pretty(c)
        .map_err(|e| format!("Cannot serialise collection: {e}"))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

fn save_item_in(base_dir: &Path, item: &StoredItem) -> Result<(), String> {
    let dir = base_dir.join(&item.collection_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create item dir {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", item.id));
    let data = serde_json::to_vec_pretty(item)
        .map_err(|e| format!("Cannot serialise item: {e}"))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

/// Metadata for a stored collection (persisted as collection.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCollection {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

/// A stored secret item.  `sealed_value` contains the TPM2-sealed secret bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    pub id: String,
    pub collection_id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    /// TPM2-sealed secret bytes produced by mykey-daemon SealSecret.
    pub sealed_value: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

pub struct StagedStorage {
    path: PathBuf,
}

pub struct ActivatedStorage {
    previous_base: Option<PathBuf>,
}

impl StagedStorage {
    pub fn new() -> Result<Self, String> {
        let path = PathBuf::from(format!("{}.staging-{}", BASE_DIR, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("Cannot create staging dir {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    pub fn save_collection(&self, c: &StoredCollection) -> Result<(), String> {
        save_collection_in(&self.path, c)
    }

    pub fn save_item(&self, item: &StoredItem) -> Result<(), String> {
        save_item_in(&self.path, item)
    }

    pub fn discard(self) -> Result<(), String> {
        if self.path.exists() {
            std::fs::remove_dir_all(&self.path)
                .map_err(|e| format!("Cannot remove staging dir {}: {e}", self.path.display()))?;
        }
        Ok(())
    }

    pub fn activate(self) -> Result<ActivatedStorage, String> {
        let base = Path::new(BASE_DIR);
        let previous_base = if base.exists() {
            let backup = PathBuf::from(format!("{}.backup-{}", BASE_DIR, uuid::Uuid::new_v4()));
            std::fs::rename(base, &backup).map_err(|e| {
                format!(
                    "Cannot move existing storage {} to {}: {e}",
                    base.display(),
                    backup.display()
                )
            })?;
            Some(backup)
        } else {
            None
        };

        if let Err(e) = std::fs::rename(&self.path, base) {
            if let Some(ref backup) = previous_base {
                let _ = std::fs::rename(backup, base);
            }
            return Err(format!(
                "Cannot activate staged storage {} -> {}: {e}",
                self.path.display(),
                base.display()
            ));
        }

        Ok(ActivatedStorage { previous_base })
    }
}

impl ActivatedStorage {
    pub fn commit(self) -> Result<(), String> {
        if let Some(previous_base) = self.previous_base {
            std::fs::remove_dir_all(&previous_base).map_err(|e| {
                format!(
                    "Cannot remove previous storage backup {}: {e}",
                    previous_base.display()
                )
            })?;
        }
        Ok(())
    }

    pub fn rollback(self) -> Result<(), String> {
        let base = Path::new(BASE_DIR);
        if base.exists() {
            std::fs::remove_dir_all(base)
                .map_err(|e| format!("Cannot remove active storage {}: {e}", base.display()))?;
        }
        if let Some(previous_base) = self.previous_base {
            std::fs::rename(&previous_base, base).map_err(|e| {
                format!(
                    "Cannot restore previous storage {} -> {}: {e}",
                    previous_base.display(),
                    base.display()
                )
            })?;
        }
        Ok(())
    }
}

/// Load all collections from disk.  Missing or unreadable entries are skipped.
pub fn load_collections() -> Vec<StoredCollection> {
    let base = Path::new(BASE_DIR);
    if !base.exists() {
        return Vec::new();
    }
    let mut cols = Vec::new();
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return cols,
    };
    for entry in entries.flatten() {
        let col_json = entry.path().join("collection.json");
        if let Ok(data) = std::fs::read(&col_json) {
            if let Ok(col) = serde_json::from_slice::<StoredCollection>(&data) {
                cols.push(col);
            }
        }
    }
    cols
}

/// Load all items belonging to a collection.
pub fn load_items(collection_id: &str) -> Vec<StoredItem> {
    let dir = Path::new(BASE_DIR).join(collection_id);
    if !dir.exists() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return items,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some("collection.json") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(item) = serde_json::from_slice::<StoredItem>(&data) {
                    items.push(item);
                }
            }
        }
    }
    items
}
