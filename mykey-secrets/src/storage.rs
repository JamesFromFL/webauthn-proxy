// storage.rs — On-disk storage for Secret Service collections and items.
//
// Secrets are stored as TPM2-sealed blobs under /etc/mykey/secrets/.
// Layout:
//   /etc/mykey/secrets/<collection_id>/collection.json
//   /etc/mykey/secrets/<collection_id>/<item_id>.json

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

const BASE_DIR: &str = "/etc/mykey/secrets";

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

/// Load all collections from disk.  Missing or unreadable entries are skipped.
pub fn load_collections() -> Vec<StoredCollection> {
    let base = std::path::Path::new(BASE_DIR);
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

/// Persist a collection's metadata to disk.
pub fn save_collection(c: &StoredCollection) -> Result<(), String> {
    let dir = std::path::Path::new(BASE_DIR).join(&c.id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create collection dir {}: {e}", dir.display()))?;
    let path = dir.join("collection.json");
    let data = serde_json::to_vec_pretty(c)
        .map_err(|e| format!("Cannot serialise collection: {e}"))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

/// Load all items belonging to a collection.
pub fn load_items(collection_id: &str) -> Vec<StoredItem> {
    let dir = std::path::Path::new(BASE_DIR).join(collection_id);
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

/// Persist an item to disk.
pub fn save_item(item: &StoredItem) -> Result<(), String> {
    let dir = std::path::Path::new(BASE_DIR).join(&item.collection_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create item dir {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", item.id));
    let data = serde_json::to_vec_pretty(item)
        .map_err(|e| format!("Cannot serialise item: {e}"))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

/// Delete an item from disk.
pub fn delete_item(collection_id: &str, item_id: &str) -> Result<(), String> {
    let path = std::path::Path::new(BASE_DIR)
        .join(collection_id)
        .join(format!("{item_id}.json"));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Cannot delete {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Delete the entire collection directory from disk.
pub fn delete_collection_dir(collection_id: &str) -> Result<(), String> {
    let dir = std::path::Path::new(BASE_DIR).join(collection_id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("Cannot delete collection dir {}: {e}", dir.display()))?;
    }
    Ok(())
}

const ALIASES_FILE: &str = "/etc/mykey/provider/aliases.json";

/// Load alias mappings from disk.  Returns an empty map if the file is absent.
pub fn load_aliases() -> HashMap<String, String> {
    let path = std::path::Path::new(ALIASES_FILE);
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice::<HashMap<String, String>>(&data)
            .unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Persist alias mappings to disk as a JSON object.
pub fn save_aliases(aliases: &HashMap<String, String>) -> Result<(), String> {
    let path = std::path::Path::new(ALIASES_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create aliases dir {}: {e}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(aliases)
        .map_err(|e| format!("Cannot serialise aliases: {e}"))?;
    std::fs::write(path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}
