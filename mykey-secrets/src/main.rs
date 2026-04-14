// main.rs — Entry point for mykey-secrets, the freedesktop Secret Service provider.
//
// Registers on the D-Bus session bus as "org.freedesktop.secrets" and serves
// the Secret Service API at /org/freedesktop/secrets.

mod collection;
mod daemon_client;
mod item;
mod prereqs;
mod service;
mod session;
mod storage;

use std::process;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use log::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;
use zbus::ConnectionBuilder;
use collection::CollectionInterface;
use item::ItemInterface;

#[tokio::main]
async fn main() {
    // Initialise file logger
    let log_path = "/tmp/mykey-secrets.log";
    let target = Box::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap_or_else(|e| {
                eprintln!("Cannot open log file {log_path}: {e}");
                process::exit(1);
            }),
    );
    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(target))
        .filter_level(log::LevelFilter::Debug)
        .init();

    info!("mykey-secrets starting");

    if let Err(e) = prereqs::enforce_prereqs() {
        error!("Prerequisites check failed: {}", e);
        eprintln!("[mykey-secrets] Prerequisites check failed: {e}");
        std::process::exit(1);
    }

    // Shared connection cell: populated after the connection is built so that
    // CollectionInterface can register new ItemInterface objects at runtime.
    let conn_cell: Arc<OnceLock<zbus::Connection>> = Arc::new(OnceLock::new());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Load all collections from disk.  Always ensure a "default" collection
    // exists so clients that create items unconditionally have somewhere to land.
    let mut stored_cols = storage::load_collections();
    if !stored_cols.iter().any(|c| c.id == "default") {
        let default_meta = storage::StoredCollection {
            id: "default".to_string(),
            label: "Default keyring".to_string(),
            created: now,
            modified: now,
        };
        if let Err(e) = storage::save_collection(&default_meta) {
            warn!("Could not persist default collection: {e}");
        }
        stored_cols.push(default_meta);
    }

    // Build the object path list for the Collections property on the Service.
    let col_paths: Vec<OwnedObjectPath> = stored_cols
        .iter()
        .filter_map(|c| {
            OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}",
                c.id
            ))
            .ok()
        })
        .collect();

    // Determine which collection the "default" alias should resolve to.
    // Prefer any non-default collection (those hold migrated secrets from a
    // previous provider such as gnome-keyring's "Login" keyring).  Fall back
    // to "default" if no other collection exists.
    let default_alias_id = stored_cols
        .iter()
        .find(|c| c.id != "default")
        .or_else(|| stored_cols.iter().find(|c| c.id == "default"))
        .map(|c| c.id.as_str())
        .unwrap_or("default");
    let default_alias = OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{default_alias_id}"
    ))
    .unwrap_or_else(|_| {
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap()
    });

    info!(
        "[main] {} collection(s) found; default alias → {}",
        stored_cols.len(),
        default_alias.as_str()
    );

    let svc = service::ServiceInterface::new(col_paths, default_alias.clone());

    // Build the D-Bus connection.  Only the top-level ServiceInterface is
    // registered here; all collections and items are registered below after
    // conn_cell is populated, because CollectionInterface holds an Arc to it.
    let conn = ConnectionBuilder::session()
        .unwrap_or_else(|e| {
            error!("Failed to connect to session bus: {e}");
            process::exit(1);
        })
        .name("org.freedesktop.secrets")
        .unwrap_or_else(|e| {
            error!("Failed to claim org.freedesktop.secrets: {e}");
            process::exit(1);
        })
        .serve_at("/org/freedesktop/secrets", svc)
        .unwrap_or_else(|e| {
            error!("Failed to serve ServiceInterface: {e}");
            process::exit(1);
        })
        .build()
        .await
        .unwrap_or_else(|e| {
            error!("Failed to build D-Bus connection: {e}");
            process::exit(1);
        });

    // Share the connection with CollectionInterface so it can register new
    // items at runtime when CreateItem is called.
    conn_cell
        .set(conn.clone())
        .expect("conn_cell set more than once");

    // Register every collection and all of its pre-existing items.
    for col_meta in &stored_cols {
        let col_path_str = format!(
            "/org/freedesktop/secrets/collection/{}",
            col_meta.id
        );

        let stored_items = storage::load_items(&col_meta.id);
        let item_paths: Vec<OwnedObjectPath> = stored_items
            .iter()
            .filter_map(|i| {
                let safe_id = i.id.replace('-', "_");
                OwnedObjectPath::try_from(format!("{}/{}", col_path_str, safe_id)).ok()
            })
            .collect();

        info!(
            "[main] Registering collection '{}' with {} item(s) at {}",
            col_meta.id,
            stored_items.len(),
            col_path_str
        );

        let col_iface = CollectionInterface {
            id: col_meta.id.clone(),
            label: col_meta.label.clone(),
            created: col_meta.created,
            modified: col_meta.modified,
            item_paths,
            conn: Arc::clone(&conn_cell),
        };

        if let Err(e) = conn.object_server().at(col_path_str.clone(), col_iface).await {
            warn!("Could not register collection '{}': {e}", col_meta.id);
        }

        // Register each item under /org/freedesktop/secrets/collection/<id>/<item_id>.
        // UUIDs contain hyphens which are invalid in D-Bus object paths; replace with underscores.
        for item in stored_items {
            let safe_id = item.id.replace('-', "_");
            let item_path = format!("{}/{}", col_path_str, safe_id);
            let item_iface = ItemInterface {
                id: item.id,
                collection_id: item.collection_id,
                label: item.label,
                attributes: item.attributes,
                content_type: item.content_type,
                created: item.created,
                modified: item.modified,
                sealed_value: item.sealed_value,
            };
            if let Err(e) = conn.object_server().at(item_path.clone(), item_iface).await {
                warn!("Could not register item at {item_path}: {e}");
            }
        }
    }

    // Register /org/freedesktop/secrets/aliases/default pointing at the
    // primary collection.  Many clients (libsecret, go-keyring used by gh,
    // etc.) call CreateItem and SearchItems directly on this alias path rather
    // than on the canonical collection path.
    let alias_source = stored_cols
        .iter()
        .find(|c| c.id == default_alias_id)
        .cloned();

    if let Some(col_meta) = alias_source {
        let col_path_str = format!(
            "/org/freedesktop/secrets/collection/{}",
            col_meta.id
        );
        let stored_items = storage::load_items(&col_meta.id);
        let item_paths: Vec<OwnedObjectPath> = stored_items
            .iter()
            .filter_map(|i| {
                let safe_id = i.id.replace('-', "_");
                OwnedObjectPath::try_from(format!("{}/{}", col_path_str, safe_id)).ok()
            })
            .collect();

        let alias_iface = CollectionInterface {
            id: col_meta.id.clone(),
            label: col_meta.label.clone(),
            created: col_meta.created,
            modified: col_meta.modified,
            item_paths,
            conn: Arc::clone(&conn_cell),
        };

        if let Err(e) = conn
            .object_server()
            .at("/org/freedesktop/secrets/aliases/default", alias_iface)
            .await
        {
            warn!("Could not register aliases/default: {e}");
        } else {
            info!("[main] Registered aliases/default → {}", col_path_str);
        }
    }

    info!("mykey-secrets ready on org.freedesktop.secrets");

    // Run forever.
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        let _ = &conn;
    }
}
