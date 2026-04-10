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

    // Load or create the default collection metadata.
    let stored_cols = storage::load_collections();
    let default_meta = stored_cols
        .into_iter()
        .find(|c| c.id == "default")
        .unwrap_or_else(|| {
            let col = storage::StoredCollection {
                id: "default".to_string(),
                label: "Default keyring".to_string(),
                created: now,
                modified: now,
            };
            if let Err(e) = storage::save_collection(&col) {
                warn!("Could not persist default collection: {e}");
            }
            col
        });

    // Pre-populate item paths so the Items property is correct on startup.
    let stored_items = storage::load_items("default");
    let item_paths: Vec<OwnedObjectPath> = stored_items
        .iter()
        .filter_map(|i| {
            OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/default/{}",
                i.id
            ))
            .ok()
        })
        .collect();

    let default_col = CollectionInterface {
        id: default_meta.id,
        label: default_meta.label,
        created: default_meta.created,
        modified: default_meta.modified,
        item_paths,
        conn: Arc::clone(&conn_cell),
    };

    let svc = service::ServiceInterface::new();

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
        .serve_at("/org/freedesktop/secrets/collection/default", default_col)
        .unwrap_or_else(|e| {
            error!("Failed to serve default collection: {e}");
            process::exit(1);
        })
        .build()
        .await
        .unwrap_or_else(|e| {
            error!("Failed to build D-Bus connection: {e}");
            process::exit(1);
        });

    // Now that the connection is live, share it so CollectionInterface can
    // register new items at runtime.
    conn_cell
        .set(conn.clone())
        .expect("conn_cell set more than once");

    // Register ItemInterface objects for items that already exist on disk.
    for item in stored_items {
        let path = format!(
            "/org/freedesktop/secrets/collection/default/{}",
            item.id
        );
        let iface = ItemInterface {
            id: item.id,
            collection_id: item.collection_id,
            label: item.label,
            attributes: item.attributes,
            content_type: item.content_type,
            created: item.created,
            modified: item.modified,
            sealed_value: item.sealed_value,
        };
        if let Err(e) = conn.object_server().at(path, iface).await {
            warn!("Could not register pre-existing item: {e}");
        }
    }

    info!("mykey-secrets ready on org.freedesktop.secrets");

    // Run forever
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        let _ = &conn;
    }
}
