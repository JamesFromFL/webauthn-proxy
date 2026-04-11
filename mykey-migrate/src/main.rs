// main.rs — MyKey Migration Tool entry point.
//
// Reads all secrets from the running Secret Service provider and imports
// them into MyKey's TPM2-sealed storage via mykey-daemon.

mod daemon_client;
mod secrets_client;
mod storage;

use std::collections::HashMap;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn main() {
    // Banner
    println!("MyKey Migration Tool");
    println!("Migrates secrets from an existing Secret Service provider");
    println!("to MyKey TPM2-sealed storage.");
    println!("Nothing will be deleted from the source provider.");
    println!();

    // 1. Detect provider
    let provider = match secrets_client::detect_provider() {
        Ok(p) => {
            print!("Detected provider: {}", p.process_name);
            if let Some(svc) = &p.service_name {
                print!(" ({svc})");
            }
            println!();
            p
        }
        Err(_) => {
            println!("No Secret Service provider detected. Nothing to migrate.");
            std::process::exit(0);
        }
    };
    println!();

    // 2. Connect to mykey-daemon
    let daemon = match daemon_client::DaemonClient::connect() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("mykey-daemon is not running. Start it with:");
            eprintln!("  systemctl start mykey-daemon");
            std::process::exit(1);
        }
    };

    // 3. Read all secrets from provider
    println!("Reading secrets from {}...", provider.process_name);
    let migrated_items = match secrets_client::read_all_secrets() {
        Ok(items) => items,
        Err(e) => {
            eprintln!("Error reading secrets: {e}");
            std::process::exit(1);
        }
    };

    let collection_count = migrated_items
        .iter()
        .map(|i| i.collection_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let n = migrated_items.len();
    println!("Found {n} secret(s) across {collection_count} collection(s).");

    if n == 0 {
        println!("Nothing to migrate.");
        std::process::exit(0);
    }
    println!();

    // 4. Seal, verify, and store each item
    let mut success_count = 0usize;
    let mut failed_count = 0usize;
    let mut created_collections: HashMap<String, bool> = HashMap::new();

    for item in &migrated_items {
        print!("Migrating: [{}] {}...", item.collection_label, item.label);

        // a. Seal
        let sealed_blob = match daemon.seal_secret(&item.plaintext) {
            Ok(b) => b,
            Err(e) => {
                println!();
                eprintln!("  ✗ Failed to seal: {e}");
                failed_count += 1;
                continue;
            }
        };

        // b. Verify round-trip
        match daemon.unseal_secret(&sealed_blob) {
            Ok(unsealed) if unsealed == item.plaintext => {
                println!(" ✓ Verified");
            }
            Ok(_) => {
                println!();
                eprintln!("  ✗ Verification failed for: {}", item.label);
                failed_count += 1;
                continue;
            }
            Err(e) => {
                println!();
                eprintln!("  ✗ Unseal for verification failed: {e}");
                failed_count += 1;
                continue;
            }
        }

        // c. Ensure collection exists in storage
        if !created_collections.contains_key(&item.collection_id) {
            let existing = storage::load_collections();
            let already_exists = existing.iter().any(|c| c.id == item.collection_id);
            if !already_exists {
                let ts = now_secs();
                let col = storage::StoredCollection {
                    id: item.collection_id.clone(),
                    label: item.collection_label.clone(),
                    created: ts,
                    modified: ts,
                };
                if let Err(e) = storage::save_collection(&col) {
                    eprintln!("  ✗ Failed to create collection: {e}");
                    failed_count += 1;
                    continue;
                }
            }
            created_collections.insert(item.collection_id.clone(), true);
        }

        // d. Build and save StoredItem
        let stored = storage::StoredItem {
            id: uuid::Uuid::new_v4().to_string(),
            collection_id: item.collection_id.clone(),
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            sealed_value: sealed_blob,
            content_type: item.content_type.clone(),
            created: item.created,
            modified: item.modified,
        };

        if let Err(e) = storage::save_item(&stored) {
            eprintln!("  ✗ Failed to save: {e}");
            failed_count += 1;
            continue;
        }

        success_count += 1;
    }

    // 5. Summary
    println!();
    println!("Migration complete.");
    println!("  Migrated: {success_count}");
    println!("  Failed:   {failed_count}");

    if failed_count > 0 {
        println!();
        println!("Some items failed. Source provider has NOT been stopped.");
        println!("Fix the errors above and run mykey-migrate again.");
        std::process::exit(1);
    }

    // 6. All succeeded — stop the provider
    println!();
    println!("All secrets migrated and verified.");
    println!("Stopping {}...", provider.process_name);

    if let Err(e) = secrets_client::stop_provider(&provider) {
        eprintln!("[warn] Could not stop provider: {e}");
        // Migration succeeded; do not exit with error.
    }

    println!("Done. MyKey Secrets can now start as the Secret Service provider.");
    println!("Run: systemctl --user start mykey-secrets");

    // 7. Optional keychain deletion
    if let Some(ref keychain_path) = provider.keychain_path {
        prompt_delete_keychain(&provider, keychain_path);
    }
}

// ---------------------------------------------------------------------------
// Keychain deletion prompt
// ---------------------------------------------------------------------------

fn prompt_delete_keychain(provider: &secrets_client::ProviderInfo, keychain_path: &str) {
    println!();
    println!("═══════════════════════════════════════════════════");
    println!("Optional: Delete old keychain");
    println!("═══════════════════════════════════════════════════");
    println!("Your secrets have been migrated and TPM2-sealed.");
    println!("The old keychain ({keychain_path}) still exists on disk.");
    println!();
    println!("Deleting it is recommended — it contains your secrets");
    println!("in a less secure format.");
    println!();
    println!("This is REVERSIBLE. If you uninstall MyKey, your secrets");
    println!("will be restored back to a reinstalled provider.");
    println!();

    print!("Delete old keychain? [y/N]: ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    if line.trim().to_lowercase() != "y" {
        println!("Keychain kept. You can delete it later.");
        return;
    }

    print!("Are you sure? This cannot be undone without MyKey. [y/N]: ");
    std::io::stdout().flush().ok();

    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm).ok();
    if confirm.trim().to_lowercase() != "y" {
        println!("Keychain kept. You can delete it later.");
        return;
    }

    match std::fs::remove_dir_all(keychain_path) {
        Ok(()) => {
            let deleted_at = now_secs();
            secrets_client::write_provider_info(provider, true, Some(deleted_at));
            println!("✓ Old keychain deleted.");
        }
        Err(e) => {
            eprintln!("[warn] Failed to delete keychain at {keychain_path}: {e}");
        }
    }
}
