// main.rs — MyKey Migration Tool entry point.
//
// Supports two subcommands:
//   --enroll    Migrate secrets from an existing provider to MyKey TPM2-sealed storage.
//   --unenroll  Restore secrets from MyKey back to the previous provider.

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

fn read_line() -> String {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s
}

fn print_usage() {
    println!("MyKey Migration Tool");
    println!();
    println!("Usage:");
    println!("  mykey-migrate --enroll     Migrate secrets from existing provider to MyKey");
    println!("  mykey-migrate --unenroll   Restore secrets from MyKey back to previous provider");
}

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--enroll") => run_enroll(),
        Some("--unenroll") => run_unenroll(),
        _ => {
            print_usage();
            std::process::exit(0);
        }
    }
}

// ---------------------------------------------------------------------------
// --enroll
// ---------------------------------------------------------------------------

fn run_enroll() {
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
        println!("Fix the errors above and run mykey-migrate --enroll again.");
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
    if read_line().trim().to_lowercase() != "y" {
        println!("Keychain kept. You can delete it later.");
        return;
    }

    print!("Are you sure? This cannot be undone without MyKey. [y/N]: ");
    std::io::stdout().flush().ok();
    if read_line().trim().to_lowercase() != "y" {
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

// ---------------------------------------------------------------------------
// --unenroll
// ---------------------------------------------------------------------------

fn run_unenroll() {
    // 1. Read provider info
    let info = match secrets_client::read_provider_info() {
        Ok(i) => i,
        Err(_) => {
            println!("No provider info found. No migration to reverse.");
            println!("Continuing with uninstall.");
            return;
        }
    };

    println!("MyKey Unenroll");
    println!("Restoring secrets to: {}", info.process_name);
    println!("Nothing in MyKey storage will be deleted until secrets are verified.");

    // 2. Check if old provider is installed
    if !secrets_client::check_provider_installed(&info.process_name) {
        println!();
        println!("⚠ Previous provider '{}' is not installed.", info.package_name);
        print!("  Reinstall it now? [Y/N]: ");
        std::io::stdout().flush().ok();
        let answer = read_line();
        if answer.trim().to_lowercase() == "y" {
            match secrets_client::reinstall_provider(&info.package_name) {
                Ok(_) => println!("✓ {} reinstalled.", info.package_name),
                Err(e) => {
                    eprintln!("✗ Failed to reinstall: {e}");
                    eprintln!(
                        "  Install {} manually then run mykey-migrate --unenroll again.",
                        info.package_name
                    );
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Cannot unenroll without a Secret Service provider.");
            eprintln!(
                "Install {} then run mykey-migrate --unenroll again.",
                info.package_name
            );
            std::process::exit(1);
        }
    }

    // 3. Stop mykey-secrets to free org.freedesktop.secrets
    println!("Stopping mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mykey-secrets"])
        .status();
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 4. Connect to mykey-daemon for unsealing (must stay running)
    let daemon = match daemon_client::DaemonClient::connect() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ Cannot connect to mykey-daemon: {e}");
            eprintln!("  mykey-daemon must be running for unenroll.");
            eprintln!("  Start it with: systemctl start mykey-daemon");
            std::process::exit(1);
        }
    };

    // 5. Start old provider and wait for it to claim the bus
    println!("Starting {}...", info.process_name);
    match secrets_client::start_provider(&info) {
        Ok(_) => println!("✓ {} is running", info.process_name),
        Err(e) => {
            eprintln!("✗ Failed to start provider: {e}");
            std::process::exit(1);
        }
    }

    // 6. Load all MyKey secrets from storage
    let collections = storage::load_collections();
    let mut all_items: Vec<storage::StoredItem> = Vec::new();
    for col in &collections {
        all_items.extend(storage::load_items(&col.id));
    }
    println!("Found {} secret(s) in MyKey storage.", all_items.len());

    // 7. Determine which secrets need restoring
    let secrets_to_restore: Vec<&storage::StoredItem> = if info.keychain_deleted {
        println!("Old keychain was deleted — restoring all {} secret(s).", all_items.len());
        all_items.iter().collect()
    } else {
        let existing = secrets_client::list_provider_secrets().unwrap_or_default();
        let existing_labels: std::collections::HashSet<String> =
            existing.into_iter().map(|(label, _)| label).collect();
        let new_secrets: Vec<&storage::StoredItem> = all_items
            .iter()
            .filter(|item| !existing_labels.contains(&item.label))
            .collect();
        println!(
            "Found {} new secret(s) to restore (not in old keychain).",
            new_secrets.len()
        );
        new_secrets
    };

    // 8. Unseal and write each secret back to old provider
    let mut success = 0usize;
    let mut failed = 0usize;

    for item in &secrets_to_restore {
        print!("Restoring: {}... ", item.label);
        std::io::stdout().flush().ok();
        match daemon.unseal_secret(&item.sealed_value) {
            Ok(plaintext) => {
                match secrets_client::write_secret_to_provider(
                    &item.label,
                    &item.attributes,
                    &plaintext,
                    &item.content_type,
                ) {
                    Ok(_) => {
                        println!("✓");
                        success += 1;
                    }
                    Err(e) => {
                        println!("✗ Failed to write: {e}");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                println!("✗ Failed to unseal: {e}");
                failed += 1;
            }
        }
    }

    // 9. Summary and halt on failure
    println!();
    println!("Restore complete.");
    println!("  Restored: {success}");
    println!("  Failed:   {failed}");

    if failed > 0 {
        eprintln!("✗ Some secrets failed to restore.");
        eprintln!("  MyKey storage has NOT been deleted.");
        eprintln!("  Fix the errors above and run mykey-migrate --unenroll again.");
        std::process::exit(1);
    }

    // 10. Clean up MyKey secrets storage
    println!("All secrets restored. Cleaning up MyKey storage...");
    if let Err(e) = std::fs::remove_dir_all("/etc/mykey/secrets") {
        eprintln!("⚠ Could not remove /etc/mykey/secrets: {e}");
    } else {
        println!("✓ /etc/mykey/secrets removed.");
    }

    // 11. Remove provider info
    let _ = secrets_client::delete_provider_info();
    println!("✓ Provider info removed.");
    println!();
    println!(
        "Unenroll complete. {} is now your Secret Service provider.",
        info.process_name
    );
    println!("MyKey uninstall can now continue.");
}
