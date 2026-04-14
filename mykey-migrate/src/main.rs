// main.rs — MyKey Migration Tool entry point.
//
// Supports two subcommands:
//   --enroll    Migrate secrets from an existing provider to MyKey TPM2-sealed storage.
//   --unenroll  Restore secrets from MyKey back to the previous provider.

mod daemon_client;
mod secrets_client;
mod storage;

fn flush_stdout() {
    use std::io::Write;
    std::io::stdout().flush().unwrap_or(());
}

fn read_line() -> String {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap_or(0);
    buf
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
    // Step 1 — Root check
    if std::env::var("USER").unwrap_or_default() == "root"
        || nix::unistd::getuid().is_root()
    {
        eprintln!("Do not run mykey-migrate as root.");
        std::process::exit(1);
    }

    // Step 2 — Check mykey-daemon is running
    match daemon_client::DaemonClient::connect() {
        Err(_) => {
            eprintln!("mykey-daemon is not running.");
            eprintln!("Install MyKey first: https://github.com/JamesFromFL/mykey");
            std::process::exit(1);
        }
        Ok(daemon) => run_enroll_with_daemon(daemon),
    }
}

fn run_enroll_with_daemon(daemon: daemon_client::DaemonClient) {
    // Step 3 — Detect what owns org.freedesktop.secrets
    let provider = secrets_client::detect_provider();

    match provider {
        // Step 4 — Nothing owns the bus
        Err(_) => {
            println!("No Secret Service provider is currently running.");
            println!();

            // Check what's installed
            let installed = secrets_client::find_installed_providers();

            if installed.is_empty() {
                println!("No known Secret Service providers are installed.");
                println!("There are no secrets to migrate.");
                println!();
                print!("Start mykey-secrets as your Secret Service provider? [Y/n]: ");
                flush_stdout();
                let ans = read_line();
                if ans.trim().to_lowercase() != "n" {
                    let _ = std::process::Command::new("systemctl")
                        .args(["--user", "start", "mykey-secrets"])
                        .status();
                    println!("✓ mykey-secrets started.");
                }
                return;
            }

            println!("The following Secret Service providers are installed but not running:");
            for (i, name) in installed.iter().enumerate() {
                println!("  {}. {}", i + 1, name);
            }
            println!();
            print!("Start one to migrate its secrets? Enter number or N to skip: ");
            flush_stdout();
            let ans = read_line();

            if ans.trim().to_lowercase() == "n" || ans.trim().is_empty() {
                println!("No provider started. Starting mykey-secrets...");
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "start", "mykey-secrets"])
                    .status();
                return;
            }

            if let Ok(idx) = ans.trim().parse::<usize>() {
                if idx >= 1 && idx <= installed.len() {
                    let chosen = &installed[idx - 1];
                    match secrets_client::start_provider_by_name(chosen) {
                        Ok(_) => {
                            println!("✓ {} started.", chosen);
                            // Re-detect and continue with migration
                            match secrets_client::detect_provider() {
                                Ok(info) => do_migration(info, daemon),
                                Err(e) => {
                                    eprintln!("Could not connect after starting provider: {e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to start {}: {e}", chosen);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        // Step 5 — mykey-secrets already owns the bus
        Ok(ref info) if info.process_name.contains("mykey-secrets") => {
            println!("MyKey is already your Secret Service provider.");
            println!("Nothing to do.");
        }

        // Step 6 — Third party provider is running
        Ok(info) => {
            do_migration(info, daemon);
        }
    }

    if !secrets_client::ss_still_owned() || secrets_client::is_mykey_secrets_running() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "mykey-secrets"])
            .status();
    }
}

fn do_migration(
    info: secrets_client::ProviderInfo,
    daemon: daemon_client::DaemonClient,
) {
    println!();
    println!(
        "Detected provider: {} ({})",
        info.process_name,
        info.service_name.as_deref().unwrap_or("no systemd service")
    );
    println!();
    println!("MyKey will:");
    println!("  • Copy your secrets and seal them with your TPM2 chip");
    println!("  • Your original keychain will NOT be deleted (unless you choose to)");
    println!("  • All sealed secrets are verified before the old provider is stopped");
    println!("  • This may take some time depending on the number of secrets — please be patient");
    println!();
    println!(
        "⚠ Your previous Secret Service provider ({}) will be uninstalled. \
You can restore it at any time by running: mykey-migrate --unenroll",
        info.process_name
    );
    println!();
    print!("Proceed? [Y/n]: ");
    flush_stdout();
    let ans = read_line();
    if ans.trim().to_lowercase() == "n" {
        println!("Cancelled. Nothing was changed.");
        return;
    }

    // Read secrets
    println!();
    println!("Reading secrets from {}...", info.process_name);
    let items = match secrets_client::read_all_secrets() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Failed to read secrets: {e}");
            std::process::exit(1);
        }
    };
    println!("Found {} secret(s) across collection(s).", items.len());

    if items.is_empty() {
        println!("Nothing to migrate.");
    } else {
        // Seal and verify each secret
        let mut success = 0;
        let mut failed = 0;
        let mut sealed_items: Vec<(secrets_client::MigratedItem, Vec<u8>)> = Vec::new();

        for item in &items {
            print!("Migrating: [{}] {}... ", item.collection_label, item.label);
            flush_stdout();

            match daemon.seal_secret(&item.plaintext) {
                Err(e) => {
                    println!("✗ Seal failed: {e}");
                    failed += 1;
                }
                Ok(sealed) => match daemon.unseal_secret(&sealed) {
                    Err(e) => {
                        println!("✗ Verify failed: {e}");
                        failed += 1;
                    }
                    Ok(verified) => {
                        if verified != item.plaintext {
                            println!("✗ Mismatch after verify");
                            failed += 1;
                        } else {
                            println!("✓ Verified");
                            success += 1;
                            sealed_items.push((item.clone(), sealed));
                        }
                    }
                },
            }
        }

        println!();
        println!("Migration complete.");
        println!("  Migrated: {}", success);
        println!("  Failed:   {}", failed);

        if failed > 0 {
            eprintln!("✗ Some secrets failed. Provider has NOT been stopped.");
            eprintln!("  Fix the errors and run mykey-migrate --enroll again.");
            std::process::exit(1);
        }

        // Save all to disk
        let mut collections_created: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (item, sealed) in &sealed_items {
            if !collections_created.contains(&item.collection_id) {
                let col = storage::StoredCollection {
                    id: item.collection_id.clone(),
                    label: item.collection_label.clone(),
                    created: item.created,
                    modified: item.modified,
                };
                let _ = storage::save_collection(&col);
                collections_created.insert(item.collection_id.clone());
            }
            let stored = storage::StoredItem {
                id: uuid::Uuid::new_v4().to_string(),
                collection_id: item.collection_id.clone(),
                label: item.label.clone(),
                attributes: item.attributes.clone(),
                sealed_value: sealed.clone(),
                content_type: item.content_type.clone(),
                created: item.created,
                modified: item.modified,
            };
            if let Err(e) = storage::save_item(&stored) {
                eprintln!("Failed to save {}: {e}", item.label);
            }
        }
    }

    // Write provider info
    if let Err(e) = secrets_client::write_provider_info(&info) {
        eprintln!("⚠ Could not write provider info: {e}");
    }

    // Stop old provider
    println!();
    println!("Stopping {}...", info.process_name);
    if let Err(e) = secrets_client::stop_provider(&info) {
        eprintln!("✗ Failed to stop provider: {e}");
        eprintln!("  Cannot start mykey-secrets while old provider owns the bus.");
        eprintln!("  Run mykey-migrate --enroll again to retry.");
        std::process::exit(1);
    }

    // Optional keychain deletion
    if let Some(ref kpath) = info.keychain_path {
        prompt_delete_keychain(kpath);
    }

    println!();
    println!("✓ Enrollment complete. MyKey is now your Secret Service provider.");
}

fn prompt_delete_keychain(keychain_path: &str) {
    println!();
    println!("═══════════════════════════════════════════════════");
    println!("Optional: Delete old keychain");
    println!("═══════════════════════════════════════════════════");
    println!("Your secrets have been migrated and TPM2-sealed.");
    println!("The old keychain ({}) still exists.", keychain_path);
    println!();
    println!("Deleting it is RECOMMENDED — it contains your secrets");
    println!("in a less secure software-encrypted format.");
    println!();
    println!("This is REVERSIBLE. If you uninstall MyKey, your secrets");
    println!("will be restored to a reinstalled provider.");
    println!();
    print!("Delete old keychain? [y/N]: ");
    flush_stdout();
    let ans = read_line();
    if ans.trim().to_lowercase() != "y" {
        println!("Keychain kept. You can delete it later by running mykey-migrate --enroll again.");
        return;
    }
    println!();
    print!("Are you sure? This cannot be undone without MyKey. [y/N]: ");
    flush_stdout();
    let confirm = read_line();
    if confirm.trim().to_lowercase() != "y" {
        println!("Keychain kept.");
        return;
    }
    match std::fs::remove_dir_all(keychain_path) {
        Ok(_) => {
            println!("✓ Old keychain deleted.");
            // Update provider info
            if let Ok(mut info) = secrets_client::read_provider_info() {
                info.keychain_deleted = true;
                // re-serialize and write back
                if let Ok(json) = serde_json::to_string_pretty(&secrets_client::ProviderInfoFile {
                    keychain_deleted: true,
                    ..info
                }) {
                    let _ = std::fs::write("/etc/mykey/provider/info.json", json);
                }
            }
        }
        Err(e) => eprintln!("⚠ Could not delete keychain: {e}"),
    }
}

// ---------------------------------------------------------------------------
// --unenroll
// ---------------------------------------------------------------------------

fn run_unenroll() {
    // Step 1 — Root check
    if std::env::var("USER").unwrap_or_default() == "root"
        || nix::unistd::getuid().is_root()
    {
        eprintln!("Do not run mykey-migrate as root.");
        std::process::exit(1);
    }

    // Step 2 — Check mykey-daemon is running
    let daemon = match daemon_client::DaemonClient::connect() {
        Ok(d) => d,
        Err(_) => {
            eprintln!("mykey-daemon is not running. It is required for unenroll.");
            std::process::exit(1);
        }
    };

    // Step 3 — Read provider info
    let info = secrets_client::read_provider_info().unwrap_or(
        secrets_client::ProviderInfoFile {
            process_name: String::new(),
            service_name: None,
            package_name: String::new(),
            keychain_path: None,
            keychain_deleted: false,
        }
    );

    // Step 4 — Warning
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║              MyKey Unenroll                          ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("⚠ WARNING: Continuing will remove your secrets from MyKey.");
    println!("  They will be restored to your chosen Secret Service provider.");
    println!("  If restoration fails for any reason, unenroll will halt");
    println!("  and your MyKey secrets will remain intact.");
    println!();

    let has_prior = !info.process_name.is_empty();

    // Step 5 — Provider selection
    // When no enrollment record exists, option 1 ("previously used") is hidden
    // and the remaining options are renumbered 1–5.
    println!("Where would you like to restore your secrets?");
    println!();
    if has_prior {
        println!("  1. {} (previously used)", info.process_name);
        println!("  2. gnome-keyring");
        println!("  3. KWallet");
        println!("  4. KeePassXC");
        println!("  5. Exit");
        println!("  6. None  ⚠ WARNING: your secrets will be deleted without a backup");
        println!();
        print!("Enter selection [1-6]: ");
    } else {
        println!("  1. gnome-keyring");
        println!("  2. KWallet");
        println!("  3. KeePassXC");
        println!("  4. Exit");
        println!("  5. None  ⚠ WARNING: your secrets will be deleted without a backup");
        println!();
        print!("Enter selection [1-5]: ");
    }
    flush_stdout();
    let selection = read_line();
    let selection = selection.trim().to_string();
    let selection = selection.as_str();

    // Normalize: when has_prior is false the menu is 1–5 instead of 1–6.
    // Map to the canonical 1–6 numbering so all downstream logic is uniform.
    let normalized: &str = if !has_prior {
        match selection {
            "1" => "2",
            "2" => "3",
            "3" => "4",
            "4" => "5",
            "5" => "6",
            other => other,
        }
    } else {
        selection
    };

    // Handle Exit
    if normalized == "5" {
        println!("Exiting. Nothing was changed.");
        return;
    }

    // Handle None
    if normalized == "6" {
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  ⚠  PERMANENT DELETION WARNING                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("You have chosen to unenroll WITHOUT migrating to a new provider.");
        println!();
        println!("This means:");
        println!("  • mykey-secrets will be stopped and disabled");
        println!("  • ALL secrets sealed in MyKey will be PERMANENTLY DELETED");
        println!("  • There will be NO Secret Service provider on your system");
        println!("  • Apps that rely on secrets (browsers, email, VPN) may break");
        println!("  • This action is NOT reversible");
        println!();
        print!("Are you absolutely sure? [y/N]: ");
        flush_stdout();
        let confirm1 = read_line();
        if confirm1.trim().to_lowercase() != "y" {
            println!("Cancelled. Nothing was changed.");
            return;
        }
        println!();
        println!("To confirm permanent deletion, type exactly:");
        println!("  I understand my secrets will not be recoverable. Delete my secrets.");
        println!();
        print!("> ");
        flush_stdout();
        let phrase = read_line();
        if phrase.trim() != "I understand my secrets will not be recoverable. Delete my secrets." {
            println!("Phrase did not match. Cancelled.");
            return;
        }
        // Delete MyKey secrets
        println!();
        println!("Deleting MyKey secrets...");
        let _ = std::fs::remove_dir_all("/etc/mykey/secrets");
        let _ = secrets_client::delete_provider_info();
        // Stop mykey-secrets
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "mykey-secrets"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "mykey-secrets"])
            .status();
        println!("✓ MyKey secrets deleted.");
        println!("  mykey-secrets has been stopped and disabled.");
        println!("  No Secret Service provider is running on your system.");
        return;
    }

    // Determine target provider
    let target_provider = match normalized {
        "1" => info.process_name.clone(),
        "2" => "gnome-keyring-daemon".to_string(),
        "3" => "kwalletd6".to_string(),
        "4" => "keepassxc".to_string(),
        _ => {
            eprintln!("Invalid selection.");
            std::process::exit(1);
        }
    };

    // Step 6 — Install if not present
    let package_name = match target_provider.as_str() {
        "gnome-keyring-daemon" => "gnome-keyring",
        "kwalletd6" | "kwalletd5" => "kwallet6",
        "keepassxc" => "keepassxc",
        _ => target_provider.as_str(),
    };

    if !secrets_client::check_provider_installed(&target_provider) {
        println!("Installing {}...", package_name);
        if let Err(e) = secrets_client::reinstall_provider(package_name) {
            eprintln!("Failed to install {}: {e}", package_name);
            std::process::exit(1);
        }
        println!("✓ {} installed.", package_name);
    }

    // Step 7 — Stop mykey-secrets
    println!("Stopping mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mykey-secrets"])
        .status();
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Step 8 — Start chosen provider
    println!("Starting {}...", target_provider);

    // Build a temporary ProviderInfo for start_provider
    let tmp_info = secrets_client::ProviderInfoFile {
        process_name: target_provider.clone(),
        service_name: if normalized == "1" {
            // Restore the exact service name that was recorded at enroll time.
            info.service_name.clone()
        } else {
            match target_provider.as_str() {
                "gnome-keyring-daemon" => Some("gnome-keyring-daemon.service".to_string()),
                "kwalletd6" => Some("plasma-kwalletd.service".to_string()),
                _ => None,
            }
        },
        package_name: package_name.to_string(),
        keychain_path: None,
        keychain_deleted: info.keychain_deleted,
    };

    match secrets_client::start_provider(&tmp_info) {
        Ok(_) => println!("✓ {} is running", target_provider),
        Err(e) => {
            eprintln!("Failed to start {}: {e}", target_provider);
            eprintln!("Restarting mykey-secrets to restore access...");
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "start", "mykey-secrets"])
                .status();
            std::process::exit(1);
        }
    }

    // Step 9 — Unlock collection
    println!("Unlocking keychain...");
    let _ = secrets_client::unlock_default_collection();

    // Step 10 — Load MyKey secrets and restore
    let collections = storage::load_collections();
    let mut all_items: Vec<storage::StoredItem> = Vec::new();
    for col in &collections {
        all_items.extend(storage::load_items(&col.id));
    }
    println!("Found {} secret(s) in MyKey storage.", all_items.len());

    let secrets_to_restore: Vec<&storage::StoredItem> = if info.keychain_deleted {
        println!("Old keychain was deleted — restoring all secrets.");
        all_items.iter().collect()
    } else {
        let existing = secrets_client::list_provider_secrets().unwrap_or_default();
        let existing_labels: std::collections::HashSet<String> =
            existing.into_iter().map(|(l, _)| l).collect();
        let new_only: Vec<&storage::StoredItem> = all_items
            .iter()
            .filter(|i| !existing_labels.contains(&i.label))
            .collect();
        println!(
            "Restoring {} new secret(s) not in old keychain.",
            new_only.len()
        );
        new_only
    };

    let mut success = 0;
    let mut failed = 0;
    for item in &secrets_to_restore {
        print!("Restoring: {}... ", item.label);
        flush_stdout();
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
                        println!("✗ {e}");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                println!("✗ {e}");
                failed += 1;
            }
        }
    }

    // Step 11 — Verify
    println!();
    println!(
        "Restore complete. Restored: {}  Failed: {}",
        success, failed
    );

    if failed > 0 {
        eprintln!("✗ Some secrets failed. MyKey storage NOT deleted.");
        eprintln!("  Restarting mykey-secrets...");
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "mykey-secrets"])
            .status();
        std::process::exit(1);
    }

    // Step 12 — Re-enable provider autostart (already done by start_provider)

    // Step 13 — Clean up MyKey storage
    println!("Cleaning up MyKey storage...");
    if let Err(e) = std::fs::remove_dir_all("/etc/mykey/secrets") {
        eprintln!("⚠ Could not remove /etc/mykey/secrets: {e}");
    } else {
        println!("✓ /etc/mykey/secrets removed.");
    }
    let _ = secrets_client::delete_provider_info();
    println!("✓ Provider info removed.");
    println!();
    println!(
        "✓ Unenroll complete. {} is now your Secret Service provider.",
        target_provider
    );
}
