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

// ---------------------------------------------------------------------------
// Error-recovery helpers
// ---------------------------------------------------------------------------

/// Prompt the user to fix a problem, then verify it up to `max_attempts` times.
///
/// Prints `what_failed`, shows `user_instruction`, waits for Enter, then calls
/// `check()`.  Returns `true` as soon as `check()` returns `true`.  Returns
/// `false` (with a support link) if all attempts are exhausted.
fn pause_and_retry<F>(
    what_failed: &str,
    user_instruction: &str,
    check: F,
    max_attempts: u32,
) -> bool
where
    F: Fn() -> bool,
{
    println!();
    println!("⚠ {what_failed}");
    println!();
    println!("Please open a new terminal and run:");
    println!("  {user_instruction}");
    println!();

    for attempt in 1..=max_attempts {
        print!("Press Enter when you have resolved the issue (attempt {attempt}/{max_attempts})...");
        flush_stdout();
        read_line();

        if check() {
            println!("✓ Issue resolved. Continuing...");
            return true;
        }

        if attempt < max_attempts {
            println!("✗ Issue not yet resolved. Please try again.");
            println!("  {user_instruction}");
        }
    }

    println!();
    println!("✗ Could not resolve: {what_failed}");
    println!("  The process cannot continue.");
    println!();
    println!("  If unable to resolve the issue, please submit an issue or discussion:");
    println!("  GitHub:  https://github.com/JamesFromFL/mykey");
    println!("  Discord: https://discord.gg/ANnzz4vQEe");
    false
}

/// Print a fatal error with support links and exit.
fn fatal_with_support(what_failed: &str) -> ! {
    println!();
    println!("✗ Fatal: {what_failed}");
    println!();
    println!("  If unable to resolve the issue, please submit an issue or discussion:");
    println!("  GitHub:  https://github.com/JamesFromFL/mykey");
    println!("  Discord: https://discord.gg/ANnzz4vQEe");
    std::process::exit(1);
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
            eprintln!("Start it with:  sudo systemctl start mykey-daemon");
            eprintln!("If not installed: https://github.com/JamesFromFL/mykey");
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
                print!("Enable and start mykey-secrets as your Secret Service provider? [Y/n]: ");
                flush_stdout();
                let ans = read_line();
                if ans.trim().to_lowercase() != "n" {
                    let _ = std::process::Command::new("systemctl")
                        .args(["--user", "enable", "mykey-secrets"])
                        .status();
                    let _ = std::process::Command::new("systemctl")
                        .args(["--user", "start", "mykey-secrets"])
                        .status();
                    println!("✓ mykey-secrets enabled and started.");
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
                println!("No provider started. Enabling and starting mykey-secrets...");
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "enable", "mykey-secrets"])
                    .status();
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
                                    fatal_with_support(&format!(
                                        "Could not connect after starting provider: {e}"
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            fatal_with_support(&format!("Failed to start {}: {e}", chosen));
                        }
                    }
                }
            }
        }

        // Step 5 — mykey-secrets already owns the bus — verify it is enabled
        Ok(ref info) if info.process_name.contains("mykey-secrets") => {
            let is_enabled = std::process::Command::new("systemctl")
                .args(["--user", "is-enabled", "--quiet", "mykey-secrets"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if is_enabled {
                println!("MyKey is already your Secret Service provider — running and enabled.");
                println!("Nothing to do.");
            } else {
                println!("MyKey is already running as your Secret Service provider.");
                println!("⚠ mykey-secrets is not enabled — enabling so it starts automatically...");
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "enable", "mykey-secrets"])
                    .status();
                println!("✓ mykey-secrets enabled.");
            }
        }

        // Step 6 — Third party provider is running
        Ok(info) => {
            do_migration(info, daemon);
        }
    }

    if !secrets_client::ss_still_owned() || secrets_client::is_mykey_secrets_running() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "mykey-secrets"])
            .status();
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
    println!();
    println!("  • Copy your secrets and seal them with your TPM2 chip");
    println!();
    println!("  • All sealed secrets are verified before the old provider is stopped");
    println!();
    println!("  • This may take some time depending on the number of secrets - Please be patient");
    println!();
    println!("  • Your original keychain will NOT be deleted (unless you choose to)");
    println!();
    println!(
        "⚠ Your previous Secret Service provider ({}) will be removed and stopped. \
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

    // Read secrets — fatal if provider is unreachable
    println!();
    println!("Reading secrets from {}...", info.process_name);
    let items = match secrets_client::read_all_secrets() {
        Ok(i) => i,
        Err(e) => fatal_with_support(&format!(
            "Failed to read secrets from {}: {e}", info.process_name
        )),
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
            fatal_with_support(&format!(
                "{failed} secret(s) failed to seal or verify. Provider has NOT been stopped. \
                 Check /tmp/mykey-daemon.log and run mykey-migrate --enroll again."
            ));
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
                fatal_with_support(&format!(
                    "Failed to write secret '{}' to disk: {e}. \
                     Check that /etc/mykey/secrets/ is accessible.",
                    item.label
                ));
            }
        }
    }

    // Write provider info — pause_and_retry on failure
    if let Err(e) = secrets_client::write_provider_info(&info) {
        eprintln!("⚠ Could not write provider info: {e}");
        if !pause_and_retry(
            "Could not write provider info to /etc/mykey/provider/",
            "sudo mkdir -p /etc/mykey/provider && sudo chown $USER:$USER /etc/mykey/provider",
            || secrets_client::write_provider_info(&info).is_ok(),
            3,
        ) {
            fatal_with_support("Could not write provider info after multiple attempts.");
        }
    }

    // Stop old provider — two-stage pause_and_retry
    println!();
    println!("Stopping {}...", info.process_name);
    if secrets_client::stop_provider(&info).is_err() {
        let pkg_cmd = secrets_client::uninstall_cmd_hint(&info.package_name);

        // Stage 1: ask user to uninstall the package
        let resolved = pause_and_retry(
            &format!("Could not uninstall {}", info.package_name),
            &pkg_cmd,
            || !secrets_client::ss_still_owned(),
            3,
        );

        // Stage 2: if package uninstall didn't free the bus, try killing the process
        if !resolved {
            let resolved2 = pause_and_retry(
                &format!("{} is still running", info.process_name),
                &format!("pkill -f {}", info.process_name),
                || !secrets_client::ss_still_owned(),
                3,
            );
            if !resolved2 {
                fatal_with_support(&format!("Could not stop {}", info.process_name));
            }
        }
    }
    println!("✓ {} stopped.", info.process_name);

    // Install autostart entry — warn only on failure
    match secrets_client::install_mykey_autostart() {
        Ok(_) => println!("✓ mykey-secrets autostart entry installed."),
        Err(e) => eprintln!("⚠ Could not install autostart entry: {e}"),
    }

    // Enable and start mykey-secrets
    println!("Enabling and starting mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "enable", "mykey-secrets"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "start", "mykey-secrets"])
        .status();

    let mykey_is_active = || {
        std::process::Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "mykey-secrets"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let mykey_is_enabled = std::process::Command::new("systemctl")
        .args(["--user", "is-enabled", "--quiet", "mykey-secrets"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !mykey_is_active() || !mykey_is_enabled {
        if !pause_and_retry(
            "mykey-secrets failed to start",
            "systemctl --user start mykey-secrets",
            || {
                std::process::Command::new("systemctl")
                    .args(["--user", "is-active", "--quiet", "mykey-secrets"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            },
            3,
        ) {
            fatal_with_support("mykey-secrets failed to start");
        }
    }
    println!("✓ mykey-secrets is running and enabled.");

    // Optional keychain deletion (after mykey-secrets is confirmed running)
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

    // Step 3 — Read provider info and advise user of previous provider
    let info = secrets_client::read_provider_info().unwrap_or(
        secrets_client::ProviderInfoFile {
            process_name: String::new(),
            service_name: None,
            package_name: String::new(),
            keychain_path: None,
            keychain_deleted: false,
        }
    );
    let has_prior = !info.process_name.is_empty();

    println!();
    if has_prior {
        println!("Previously registered Secret Service provider: {}", info.process_name);
        if let Some(ref svc) = info.service_name {
            println!("  Systemd service: {svc}");
        }
    } else {
        println!("No enrollment record found — MyKey may not have been set up via mykey-migrate.");
        println!("You can still restore secrets to a new provider.");
    }
    println!();

    // Step 4 — Warning
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║              MyKey Unenroll                          ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("⚠ WARNING: Continuing will remove your secrets from MyKey.");
    println!("  They will be restored to your chosen Secret Service provider.");
    println!("  If restoration fails for any reason, unenroll will halt");
    println!("  and your MyKey secrets will remain intact.");
    println!();

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
    let raw = read_line();
    let trimmed = raw.trim();
    // Empty input selects option 1 (previously used, or gnome-keyring if no prior).
    let selection: &str = if trimmed.is_empty() { "1" } else { trimmed };

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
        println!("  Yes. Permanently delete all my keys without migrating to a new provider");
        println!();
        print!("> ");
        flush_stdout();
        let phrase = read_line();
        if phrase.trim() != "Yes. Permanently delete all my keys without migrating to a new provider" {
            println!("Phrase did not match. Cancelled.");
            return;
        }
        // Delete MyKey secrets (/etc/mykey/ is root-owned; use sudo).
        println!();
        println!("Deleting MyKey secrets...");
        std::process::Command::new("sudo")
            .args(["rm", "-rf", "/etc/mykey/secrets"])
            .status()
            .ok();
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
        if let Err(_) = secrets_client::reinstall_provider(package_name) {
            let hint = secrets_client::install_cmd_hint(package_name);
            if !pause_and_retry(
                &format!("Could not install {package_name}"),
                &hint,
                || secrets_client::check_provider_installed(&target_provider),
                3,
            ) {
                fatal_with_support(&format!("Could not install {package_name}"));
            }
        }
        println!("✓ {} installed.", package_name);
    }

    // Step 7 — Stop mykey-secrets
    println!("Stopping mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mykey-secrets"])
        .status();
    std::thread::sleep(std::time::Duration::from_secs(2));
    if secrets_client::is_mykey_secrets_running() {
        if !pause_and_retry(
            "mykey-secrets did not stop",
            "systemctl --user stop mykey-secrets",
            || !secrets_client::is_mykey_secrets_running(),
            3,
        ) {
            fatal_with_support("mykey-secrets did not stop");
        }
    }
    println!("✓ mykey-secrets stopped.");

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

    if let Err(_) = secrets_client::start_provider(&tmp_info) {
        let svc_hint = tmp_info.service_name.as_deref()
            .map(|s| format!("systemctl --user start {s}"))
            .unwrap_or_else(|| format!("{} &", target_provider));
        if !pause_and_retry(
            &format!("{target_provider} did not claim org.freedesktop.secrets"),
            &svc_hint,
            || secrets_client::ss_still_owned() && !secrets_client::is_mykey_secrets_running(),
            3,
        ) {
            // Restart mykey-secrets to restore access before giving up
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "start", "mykey-secrets"])
                .status();
            fatal_with_support(&format!("Could not start {target_provider}"));
        }
    }
    println!("✓ {} is running", target_provider);

    // Step 9 — Unlock the collection and wait for the user.
    std::thread::sleep(std::time::Duration::from_secs(3));
    if let Err(e) = secrets_client::unlock_default_collection() {
        eprintln!("⚠ Could not unlock collection: {e} — some providers auto-unlock, continuing.");
    }
    println!("Please unlock your keychain if prompted, then press Enter...");
    flush_stdout();
    read_line();

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
        eprintln!("  Restarting mykey-secrets...");
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "mykey-secrets"])
            .status();
        fatal_with_support(&format!(
            "{failed} secret(s) failed to restore to {target_provider}. \
             MyKey storage NOT deleted."
        ));
    }

    // Step 12 — Ensure chosen provider is enabled for autostart
    if let Some(ref svc) = tmp_info.service_name {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", svc.as_str()])
            .status();
        println!("✓ {} enabled to start automatically.", target_provider);
    }

    // Step 13 — Clean up MyKey storage
    // /etc/mykey/ is root-owned; use sudo for the removal.
    println!("Cleaning up MyKey storage...");
    let rm_ok = std::process::Command::new("sudo")
        .args(["rm", "-rf", "/etc/mykey/secrets"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !rm_ok {
        if !pause_and_retry(
            "Could not remove /etc/mykey/secrets",
            "sudo rm -rf /etc/mykey/secrets",
            || !std::path::Path::new("/etc/mykey/secrets").exists(),
            3,
        ) {
            fatal_with_support("Could not remove /etc/mykey/secrets");
        }
    }
    println!("✓ /etc/mykey/secrets removed.");

    if let Err(e) = secrets_client::delete_provider_info() {
        eprintln!("⚠ Could not remove provider info: {e}");
        if !pause_and_retry(
            "Could not remove /etc/mykey/provider/info.json",
            "sudo rm -f /etc/mykey/provider/info.json",
            || !std::path::Path::new("/etc/mykey/provider/info.json").exists(),
            3,
        ) {
            fatal_with_support("Could not remove /etc/mykey/provider/info.json");
        }
    }
    println!("✓ Provider info removed.");

    // Remove the mykey-secrets autostart entry — warn only on failure
    match secrets_client::remove_mykey_autostart() {
        Ok(_) => println!("✓ mykey-secrets autostart entry removed."),
        Err(e) => eprintln!("⚠ Could not remove autostart entry: {e}"),
    }

    println!();
    println!(
        "✓ Unenroll complete. {} is now your Secret Service provider.",
        target_provider
    );
}
