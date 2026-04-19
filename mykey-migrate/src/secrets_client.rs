// secrets_client.rs — Read-only D-Bus client for org.freedesktop.secrets on the session bus.
//
// Connects to whatever Secret Service provider is currently running
// (gnome-keyring, KWallet, KeePassXC, etc.) and reads all secrets
// so they can be migrated into MyKey's TPM2-sealed storage.

use std::collections::HashMap;
use std::io::Write as _;
use std::time::Duration;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroize;

const SS_DEST: &str = "org.freedesktop.secrets";
const SS_PATH: &str = "/org/freedesktop/secrets";
const SS_IFACE: &str = "org.freedesktop.Secret.Service";
const COL_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const PROP_IFACE: &str = "org.freedesktop.DBus.Properties";
const PROVIDER_DIR: &str = "/etc/mykey/provider";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Detected Secret Service provider information (from live detection).
pub struct ProviderInfo {
    pub process_name: String,
    pub pid: u32,
    /// Systemd user service name, if detected via `systemctl --user status {pid}`.
    pub service_name: Option<String>,
    /// Best-guess package manager name for this provider.
    pub package_name: String,
    /// Known on-disk keychain location, if any.
    pub keychain_path: Option<String>,
}

/// Provider information read back from /etc/mykey/provider/info.json.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProviderInfoFile {
    pub process_name: String,
    pub service_name: Option<String>,
    pub package_name: String,
    pub keychain_path: Option<String>,
    pub keychain_deleted: bool,
}

/// A secret item read from the source Secret Service provider.
#[derive(Clone)]
pub struct MigratedItem {
    pub collection_label: String,
    pub collection_id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    /// Plaintext secret bytes — zeroized on drop.
    pub plaintext: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl Drop for MigratedItem {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

// ---------------------------------------------------------------------------
// D-Bus helpers
// ---------------------------------------------------------------------------

fn session_bus() -> Result<Connection, String> {
    Connection::session().map_err(|e| format!("D-Bus session connection failed: {e}"))
}

fn dbus_proxy(conn: &Connection) -> Result<Proxy<'_>, String> {
    Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(|e| format!("DBus meta-proxy failed: {e}"))
}

fn service_proxy(conn: &Connection) -> Result<Proxy<'_>, String> {
    Proxy::new(conn, SS_DEST, SS_PATH, SS_IFACE)
        .map_err(|e| format!("Secret Service proxy failed: {e}"))
}

fn props_proxy<'a, 'p>(conn: &'a Connection, path: &'p str) -> Result<Proxy<'a>, String>
where
    'p: 'a,
{
    Proxy::new(conn, SS_DEST, path, PROP_IFACE)
        .map_err(|e| format!("Properties proxy for {path} failed: {e}"))
}

fn get_string_prop(conn: &Connection, path: &str, iface: &str, prop: &str) -> Result<String, String> {
    let proxy = props_proxy(conn, path)?;
    let val: OwnedValue = proxy
        .call("Get", &(iface, prop))
        .map_err(|e| format!("Get {prop} on {path} failed: {e}"))?;
    String::try_from(val).map_err(|_| format!("Property {prop} on {path} is not a string"))
}

fn get_u64_prop(conn: &Connection, path: &str, iface: &str, prop: &str) -> Result<u64, String> {
    let proxy = props_proxy(conn, path)?;
    let val: OwnedValue = proxy
        .call("Get", &(iface, prop))
        .map_err(|e| format!("Get {prop} on {path} failed: {e}"))?;
    let val2 = val.try_clone().ok();
    u64::try_from(val)
        .or_else(|_| {
            val2.ok_or(())
                .and_then(|v| u32::try_from(v).map_err(|_| ()))
                .map(|n| n as u64)
        })
        .map_err(|_| format!("Property {prop} on {path} is not u64/u32"))
}

fn get_object_paths_prop(
    conn: &Connection,
    path: &str,
    iface: &str,
    prop: &str,
) -> Result<Vec<OwnedObjectPath>, String> {
    let proxy = props_proxy(conn, path)?;
    let val: OwnedValue = proxy
        .call("Get", &(iface, prop))
        .map_err(|e| format!("Get {prop} on {path} failed: {e}"))?;
    Vec::<OwnedObjectPath>::try_from(val)
        .map_err(|e| format!("Property {prop} on {path} is not array of object paths: {e}"))
}

fn get_attributes(conn: &Connection, item_path: &str) -> Result<HashMap<String, String>, String> {
    let proxy = props_proxy(conn, item_path)?;
    let val: OwnedValue = proxy
        .call("Get", &(ITEM_IFACE, "Attributes"))
        .map_err(|e| format!("Get Attributes on {item_path} failed: {e}"))?;
    HashMap::<String, String>::try_from(val)
        .map_err(|e| format!("Attributes on {item_path} is not dict<string,string>: {e}"))
}

/// Slugify a label: lowercase, spaces → hyphens, strip non-alphanumeric except hyphens.
fn slugify(label: &str) -> String {
    label
        .to_lowercase()
        .chars()
        .map(|c| if c == ' ' { '-' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect()
}

/// Return true if something currently owns `org.freedesktop.secrets` on the session bus.
pub fn ss_still_owned() -> bool {
    let conn = match Connection::session() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let proxy = match dbus_proxy(&conn) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let r: Result<String, _> = proxy.call("GetNameOwner", &(SS_DEST,));
    r.is_ok()
}

// ---------------------------------------------------------------------------
// Provider detection helpers
// ---------------------------------------------------------------------------

/// Ask systemd which user service owns `pid` by parsing `systemctl --user status {pid}`.
fn detect_systemd_service(pid: u32) -> Option<String> {
    let pid_str = pid.to_string();
    // Try user-level first, then system-level as fallback.
    // Some providers (e.g. gnome-keyring started by the GNOME session manager)
    // may not appear as user services and require the system-level query.
    let attempts: [Vec<&str>; 2] = [
        vec!["--user", "status", &pid_str],
        vec!["status", &pid_str],
    ];
    for args in &attempts {
        if let Ok(output) = std::process::Command::new("systemctl")
            .args(args)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // First line is typically: "● service-name.service - Description"
                let trimmed = line.trim_start_matches(|c: char| c == '\u{25cf}' || c == '*' || c == ' ');
                if let Some(word) = trimmed.split_whitespace().next() {
                    if word.ends_with(".service") {
                        return Some(word.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Return the known on-disk keychain directory for a process name, if any.
fn keychain_path_for(process_name: &str) -> Option<String> {
    let lower = process_name.to_lowercase();
    let home = std::env::var("HOME").ok()?;
    if lower.contains("gnome-keyring") {
        Some(format!("{home}/.local/share/keyrings/"))
    } else if lower.contains("kwallet") {
        Some(format!("{home}/.local/share/kwalletd/"))
    } else {
        None
    }
}

/// Return the best-guess package manager name for a process name.
fn package_name_for(process_name: &str) -> String {
    let lower = process_name.to_lowercase();
    if lower.contains("gnome-keyring") {
        "gnome-keyring".to_string()
    } else if lower.contains("kwalletd5") {
        "kwallet5".to_string()
    } else if lower.contains("kwalletd6") || lower.contains("kwalletd") {
        "kwallet6".to_string()
    } else if lower.contains("keepassxc") {
        "keepassxc".to_string()
    } else {
        process_name.to_string()
    }
}

/// Parse the ID field from /etc/os-release.
fn detect_distro_id() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            return Some(rest.trim_matches('"').to_lowercase());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public API — enroll (detection + read + stop)
// ---------------------------------------------------------------------------

/// Detect which Secret Service provider is currently running.
///
/// Connects to the session bus, resolves the owner of `org.freedesktop.secrets`,
/// reads its PID via D-Bus and `/proc/{pid}/cmdline`, then probes systemd for the
/// associated user service name.  Returns `Err` if no provider is registered.
pub fn detect_provider() -> Result<ProviderInfo, String> {
    let conn = session_bus()?;
    let dbus = dbus_proxy(&conn)?;

    let owner: String = dbus
        .call("GetNameOwner", &(SS_DEST,))
        .map_err(|_| "No Secret Service provider found".to_string())?;

    let pid: u32 = dbus
        .call("GetConnectionUnixProcessID", &(owner.as_str(),))
        .map_err(|e| format!("Cannot get PID of Secret Service owner: {e}"))?;

    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|e| format!("Cannot read /proc/{pid}/cmdline: {e}"))?;

    let exe = cmdline
        .split(|&b| b == 0)
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("unknown");

    let process_name = std::path::Path::new(exe)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(exe)
        .to_string();

    let service_name = detect_systemd_service(pid);
    let keychain_path = keychain_path_for(&process_name);
    let package_name = package_name_for(&process_name);

    Ok(ProviderInfo {
        process_name,
        pid,
        service_name,
        package_name,
        keychain_path,
    })
}

/// Read every secret from the running Secret Service provider.
///
/// Opens a plain (unencrypted) session — the session bus is local and trusted.
/// Returns one [`MigratedItem`] per secret item found.
pub fn read_all_secrets() -> Result<Vec<MigratedItem>, String> {
    let conn = session_bus()?;
    let svc = service_proxy(&conn)?;

    // Open a plain session (no DH negotiation needed for local reads).
    let (_, session_path): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", Value::from("")))
        .map_err(|e| format!("OpenSession failed: {e}"))?;

    let col_paths = get_object_paths_prop(&conn, SS_PATH, SS_IFACE, "Collections")?;
    let mut items = Vec::new();

    for col_path in &col_paths {
        let col_str = col_path.as_str();
        if col_str.ends_with("/session") {
            continue;
        }

        let col_label = match get_string_prop(&conn, col_str, COL_IFACE, "Label") {
            Ok(l) => l,
            Err(_) => continue,
        };
        let collection_id = slugify(&col_label);

        let item_paths = match get_object_paths_prop(&conn, col_str, COL_IFACE, "Items") {
            Ok(p) => p,
            Err(_) => continue,
        };

        for item_path in &item_paths {
            let item_str = item_path.as_str();

            let label = get_string_prop(&conn, item_str, ITEM_IFACE, "Label").unwrap_or_default();
            let attributes = get_attributes(&conn, item_str).unwrap_or_default();
            let created = get_u64_prop(&conn, item_str, ITEM_IFACE, "Created").unwrap_or(0);
            let modified = get_u64_prop(&conn, item_str, ITEM_IFACE, "Modified").unwrap_or(0);

            // Secret struct: (session, parameters, value, content_type)
            let item_proxy = Proxy::new(&conn, SS_DEST, item_str, ITEM_IFACE)
                .map_err(|e| format!("Item proxy for {item_str} failed: {e}"))?;

            let secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String) =
                match item_proxy.call("GetSecret", &(&session_path,)) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("  [warn] GetSecret failed for {item_str}: {e}");
                        continue;
                    }
                };

            let (_session, _parameters, value, content_type) = secret;

            items.push(MigratedItem {
                collection_label: col_label.clone(),
                collection_id: collection_id.clone(),
                label,
                attributes,
                plaintext: value,
                content_type,
                created,
                modified,
            });
        }
    }

    Ok(items)
}

/// Stop the detected Secret Service provider so MyKey can take over.
///
/// KeePassXC requires interactive user confirmation and is NOT uninstalled.
/// All other providers are stopped via systemd (service + socket units),
/// pkill, and then uninstalled via the system package manager.
///
/// Only called after all secrets have been successfully migrated and verified.
pub fn stop_provider(info: &ProviderInfo) -> Result<(), String> {
    if info.process_name.to_lowercase().contains("keepassxc") {
        stop_keepassxc()?;
    } else {
        stop_generic(info)?;
    }
    Ok(())
}

/// Write /etc/mykey/provider/info.json recording what was disabled.
///
/// `keychain_deleted` defaults to false and can be updated later by the
/// caller after the user optionally removes the old keychain directory.
pub fn write_provider_info(info: &ProviderInfo) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let migrated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let json = serde_json::json!({
        "process_name": info.process_name,
        "service_name": info.service_name,
        "package_name": info.package_name,
        "keychain_path": info.keychain_path,
        "disabled_by_mykey": true,
        "keychain_deleted": false,
        "migrated_at": migrated_at,
    });

    let dir = std::path::Path::new(PROVIDER_DIR);
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Cannot create {PROVIDER_DIR}: {e}"))?;
    let path = dir.join("info.json");
    let data = serde_json::to_vec_pretty(&json)
        .map_err(|e| format!("Cannot serialise provider info: {e}"))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Public API — unenroll (restore + cleanup)
// ---------------------------------------------------------------------------

/// Read and parse /etc/mykey/provider/info.json written during enroll.
///
/// Returns `Err` if the file does not exist — the caller treats this as
/// "no migration was done, skip unenroll".
pub fn read_provider_info() -> Result<ProviderInfoFile, String> {
    let path = std::path::Path::new(PROVIDER_DIR).join("info.json");
    let data = std::fs::read(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&data)
        .map_err(|e| format!("Cannot parse provider info: {e}"))
}

/// Return true if `process_name` is findable on the system PATH or in /usr/bin.
pub fn check_provider_installed(process_name: &str) -> bool {
    if std::process::Command::new("which")
        .arg(process_name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }
    std::path::Path::new("/usr/bin").join(process_name).exists()
}

/// Reinstall the old provider package using the system package manager.
///
/// Distro is detected from the `ID` field in `/etc/os-release`.
pub fn reinstall_provider(package_name: &str) -> Result<(), String> {
    let id = detect_distro_id();
    let cmd_args: Vec<&str> = match id.as_deref() {
        Some("arch") | Some("manjaro") => {
            vec!["sudo", "pacman", "-S", "--noconfirm", package_name]
        }
        Some("ubuntu") | Some("debian") => {
            vec!["sudo", "apt-get", "install", "-y", package_name]
        }
        Some("fedora") => {
            vec!["sudo", "dnf", "install", "-y", package_name]
        }
        Some("opensuse") | Some("opensuse-leap") | Some("opensuse-tumbleweed") => {
            vec!["sudo", "zypper", "install", "-y", package_name]
        }
        other => {
            eprintln!("Unknown distro ID: {other:?}");
            eprintln!("Install {package_name} manually, then run mykey-migrate --unenroll again.");
            return Err(format!("Cannot detect package manager for distro: {other:?}"));
        }
    };

    let status = std::process::Command::new(cmd_args[0])
        .args(&cmd_args[1..])
        .status()
        .map_err(|e| format!("Failed to run package manager: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Package manager exited with status {status}"))
    }
}

/// Start the old provider and wait up to 10 seconds for it to claim the bus.
///
/// Uses systemd if a service name is known; otherwise spawns the binary directly.
pub fn start_provider(info: &ProviderInfoFile) -> Result<(), String> {
    if let Some(svc) = &info.service_name {
        // Propagate display environment into the systemd user manager so that
        // services started here (e.g. gnome-keyring-daemon) can spawn graphical
        // helpers like gcr-prompter with the correct display context.
        std::process::Command::new("dbus-update-activation-environment")
            .args([
                "--systemd",
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XDG_RUNTIME_DIR",
                "XDG_CURRENT_DESKTOP",
                "DBUS_SESSION_BUS_ADDRESS",
            ])
            .status()
            .ok();
        std::process::Command::new("systemctl")
            .args(["--user", "start", svc.as_str()])
            .status()
            .ok();
        std::process::Command::new("systemctl")
            .args(["--user", "enable", svc.as_str()])
            .status()
            .ok();
    } else {
        std::process::Command::new(&info.process_name)
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {e}", info.process_name))?;
    }

    // Poll every 500 ms for up to 10 seconds.
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(500));
        if ss_still_owned() {
            return Ok(());
        }
    }

    Err(format!(
        "{} did not claim org.freedesktop.secrets within 10 seconds",
        info.process_name
    ))
}

/// Write a single secret into a Secret Service collection.
///
/// `collection_path` must be a live, unlocked collection obtained from
/// `prepare_collection()`.  Opens a plain session (the session bus is local
/// and trusted) and calls `CreateItem` with `replace=true`.
pub fn write_secret_to_provider(
    collection_path: &OwnedObjectPath,
    label: &str,
    attributes: &HashMap<String, String>,
    value: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let conn = session_bus()?;
    let svc = service_proxy(&conn)?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", Value::from("")))
        .map_err(|e| format!("OpenSession failed: {e}"))?;

    let col_proxy = Proxy::new(&conn, SS_DEST, collection_path.as_str(), COL_IFACE)
        .map_err(|e| format!("Collection proxy failed: {e}"))?;

    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
    props.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Value::from(attributes.clone()),
    );

    let secret = (&session_path, Vec::<u8>::new(), value.to_vec(), content_type);

    let _: (OwnedObjectPath, OwnedObjectPath) = col_proxy
        .call("CreateItem", &(&props, &secret, true))
        .map_err(|e| format!("CreateItem failed: {e}"))?;

    Ok(())
}

/// List all (label, attributes) pairs from the running Secret Service provider.
///
/// Used during unenroll to detect which secrets are already in the old keychain
/// so we can avoid writing duplicates.
pub fn list_provider_secrets() -> Result<Vec<(String, HashMap<String, String>)>, String> {
    let conn = session_bus()?;
    let svc = service_proxy(&conn)?;

    let (_, _session_path): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", Value::from("")))
        .map_err(|e| format!("OpenSession failed: {e}"))?;

    let col_paths = get_object_paths_prop(&conn, SS_PATH, SS_IFACE, "Collections")?;
    let mut result = Vec::new();

    for col_path in &col_paths {
        let col_str = col_path.as_str();
        if col_str.ends_with("/session") {
            continue;
        }
        let item_paths = match get_object_paths_prop(&conn, col_str, COL_IFACE, "Items") {
            Ok(p) => p,
            Err(_) => continue,
        };
        for item_path in &item_paths {
            let item_str = item_path.as_str();
            let label = get_string_prop(&conn, item_str, ITEM_IFACE, "Label").unwrap_or_default();
            let attrs = get_attributes(&conn, item_str).unwrap_or_default();
            result.push((label, attrs));
        }
    }

    Ok(result)
}

/// Remove /etc/mykey/provider/info.json and the directory if it is then empty.
///
/// Uses `sudo rm` because /etc/mykey/ is root-owned.
pub fn delete_provider_info() -> Result<(), String> {
    let path = std::path::Path::new(PROVIDER_DIR).join("info.json");
    if path.exists() {
        let status = std::process::Command::new("sudo")
            .args(["rm", "-f", path.to_str().unwrap_or("/etc/mykey/provider/info.json")])
            .status()
            .map_err(|e| format!("Cannot run sudo rm: {e}"))?;
        if !status.success() {
            return Err(format!("sudo rm failed for {}", path.display()));
        }
    }
    // Remove the directory only if it is now empty (ignore failure — may still have aliases.json).
    std::process::Command::new("sudo")
        .args(["rmdir", "--ignore-fail-on-non-empty", PROVIDER_DIR])
        .status()
        .ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// Stop helpers (enroll path)
// ---------------------------------------------------------------------------

/// Interactive stop flow for KeePassXC.
fn stop_keepassxc() -> Result<(), String> {
    println!("KeePassXC detected as your Secret Service provider.");
    println!("MyKey cannot stop KeePassXC automatically.");
    println!("Please do the following before continuing:");
    println!("  1. Open KeePassXC");
    println!("  2. Go to Tools → Settings → Secret Service Integration");
    println!("  3. Uncheck 'Enable KeePassXC Secret Service integration'");
    println!("  4. Close KeePassXC completely");
    println!();

    loop {
        print!("Have you disabled and closed KeePassXC? [Y/N]: ");
        std::io::stdout().flush().ok();

        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();

        if line.trim().to_uppercase() == "Y" {
            if ss_still_owned() {
                println!("KeePassXC is still running. Please close it completely.");
            } else {
                println!("✓ KeePassXC stopped.");
                break;
            }
        } else {
            println!("Please complete the steps above before continuing.");
        }
    }

    Ok(())
}

/// Stop a provider by uninstalling its package, then killing any surviving
/// process, and verifying the bus name is released.
fn stop_generic(info: &ProviderInfo) -> Result<(), String> {
    // Step 1 — Uninstall the package first.
    // The process continues even if the package removal fails.
    let id = detect_distro_id();
    let uninstall_cmd: Option<Vec<&str>> = match id.as_deref() {
        Some("arch") | Some("manjaro") => Some(vec![
            "sudo", "pacman", "-Rns", "--noconfirm", info.package_name.as_str(),
        ]),
        Some("ubuntu") | Some("debian") => Some(vec![
            "sudo", "apt-get", "remove", "-y", info.package_name.as_str(),
        ]),
        Some("fedora") => Some(vec![
            "sudo", "dnf", "remove", "-y", info.package_name.as_str(),
        ]),
        Some("opensuse") | Some("opensuse-leap") | Some("opensuse-tumbleweed") => Some(vec![
            "sudo", "zypper", "remove", "-y", info.package_name.as_str(),
        ]),
        other => {
            eprintln!("[warn] Unknown distro {other:?} — skipping package uninstall");
            None
        }
    };

    if let Some(cmd) = uninstall_cmd {
        match std::process::Command::new(cmd[0]).args(&cmd[1..]).status() {
            Ok(s) if s.success() => {
                eprintln!("[info] Package {} removed.", info.package_name);
            }
            Ok(s) => {
                eprintln!(
                    "[warn] Package removal for {} exited with {s} — continuing.",
                    info.package_name
                );
            }
            Err(e) => {
                eprintln!("[warn] Failed to run package manager: {e} — continuing.");
            }
        }
    }

    // Step 2 — Kill the process; it stays alive after package removal.
    std::process::Command::new("pkill")
        .args(["-f", info.process_name.as_str()])
        .stderr(std::process::Stdio::null())
        .status()
        .ok();
    std::thread::sleep(Duration::from_secs(2));

    // Step 3 — Verify the bus name has been released.
    if ss_still_owned() {
        Err(format!(
            "Could not stop {} — org.freedesktop.secrets is still owned",
            info.process_name
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Package manager command hints (for user-facing pause_and_retry messages)
// ---------------------------------------------------------------------------

/// Return the distro-appropriate package install command as a displayable string.
pub fn install_cmd_hint(package_name: &str) -> String {
    match detect_distro_id().as_deref() {
        Some("arch") | Some("manjaro") => {
            format!("sudo pacman -S --noconfirm {package_name}")
        }
        Some("ubuntu") | Some("debian") => {
            format!("sudo apt-get install -y {package_name}")
        }
        Some("fedora") => {
            format!("sudo dnf install -y {package_name}")
        }
        Some("opensuse") | Some("opensuse-leap") | Some("opensuse-tumbleweed") => {
            format!("sudo zypper install -y {package_name}")
        }
        _ => format!("Install {package_name} using your system package manager"),
    }
}

/// Return the distro-appropriate package removal command as a displayable string.
pub fn uninstall_cmd_hint(package_name: &str) -> String {
    match detect_distro_id().as_deref() {
        Some("arch") | Some("manjaro") => {
            format!("sudo pacman -Rns --noconfirm {package_name}")
        }
        Some("ubuntu") | Some("debian") => {
            format!("sudo apt-get remove -y {package_name}")
        }
        Some("fedora") => {
            format!("sudo dnf remove -y {package_name}")
        }
        Some("opensuse") | Some("opensuse-leap") | Some("opensuse-tumbleweed") => {
            format!("sudo zypper remove -y {package_name}")
        }
        _ => format!("Uninstall {package_name} using your system package manager"),
    }
}

// ---------------------------------------------------------------------------
// Autostart management
// ---------------------------------------------------------------------------

/// Install a XDG autostart entry so mykey-secrets launches on login.
///
/// Creates `~/.config/autostart/mykey-secrets.desktop`, creating the
/// `~/.config/autostart/` directory if it does not exist.
pub fn install_mykey_autostart() -> Result<(), String> {
    let home = std::env::var("HOME")
        .map_err(|_| "HOME environment variable not set".to_string())?;
    let autostart_dir = std::path::Path::new(&home).join(".config/autostart");
    std::fs::create_dir_all(&autostart_dir)
        .map_err(|e| format!("Cannot create {}: {e}", autostart_dir.display()))?;
    let desktop_path = autostart_dir.join("mykey-secrets.desktop");
    let content = "[Desktop Entry]\n\
                   Type=Application\n\
                   Name=MyKey Secrets\n\
                   Comment=MyKey TPM2-backed Secret Service provider\n\
                   Exec=/usr/local/bin/mykey-secrets\n\
                   Hidden=false\n\
                   NoDisplay=true\n";
    std::fs::write(&desktop_path, content)
        .map_err(|e| format!("Cannot write {}: {e}", desktop_path.display()))
}

/// Remove the XDG autostart entry for mykey-secrets, if it exists.
pub fn remove_mykey_autostart() -> Result<(), String> {
    let home = std::env::var("HOME")
        .map_err(|_| "HOME environment variable not set".to_string())?;
    let desktop_path = std::path::Path::new(&home)
        .join(".config/autostart/mykey-secrets.desktop");
    if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)
            .map_err(|e| format!("Cannot remove {}: {e}", desktop_path.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// prepare_collection — spec-correct collection setup for unenroll
// ---------------------------------------------------------------------------

/// Return true if the collection at `path` is currently locked.
///
/// Reads the `Locked` property from the `org.freedesktop.Secret.Collection`
/// interface.  Returns `true` on any D-Bus error (conservative default).
fn is_col_locked(conn: &Connection, path: &str) -> bool {
    let proxy = match props_proxy(conn, path) {
        Ok(p) => p,
        Err(_) => return true,
    };
    let val: Result<OwnedValue, _> = proxy.call("Get", &(COL_IFACE, "Locked"));
    match val {
        Ok(v) => bool::try_from(v).unwrap_or(true),
        Err(_) => true,
    }
}

/// Invoke a Secret Service Prompt and block until `Prompt.Completed` fires.
///
/// Spawns a thread that subscribes to the `Completed` signal on a dedicated
/// D-Bus connection (so the match rule is active before `Prompt.Prompt` is
/// called, eliminating any race window), then calls `Prompt.Prompt("")` on the
/// caller's connection and waits up to 60 seconds for the result.
///
/// Returns `Err` if the user dismissed the prompt or the timeout expires.
fn invoke_prompt_and_wait(conn: &Connection, prompt_path: &str) -> Result<OwnedValue, String> {
    use std::sync::mpsc;

    let prompt_path_owned = prompt_path.to_string();
    let (result_tx, result_rx) = mpsc::channel::<Result<OwnedValue, String>>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    std::thread::spawn(move || {
        let result: Result<OwnedValue, String> = (|| {
            let conn2 = Connection::session()
                .map_err(|e| format!("Session bus for signal: {e}"))?;
            let proxy = Proxy::new(
                &conn2,
                SS_DEST,
                prompt_path_owned.as_str(),
                "org.freedesktop.Secret.Prompt",
            )
            .map_err(|e| format!("Prompt signal proxy: {e}"))?;

            let mut iter = proxy
                .receive_signal("Completed")
                .map_err(|e| format!("Cannot subscribe to Prompt.Completed: {e}"))?;

            ready_tx.send(()).ok(); // match rule is now active on conn2

            match iter.next() {
                Some(msg) => {
                    let (dismissed, result): (bool, OwnedValue) = msg
                        .body()
                        .deserialize()
                        .map_err(|e| format!("Completed body: {e}"))?;
                    if dismissed {
                        Err("Prompt was dismissed by the user.".to_string())
                    } else {
                        Ok(result)
                    }
                }
                None => Err("Prompt.Completed stream ended unexpectedly".to_string()),
            }
        })();
        result_tx.send(result).ok();
    });

    // Wait for subscription to be established (or thread failure within 5 s).
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {}
        Err(_) => {
            return result_rx
                .recv_timeout(Duration::from_millis(200))
                .unwrap_or(Err("Cannot subscribe to Prompt.Completed".to_string()));
        }
    }

    // Invoke the prompt on the caller's connection.
    let prompt_proxy = Proxy::new(conn, SS_DEST, prompt_path, "org.freedesktop.Secret.Prompt")
        .map_err(|e| format!("Prompt proxy: {e}"))?;
    let _: () = prompt_proxy
        .call("Prompt", &("0",))
        .map_err(|e| format!("Prompt.Prompt: {e}"))?;

    // Block until Prompt.Completed arrives (60-second timeout for user interaction).
    result_rx
        .recv_timeout(Duration::from_secs(60))
        .map_err(|_| {
            "Timed out waiting for keychain dialog (60 s). \
             Run mykey-migrate --unenroll again."
                .to_string()
        })?
}

/// Ensure a collection is unlocked, invoking a Prompt if the provider requires one.
fn ensure_unlocked_col(conn: &Connection, path: OwnedObjectPath) -> Result<OwnedObjectPath, String> {
    if !is_col_locked(conn, path.as_str()) {
        return Ok(path);
    }

    let svc = service_proxy(conn)?;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call("Unlock", &(vec![path.clone()],))
        .map_err(|e| format!("Unlock failed: {e}"))?;

    // prompt == "/" means Unlock succeeded immediately — no dialog needed.
    // Only invoke the prompt flow when the provider explicitly requests one.
    if prompt.as_str() == "/" {
        return Ok(path);
    }

    println!("  (If a dialog appears, please complete it — this will continue automatically.)");
    invoke_prompt_and_wait(conn, prompt.as_str())?;

    if is_col_locked(conn, path.as_str()) {
        Err(format!(
            "Collection {} is still locked after Unlock",
            path.as_str()
        ))
    } else {
        Ok(path)
    }
}

/// Call `CreateCollection` and handle the Prompt, returning the new collection path.
fn create_and_get_collection(conn: &Connection) -> Result<OwnedObjectPath, String> {
    let svc = service_proxy(conn)?;
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("login"),
    );

    let (col_path, prompt): (OwnedObjectPath, OwnedObjectPath) = svc
        .call("CreateCollection", &(&props, "default"))
        .map_err(|e| format!("CreateCollection failed: {e}"))?;

    if col_path.as_str() != "/" {
        return Ok(col_path);
    }
    if prompt.as_str() == "/" {
        return Err(
            "CreateCollection returned neither a collection nor a prompt. \
             Try creating the keychain manually (e.g. via Passwords and Keys / seahorse)."
                .to_string(),
        );
    }

    println!("  (If a dialog appears, please complete it — this will continue automatically.)");
    let result = invoke_prompt_and_wait(conn, prompt.as_str())?;

    OwnedObjectPath::try_from(result)
        .map_err(|_| "CreateCollection Completed result is not an ObjectPath".to_string())
}

/// Ensure there is a live, unlocked Secret Service collection and return its path.
///
/// Provider-agnostic flow per the Secret Service specification:
/// 1. Try `ReadAlias("default")` — if valid and non-session, ensure it is unlocked.
/// 2. Scan `GetCollections` for any non-session collection and unlock it.
/// 3. If no collection exists at all, call `CreateCollection` to create one,
///    handle the resulting Prompt, and return the new collection path.
///
/// Prompts are invoked via `invoke_prompt_and_wait`, which subscribes to
/// `Prompt.Completed` before calling `Prompt.Prompt` so the signal is never
/// missed, then blocks until the dialog completes (up to 60 seconds).
pub fn prepare_collection() -> Result<OwnedObjectPath, String> {
    let conn = session_bus()?;
    let svc = service_proxy(&conn)?;

    // 1. Try the default alias.
    let alias: OwnedObjectPath = svc
        .call("ReadAlias", &("default",))
        .map_err(|e| format!("ReadAlias failed: {e}"))?;

    if alias.as_str() != "/" && !alias.as_str().ends_with("/session") {
        return ensure_unlocked_col(&conn, alias);
    }

    // 2. Scan GetCollections.
    let cols = get_object_paths_prop(&conn, SS_PATH, SS_IFACE, "Collections")?;
    if let Some(col) = cols
        .into_iter()
        .find(|p| !p.as_str().ends_with("/session"))
    {
        return ensure_unlocked_col(&conn, col);
    }

    // 3. No collection exists — create one.
    create_and_get_collection(&conn)
}

/// Return true if `org.freedesktop.secrets` is currently owned by mykey-secrets.
pub fn is_mykey_secrets_running() -> bool {
    let conn = match Connection::session() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dbus = match dbus_proxy(&conn) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let owner: String = match dbus.call("GetNameOwner", &(SS_DEST,)) {
        Ok(o) => o,
        Err(_) => return false,
    };
    let pid: u32 = match dbus.call("GetConnectionUnixProcessID", &(owner.as_str(),)) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let cmdline = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let exe = cmdline
        .split(|&b| b == 0)
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("");
    let name = std::path::Path::new(exe)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(exe);
    name.contains("mykey-secrets")
}

/// Return the names of well-known Secret Service providers that are installed.
///
/// Checks for binary existence in /usr/bin.
pub fn find_installed_providers() -> Vec<String> {
    let candidates = [
        ("gnome-keyring", "/usr/bin/gnome-keyring-daemon"),
        ("kwalletd6", "/usr/bin/kwalletd6"),
        ("kwalletd5", "/usr/bin/kwalletd5"),
        ("keepassxc", "/usr/bin/keepassxc"),
    ];
    candidates
        .iter()
        .filter(|(_, path)| std::path::Path::new(path).exists())
        .map(|(name, _)| name.to_string())
        .collect()
}

/// Start a provider by friendly name and wait up to 10 seconds for it to claim
/// `org.freedesktop.secrets`.  KeePassXC is interactive.
pub fn start_provider_by_name(name: &str) -> Result<(), String> {
    match name {
        "gnome-keyring" => {
            std::process::Command::new("systemctl")
                .args(["--user", "start", "gnome-keyring-daemon.service"])
                .status()
                .ok();
            std::process::Command::new("systemctl")
                .args(["--user", "start", "gnome-keyring-daemon.socket"])
                .status()
                .ok();
        }
        "kwalletd6" | "kwalletd5" => {
            std::process::Command::new("systemctl")
                .args(["--user", "start", "plasma-kwalletd.service"])
                .status()
                .ok();
        }
        "keepassxc" => {
            println!("KeePassXC must be started manually.");
            println!("  1. Open KeePassXC");
            println!("  2. Go to Tools → Settings → Secret Service Integration");
            println!("  3. Check 'Enable KeePassXC Secret Service integration'");
            println!("  4. Click OK");
            println!();
            loop {
                use std::io::Write as _;
                print!("Press Enter once KeePassXC is running with Secret Service enabled: ");
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                if ss_still_owned() {
                    return Ok(());
                }
                println!("org.freedesktop.secrets is not yet claimed — please complete the steps above.");
            }
        }
        other => {
            return Err(format!("Unknown provider name: {other}"));
        }
    }

    // Poll every 500 ms for up to 10 seconds.
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(500));
        if ss_still_owned() {
            return Ok(());
        }
    }

    Err(format!(
        "{name} did not claim org.freedesktop.secrets within 10 seconds"
    ))
}
