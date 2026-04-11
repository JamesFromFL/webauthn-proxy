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

/// Detected Secret Service provider information.
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

/// A secret item read from the source Secret Service provider.
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

// ---------------------------------------------------------------------------
// Provider detection helpers
// ---------------------------------------------------------------------------

/// Ask systemd which user service owns `pid` by parsing `systemctl --user status {pid}`.
fn detect_systemd_service(pid: u32) -> Option<String> {
    let output = std::process::Command::new("systemctl")
        .args(["--user", "status", &pid.to_string()])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // The first line is typically: "● service-name.service - Description"
        let trimmed = line.trim_start_matches(|c: char| c == '\u{25cf}' || c == '*' || c == ' ');
        if let Some(word) = trimmed.split_whitespace().next() {
            if word.ends_with(".service") {
                return Some(word.to_string());
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

// ---------------------------------------------------------------------------
// Public API
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

        // Skip the "session" ephemeral collection — it has no persistent items.
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
/// KeePassXC requires interactive user confirmation; all other providers are
/// stopped via systemd and/or pkill.  On success, writes a provider info file
/// to `/etc/mykey/provider/info.json`.
///
/// Only called after all secrets have been successfully migrated and verified.
pub fn stop_provider(info: &ProviderInfo) -> Result<(), String> {
    let name_lower = info.process_name.to_lowercase();

    if name_lower.contains("keepassxc") {
        stop_keepassxc(info)?;
    } else {
        stop_generic(info)?;
    }

    write_provider_info(info, false, None);
    Ok(())
}

/// Write /etc/mykey/provider/info.json recording what was disabled.
///
/// `keychain_deleted` and `keychain_deleted_at` are updated separately after
/// optional keychain deletion.
pub fn write_provider_info(info: &ProviderInfo, keychain_deleted: bool, keychain_deleted_at: Option<u64>) {
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
        "keychain_deleted": keychain_deleted,
        "keychain_deleted_at": keychain_deleted_at,
        "migrated_at": migrated_at,
    });

    let dir = std::path::Path::new(PROVIDER_DIR);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[warn] Cannot create {PROVIDER_DIR}: {e}");
        return;
    }
    let path = dir.join("info.json");
    match serde_json::to_vec_pretty(&json) {
        Ok(data) => {
            if let Err(e) = std::fs::write(&path, data) {
                eprintln!("[warn] Cannot write {}: {e}", path.display());
            }
        }
        Err(e) => eprintln!("[warn] Cannot serialise provider info: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Stop helpers
// ---------------------------------------------------------------------------

/// Return true if something still owns `org.freedesktop.secrets` on the session bus.
fn ss_still_owned() -> bool {
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

/// Interactive stop flow for KeePassXC.
fn stop_keepassxc(info: &ProviderInfo) -> Result<(), String> {
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
        let answer = line.trim().to_uppercase();

        if answer == "Y" {
            // Check if the name is still owned.
            if ss_still_owned() {
                println!("KeePassXC is still running. Please close it completely.");
            } else {
                println!("✓ KeePassXC stopped.");
                break;
            }
        } else {
            println!("Please complete the steps above before continuing.");
        }

        let _ = info; // suppress unused warning
    }

    Ok(())
}

/// Stop a provider via systemd and/or pkill, then verify it is gone.
fn stop_generic(info: &ProviderInfo) -> Result<(), String> {
    let run = |args: &[&str]| {
        std::process::Command::new(args[0])
            .args(&args[1..])
            .status()
            .ok();
    };

    if let Some(svc) = &info.service_name {
        run(&["systemctl", "--user", "stop", svc.as_str()]);
        run(&["systemctl", "--user", "disable", svc.as_str()]);
    }

    // pkill as fallback regardless of whether systemd stopped it.
    run(&["pkill", "-f", info.process_name.as_str()]);

    std::thread::sleep(Duration::from_secs(2));

    if ss_still_owned() {
        Err(format!(
            "Could not stop {} — org.freedesktop.secrets is still owned",
            info.process_name
        ))
    } else {
        Ok(())
    }
}
