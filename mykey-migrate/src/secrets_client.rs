// secrets_client.rs — Read-only D-Bus client for org.freedesktop.secrets on the session bus.
//
// Connects to whatever Secret Service provider is currently running
// (gnome-keyring, KWallet, KeePassXC, etc.) and reads all secrets
// so they can be migrated into MyKey's TPM2-sealed storage.

use std::collections::HashMap;
use std::io::Write as _;
use std::time::Duration;
use sha2::{Digest, Sha256};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    GnomeKeyring,
    KWallet,
    KeepassXC,
    Generic,
}

#[derive(Debug, Clone)]
pub struct SourceCollectionSpec {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct DestinationPlan {
    pub default_collection: OwnedObjectPath,
    collection_by_source: HashMap<String, OwnedObjectPath>,
}

impl DestinationPlan {
    pub fn collection_for_source(&self, source_collection_id: &str) -> &OwnedObjectPath {
        self.collection_by_source
            .get(source_collection_id)
            .unwrap_or(&self.default_collection)
    }
}

#[derive(Debug, Clone)]
pub struct ProviderSecretInfo {
    pub collection_path: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub content_type: String,
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

fn stable_collection_id(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    format!("collection-{}", hex::encode(hasher.finalize()))
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

/// Return true if the process that owns `org.freedesktop.secrets` is `expected_process`.
///
/// Resolves the owning PID via `GetConnectionUnixProcessID`, then checks
/// `/proc/{pid}/comm` (and `/proc/{pid}/exe` as a fallback) for the name.
pub fn bus_owner_matches(expected_process: &str) -> bool {
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
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        if comm.trim().contains(expected_process) {
            return true;
        }
    }
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            return name.contains(expected_process);
        }
    }
    false
}

fn provider_kind(process_name: &str) -> ProviderKind {
    let lower = process_name.to_lowercase();
    if lower.contains("gnome-keyring") {
        ProviderKind::GnomeKeyring
    } else if lower.contains("kwalletd") || lower.contains("kwallet") || lower.contains("ksecretd") {
        ProviderKind::KWallet
    } else if lower.contains("keepassxc") {
        ProviderKind::KeepassXC
    } else {
        ProviderKind::Generic
    }
}

fn collection_label(conn: &Connection, path: &str) -> Option<String> {
    get_string_prop(conn, path, COL_IFACE, "Label").ok()
}

fn collection_locked(conn: &Connection, path: &str) -> Option<bool> {
    let proxy = props_proxy(conn, path).ok()?;
    let val: OwnedValue = proxy.call("Get", &(COL_IFACE, "Locked")).ok()?;
    bool::try_from(val).ok()
}

fn is_live_collection(conn: &Connection, path: &str) -> bool {
    if path == "/" {
        return false;
    }
    let proxy = match props_proxy(conn, path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let label: Result<OwnedValue, _> = proxy.call("Get", &(COL_IFACE, "Label"));
    if label.is_ok() {
        return true;
    }
    let items: Result<OwnedValue, _> = proxy.call("Get", &(COL_IFACE, "Items"));
    items.is_ok()
}

fn is_ready_collection(conn: &Connection, path: &str) -> bool {
    is_live_collection(conn, path) && matches!(collection_locked(conn, path), Some(false))
}

fn unique_paths(paths: impl IntoIterator<Item = OwnedObjectPath>) -> Vec<OwnedObjectPath> {
    let mut out: Vec<OwnedObjectPath> = Vec::new();
    for path in paths {
        if out.iter().all(|existing| existing.as_str() != path.as_str()) {
            out.push(path);
        }
    }
    out
}

fn read_alias_path(conn: &Connection, alias: &str) -> Option<OwnedObjectPath> {
    let svc = service_proxy(conn).ok()?;
    let path: OwnedObjectPath = svc.call("ReadAlias", &(alias,)).ok()?;
    (path.as_str() != "/").then_some(path)
}

fn list_reported_collections(conn: &Connection) -> Vec<OwnedObjectPath> {
    get_object_paths_prop(conn, SS_PATH, SS_IFACE, "Collections").unwrap_or_default()
}

fn list_live_non_session_collections(conn: &Connection) -> Vec<OwnedObjectPath> {
    unique_paths(
        list_reported_collections(conn)
            .into_iter()
            .filter(|p| !p.as_str().ends_with("/session"))
            .filter(|p| is_live_collection(conn, p.as_str())),
    )
}

fn resolve_live_default_alias(conn: &Connection) -> Option<OwnedObjectPath> {
    let path = read_alias_path(conn, "default")?;
    if path.as_str().ends_with("/session") || !is_live_collection(conn, path.as_str()) {
        return None;
    }
    Some(path)
}

fn find_live_collection_by_label(conn: &Connection, label: &str) -> Option<OwnedObjectPath> {
    list_live_non_session_collections(conn)
        .into_iter()
        .find(|p| collection_label(conn, p.as_str()).as_deref() == Some(label))
}

fn wait_for_ready_collection(
    conn: &Connection,
    preferred_path: Option<&str>,
    preferred_label: Option<&str>,
    timeout_ms: u64,
) -> Option<OwnedObjectPath> {
    let attempts = std::cmp::max(1, timeout_ms / 250);
    for _ in 0..attempts {
        if let Some(path) = preferred_path {
            if is_ready_collection(conn, path) {
                return OwnedObjectPath::try_from(path).ok();
            }
        }
        if let Some(label) = preferred_label {
            if let Some(path) = find_live_collection_by_label(conn, label) {
                if is_ready_collection(conn, path.as_str()) {
                    return Some(path);
                }
            }
        }
        if preferred_path.is_none() && preferred_label.is_none() {
            if let Some(path) = resolve_live_default_alias(conn) {
                if is_ready_collection(conn, path.as_str()) {
                    return Some(path);
                }
            }
            for path in list_live_non_session_collections(conn) {
                if is_ready_collection(conn, path.as_str()) {
                    return Some(path);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
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
    } else if lower.contains("kwallet") || lower.contains("ksecretd") {
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
    } else if lower.contains("ksecretd") {
        "kwallet6".to_string()
    } else if lower.contains("kwalletd5") {
        "kwallet".to_string()
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
    let mut errors = Vec::new();

    for col_path in &col_paths {
        let col_str = col_path.as_str();
        if col_str.ends_with("/session") {
            continue;
        }

        let col_label = match get_string_prop(&conn, col_str, COL_IFACE, "Label") {
            Ok(l) => l,
            Err(e) => {
                errors.push(format!("Cannot read collection label for {col_str}: {e}"));
                continue;
            }
        };
        let collection_id = stable_collection_id(col_str);

        let item_paths = match get_object_paths_prop(&conn, col_str, COL_IFACE, "Items") {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("Cannot list items for collection {col_str}: {e}"));
                continue;
            }
        };

        for item_path in &item_paths {
            let item_str = item_path.as_str();

            let label = match get_string_prop(&conn, item_str, ITEM_IFACE, "Label") {
                Ok(label) => label,
                Err(e) => {
                    errors.push(format!("Cannot read item label for {item_str}: {e}"));
                    continue;
                }
            };
            let attributes = match get_attributes(&conn, item_str) {
                Ok(attributes) => attributes,
                Err(e) => {
                    errors.push(format!("Cannot read attributes for {item_str}: {e}"));
                    continue;
                }
            };
            let created = get_u64_prop(&conn, item_str, ITEM_IFACE, "Created").unwrap_or(0);
            let modified = get_u64_prop(&conn, item_str, ITEM_IFACE, "Modified").unwrap_or(0);

            // Secret struct: (session, parameters, value, content_type)
            let item_proxy = Proxy::new(&conn, SS_DEST, item_str, ITEM_IFACE)
                .map_err(|e| format!("Item proxy for {item_str} failed: {e}"))?;

            let secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String) =
                match item_proxy.call("GetSecret", &(&session_path,)) {
                    Ok(s) => s,
                    Err(e) => {
                        errors.push(format!("GetSecret failed for {item_str}: {e}"));
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

    if !errors.is_empty() {
        let sample: Vec<String> = errors.iter().take(3).cloned().collect();
        let mut msg = format!(
            "Failed to read a complete source secret set. {} read error(s) occurred",
            errors.len()
        );
        if !sample.is_empty() {
            msg.push_str(&format!(": {}", sample.join("; ")));
        }
        if errors.len() > sample.len() {
            msg.push_str(&format!("; and {} more", errors.len() - sample.len()));
        }
        return Err(msg);
    }

    Ok(items)
}

/// Stop the detected Secret Service provider so MyKey can take over.
///
/// KeePassXC requires interactive user confirmation.
/// All other providers are stopped via systemd (service + socket units)
/// and pkill.
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

/// Start the old provider and wait for it to claim `org.freedesktop.secrets`.
///
/// Provider-specific paths are used because activation semantics differ
/// substantially between gnome-keyring, KWallet, and KeePassXC.
fn update_activation_environment() {
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
}

fn user_systemctl(args: &[&str]) {
    std::process::Command::new("systemctl")
        .args(["--user"])
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok();
}

fn dbus_ping(conn: &Connection, dest: &str, path: &str) -> bool {
    Proxy::new(conn, dest, path, "org.freedesktop.DBus.Peer")
        .and_then(|proxy| proxy.call::<_, _, ()>("Ping", &()))
        .is_ok()
}

pub fn provider_ready(info: &ProviderInfoFile) -> bool {
    match provider_kind(&info.process_name) {
        ProviderKind::GnomeKeyring => bus_owner_matches("gnome-keyring-daemon"),
        ProviderKind::KWallet => bus_owner_matches("ksecretd") || bus_owner_matches("kwalletd"),
        ProviderKind::KeepassXC => bus_owner_matches("keepassxc"),
        ProviderKind::Generic => bus_owner_matches(&info.process_name),
    }
}

pub fn start_provider(info: &ProviderInfoFile) -> Result<(), String> {
    let kind = provider_kind(&info.process_name);

    user_systemctl(&["daemon-reload"]);
    update_activation_environment();

    match kind {
        ProviderKind::GnomeKeyring => {
            for unit in &["gnome-keyring-daemon.socket", "gnome-keyring-daemon.service"] {
                user_systemctl(&["reset-failed", unit]);
                user_systemctl(&["unmask", unit]);
                user_systemctl(&["enable", unit]);
            }
            user_systemctl(&["restart", "gnome-keyring-daemon.socket"]);
            user_systemctl(&["restart", "gnome-keyring-daemon.service"]);
        }
        ProviderKind::KWallet => {
            let conn = session_bus().ok();
            if let Some(conn) = conn.as_ref() {
                let _ = dbus_ping(conn, "org.kde.kwalletd6", "/modules/kwalletd6");
                let _ = dbus_ping(conn, "org.kde.secretservicecompat", "/");
            }

            let mut spawned = false;
            if !spawned {
                let service_candidates = [
                    info.service_name.as_deref(),
                    Some("plasma-kwalletd.service"),
                    Some("kwalletd6.service"),
                    Some("kwalletd5.service"),
                ];
                for svc in service_candidates.into_iter().flatten() {
                    let socket = svc.replace(".service", ".socket");
                    user_systemctl(&["reset-failed", &socket]);
                    user_systemctl(&["reset-failed", svc]);
                    user_systemctl(&["unmask", &socket]);
                    user_systemctl(&["unmask", svc]);
                    user_systemctl(&["enable", &socket]);
                    user_systemctl(&["enable", svc]);
                    user_systemctl(&["restart", &socket]);
                    user_systemctl(&["restart", svc]);
                }
            }

            if !spawned && check_provider_installed(&info.process_name) {
                if std::process::Command::new(&info.process_name).spawn().is_ok() {
                    spawned = true;
                }
            }

            if !spawned && check_provider_installed("kwalletd6") {
                std::process::Command::new("kwalletd6").spawn().ok();
            }
        }
        ProviderKind::KeepassXC => {
            std::process::Command::new("keepassxc").spawn().ok();
            println!("KeePassXC requires manual setup:");
            println!("1. Open KeePassXC");
            println!(
                "2. Enable Tools -> Settings -> Secret Service Integration -> Enable KeePassXC Freedesktop.org Secret Service Integration"
            );
            println!("3. Open or create a database");
            println!(
                "4. In Database -> Database Settings -> Secret Service Integration, expose a group"
            );
            if let Some(exec) = secret_service_activation_exec() {
                if !exec.contains("keepassxc") {
                    println!(
                        "5. If another provider keeps taking org.freedesktop.secrets, create ~/.local/share/dbus-1/services/org.freedesktop.secrets.service with Exec=/usr/bin/keepassxc"
                    );
                }
            }
        }
        ProviderKind::Generic => {
            if let Some(svc) = &info.service_name {
                let socket = svc.replace(".service", ".socket");
                user_systemctl(&["reset-failed", &socket]);
                user_systemctl(&["reset-failed", svc.as_str()]);
                user_systemctl(&["unmask", &socket]);
                user_systemctl(&["unmask", svc.as_str()]);
                user_systemctl(&["enable", &socket]);
                user_systemctl(&["enable", svc.as_str()]);
                user_systemctl(&["restart", &socket]);
                user_systemctl(&["restart", svc.as_str()]);
            } else {
                std::process::Command::new(&info.process_name)
                    .spawn()
                    .map_err(|e| format!("Failed to spawn {}: {e}", info.process_name))?;
            }
        }
    }

    let attempts = if kind == ProviderKind::KeepassXC { 120 } else { 20 };
    let sleep_ms = if kind == ProviderKind::KeepassXC { 1000 } else { 500 };

    for _ in 0..attempts {
        std::thread::sleep(Duration::from_millis(sleep_ms));
        if provider_ready(info) {
            return Ok(());
        }
    }

    if kind == ProviderKind::KeepassXC {
        Err(keepassxc_startup_error())
    } else {
        Err(format!(
            "{} did not become ready for Secret Service restore",
            info.process_name
        ))
    }
}

fn create_item_on_collection(
    conn: &Connection,
    collection_path: &OwnedObjectPath,
    label: &str,
    attributes: &HashMap<String, String>,
    value: &[u8],
    content_type: &str,
    replace: bool,
) -> Result<OwnedObjectPath, String> {
    if !is_live_collection(conn, collection_path.as_str()) {
        return Err(format!(
            "Collection {} is not a live Secret Service collection",
            collection_path.as_str()
        ));
    }

    let svc = service_proxy(conn)?;
    let (_, session_path): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", Value::from("")))
        .map_err(|e| format!("OpenSession failed: {e}"))?;

    let col_proxy = Proxy::new(conn, SS_DEST, collection_path.as_str(), COL_IFACE)
        .map_err(|e| format!("Collection proxy failed: {e}"))?;

    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
    props.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Value::from(attributes.clone()),
    );

    let secret = (&session_path, Vec::<u8>::new(), value.to_vec(), content_type);

    let (item_path, prompt): (OwnedObjectPath, OwnedObjectPath) = col_proxy
        .call("CreateItem", &(&props, &secret, replace))
        .map_err(|e| format!("CreateItem failed: {e}"))?;

    if item_path.as_str() != "/" {
        return Ok(item_path);
    }
    if prompt.as_str() == "/" {
        return Err("CreateItem returned neither an item nor a prompt".to_string());
    }

    let result = invoke_prompt_and_wait(conn, prompt.as_str())?;
    OwnedObjectPath::try_from(result)
        .map_err(|_| "CreateItem prompt result is not an ObjectPath".to_string())
}

fn delete_item_from_provider(conn: &Connection, item_path: &OwnedObjectPath) -> Result<(), String> {
    let item_proxy = Proxy::new(conn, SS_DEST, item_path.as_str(), ITEM_IFACE)
        .map_err(|e| format!("Item proxy failed: {e}"))?;
    let prompt: OwnedObjectPath = item_proxy
        .call("Delete", &())
        .map_err(|e| format!("Delete failed: {e}"))?;

    if prompt.as_str() != "/" {
        invoke_prompt_and_wait(conn, prompt.as_str())?;
    }
    Ok(())
}

pub fn probe_collection_write(collection_path: &OwnedObjectPath) -> Result<(), String> {
    let conn = session_bus()?;
    let mut attrs = HashMap::new();
    attrs.insert("mykey:migrate-probe".to_string(), uuid::Uuid::new_v4().to_string());
    let item = create_item_on_collection(
        &conn,
        collection_path,
        "MyKey migration probe",
        &attrs,
        b"probe",
        "text/plain",
        false,
    )?;
    delete_item_from_provider(&conn, &item)
}

/// Write a single secret into a Secret Service collection.
///
/// `collection_path` must be a live, unlocked collection obtained from
/// `prepare_destination()`. The path is validated before each write to avoid
/// blindly targeting stale alias paths.
pub fn write_secret_to_provider(
    collection_path: &OwnedObjectPath,
    label: &str,
    attributes: &HashMap<String, String>,
    value: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let conn = session_bus()?;
    let _ = create_item_on_collection(
        &conn,
        collection_path,
        label,
        attributes,
        value,
        content_type,
        true,
    )?;
    Ok(())
}

/// List visible provider items with enough metadata to detect duplicates and
/// verify restore placement.
pub fn list_provider_secrets() -> Result<Vec<ProviderSecretInfo>, String> {
    let conn = session_bus()?;
    let svc = service_proxy(&conn)?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = svc
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
            let content_type = Proxy::new(&conn, SS_DEST, item_str, ITEM_IFACE)
                .ok()
                .and_then(|proxy| {
                    proxy
                        .call::<_, _, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)>(
                            "GetSecret",
                            &(&session_path,),
                        )
                        .ok()
                        .map(|(_, _, _, content_type)| content_type)
                })
                .unwrap_or_default();
            result.push(ProviderSecretInfo {
                collection_path: col_str.to_string(),
                label,
                attributes: attrs,
                content_type,
            });
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

/// Stop a provider via systemd and kill any surviving process.
///
/// gnome-keyring: stop and disable both the socket and service units (FIX 5).
/// All others: stop, disable, and mask the service and its corresponding socket
/// unit (FIX 9 — package removal is not used; it left socket units in bad state).
fn stop_generic(info: &ProviderInfo) -> Result<(), String> {
    let lower = info.process_name.to_lowercase();

    if lower.contains("gnome-keyring") {
        for unit in &["gnome-keyring-daemon.socket", "gnome-keyring-daemon.service"] {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "stop", unit])
                .status();
        }
        for unit in &["gnome-keyring-daemon.socket", "gnome-keyring-daemon.service"] {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", unit])
                .status();
        }
    } else if let Some(ref svc) = info.service_name {
        let socket = svc.replace(".service", ".socket");
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", &socket])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", svc.as_str()])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", &socket])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", svc.as_str()])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "mask", &socket])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "mask", svc.as_str()])
            .status();
    }

    // Kill any surviving process.
    std::process::Command::new("pkill")
        .args(["-f", info.process_name.as_str()])
        .stderr(std::process::Stdio::null())
        .status()
        .ok();
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

// ---------------------------------------------------------------------------
// Autostart management
// ---------------------------------------------------------------------------

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
        .call("Prompt", &("",))
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

fn invoke_prompt_and_wait_for_collection(
    conn: &Connection,
    prompt_path: &str,
    preferred_path: Option<&str>,
    preferred_label: Option<&str>,
    timeout_ms: u64,
) -> Result<OwnedObjectPath, String> {
    let prompt_proxy = Proxy::new(conn, SS_DEST, prompt_path, "org.freedesktop.Secret.Prompt")
        .map_err(|e| format!("Prompt proxy: {e}"))?;
    let _: () = prompt_proxy
        .call("Prompt", &("",))
        .map_err(|e| format!("Prompt.Prompt: {e}"))?;

    wait_for_ready_collection(conn, preferred_path, preferred_label, timeout_ms).ok_or_else(|| {
        "Timed out waiting for keychain dialog (60 s). Run mykey-migrate --unenroll again."
            .to_string()
    })
}

/// Unlock a collection, invoking a Prompt if the provider requires one.
fn ensure_unlocked_col(conn: &Connection, path: OwnedObjectPath) -> Result<OwnedObjectPath, String> {
    if !is_live_collection(conn, path.as_str()) {
        return Err(format!(
            "Collection {} is not a live Secret Service collection",
            path.as_str()
        ));
    }

    if matches!(collection_locked(conn, path.as_str()), Some(false)) {
        return Ok(path);
    }

    let label = collection_label(conn, path.as_str());
    let svc = service_proxy(conn)?;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call("Unlock", &(vec![path.clone()],))
        .map_err(|e| format!("Unlock failed: {e}"))?;

    if prompt.as_str() != "/" {
        println!("  (If a dialog appears, please complete it — this will continue automatically.)");
        return invoke_prompt_and_wait_for_collection(
            conn,
            prompt.as_str(),
            Some(path.as_str()),
            label.as_deref(),
            60_000,
        );
    }

    wait_for_ready_collection(conn, Some(path.as_str()), label.as_deref(), 5000).ok_or_else(|| {
        format!(
            "Collection {} did not become a live, unlocked Secret Service collection",
            path.as_str()
        )
    })
}

fn supports_collection_creation(kind: ProviderKind) -> bool {
    matches!(
        kind,
        ProviderKind::GnomeKeyring | ProviderKind::Generic
    )
}

fn supports_multi_collection(kind: ProviderKind) -> bool {
    matches!(kind, ProviderKind::GnomeKeyring)
}

fn default_collection_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::GnomeKeyring => "login",
        ProviderKind::KWallet => "kdewallet",
        ProviderKind::KeepassXC => "Secret Service",
        ProviderKind::Generic => "login",
    }
}

fn kwallet_wallet_ready_error() -> String {
    "KWallet Secret Service compatibility is running, but no wallet is open or exported. \
Open or create the KDE wallet (usually 'kdewallet') in KDE Wallet Manager or from a KDE password prompt, unlock it, then run mykey-migrate --unenroll again."
        .to_string()
}

fn secret_service_activation_exec() -> Option<String> {
    let mut candidates = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!(
            "{home}/.local/share/dbus-1/services/org.freedesktop.secrets.service"
        ));
    }
    candidates.push("/usr/local/share/dbus-1/services/org.freedesktop.secrets.service".to_string());
    candidates.push("/usr/share/dbus-1/services/org.freedesktop.secrets.service".to_string());

    for path in candidates {
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => continue,
        };
        for line in content.lines() {
            if let Some(exec) = line.strip_prefix("Exec=") {
                return Some(exec.trim().to_string());
            }
        }
    }

    None
}

fn keepassxc_startup_error() -> String {
    let mut msg = "KeePassXC did not become the active Secret Service provider. \
Open KeePassXC, enable Tools -> Settings -> Secret Service Integration -> Enable KeePassXC Freedesktop.org Secret Service Integration, open or create a database, then in Database -> Database Settings -> Secret Service Integration expose a group."
        .to_string();

    match secret_service_activation_exec() {
        Some(exec) if exec.contains("keepassxc") => {}
        Some(exec) => {
            msg.push_str(&format!(
                " Your current org.freedesktop.secrets D-Bus activation command is '{exec}'. \
If another provider keeps starting instead of KeePassXC, create ~/.local/share/dbus-1/services/org.freedesktop.secrets.service with:\n[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/keepassxc"
            ));
        }
        None => {
            msg.push_str(
                " If another provider keeps starting instead of KeePassXC, create ~/.local/share/dbus-1/services/org.freedesktop.secrets.service with:\n[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/keepassxc",
            );
        }
    }

    msg.push_str(" Then run mykey-migrate --unenroll again.");
    msg
}

fn keepassxc_ready_error() -> String {
    "KeePassXC Secret Service integration is not ready. Open KeePassXC, enable Tools -> Settings -> Secret Service Integration -> Enable KeePassXC Freedesktop.org Secret Service Integration, open or create a database, then in Database -> Database Settings -> Secret Service Integration expose a group and run mykey-migrate --unenroll again."
        .to_string()
}

/// Call `CreateCollection` and handle the Prompt, returning the live collection path.
fn create_and_get_collection(
    conn: &Connection,
    label: &str,
    alias: Option<&str>,
) -> Result<OwnedObjectPath, String> {
    let svc = service_proxy(conn)?;
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("org.freedesktop.Secret.Collection.Label", Value::from(label));

    let alias = alias.unwrap_or("");
    let (col_path, prompt): (OwnedObjectPath, OwnedObjectPath) = svc
        .call("CreateCollection", &(&props, alias))
        .map_err(|e| format!("CreateCollection failed: {e}"))?;

    let mut preferred_path: Option<String> = None;
    if col_path.as_str() != "/" {
        preferred_path = Some(col_path.as_str().to_string());
    }

    if prompt.as_str() != "/" {
        println!("  (If a dialog appears, please complete it — this will continue automatically.)");
        return invoke_prompt_and_wait_for_collection(
            conn,
            prompt.as_str(),
            preferred_path.as_deref(),
            Some(label),
            60_000,
        );
    }

    wait_for_ready_collection(conn, preferred_path.as_deref(), Some(label), 5000).ok_or_else(|| {
        format!(
            "Collection '{label}' was reported but never became a live Secret Service collection"
        )
    })
}

fn resolve_or_create_collection(
    conn: &Connection,
    kind: ProviderKind,
    label: &str,
    make_default_alias: bool,
) -> Result<OwnedObjectPath, String> {
    if make_default_alias {
        if let Some(path) = resolve_live_default_alias(conn) {
            return ensure_unlocked_col(conn, path);
        }
    }

    if let Some(path) = find_live_collection_by_label(conn, label) {
        return ensure_unlocked_col(conn, path);
    }

    if make_default_alias {
        if let Some(path) = list_live_non_session_collections(conn).into_iter().next() {
            return ensure_unlocked_col(conn, path);
        }
    }

    if kind == ProviderKind::KWallet {
        return Err(kwallet_wallet_ready_error());
    }

    if kind == ProviderKind::KeepassXC {
        return Err(keepassxc_ready_error());
    }

    if !supports_collection_creation(kind) {
        return Err(
            "No writable Secret Service collection is available. \
             Open or create the destination keyring/wallet, then run mykey-migrate --unenroll again."
                .to_string(),
        );
    }

    let created = create_and_get_collection(
        conn,
        label,
        if make_default_alias { Some("default") } else { None },
    )?;
    ensure_unlocked_col(conn, created)
}

pub fn prepare_destination(
    info: &ProviderInfoFile,
    source_collections: &[SourceCollectionSpec],
) -> Result<DestinationPlan, String> {
    let conn = session_bus()?;
    let kind = provider_kind(&info.process_name);

    let preferred_default_label = source_collections
        .iter()
        .find(|c| c.label.eq_ignore_ascii_case("login"))
        .or_else(|| {
            source_collections
                .iter()
                .find(|c| c.label.eq_ignore_ascii_case("default"))
        })
        .map(|c| c.label.as_str())
        .unwrap_or(default_collection_label(kind));

    let default_collection =
        resolve_or_create_collection(&conn, kind, preferred_default_label, true)?;

    let mut collection_by_source = HashMap::new();
    let mut probed_paths = std::collections::HashSet::new();

    for source in source_collections {
        let target = if supports_multi_collection(kind) {
            let desired_label = if source.label.eq_ignore_ascii_case("default") {
                preferred_default_label
            } else {
                source.label.as_str()
            };

            if desired_label == preferred_default_label {
                default_collection.clone()
            } else {
                resolve_or_create_collection(&conn, kind, desired_label, false)?
            }
        } else {
            default_collection.clone()
        };

        if probed_paths.insert(target.as_str().to_string()) {
            probe_collection_write(&target)?;
        }
        collection_by_source.insert(source.id.clone(), target);
    }

    if probed_paths.is_empty() {
        probe_collection_write(&default_collection)?;
    }

    Ok(DestinationPlan {
        default_collection,
        collection_by_source,
    })
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
    let kwallet_process = if check_provider_installed("ksecretd") {
        "ksecretd"
    } else {
        "kwalletd6"
    };

    let info = match name {
        "gnome-keyring" => ProviderInfoFile {
            process_name: "gnome-keyring-daemon".to_string(),
            service_name: Some("gnome-keyring-daemon.service".to_string()),
            package_name: "gnome-keyring".to_string(),
            keychain_path: None,
            keychain_deleted: false,
        },
        "kwalletd6" => ProviderInfoFile {
            process_name: kwallet_process.to_string(),
            service_name: Some("plasma-kwalletd.service".to_string()),
            package_name: "kwallet6".to_string(),
            keychain_path: None,
            keychain_deleted: false,
        },
        "kwalletd5" => ProviderInfoFile {
            process_name: if check_provider_installed("ksecretd") {
                "ksecretd".to_string()
            } else {
                "kwalletd5".to_string()
            },
            service_name: Some("kwalletd5.service".to_string()),
            package_name: "kwallet".to_string(),
            keychain_path: None,
            keychain_deleted: false,
        },
        "keepassxc" => ProviderInfoFile {
            process_name: "keepassxc".to_string(),
            service_name: None,
            package_name: "keepassxc".to_string(),
            keychain_path: None,
            keychain_deleted: false,
        },
        other => return Err(format!("Unknown provider name: {other}")),
    };

    start_provider(&info)
}
