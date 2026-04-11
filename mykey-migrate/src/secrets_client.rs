// secrets_client.rs — Read-only D-Bus client for org.freedesktop.secrets on the session bus.
//
// Connects to whatever Secret Service provider is currently running
// (gnome-keyring, KWallet, KeePassXC, etc.) and reads all secrets
// so they can be migrated into MyKey's TPM2-sealed storage.

use std::collections::HashMap;
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

fn get_attributes(
    conn: &Connection,
    item_path: &str,
) -> Result<HashMap<String, String>, String> {
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

/// Detect which Secret Service provider is currently running.
///
/// Returns a human-readable process name like `"gnome-keyring-daemon"` or
/// `"kwalletd6"`, or an `Err` if no provider is registered on the session bus.
pub fn detect_provider() -> Result<String, String> {
    let conn = session_bus()?;
    let dbus = dbus_proxy(&conn)?;

    // Check that org.freedesktop.secrets is owned by someone.
    let owner: String = dbus
        .call("GetNameOwner", &(SS_DEST,))
        .map_err(|_| "No Secret Service provider found".to_string())?;

    // Get the PID of that owner.
    let pid: u32 = dbus
        .call("GetConnectionUnixProcessID", &(owner.as_str(),))
        .map_err(|e| format!("Cannot get PID of Secret Service owner: {e}"))?;

    // Read /proc/{pid}/cmdline to determine the process name.
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|e| format!("Cannot read /proc/{pid}/cmdline: {e}"))?;

    // cmdline is NUL-separated; take the first token.
    let exe = cmdline
        .split(|&b| b == 0)
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("unknown");

    // Return just the basename.
    let name = std::path::Path::new(exe)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(exe)
        .to_string();

    Ok(name)
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

    // Get all collection paths.
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

        let item_paths =
            match get_object_paths_prop(&conn, col_str, COL_IFACE, "Items") {
                Ok(p) => p,
                Err(_) => continue,
            };

        for item_path in &item_paths {
            let item_str = item_path.as_str();

            let label =
                get_string_prop(&conn, item_str, ITEM_IFACE, "Label").unwrap_or_default();
            let attributes = get_attributes(&conn, item_str).unwrap_or_default();
            let created = get_u64_prop(&conn, item_str, ITEM_IFACE, "Created").unwrap_or(0);
            let modified = get_u64_prop(&conn, item_str, ITEM_IFACE, "Modified").unwrap_or(0);

            // Call GetSecret(session_path) → (OwnedObjectPath, Vec<u8>, Vec<u8>, String)
            // Secret struct: (session, parameters, value, content_type)
            let item_proxy =
                Proxy::new(&conn, SS_DEST, item_str, ITEM_IFACE)
                    .map_err(|e| format!("Item proxy for {item_str} failed: {e}"))?;

            let secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = match item_proxy
                .call("GetSecret", &(&session_path,))
            {
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
/// On partial migration failure this is NOT called — the caller decides.
pub fn stop_provider(provider_name: &str) -> Result<(), String> {
    use std::process::Command;

    let run = |args: &[&str]| {
        Command::new(args[0])
            .args(&args[1..])
            .status()
            .ok();
    };

    let name_lower = provider_name.to_lowercase();

    if name_lower.contains("gnome-keyring") {
        run(&["pkill", "-f", "gnome-keyring-daemon"]);
        run(&["systemctl", "--user", "stop", "gnome-keyring.service"]);
        run(&["systemctl", "--user", "disable", "gnome-keyring.service"]);

        // Suppress autostart.
        if let Some(home) = std::env::var_os("HOME") {
            let dir = std::path::Path::new(&home)
                .join(".config")
                .join("autostart");
            let _ = std::fs::create_dir_all(&dir);
            let desktop = dir.join("gnome-keyring-secrets.desktop");
            let content = "[Desktop Entry]\nType=Application\nName=gnome-keyring-secrets\nHidden=true\n";
            let _ = std::fs::write(desktop, content);
        }
    } else if name_lower.contains("kwallet") {
        run(&["systemctl", "--user", "stop", "plasma-kwalletd.service"]);
        run(&["qdbus", "org.kde.kwalletd6", "/modules/kwalletd6", "quit"]);
    } else if name_lower.contains("keepassxc") {
        println!(
            "[warn] Cannot stop KeePassXC automatically.\n\
             Please open KeePassXC → Tools → Settings → Secret Service Integration\n\
             and disable the Secret Service provider, then restart KeePassXC."
        );
        return Ok(());
    } else {
        let result = Command::new("pkill")
            .arg("-f")
            .arg(provider_name)
            .status();
        if result.map(|s| !s.success()).unwrap_or(true) {
            return Err(format!(
                "pkill {provider_name} failed — stop it manually before starting mykey-secrets"
            ));
        }
    }

    // Wait up to 2 s for the name to disappear from the bus.
    std::thread::sleep(Duration::from_secs(2));

    if let Ok(conn) = session_bus() {
        if let Ok(proxy) = dbus_proxy(&conn) {
            let owner: Result<String, _> = proxy.call("GetNameOwner", &(SS_DEST,));
            if owner.is_ok() {
                return Err(format!(
                    "{provider_name} still owns org.freedesktop.secrets after stop attempt"
                ));
            }
        }
    }

    Ok(())
}
