// daemon_client.rs — Async D-Bus client for com.mykey.Daemon on the system bus.
//
// Uses the zbus async API (not zbus::blocking) so it is safe to call from
// within tokio async handlers without blocking the runtime or deadlocking.
//
// Every proxy is created with CacheProperties::No.  The default
// CacheProperties::Lazily causes zbus to call block_on internally when
// setting up PropertiesChanged signal subscriptions for the cache, which
// panics if a tokio runtime is already running on the current thread.
// The daemon interface exposes no D-Bus properties, so caching is useless.

use log::{debug, info};
use zbus::{CacheProperties, Connection};

// ---------------------------------------------------------------------------
// D-Bus proxy definition
// ---------------------------------------------------------------------------

/// Generated async proxy for the com.mykey.Daemon interface.
///
/// Method names are automatically mapped to D-Bus PascalCase:
///   connect       → Connect
///   seal_secret   → SealSecret
///   unseal_secret → UnsealSecret
///   disconnect    → Disconnect
#[zbus::proxy(
    interface = "com.mykey.Daemon",
    default_service = "com.mykey.Daemon",
    default_path = "/com/mykey/Daemon"
)]
trait DaemonIface {
    async fn connect(&self, pid: u32) -> zbus::Result<Vec<u8>>;
    async fn seal_secret(&self, pid: u32, data: Vec<u8>) -> zbus::Result<Vec<u8>>;
    async fn unseal_secret(&self, pid: u32, blob: Vec<u8>) -> zbus::Result<Vec<u8>>;
    async fn disconnect(&self, pid: u32) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a DaemonIfaceProxy with property caching disabled.
///
/// Using `DaemonIfaceProxy::new()` would default to `CacheProperties::Lazily`,
/// which causes an internal `block_on` call and panics inside a running tokio
/// runtime.  The builder lets us opt out of caching entirely.
async fn make_proxy(conn: &Connection) -> Result<DaemonIfaceProxy<'_>, String> {
    DaemonIfaceProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| format!("D-Bus proxy creation failed: {e}"))
}

// ---------------------------------------------------------------------------
// DaemonClient
// ---------------------------------------------------------------------------

/// Client connected to com.mykey.Daemon on the system bus.
pub struct DaemonClient {
    conn: Connection,
    pid: u32,
}

impl DaemonClient {
    /// Connect to the system bus and call Connect(pid) to establish a session.
    pub async fn connect() -> Result<Self, String> {
        let pid = std::process::id();
        info!("[daemon_client] Connecting to com.mykey.Daemon (pid={pid})");

        let conn = Connection::system()
            .await
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;

        make_proxy(&conn)
            .await?
            .connect(pid)
            .await
            .map_err(|e| format!("D-Bus Connect failed: {e}"))?;

        info!("[daemon_client] Session established with mykey-daemon");
        Ok(DaemonClient { conn, pid })
    }

    /// Seal `data` via the daemon's TPM2 and return the sealed blob.
    pub async fn seal_secret(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] SealSecret ({} bytes)", data.len());
        make_proxy(&self.conn)
            .await?
            .seal_secret(self.pid, data.to_vec())
            .await
            .map_err(|e| format!("D-Bus SealSecret failed: {e}"))
    }

    /// Unseal a blob previously produced by `seal_secret`.
    pub async fn unseal_secret(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] UnsealSecret ({} bytes)", blob.len());
        make_proxy(&self.conn)
            .await?
            .unseal_secret(self.pid, blob.to_vec())
            .await
            .map_err(|e| format!("D-Bus UnsealSecret failed: {e}"))
    }

    /// Disconnect from the daemon, revoking the session token.
    ///
    /// Best-effort: errors are silently ignored since this is cleanup.
    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
