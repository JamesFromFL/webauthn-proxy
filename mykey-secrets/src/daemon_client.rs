// daemon_client.rs — Async D-Bus client for com.mykey.Daemon on the system bus.
//
// Uses the zbus async API (not zbus::blocking) so it is safe to call from
// within tokio async handlers without blocking the runtime or deadlocking.

use log::{debug, info};
use zbus::Connection;

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

        let proxy = DaemonIfaceProxy::new(&conn)
            .await
            .map_err(|e| format!("D-Bus proxy creation failed: {e}"))?;

        proxy
            .connect(pid)
            .await
            .map_err(|e| format!("D-Bus Connect failed: {e}"))?;

        info!("[daemon_client] Session established with mykey-daemon");
        Ok(DaemonClient { conn, pid })
    }

    /// Seal `data` via the daemon's TPM2 and return the sealed blob.
    pub async fn seal_secret(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] SealSecret ({} bytes)", data.len());
        let proxy = DaemonIfaceProxy::new(&self.conn)
            .await
            .map_err(|e| format!("D-Bus proxy creation failed: {e}"))?;
        proxy
            .seal_secret(self.pid, data.to_vec())
            .await
            .map_err(|e| format!("D-Bus SealSecret failed: {e}"))
    }

    /// Unseal a blob previously produced by `seal_secret`.
    pub async fn unseal_secret(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] UnsealSecret ({} bytes)", blob.len());
        let proxy = DaemonIfaceProxy::new(&self.conn)
            .await
            .map_err(|e| format!("D-Bus proxy creation failed: {e}"))?;
        proxy
            .unseal_secret(self.pid, blob.to_vec())
            .await
            .map_err(|e| format!("D-Bus UnsealSecret failed: {e}"))
    }

    /// Disconnect from the daemon, revoking the session token.
    ///
    /// Best-effort: errors are silently ignored since this is cleanup.
    pub async fn disconnect(self) {
        if let Ok(proxy) = DaemonIfaceProxy::new(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
