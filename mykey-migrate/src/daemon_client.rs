// daemon_client.rs — D-Bus client for com.mykey.Daemon on the system bus.
//
// Used by mykey-secrets to seal and unseal secret values via the daemon's
// TPM2-backed SealSecret / UnsealSecret methods.

use log::{debug, info};
use zbus::blocking::{Connection, Proxy};

/// Client connected to com.mykey.Daemon on the system bus.
pub struct DaemonClient {
    conn: Connection,
    pid: u32,
}

impl DaemonClient {
    /// Connect to the system bus and call Connect(pid) to establish a session.
    pub fn connect() -> Result<Self, String> {
        let pid = std::process::id();
        info!("[daemon_client] Connecting to com.mykey.Daemon (pid={pid})");

        let conn = Connection::system()
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;

        // Scope the proxy so it is dropped before `conn` is moved into the struct.
        {
            let proxy = Self::make_proxy(&conn)?;
            let _token: Vec<u8> = proxy
                .call("Connect", &(pid,))
                .map_err(|e| format!("D-Bus Connect failed: {e}"))?;
        }

        info!("[daemon_client] Session established with mykey-daemon");
        Ok(DaemonClient { conn, pid })
    }

    fn make_proxy(conn: &Connection) -> Result<Proxy<'_>, String> {
        Proxy::new(
            conn,
            "com.mykey.Daemon",
            "/com/mykey/Daemon",
            "com.mykey.Daemon",
        )
        .map_err(|e| format!("D-Bus proxy creation failed: {e}"))
    }

    fn proxy(&self) -> Result<Proxy<'_>, String> {
        Self::make_proxy(&self.conn)
    }

    /// Seal `data` via the daemon's TPM2 and return the sealed blob.
    pub fn seal_secret(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] SealSecret ({} bytes)", data.len());
        self.proxy()?
            .call("SealSecret", &(self.pid, data.to_vec()))
            .map_err(|e| format!("D-Bus SealSecret failed: {e}"))
    }

    /// Unseal a blob previously produced by `seal_secret`.
    pub fn unseal_secret(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[daemon_client] UnsealSecret ({} bytes)", blob.len());
        self.proxy()?
            .call("UnsealSecret", &(self.pid, blob.to_vec()))
            .map_err(|e| format!("D-Bus UnsealSecret failed: {e}"))
    }
}

impl Drop for DaemonClient {
    fn drop(&mut self) {
        if let Ok(proxy) = self.proxy() {
            let _: Result<(), _> = proxy.call("Disconnect", &(self.pid,));
        }
    }
}
