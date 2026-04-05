// dbus_client.rs — Blocking D-Bus client for com.webauthnproxy.Daemon.

use zbus::blocking::{Connection, Proxy};

pub struct DaemonClient {
    conn: Connection,
}

impl DaemonClient {
    pub fn new() -> Result<Self, String> {
        let conn = Connection::system()
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;
        Ok(DaemonClient { conn })
    }

    fn proxy(&self) -> Result<Proxy<'_>, String> {
        Proxy::new(
            &self.conn,
            "com.webauthnproxy.Daemon",
            "/com/webauthnproxy/Daemon",
            "com.webauthnproxy.Daemon",
        )
        .map_err(|e| format!("D-Bus proxy creation failed: {e}"))
    }

    pub fn connect_daemon(&self, pid: u32) -> Result<String, String> {
        self.proxy()?
            .call("Connect", &(pid,))
            .map_err(|e| format!("D-Bus Connect failed: {e}"))
    }

    pub fn register(&self, pid: u32, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        self.proxy()?
            .call("Register", &(pid, payload))
            .map_err(|e| format!("D-Bus Register failed: {e}"))
    }

    pub fn authenticate(&self, pid: u32, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        self.proxy()?
            .call("Authenticate", &(pid, payload))
            .map_err(|e| format!("D-Bus Authenticate failed: {e}"))
    }

    pub fn disconnect(&self, pid: u32) -> Result<(), String> {
        self.proxy()?
            .call("Disconnect", &(pid,))
            .map_err(|e| format!("D-Bus Disconnect failed: {e}"))
    }
}
