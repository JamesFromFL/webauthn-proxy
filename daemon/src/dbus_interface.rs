// dbus_interface.rs — zbus D-Bus interface for the WebAuthn Proxy daemon.
//
// Interface name:  com.webauthnproxy.Daemon
// Object path:     /com/webauthnproxy/Daemon
//
// Methods:
//   Connect(pid)                      → encrypted session token (JSON)
//   Register(pid, encrypted_request)  → encrypted response (JSON)
//   Authenticate(pid, encrypted_request) → encrypted response (JSON)
//   Disconnect(pid)                   → ()
//
// The native host supplies its own PID.  In production the daemon should
// cross-check this against the D-Bus connection's Unix credentials, but for
// the initial implementation we trust the caller-supplied value and note this
// as a future hardening item.

use std::sync::Arc;
use log::{debug, info, warn};
use zeroize::Zeroizing;

use crate::authentication;
use crate::crypto;
use crate::protocol::{CreateRequest, GetRequest};
use crate::registration;
use crate::replay::AsyncReplayCache;
use crate::session::{load_bootstrap_key, SessionStore};
use crate::validator;

// ---------------------------------------------------------------------------
// Shared daemon state
// ---------------------------------------------------------------------------

/// State shared by the D-Bus interface across all D-Bus method calls.
pub struct DaemonState {
    pub sessions:       SessionStore,
    pub replay_cache:   AsyncReplayCache,
    pub bootstrap_key:  Zeroizing<[u8; 32]>,
}

impl DaemonState {
    pub fn new() -> Self {
        DaemonState {
            sessions:      SessionStore::new(),
            replay_cache:  AsyncReplayCache::new(),
            bootstrap_key: load_bootstrap_key(),
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface struct
// ---------------------------------------------------------------------------

/// Implements the com.webauthnproxy.Daemon D-Bus interface.
///
/// Holds an `Arc<DaemonState>` so all method calls share the same session store
/// and replay cache.  `Arc` is used (not `Mutex<DaemonState>`) because the
/// individual fields already carry their own async locks.
pub struct DaemonInterface {
    state: Arc<DaemonState>,
}

impl DaemonInterface {
    pub fn new(state: Arc<DaemonState>) -> Self {
        DaemonInterface { state }
    }
}

// ---------------------------------------------------------------------------
// zbus interface implementation
// ---------------------------------------------------------------------------

#[zbus::interface(name = "com.webauthnproxy.Daemon")]
impl DaemonInterface {
    // ── Connect ─────────────────────────────────────────────────────────────
    /// Called by the native host on startup.
    ///
    /// Validates that `pid` belongs to a Chrome/Chromium process, then issues a
    /// fresh session token and returns it AES-GCM encrypted with the bootstrap key.
    async fn connect(&self, pid: u32) -> Result<String, zbus::fdo::Error> {
        info!("[dbus] Connect called from pid={pid}");

        if !validator::verify_caller_process(pid) {
            warn!("[dbus] Connect rejected: pid={pid} failed caller verification");
            return Err(zbus::fdo::Error::AccessDenied(
                format!("pid={pid} is not a Chrome/Chromium process"),
            ));
        }

        let token_bytes = self.state.sessions.issue_token(pid).await;

        let wrapped = crypto::wrap_session_token(&self.state.bootstrap_key, &token_bytes)
            .map_err(|e| zbus::fdo::Error::Failed(e))?;

        info!("[dbus] Connect successful for pid={pid}");
        Ok(wrapped)
    }

    // ── Register ─────────────────────────────────────────────────────────────
    /// Handle a WebAuthn registration (create) request from the native host.
    ///
    /// The request is AES-GCM encrypted with the session token.  The response
    /// is returned encrypted with the same token.
    async fn register(
        &self,
        pid: u32,
        encrypted_request: Vec<u8>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        debug!("[dbus] Register called from pid={pid}");

        // Decrypt request using this pid's session token
        let plaintext = self
            .decrypt_with_session(pid, &encrypted_request)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(e))?;

        // Parse the request envelope: { sequence, timestamp, hmac, payload }
        let envelope: RequestEnvelope = serde_json::from_slice(&plaintext)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad request JSON: {e}")))?;

        // Replay protection
        self.state
            .replay_cache
            .check_and_record(envelope.sequence, envelope.timestamp_secs)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(format!("Replay check: {e}")))?;

        // HMAC verification
        let hmac_valid = self
            .verify_hmac_with_session(pid, &envelope.payload, &envelope.hmac)
            .await;
        if !hmac_valid {
            warn!("[dbus] Register HMAC verification failed for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                "HMAC verification failed".to_string(),
            ));
        }

        // Deserialise and dispatch to the registration handler
        let create_req: CreateRequest = serde_json::from_slice(&envelope.payload)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad CreateRequest: {e}")))?;

        info!("[dbus] Register: dispatching registration for pid={pid}");
        let create_resp = registration::handle_create(create_req)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Registration failed: {e}")))?;

        let response_bytes = serde_json::to_vec(&create_resp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Serialise CreateResponse: {e}")))?;

        // Encrypt response
        self.encrypt_with_session(pid, &response_bytes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e))
    }

    // ── Authenticate ─────────────────────────────────────────────────────────
    /// Handle a WebAuthn authentication (get) request from the native host.
    async fn authenticate(
        &self,
        pid: u32,
        encrypted_request: Vec<u8>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        debug!("[dbus] Authenticate called from pid={pid}");

        let plaintext = self
            .decrypt_with_session(pid, &encrypted_request)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(e))?;

        let envelope: RequestEnvelope = serde_json::from_slice(&plaintext)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad request JSON: {e}")))?;

        self.state
            .replay_cache
            .check_and_record(envelope.sequence, envelope.timestamp_secs)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(format!("Replay check: {e}")))?;

        let hmac_valid = self
            .verify_hmac_with_session(pid, &envelope.payload, &envelope.hmac)
            .await;
        if !hmac_valid {
            warn!("[dbus] Authenticate HMAC verification failed for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                "HMAC verification failed".to_string(),
            ));
        }

        // Deserialise and dispatch to the authentication handler
        let get_req: GetRequest = serde_json::from_slice(&envelope.payload)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad GetRequest: {e}")))?;

        info!("[dbus] Authenticate: dispatching authentication for pid={pid}");
        let get_resp = authentication::handle_get(get_req)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Authentication failed: {e}")))?;

        let response_bytes = serde_json::to_vec(&get_resp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Serialise GetResponse: {e}")))?;

        self.encrypt_with_session(pid, &response_bytes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e))
    }

    // ── Disconnect ────────────────────────────────────────────────────────────
    /// Revoke the session token for `pid` and clean up state.
    async fn disconnect(&self, pid: u32) -> Result<(), zbus::fdo::Error> {
        info!("[dbus] Disconnect called from pid={pid}");
        self.state.sessions.revoke_token(pid).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (not exposed on D-Bus)
// ---------------------------------------------------------------------------

impl DaemonInterface {
    /// Decrypt `ciphertext` (JSON-serialised EncryptedPayload) using the
    /// session token for `pid`.
    async fn decrypt_with_session(&self, pid: u32, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let json_str = std::str::from_utf8(ciphertext)
            .map_err(|_| format!("Encrypted request for pid={pid} is not valid UTF-8"))?;

        let envelope: crypto::EncryptedPayload = serde_json::from_str(json_str)
            .map_err(|e| format!("Cannot parse EncryptedPayload for pid={pid}: {e}"))?;

        let result = self
            .state
            .sessions
            .with_token(pid, |token| crypto::decrypt_payload(token, envelope))
            .await;

        match result {
            None => Err(format!("No session for pid={pid} — call Connect first")),
            Some(Ok(plaintext)) => Ok(plaintext.to_vec()),
            Some(Err(e)) => Err(e),
        }
    }

    /// Encrypt `plaintext` using the session token for `pid`.
    async fn encrypt_with_session(&self, pid: u32, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let result = self
            .state
            .sessions
            .with_token(pid, |token| crypto::encrypt_payload(token, plaintext))
            .await;

        match result {
            None => Err(format!("No session for pid={pid}")),
            Some(Ok(envelope)) => serde_json::to_vec(&envelope)
                .map_err(|e| format!("Cannot serialise response envelope: {e}")),
            Some(Err(e)) => Err(e),
        }
    }

    /// Verify the HMAC on `payload` using the session token for `pid`.
    async fn verify_hmac_with_session(&self, pid: u32, payload: &[u8], hmac: &[u8]) -> bool {
        let result = self
            .state
            .sessions
            .with_token(pid, |token| {
                validator::verify_request_hmac(token, payload, hmac)
            })
            .await;
        result.unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Request envelope (authenticated + replay-protected)
// ---------------------------------------------------------------------------

/// The structure every Register/Authenticate request must use.
#[derive(serde::Deserialize)]
struct RequestEnvelope {
    /// Monotonically increasing counter chosen by the caller.
    sequence: u64,
    /// Unix timestamp (seconds) when the request was created.
    timestamp_secs: u64,
    /// HMAC-SHA256(session_token, payload) — hex-encoded.
    hmac: Vec<u8>,
    /// The actual request payload (JSON bytes).
    payload: Vec<u8>,
}
