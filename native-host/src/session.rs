// session.rs — Session token management and IPC message crypto for the native host.
//
// EncryptedPayload and RequestEnvelope mirror daemon/src/crypto.rs and
// daemon/src/dbus_interface.rs exactly so both ends agree on wire format.
//
// The session token is received as raw bytes over the kernel-mediated D-Bus
// system bus — no bootstrap key decryption is required.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::dbus_client::DaemonClient;

type HmacSha256 = Hmac<Sha256>;

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Wire types — must match daemon exactly
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedPayload {
    nonce:      [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(serde::Serialize)]
struct RequestEnvelope {
    sequence:       u64,
    timestamp_secs: u64,
    hmac:           Vec<u8>,
    payload:        Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Wrap `payload` in a replay-protected, HMAC-authenticated envelope.
/// Returns the JSON-serialised RequestEnvelope bytes.
pub fn make_envelope(token: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hmac = compute_hmac(token, payload)?;

    let envelope = RequestEnvelope {
        sequence,
        timestamp_secs,
        hmac: hmac.to_vec(),
        payload: payload.to_vec(),
    };
    serde_json::to_vec(&envelope).map_err(|e| format!("Envelope serialisation failed: {e}"))
}

/// AES-256-GCM encrypt `data`; returns JSON bytes of EncryptedPayload.
pub fn encrypt_request(token: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(token)
        .map_err(|e| format!("AES key init failed: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| "AES-256-GCM encryption failed".to_string())?;

    let payload = EncryptedPayload { nonce: nonce_bytes, ciphertext };
    serde_json::to_vec(&payload)
        .map_err(|e| format!("EncryptedPayload serialisation failed: {e}"))
}

/// Decrypt JSON-encoded EncryptedPayload bytes; returns plaintext.
pub fn decrypt_response(token: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let json_str = std::str::from_utf8(data)
        .map_err(|_| "Response is not valid UTF-8".to_string())?;
    let payload: EncryptedPayload = serde_json::from_str(json_str)
        .map_err(|e| format!("Cannot parse EncryptedPayload: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(token)
        .map_err(|e| format!("AES key init failed: {e}"))?;
    let nonce = Nonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| "Decryption failed: authentication tag mismatch".to_string())?;

    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// Internal crypto
// ---------------------------------------------------------------------------

fn compute_hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key)
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

// ---------------------------------------------------------------------------
// DaemonSession
// ---------------------------------------------------------------------------

pub struct DaemonSession {
    pub client: DaemonClient,
    pub token:  Zeroizing<[u8; 32]>,
}

impl DaemonSession {
    pub fn new() -> Result<Self, String> {
        let client = DaemonClient::new()?;
        let pid = std::process::id();
        let token_bytes = client.connect_daemon(pid)?;
        if token_bytes.len() != 32 {
            return Err(format!("Session token wrong length: {} bytes", token_bytes.len()));
        }
        let mut token = Zeroizing::new([0u8; 32]);
        token.copy_from_slice(&token_bytes);
        Ok(DaemonSession { client, token })
    }
}
