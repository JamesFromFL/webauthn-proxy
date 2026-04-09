// crypto.rs — AES-256-GCM payload encryption/decryption and HMAC helpers.
//
// Used for encrypting session tokens returned to callers (keyed on bootstrap
// secret) and for encrypting/decrypting request/response payloads (keyed on
// session token).
//
// IMPORTANT: key material and plaintext are never logged.  Only sizes and
// status outcomes are logged, with [crypto] prefix.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use log::{debug, warn};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Encrypted payload envelope
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPayload {
    /// Random 12-byte nonce (base64url encoded in JSON serialisation).
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext + authentication tag.
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM using `key` (32 bytes).
///
/// Generates a fresh random nonce on each call.  Returns an `EncryptedPayload`
/// containing the nonce and ciphertext.
pub fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPayload, String> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "[crypto] AES-256-GCM encryption failed".to_string())?;

    debug!("[crypto] Encrypted {} bytes → {} bytes ciphertext", plaintext.len(), ciphertext.len());
    Ok(EncryptedPayload { nonce: nonce_bytes, ciphertext })
}

/// Decrypt an `EncryptedPayload` with AES-256-GCM using `key` (32 bytes).
///
/// Fails if the authentication tag does not match (ciphertext was tampered
/// with or the wrong key was used).
pub fn decrypt_payload(key: &[u8; 32], payload: EncryptedPayload) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| {
            warn!("[crypto] AES-256-GCM decryption failed — authentication tag mismatch");
            "[crypto] Decryption failed: authentication tag mismatch".to_string()
        })?;

    debug!("[crypto] Decrypted {} bytes ciphertext → {} bytes plaintext", payload.ciphertext.len(), plaintext.len());
    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, data) and return the 32-byte result.
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key)
        .map_err(|e| format!("[crypto] HMAC init failed: {e}"))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Verify HMAC-SHA256(key, data) == expected in constant time.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = match <HmacSha256 as HmacKeyInit>::new_from_slice(key) {
        Ok(m) => m,
        Err(e) => {
            warn!("[crypto] HMAC verify init failed: {e}");
            return false;
        }
    };
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

// ---------------------------------------------------------------------------
// Convenience: encrypt a session token with the bootstrap key
// ---------------------------------------------------------------------------

/// Wrap a 32-byte session token in an AES-GCM envelope keyed by the bootstrap
/// secret.  Returns the envelope as a JSON string (base64url nonce + ciphertext).
pub fn wrap_session_token(
    bootstrap_key: &[u8; 32],
    token: &[u8; 32],
) -> Result<String, String> {
    let envelope = encrypt_payload(bootstrap_key, token)?;
    serde_json::to_string(&envelope)
        .map_err(|e| format!("[crypto] Failed to serialise session token envelope: {e}"))
}

/// Unwrap a JSON session token envelope produced by `wrap_session_token`.
pub fn unwrap_session_token(
    bootstrap_key: &[u8; 32],
    wrapped: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let envelope: EncryptedPayload = serde_json::from_str(wrapped)
        .map_err(|e| format!("[crypto] Invalid session token envelope JSON: {e}"))?;
    decrypt_payload(bootstrap_key, envelope)
}
