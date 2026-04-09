// credentials.rs — On-disk credential metadata I/O.
//
// Credential metadata JSON files live at:
//   /etc/mykey/credentials/{credential_id_hex}.json
//
// No key material is stored here; private keys live in tpm.rs.

use std::path::{Path, PathBuf};
use log::debug;

use crate::protocol::{AllowCredential, CredentialMeta, GetRequest};

const CRED_DIR: &str = "/etc/mykey/credentials";

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Serialise `meta` and write it to the credential store.
pub fn write_credential_metadata(meta: &CredentialMeta) -> Result<(), String> {
    std::fs::create_dir_all(CRED_DIR)
        .map_err(|e| format!("Cannot create credential directory: {e}"))?;

    let path = cred_path(&meta.credential_id);
    let json = serde_json::to_vec_pretty(meta)
        .map_err(|e| format!("Cannot serialise credential metadata: {e}"))?;

    std::fs::write(&path, &json)
        .map_err(|e| format!("Cannot write credential metadata to {}: {e}", path.display()))?;

    debug!("Wrote credential metadata to {}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Load the `CredentialMeta` for a known credential ID (hex string).
pub fn load_credential_metadata(credential_id_hex: &str) -> Result<CredentialMeta, String> {
    let path = cred_path(credential_id_hex);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("Cannot read credential {credential_id_hex}: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("Cannot parse credential metadata for {credential_id_hex}: {e}"))
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

/// Find the credential to use for a GetRequest.
///
/// If `allow_credentials` is non-empty, try each listed credential ID in order.
/// Otherwise scan the credential directory for a matching `rp_id`.
pub fn resolve_credential(request: &GetRequest) -> Result<CredentialMeta, String> {
    if !request.allow_credentials.is_empty() {
        return resolve_from_allow_list(&request.allow_credentials, &request.rp_id);
    }
    scan_by_rp_id(&request.rp_id)
}

fn resolve_from_allow_list(
    allow: &[AllowCredential],
    rp_id: &str,
) -> Result<CredentialMeta, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    for entry in allow {
        let id_bytes = URL_SAFE_NO_PAD
            .decode(&entry.id)
            .map_err(|e| format!("Invalid allowCredentials id base64url: {e}"))?;
        let id_hex = hex::encode(&id_bytes);
        let path = cred_path(&id_hex);
        if !path.exists() {
            continue;
        }
        match load_credential_metadata(&id_hex) {
            Ok(meta) if meta.rp_id == rp_id => return Ok(meta),
            Ok(_) => continue, // rpId mismatch — skip
            Err(_) => continue,
        }
    }
    Err(format!("No matching credential found for rpId={rp_id}"))
}

fn scan_by_rp_id(rp_id: &str) -> Result<CredentialMeta, String> {
    let dir = std::fs::read_dir(CRED_DIR)
        .map_err(|e| format!("Cannot read credential directory: {e}"))?;

    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(meta) = serde_json::from_slice::<CredentialMeta>(&bytes) {
                if meta.rp_id == rp_id {
                    return Ok(meta);
                }
            }
        }
    }
    Err(format!("No credential found for rpId={rp_id}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cred_path(credential_id_hex: &str) -> PathBuf {
    Path::new(CRED_DIR).join(format!("{}.json", credential_id_hex))
}

/// Current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
