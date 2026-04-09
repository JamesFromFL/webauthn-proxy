// authentication.rs — WebAuthn authentication (get) handler.
//
// Delegates to the daemon over D-Bus. The daemon performs PAM, key unsealing,
// authenticatorData construction, and assertion signing.

use log::info;

use crate::crypto::b64url_decode;
use crate::protocol::{GetRequest, GetResponse};
use crate::session::{self, DaemonSession};

pub fn handle_get(request: GetRequest, session: &DaemonSession) -> Result<GetResponse, String> {
    info!(
        "handle_get: rpId='{}' allowCredentials={} requestId='{}'",
        request.rp_id,
        request.allow_credentials.len(),
        request.request_id
    );

    let pid = std::process::id();
    let payload = serde_json::to_vec(&request)
        .map_err(|e| format!("Serialise GetRequest failed: {e}"))?;
    let envelope = session::make_envelope(&session.token, &payload)?;
    let encrypted = session::encrypt_request(&session.token, &envelope)?;
    let response_raw = session.client.authenticate(pid, encrypted)?;
    let plaintext = session::decrypt_response(&session.token, &response_raw)?;

    info!("Authentication complete: rpId='{}'", request.rp_id);
    serde_json::from_slice::<GetResponse>(&plaintext)
        .map_err(|e| format!("Daemon authentication response: {e}"))
}

// ---------------------------------------------------------------------------
// Local credential resolution (used for pre-flight checks)
// ---------------------------------------------------------------------------

/// Find the first credential in `allowCredentials` stored on disk, or scan
/// for a resident key matching `rpId` if `allowCredentials` is empty.
#[allow(dead_code)]
pub fn resolve_credential(request: &GetRequest) -> Result<(String, Vec<u8>), String> {
    if !request.allow_credentials.is_empty() {
        for ac in &request.allow_credentials {
            let id_bytes = b64url_decode(&ac.id)
                .map_err(|e| format!("Invalid allowCredentials id: {e}"))?;
            let id_hex = hex::encode(&id_bytes);
            if credential_exists(&id_hex) {
                return Ok((id_hex, id_bytes));
            }
        }
        Err(format!(
            "None of the {} allowedCredentials are stored on this device",
            request.allow_credentials.len()
        ))
    } else {
        find_credential_for_rp(&request.rp_id)
    }
}

#[allow(dead_code)]
fn credential_exists(credential_id_hex: &str) -> bool {
    std::path::Path::new(crate::registration::CREDENTIAL_DIR)
        .join(format!("{}.json", credential_id_hex))
        .exists()
}

#[allow(dead_code)]
fn find_credential_for_rp(rp_id: &str) -> Result<(String, Vec<u8>), String> {
    let dir = std::path::Path::new(crate::registration::CREDENTIAL_DIR);
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("Cannot read credential directory: {e}"))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(meta) =
                serde_json::from_slice::<crate::protocol::CredentialMeta>(&data)
            {
                if meta.rp_id == rp_id {
                    let id_bytes = hex::decode(&meta.credential_id)
                        .map_err(|e| format!("Corrupt credential ID in metadata: {e}"))?;
                    return Ok((meta.credential_id, id_bytes));
                }
            }
        }
    }

    Err(format!("No stored credential found for rpId='{rp_id}'"))
}
