// authentication.rs — WebAuthn authentication (get) handler.
//
// Flow:
//   1. PAM user-presence gate
//   2. Resolve which stored credential to use from allowCredentials
//   3. Load sealed key via tpm::unseal_key
//   4. Verify rpIdHash matches the stored credential's rpId
//   5. Build authenticatorData (UP + UV flags, incremented sign count)
//   6. Sign authenticatorData || SHA-256(clientDataJSON)
//   7. Increment stored sign counter
//   8. Return response to main dispatcher

use log::{info, warn};

use crate::crypto::{b64url_decode, b64url_encode, build_authenticator_data, sign_assertion};
use crate::pam;
use crate::protocol::{AssertionResponse, GetRequest, GetResponse, PublicKeyCredentialGet};
use crate::registration::{load_credential_meta, update_sign_count};
use crate::tpm;

/// Handle a WebAuthn authentication request end-to-end.
pub fn handle_get(request: GetRequest) -> Result<GetResponse, String> {
    info!(
        "handle_get: rpId='{}' allowCredentials={} requestId='{}'",
        request.rp_id,
        request.allow_credentials.len(),
        request.request_id
    );

    // ── Layer 3: PAM user-presence ────────────────────────────────────────
    if !pam::verify_user_presence() {
        return Err("User presence verification failed (PAM)".to_string());
    }

    // ── Resolve credential ────────────────────────────────────────────────
    let (credential_id_hex, credential_id_bytes) =
        resolve_credential(&request)?;

    // ── Load metadata & verify rpId ───────────────────────────────────────
    let meta = load_credential_meta(&credential_id_hex)?;

    if meta.rp_id != request.rp_id {
        warn!(
            "rpId mismatch: stored='{}' requested='{}'",
            meta.rp_id, request.rp_id
        );
        return Err(format!(
            "rpId mismatch for credential {credential_id_hex}: \
             stored='{}' vs requested='{}'",
            meta.rp_id, request.rp_id
        ));
    }

    // ── Layer 4 (stub): Load private key ─────────────────────────────────
    let private_key = tpm::unseal_key(&credential_id_hex)?;

    // ── Build authenticatorData ───────────────────────────────────────────
    let new_sign_count = meta.sign_count.saturating_add(1);
    let auth_data = build_authenticator_data(
        &request.rp_id,
        new_sign_count,
        None, // no attested credential data in assertion responses
    );

    // ── Sign ──────────────────────────────────────────────────────────────
    let signature = sign_assertion(&private_key, &auth_data, &request.client_data_json)?;

    // ── Persist updated sign count ────────────────────────────────────────
    update_sign_count(&credential_id_hex, new_sign_count)?;

    // ── Encode response ───────────────────────────────────────────────────
    let credential_id_b64  = b64url_encode(&credential_id_bytes);
    let auth_data_b64      = b64url_encode(&auth_data);
    let signature_b64      = b64url_encode(&signature);
    let client_data_b64    = b64url_encode(request.client_data_json.as_bytes());
    let user_handle        = if meta.user_id.is_empty() { None } else { Some(meta.user_id.clone()) };

    info!(
        "Authentication complete: credentialId={} rpId='{}' signCount={}",
        credential_id_b64, request.rp_id, new_sign_count
    );

    Ok(GetResponse {
        response: PublicKeyCredentialGet {
            id:     credential_id_b64.clone(),
            raw_id: credential_id_b64,
            type_:  "public-key".to_string(),
            response: AssertionResponse {
                client_data_json:   client_data_b64,
                authenticator_data: auth_data_b64,
                signature:          signature_b64,
                user_handle,
            },
            authenticator_attachment: "platform".to_string(),
            client_extension_results: serde_json::json!({}),
        },
    })
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

/// Find the first credential in `allowCredentials` that we have stored on disk.
/// If `allowCredentials` is empty (resident key flow), scan the credential
/// directory for any credential matching the requested rpId.
fn resolve_credential(request: &GetRequest) -> Result<(String, Vec<u8>), String> {
    if !request.allow_credentials.is_empty() {
        // Try each allowed credential in order
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
        // Resident key flow — find any credential for this rpId
        find_credential_for_rp(&request.rp_id)
    }
}

fn credential_exists(credential_id_hex: &str) -> bool {
    let path = std::path::Path::new(crate::registration::CREDENTIAL_DIR)
        .join(format!("{}.json", credential_id_hex));
    path.exists()
}

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
            if let Ok(meta) = serde_json::from_slice::<crate::protocol::CredentialMeta>(&data) {
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
