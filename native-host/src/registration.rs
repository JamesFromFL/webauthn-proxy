// registration.rs — WebAuthn registration (create) handler.
//
// Flow:
//   1. PAM user-presence gate
//   2. Generate P-256 keypair
//   3. Store private key via tpm::seal_key (software fallback until tpm2 feature is enabled)
//   4. Write credential metadata to disk
//   5. Build authenticatorData with attested credential data (AT flag)
//   6. Encode "none" attestation object
//   7. Return response to main dispatcher

use log::info;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{
    b64url_encode, build_authenticator_data, encode_attestation_object,
    generate_credential_keypair,
};
use crate::pam;
use crate::protocol::{
    AttestationResponse, CreateRequest, CreateResponse, CredentialMeta, PublicKeyCredentialCreate,
};
use crate::tpm;

pub(crate) const CREDENTIAL_DIR: &str = "/etc/webauthn-proxy/credentials";

/// Handle a WebAuthn registration request end-to-end.
pub fn handle_create(request: CreateRequest) -> Result<CreateResponse, String> {
    info!(
        "handle_create: rpId='{}' user='{}' requestId='{}'",
        request.rp_id, request.user_name, request.request_id
    );

    // ── Layer 3: PAM user-presence ────────────────────────────────────────
    if !pam::verify_user_presence() {
        return Err("User presence verification failed (PAM)".to_string());
    }

    // ── Layer 4 (stub): Generate keypair ─────────────────────────────────
    let keypair = generate_credential_keypair();
    let credential_id_hex = hex::encode(&keypair.credential_id);

    // Store private key (software fallback warns loudly)
    tpm::seal_key(&credential_id_hex, &keypair.private_key_bytes)?;

    // ── Persist metadata ──────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let meta = CredentialMeta {
        credential_id: credential_id_hex.clone(),
        rp_id:         request.rp_id.clone(),
        user_id:       request.user_id.clone(),
        user_name:     request.user_name.clone(),
        sign_count:    0,
        created_at:    now,
    };
    save_credential_meta(&meta)?;

    // ── Build authenticatorData ───────────────────────────────────────────
    const AAGUID: [u8; 16] = [0u8; 16]; // all-zeros = software authenticator
    let auth_data = build_authenticator_data(
        &request.rp_id,
        0, // initial sign count
        Some((&AAGUID, &keypair.credential_id, &keypair.cose_public_key)),
    );

    // ── Build attestation object (none) ───────────────────────────────────
    let att_obj = encode_attestation_object(&auth_data);

    // ── Encode response ───────────────────────────────────────────────────
    let credential_id_b64 = b64url_encode(&keypair.credential_id);
    let client_data_json_b64 = b64url_encode(request.client_data_json.as_bytes());
    let att_obj_b64 = b64url_encode(&att_obj);

    info!(
        "Registration complete: credentialId={} rpId='{}'",
        credential_id_b64, request.rp_id
    );

    Ok(CreateResponse {
        response: PublicKeyCredentialCreate {
            id:     credential_id_b64.clone(),
            raw_id: credential_id_b64,
            type_:  "public-key".to_string(),
            response: AttestationResponse {
                client_data_json:   client_data_json_b64,
                attestation_object: att_obj_b64,
                transports:         vec!["internal".to_string()],
            },
            authenticator_attachment: "platform".to_string(),
            client_extension_results: serde_json::json!({}),
        },
    })
}

// ---------------------------------------------------------------------------
// Credential metadata persistence
// ---------------------------------------------------------------------------

fn save_credential_meta(meta: &CredentialMeta) -> Result<(), String> {
    std::fs::create_dir_all(CREDENTIAL_DIR)
        .map_err(|e| format!("Cannot create credential directory: {e}"))?;

    let path = std::path::Path::new(CREDENTIAL_DIR)
        .join(format!("{}.json", meta.credential_id));

    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| format!("Serialisation error: {e}"))?;

    std::fs::write(&path, json.as_bytes())
        .map_err(|e| format!("Cannot write credential metadata to {}: {e}", path.display()))?;

    Ok(())
}

/// Load credential metadata for a given hex credential ID.
pub fn load_credential_meta(credential_id_hex: &str) -> Result<CredentialMeta, String> {
    let path = std::path::Path::new(CREDENTIAL_DIR)
        .join(format!("{}.json", credential_id_hex));

    let data = std::fs::read(&path)
        .map_err(|e| format!("Credential not found ({}): {e}", path.display()))?;

    serde_json::from_slice(&data)
        .map_err(|e| format!("Corrupt credential metadata: {e}"))
}

/// Persist an updated sign counter.
pub fn update_sign_count(credential_id_hex: &str, new_count: u32) -> Result<(), String> {
    let mut meta = load_credential_meta(credential_id_hex)?;
    meta.sign_count = new_count;
    save_credential_meta(&meta)
}
