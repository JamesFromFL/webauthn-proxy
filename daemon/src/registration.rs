// registration.rs — WebAuthn registration handler for the daemon.
//
// Orchestrates PAM user-presence verification, P-256 key generation, TPM key
// sealing, authenticatorData assembly, and attestation object encoding.

use log::info;
use serde_json::Value;

use crate::credentials::{unix_now, write_credential_metadata};
use crate::crypto_ops;
use crate::pam;
use crate::protocol::{
    AttestationResponse, CreateRequest, CreateResponse, CredentialMeta, PublicKeyCredentialCreate,
};
use crate::tpm;

/// Handle a WebAuthn registration request end-to-end.
///
/// Returns a `CreateResponse` ready to be serialised and sent back to the
/// native host, or an error string on any failure.
pub async fn handle_create(request: CreateRequest) -> Result<CreateResponse, String> {
    // ── 1. PAM user-presence gate ─────────────────────────────────────────
    let pam_ok = pam::verify_user_presence()
        .await
        .map_err(|e| format!("PAM error: {e}"))?;
    if !pam_ok {
        return Err("PAM authentication failed — user presence not confirmed".to_string());
    }

    // ── 2. Generate P-256 keypair ─────────────────────────────────────────
    let keypair = crypto_ops::generate_credential_keypair();
    let cred_id_hex = hex::encode(&keypair.credential_id);
    info!("[registration] Generated credential id={cred_id_hex} for rpId={}", request.rp_id);

    // ── 3. Seal private key via TPM ───────────────────────────────────────
    tpm::seal_key(&cred_id_hex, &keypair.private_key_bytes)
        .map_err(|e| format!("TPM seal_key failed: {e}"))?;

    // ── 4. Persist credential metadata ───────────────────────────────────
    let meta = CredentialMeta {
        credential_id: cred_id_hex.clone(),
        rp_id:         request.rp_id.clone(),
        user_id:       request.user_id.clone(),
        user_name:     request.user_name.clone(),
        sign_count:    0,
        created_at:    unix_now(),
    };
    write_credential_metadata(&meta)
        .map_err(|e| format!("Cannot write credential metadata: {e}"))?;

    // ── 5. Build authenticatorData ────────────────────────────────────────
    let aaguid = [0u8; 16]; // AAGUID all zeros — no attestation identity
    let auth_data = crypto_ops::build_authenticator_data(
        &request.rp_id,
        0, // sign_count = 0 at registration
        Some((&aaguid, &keypair.credential_id, &keypair.cose_public_key)),
    );

    // ── 6. Encode attestation object (format: none) ───────────────────────
    let att_obj = crypto_ops::encode_attestation_object(&auth_data);

    // ── 7. Assemble response ──────────────────────────────────────────────
    let cred_id_b64 = crypto_ops::b64url_encode(&keypair.credential_id);
    let client_data_json_b64 =
        crypto_ops::b64url_encode(request.client_data_json.as_bytes());

    info!("[registration] Registration complete for credential id={cred_id_hex}");

    Ok(CreateResponse {
        response: PublicKeyCredentialCreate {
            id:     cred_id_b64.clone(),
            raw_id: cred_id_b64,
            type_:  "public-key".to_string(),
            response: AttestationResponse {
                client_data_json:   client_data_json_b64,
                attestation_object: crypto_ops::b64url_encode(&att_obj),
                transports:         vec!["internal".to_string()],
            },
            authenticator_attachment: "platform".to_string(),
            client_extension_results: Value::Object(serde_json::Map::new()),
        },
    })
}
