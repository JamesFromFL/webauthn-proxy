// authentication.rs — WebAuthn authentication handler for the daemon.
//
// Orchestrates PAM user-presence verification, credential resolution, TPM key
// unsealing, authenticatorData assembly, ECDSA assertion signing, and sign
// counter increment.

use log::info;
use serde_json::Value;

use crate::credentials::{resolve_credential, write_credential_metadata};
use crate::crypto_ops;
use crate::pam;
use crate::protocol::{
    AssertionResponse, GetRequest, GetResponse, PublicKeyCredentialGet,
};
use crate::tpm;

/// Handle a WebAuthn authentication request end-to-end.
///
/// Returns a `GetResponse` ready to be serialised and sent back to the
/// native host, or an error string on any failure.
pub async fn handle_get(request: GetRequest) -> Result<GetResponse, String> {
    // ── 1. PAM user-presence gate ─────────────────────────────────────────
    let pam_ok = pam::verify_user_presence()
        .await
        .map_err(|e| format!("PAM error: {e}"))?;
    if !pam_ok {
        return Err("PAM authentication failed — user presence not confirmed".to_string());
    }

    // ── 2. Resolve credential ─────────────────────────────────────────────
    let meta = resolve_credential(&request)
        .map_err(|e| format!("Credential resolution failed: {e}"))?;
    info!(
        "[authentication] Resolved credential id={} for rpId={}",
        meta.credential_id, request.rp_id
    );

    // ── 3. Unseal private key ─────────────────────────────────────────────
    let private_key = tpm::unseal_key(&meta.credential_id)
        .map_err(|e| format!("TPM unseal_key failed: {e}"))?;

    // ── 4. Verify rpIdHash ────────────────────────────────────────────────
    let request_rp_hash = crypto_ops::compute_rp_id_hash(&request.rp_id);
    let stored_rp_hash  = crypto_ops::compute_rp_id_hash(&meta.rp_id);
    if request_rp_hash != stored_rp_hash {
        return Err(format!(
            "rpId mismatch: request has '{}', credential has '{}'",
            request.rp_id, meta.rp_id
        ));
    }

    // ── 5. Build authenticatorData (no attested data for authentication) ──
    let new_sign_count = meta.sign_count.saturating_add(1);
    let auth_data =
        crypto_ops::build_authenticator_data(&request.rp_id, new_sign_count, None);

    // ── 6. Sign assertion ─────────────────────────────────────────────────
    let signature =
        crypto_ops::sign_assertion(&private_key, &auth_data, &request.client_data_json)
            .map_err(|e| format!("Assertion signing failed: {e}"))?;

    // ── 7. Increment sign counter ─────────────────────────────────────────
    let updated_meta = crate::protocol::CredentialMeta {
        sign_count: new_sign_count,
        ..meta
    };
    write_credential_metadata(&updated_meta)
        .map_err(|e| format!("Cannot update credential metadata: {e}"))?;

    // ── 8. Assemble response ──────────────────────────────────────────────
    let cred_id_bytes = hex::decode(&updated_meta.credential_id)
        .map_err(|e| format!("Invalid credential_id hex in metadata: {e}"))?;
    let cred_id_b64 = crypto_ops::b64url_encode(&cred_id_bytes);

    let user_handle = if updated_meta.user_id.is_empty() {
        None
    } else {
        Some(updated_meta.user_id.clone())
    };

    info!(
        "[authentication] Authentication complete for credential id={}",
        updated_meta.credential_id
    );

    Ok(GetResponse {
        response: PublicKeyCredentialGet {
            id:     cred_id_b64.clone(),
            raw_id: cred_id_b64,
            type_:  "public-key".to_string(),
            response: AssertionResponse {
                client_data_json:   crypto_ops::b64url_encode(request.client_data_json.as_bytes()),
                authenticator_data: crypto_ops::b64url_encode(&auth_data),
                signature:          crypto_ops::b64url_encode(&signature),
                user_handle,
            },
            authenticator_attachment: "platform".to_string(),
            client_extension_results: Value::Object(serde_json::Map::new()),
        },
    })
}
