// registration.rs — WebAuthn registration (create) handler.
//
// Delegates to the daemon over D-Bus. The daemon performs PAM, key generation,
// TPM sealing, authenticatorData construction, and attestation encoding.

use log::info;

use crate::protocol::{CreateRequest, CreateResponse, CredentialMeta};
use crate::session::{self, DaemonSession};

pub(crate) const CREDENTIAL_DIR: &str = "/etc/mykey-proxy/credentials";

pub fn handle_create(request: CreateRequest, session: &DaemonSession) -> Result<CreateResponse, String> {
    info!(
        "handle_create: rpId='{}' user='{}' requestId='{}'",
        request.rp_id, request.user_name, request.request_id
    );

    let pid = std::process::id();
    let payload = serde_json::to_vec(&request)
        .map_err(|e| format!("Serialise CreateRequest failed: {e}"))?;
    let envelope = session::make_envelope(&session.token, &payload)?;
    let encrypted = session::encrypt_request(&session.token, &envelope)?;
    let response_raw = session.client.register(pid, encrypted)?;
    let plaintext = session::decrypt_response(&session.token, &response_raw)?;

    info!("Registration complete: rpId='{}'", request.rp_id);
    serde_json::from_slice::<CreateResponse>(&plaintext)
        .map_err(|e| format!("Daemon registration response: {e}"))
}

// ---------------------------------------------------------------------------
// Credential metadata persistence (used by authentication.rs)
// ---------------------------------------------------------------------------

pub fn load_credential_meta(credential_id_hex: &str) -> Result<CredentialMeta, String> {
    let path = std::path::Path::new(CREDENTIAL_DIR)
        .join(format!("{}.json", credential_id_hex));
    let data = std::fs::read(&path)
        .map_err(|e| format!("Credential not found ({}): {e}", path.display()))?;
    serde_json::from_slice(&data).map_err(|e| format!("Corrupt credential metadata: {e}"))
}

pub fn update_sign_count(credential_id_hex: &str, new_count: u32) -> Result<(), String> {
    let mut meta = load_credential_meta(credential_id_hex)?;
    meta.sign_count = new_count;
    save_credential_meta(&meta)
}

#[allow(dead_code)]
fn save_credential_meta(meta: &CredentialMeta) -> Result<(), String> {
    std::fs::create_dir_all(CREDENTIAL_DIR)
        .map_err(|e| format!("Cannot create credential directory: {e}"))?;
    let path = std::path::Path::new(CREDENTIAL_DIR)
        .join(format!("{}.json", meta.credential_id));
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| format!("Serialisation error: {e}"))?;
    std::fs::write(&path, json.as_bytes())
        .map_err(|e| format!("Cannot write credential metadata to {}: {e}", path.display()))
}
