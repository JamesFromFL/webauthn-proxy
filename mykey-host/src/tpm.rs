// tpm.rs — TPM2 key sealing layer.
//
// Production intent (behind the `tpm2` feature flag):
//
//   TODO: seal_key(key_bytes) → sealed blob
//         Create a TPM2 primary key under the SRK, then use TPM2_Create to
//         generate a restricted signing key sealed to a PCR policy covering
//         PCR 0 (firmware), PCR 7 (Secure Boot state), and PCR 11 (boot loader).
//         Return the encrypted key blob; private key material never leaves the TPM.
//
//   TODO: unseal_key(sealed_blob) → key_bytes
//         Load the sealed blob back into the TPM with TPM2_Load, verify the
//         PCR policy, and use TPM2_Sign to produce the signature inside the TPM.
//         If the PCR values have changed (firmware update, OS swap) the TPM
//         refuses to unseal and this function returns an error.
//
//   TODO: generate_in_tpm() → (public_key_bytes, key_handle)
//         Generate the P-256 key entirely inside the TPM using TPM2_Create with
//         TPM_ALG_ECDSA + TPM_ECC_NIST_P256.  The private key is never exported.
//
// Current state — SOFTWARE FALLBACK (not production safe):
//
//   Private key bytes are stored as a hex file under /etc/mykey/keys/.
//   This is provided solely to make the end-to-end registration/authentication
//   flow testable without TPM2 hardware.
//
//   ⚠ WARNING: This fallback stores key material on disk in plaintext.
//              It provides NO hardware binding and NO boot-chain protection.
//              Replace with real TPM2 sealing before any production use.

use log::warn;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_DIR: &str = "/etc/mykey/keys";

// ---------------------------------------------------------------------------
// Software fallback
// ---------------------------------------------------------------------------

/// Store private key bytes as a hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.  Replace with TPM2 sealing.
pub fn seal_key(credential_id_hex: &str, key_bytes: &[u8]) -> Result<(), String> {
    warn!(
        "⚠ SOFTWARE FALLBACK: storing key for credential {} in plaintext on disk. \
         This is NOT production safe. Enable the `tpm2` feature for real TPM sealing.",
        credential_id_hex
    );

    std::fs::create_dir_all(KEY_DIR)
        .map_err(|e| format!("Cannot create key directory {KEY_DIR}: {e}"))?;

    let path = key_path(credential_id_hex);
    let hex = hex::encode(key_bytes);

    std::fs::write(&path, hex.as_bytes())
        .map_err(|e| format!("Cannot write key to {}: {e}", path.display()))?;

    // Restrict to owner-readable only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("Cannot chmod key file: {e}"))?;
    }

    Ok(())
}

/// Load and return private key bytes from the hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.
pub fn unseal_key(credential_id_hex: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    warn!(
        "⚠ SOFTWARE FALLBACK: loading plaintext key for credential {}. \
         Enable the `tpm2` feature for real TPM sealing.",
        credential_id_hex
    );

    let path = key_path(credential_id_hex);
    let hex_bytes = std::fs::read(&path)
        .map_err(|e| format!("Cannot read key from {}: {e}", path.display()))?;

    let hex_str = std::str::from_utf8(&hex_bytes)
        .map_err(|_| "Key file is not valid UTF-8".to_string())?
        .trim();

    let key = hex::decode(hex_str)
        .map_err(|e| format!("Key file contains invalid hex: {e}"))?;

    Ok(Zeroizing::new(key))
}

fn key_path(credential_id_hex: &str) -> PathBuf {
    Path::new(KEY_DIR).join(format!("{}.key", credential_id_hex))
}

// ---------------------------------------------------------------------------
// TPM2 stubs (compiled only with --features tpm2)
// ---------------------------------------------------------------------------

#[cfg(feature = "tpm2")]
pub mod tpm2 {
    // TODO: Implement using tss_esapi::Context::new() with a TCTI of
    // tss_esapi::tcti_ldr::TctiNameConf::Device("/dev/tpmrm0").
    //
    // Key creation PCR policy sketch:
    //   1. context.pcr_read(PcrSelectionList for PCR 0, 7, 11) → current values
    //   2. context.policy_pcr(session, pcrDigest, selection) → PCR policy digest
    //   3. context.create(parent, template_with_policy, ...) → key blob
    //
    // Key loading + signing sketch:
    //   1. context.load(parent, key_blob) → key_handle
    //   2. context.sign(key_handle, digest, scheme) → TPMT_SIGNATURE
    //   3. Verify PCR policy has not drifted (policy session enforces this)

    pub fn seal_key_tpm2(_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
        Err("TPM2 sealing not yet implemented".to_string())
    }

    pub fn unseal_key_tpm2(_sealed_blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("TPM2 unsealing not yet implemented".to_string())
    }

    pub fn generate_in_tpm() -> Result<Vec<u8>, String> {
        Err("TPM2 in-TPM key generation not yet implemented".to_string())
    }
}
