// tpm.rs — TPM2 key sealing layer (daemon-side).
//
// With --features tpm2: seals/unseals credential key material through the TPM2
// resource manager at /dev/tpmrm0.  Keys are bound to PCR 0 (firmware
// measurements) and PCR 7 (Secure Boot state); any PCR drift at unseal time
// causes a hard failure — indicating boot-time tampering.
//
// Without --features tpm2: plaintext-on-disk fallback with loud warnings.
// This path is NOT production safe and exists only for development / CI.

use log::warn;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_DIR: &str = "/etc/mykey/keys";

// ---------------------------------------------------------------------------
// Public API — real TPM2 path (--features tpm2)
// ---------------------------------------------------------------------------

/// Seal `key_bytes` to the TPM under a PCR 0+7 policy and persist the
/// resulting blob as JSON to `KEY_DIR/{credential_id}.sealed`.
#[cfg(feature = "tpm2")]
pub fn seal_key(credential_id_hex: &str, key_bytes: &[u8]) -> Result<(), String> {
    use tpm2_impl::tpm_seal;

    std::fs::create_dir_all(KEY_DIR)
        .map_err(|e| format!("Cannot create key directory {KEY_DIR}: {e}"))?;

    let (pub_bytes, priv_bytes) = tpm_seal(key_bytes)?;

    let json_str = serde_json::to_string(&serde_json::json!({
        "public":  hex::encode(&pub_bytes),
        "private": hex::encode(&priv_bytes),
    }))
    .map_err(|e| format!("JSON serialization error: {e}"))?;

    let path = sealed_path(credential_id_hex);
    std::fs::write(&path, json_str.as_bytes())
        .map_err(|e| format!("Cannot write sealed blob to {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod sealed file: {e}"))?;
    }

    Ok(())
}

/// Load the sealed blob for `credential_id_hex` and unseal it via the TPM.
///
/// Returns `Err` if the PCR values have changed since sealing.
#[cfg(feature = "tpm2")]
pub fn unseal_key(credential_id_hex: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    use tpm2_impl::tpm_unseal;

    let path = sealed_path(credential_id_hex);
    let json_bytes = std::fs::read(&path)
        .map_err(|e| format!("Cannot read sealed blob from {}: {e}", path.display()))?;

    let json: serde_json::Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Invalid JSON in sealed blob: {e}"))?;

    let pub_bytes = hex::decode(
        json["public"].as_str().ok_or("Missing 'public' field in sealed blob")?,
    )
    .map_err(|e| format!("Invalid hex in 'public': {e}"))?;

    let priv_bytes = hex::decode(
        json["private"].as_str().ok_or("Missing 'private' field in sealed blob")?,
    )
    .map_err(|e| format!("Invalid hex in 'private': {e}"))?;

    tpm_unseal(&pub_bytes, &priv_bytes)
}

// ---------------------------------------------------------------------------
// Public API — software fallback (no tpm2 feature)
// ---------------------------------------------------------------------------

/// Store a private key as a hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.  Enable --features tpm2.
#[cfg(not(feature = "tpm2"))]
pub fn seal_key(credential_id_hex: &str, key_bytes: &[u8]) -> Result<(), String> {
    warn!(
        "⚠ SOFTWARE FALLBACK (daemon): storing key for credential {} in plaintext. \
         Enable --features tpm2 for real TPM sealing.",
        credential_id_hex
    );

    std::fs::create_dir_all(KEY_DIR)
        .map_err(|e| format!("Cannot create key directory {KEY_DIR}: {e}"))?;

    let path = fallback_path(credential_id_hex);
    std::fs::write(&path, hex::encode(key_bytes).as_bytes())
        .map_err(|e| format!("Cannot write key to {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot chmod key file: {e}"))?;
    }

    Ok(())
}

/// Load a private key from the hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.
#[cfg(not(feature = "tpm2"))]
pub fn unseal_key(credential_id_hex: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    warn!(
        "⚠ SOFTWARE FALLBACK (daemon): loading plaintext key for credential {}.",
        credential_id_hex
    );

    let path = fallback_path(credential_id_hex);
    let hex_bytes = std::fs::read(&path)
        .map_err(|e| format!("Cannot read key from {}: {e}", path.display()))?;
    let hex_str = std::str::from_utf8(&hex_bytes)
        .map_err(|_| "Key file is not valid UTF-8".to_string())?
        .trim();
    let key =
        hex::decode(hex_str).map_err(|e| format!("Key file contains invalid hex: {e}"))?;

    Ok(Zeroizing::new(key))
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn sealed_path(credential_id_hex: &str) -> PathBuf {
    Path::new(KEY_DIR).join(format!("{}.sealed", credential_id_hex))
}

fn fallback_path(credential_id_hex: &str) -> PathBuf {
    Path::new(KEY_DIR).join(format!("{}.key", credential_id_hex))
}

// ---------------------------------------------------------------------------
// Blob API — seal/unseal raw bytes without credential-ID disk storage
// ---------------------------------------------------------------------------

/// Seal raw `data` bytes via the TPM2 and return the sealed blob as bytes.
///
/// The blob is a JSON object encoding the TPM2B_PUBLIC and TPM2B_PRIVATE of
/// the sealed data object.  Pass the returned bytes directly to `unseal_blob`
/// to recover the original data.  Nothing is written to disk.
///
/// ⚠ SOFTWARE FALLBACK — returns hex-encoded plaintext when the `tpm2`
/// feature is absent.  Not production safe.
#[cfg(feature = "tpm2")]
pub fn seal_blob(data: &[u8]) -> Result<Vec<u8>, String> {
    use tpm2_impl::tpm_seal;
    let (pub_bytes, priv_bytes) = tpm_seal(data)?;
    serde_json::to_vec(&serde_json::json!({
        "public":  hex::encode(&pub_bytes),
        "private": hex::encode(&priv_bytes),
    }))
    .map_err(|e| format!("JSON serialization error: {e}"))
}

#[cfg(not(feature = "tpm2"))]
pub fn seal_blob(data: &[u8]) -> Result<Vec<u8>, String> {
    warn!(
        "⚠ SOFTWARE FALLBACK (daemon): seal_blob storing {} bytes as plaintext hex. \
         Enable --features tpm2 for real TPM sealing.",
        data.len()
    );
    Ok(hex::encode(data).into_bytes())
}

/// Unseal bytes from a blob produced by `seal_blob`.
///
/// Fails if PCR 0 or PCR 7 have changed since the blob was sealed —
/// indicating firmware or Secure Boot configuration tampering.
///
/// ⚠ SOFTWARE FALLBACK — hex-decodes plaintext when the `tpm2` feature is
/// absent.
#[cfg(feature = "tpm2")]
pub fn unseal_blob(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use tpm2_impl::tpm_unseal;
    let json: serde_json::Value = serde_json::from_slice(blob)
        .map_err(|e| format!("Invalid blob JSON: {e}"))?;
    let pub_bytes = hex::decode(
        json["public"].as_str().ok_or("Missing 'public' field in blob")?,
    )
    .map_err(|e| format!("Invalid hex in 'public': {e}"))?;
    let priv_bytes = hex::decode(
        json["private"].as_str().ok_or("Missing 'private' field in blob")?,
    )
    .map_err(|e| format!("Invalid hex in 'private': {e}"))?;
    tpm_unseal(&pub_bytes, &priv_bytes)
}

#[cfg(not(feature = "tpm2"))]
pub fn unseal_blob(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    warn!("⚠ SOFTWARE FALLBACK (daemon): unseal_blob decoding plaintext hex.");
    let hex_str = std::str::from_utf8(blob)
        .map_err(|_| "Blob is not valid UTF-8".to_string())?
        .trim();
    let data = hex::decode(hex_str)
        .map_err(|e| format!("Invalid hex in blob: {e}"))?;
    Ok(Zeroizing::new(data))
}

// ---------------------------------------------------------------------------
// TPM2 internals — compiled only with --features tpm2
// ---------------------------------------------------------------------------

#[cfg(feature = "tpm2")]
mod tpm2_impl {
    use std::str::FromStr;

    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        constants::SessionType,
        handles::{KeyHandle, SessionHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
            session_handles::{AuthSession, PolicySession},
        },
        structures::{
            Digest, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
            Private, Public, PublicBuilder, PublicKeyRsa, PublicKeyedHashParameters,
            PublicRsaParametersBuilder, RsaExponent, RsaScheme, SensitiveData,
            SymmetricDefinition, SymmetricDefinitionObject,
        },
        traits::{Marshall, UnMarshall},
        Context, TctiNameConf,
    };
    use zeroize::Zeroizing;

    const TCTI: &str = "device:/dev/tpmrm0";

    // -----------------------------------------------------------------------
    // Entry points
    // -----------------------------------------------------------------------

    /// Seal `key_bytes` under the TPM Owner SRK with a PCR 0+7 policy.
    ///
    /// Returns `(public_bytes, private_bytes)` — the marshalled TPM2B_PUBLIC
    /// and TPM2B_PRIVATE of the sealed data object.  All TPM sessions are
    /// flushed before returning.
    pub fn tpm_seal(key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut ctx = connect()?;

        let policy_digest = pcr_policy_digest(&mut ctx)?;
        let srk = create_srk(&mut ctx)?;

        let sealed_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_no_da(true)
            // user_with_auth=false — policy auth only; no password bypass.
            // sensitive_data_origin=false — we supply the data to seal.
            .build()
            .map_err(|e| format!("Sealed object attributes: {e}"))?;

        let sealed_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(sealed_attrs)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .with_auth_policy(policy_digest)
            .build()
            .map_err(|e| format!("Sealed object template: {e}"))?;

        let sensitive = SensitiveData::try_from(key_bytes.to_vec())
            .map_err(|e| format!("SensitiveData (key too large?): {e}"))?;

        let create_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(srk, sealed_template, None, Some(sensitive), None, None)
            })
            .map_err(|e| format!("TPM2_Create (sealed object): {e}"))?;

        let pub_bytes = create_result
            .out_public
            .marshall()
            .map_err(|e| format!("Marshal TPM2B_PUBLIC: {e}"))?;
        // Private is a plain buffer type — its value() bytes are the raw TPM2B_PRIVATE content.
        let priv_bytes = create_result.out_private.value().to_vec();

        let _ = ctx.flush_context(srk.into());

        Ok((pub_bytes, priv_bytes))
    }

    /// Unseal key bytes from a marshalled (public, private) blob pair.
    ///
    /// Fails with a clear error if PCR 0 or PCR 7 values have changed since
    /// sealing — indicating firmware or Secure Boot configuration tampering.
    /// All TPM sessions are flushed before returning.
    pub fn tpm_unseal(
        pub_bytes: &[u8],
        priv_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut ctx = connect()?;

        let out_public = Public::unmarshall(pub_bytes)
            .map_err(|e| format!("Unmarshal TPM2B_PUBLIC: {e}"))?;
        let out_private = Private::try_from(priv_bytes.to_vec())
            .map_err(|e| format!("Reconstruct TPM2B_PRIVATE: {e}"))?;

        let srk = create_srk(&mut ctx)?;

        let load_handle = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.load(srk, out_private, out_public)
            })
            .map_err(|e| format!("TPM2_Load (sealed object): {e}"))?;

        // Start a real (non-trial) policy session and assert PCR 0 + 7.
        // TPM2_PolicyPCR with an empty pcrDigest causes the TPM to compute the
        // expected digest from the *current* PCR bank.  If the values have
        // drifted from those that were in place at seal time the session will
        // be invalidated and the subsequent TPM2_Unseal will fail.
        let auth_session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| format!("TPM2_StartAuthSession (policy): {e}"))?
            .ok_or("Policy session returned None")?;

        let policy_session = PolicySession::try_from(auth_session)
            .map_err(|e| format!("PolicySession conversion: {e}"))?;

        ctx.policy_pcr(policy_session, Digest::default(), pcr_selection()?)
            .map_err(|e| {
                format!(
                    "PCR policy mismatch — possible boot-time tampering detected \
                     (PCR 0 or PCR 7 changed since key was sealed): {e}"
                )
            })?;

        let sensitive_data = ctx
            .execute_with_sessions(
                (Some(AuthSession::from(policy_session)), None, None),
                |ctx| ctx.unseal(load_handle.into()),
            )
            .map_err(|e| format!("TPM2_Unseal: {e}"))?;

        let key_bytes = Zeroizing::new(sensitive_data.value().to_vec());

        // Flush in child-first order; ignore individual flush errors since the
        // resource manager will reclaim handles when the TCTI connection closes.
        let _ = ctx.flush_context(load_handle.into());
        let _ = ctx.flush_context(SessionHandle::from(policy_session).into());
        let _ = ctx.flush_context(srk.into());

        Ok(key_bytes)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn connect() -> Result<Context, String> {
        let tcti = TctiNameConf::from_str(TCTI)
            .map_err(|e| format!("TCTI parse error: {e}"))?;
        Context::new(tcti).map_err(|e| format!("TPM context error: {e}"))
    }

    fn pcr_selection() -> Result<PcrSelectionList, String> {
        PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot7])
            .build()
            .map_err(|e| format!("PCR selection list: {e}"))
    }

    /// Compute a PCR policy digest for PCR 0+PCR 7 using a trial session.
    ///
    /// The trial session is always flushed before returning.
    fn pcr_policy_digest(ctx: &mut Context) -> Result<Digest, String> {
        let auth_session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| format!("TPM2_StartAuthSession (trial): {e}"))?
            .ok_or("Trial session returned None")?;

        let policy_session = PolicySession::try_from(auth_session)
            .map_err(|e| format!("PolicySession (trial): {e}"))?;

        ctx.policy_pcr(policy_session, Digest::default(), pcr_selection()?)
            .map_err(|e| format!("TPM2_PolicyPCR (trial): {e}"))?;

        let digest = ctx
            .policy_get_digest(policy_session)
            .map_err(|e| format!("TPM2_PolicyGetDigest: {e}"))?;

        let _ = ctx.flush_context(SessionHandle::from(policy_session).into());

        Ok(digest)
    }

    /// Create a primary RSA-2048 restricted-decryption key (SRK equivalent)
    /// under the Owner hierarchy with null auth.
    ///
    /// The caller is responsible for flushing the returned `KeyHandle`.
    fn create_srk(ctx: &mut Context) -> Result<KeyHandle, String> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()
            .map_err(|e| format!("SRK attributes: {e}"))?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(|e| format!("SRK RSA parameters: {e}"))?;

        let srk_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .map_err(|e| format!("SRK template: {e}"))?;

        let result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, srk_template, None, None, None, None)
            })
            .map_err(|e| format!("TPM2_CreatePrimary (SRK): {e}"))?;

        Ok(result.key_handle)
    }
}
