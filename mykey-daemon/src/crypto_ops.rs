// crypto_ops.rs — P-256 key generation, ECDSA signing, authenticatorData assembly,
// and COSE key encoding for the daemon.
//
// Mirrors native-host/src/crypto.rs.  No private key bytes are written to disk
// here; that responsibility belongs to tpm.rs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// A freshly generated P-256 credential.  Private key bytes are wrapped in
/// `Zeroizing` so the memory is wiped when the struct is dropped.
pub struct Keypair {
    pub credential_id:     Vec<u8>,               // 16 random bytes
    pub private_key_bytes: Zeroizing<Vec<u8>>,    // 32-byte P-256 scalar
    pub cose_public_key:   Vec<u8>,               // CBOR-encoded COSE_Key
}

/// Generate a fresh P-256 signing keypair with a random 16-byte credential ID.
pub fn generate_credential_keypair() -> Keypair {
    let mut rng = rand::rngs::OsRng;

    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false /* uncompressed */);

    let x: &[u8] = point.x().expect("x coordinate missing").as_ref();
    let y: &[u8] = point.y().expect("y coordinate missing").as_ref();

    let cose_key = encode_cose_public_key(x, y);

    let mut credential_id = vec![0u8; 16];
    rng.fill_bytes(&mut credential_id);

    let private_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());

    Keypair { credential_id, private_key_bytes, cose_public_key: cose_key }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign `authenticatorData || SHA-256(clientDataJSON)` with a P-256 key.
/// Returns a DER-encoded ECDSA signature.
///
/// The signing key is reconstructed from bytes and drops (zeroize) after use.
pub fn sign_assertion(
    private_key_bytes: &[u8],
    authenticator_data: &[u8],
    client_data_json: &str,
) -> Result<Vec<u8>, String> {
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut to_sign = Vec::with_capacity(authenticator_data.len() + 32);
    to_sign.extend_from_slice(authenticator_data);
    to_sign.extend_from_slice(&client_data_hash);

    let key_buf = Zeroizing::new(private_key_bytes.to_vec());
    let signing_key = SigningKey::try_from(key_buf.as_slice())
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let der_sig: DerSignature = signing_key.sign(&to_sign);
    Ok(der_sig.as_ref().to_vec())
}

// ---------------------------------------------------------------------------
// rpIdHash
// ---------------------------------------------------------------------------

/// Returns true if `s` looks like a Chrome extension ID: exactly 32 lowercase a-z chars.
fn is_extension_id(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_lowercase())
}

/// SHA-256 of the RP ID, as required by WebAuthn §6.1.
///
/// - Full URLs (contain `://`) are hashed verbatim.
/// - Chrome extension IDs (exactly 32 lowercase a-z chars) are prefixed with
///   `chrome-extension://` before hashing.
/// - All other values (standard web domains) are hashed as-is.
pub fn compute_rp_id_hash(rp_id: &str) -> [u8; 32] {
    let origin = if rp_id.contains("://") {
        rp_id.to_string()
    } else if is_extension_id(rp_id) {
        format!("chrome-extension://{}", rp_id)
    } else {
        rp_id.to_string()
    };

    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// authenticatorData builder
// ---------------------------------------------------------------------------

/// Flags byte constants (WebAuthn §6.1).
pub mod flags {
    pub const UP: u8 = 0x01; // User Present
    pub const UV: u8 = 0x04; // User Verified
    pub const AT: u8 = 0x40; // Attested credential data present
}

/// Build the authenticatorData byte string (WebAuthn §6.1).
///
/// Pass `attested_data = Some((aaguid, credential_id, cose_public_key))` for
/// registration (AT flag set).  Pass `None` for authentication.
pub fn build_authenticator_data(
    rp_id: &str,
    sign_count: u32,
    attested_data: Option<(&[u8; 16], &[u8], &[u8])>,
) -> Vec<u8> {
    let rp_id_hash = compute_rp_id_hash(rp_id);

    let flag_byte = if attested_data.is_some() {
        flags::UP | flags::UV | flags::AT
    } else {
        flags::UP | flags::UV
    };

    let mut data = Vec::with_capacity(
        37 + attested_data.map_or(0, |(_, id, k)| 18 + id.len() + k.len()),
    );

    data.extend_from_slice(&rp_id_hash);               // 32 bytes
    data.push(flag_byte);                               // 1 byte
    data.extend_from_slice(&sign_count.to_be_bytes());  // 4 bytes

    if let Some((aaguid, cred_id, cose_key)) = attested_data {
        data.extend_from_slice(aaguid);                                   // 16 bytes
        data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());   // 2 bytes
        data.extend_from_slice(cred_id);
        data.extend_from_slice(cose_key);
    }

    data
}

// ---------------------------------------------------------------------------
// COSE key encoding (manual CBOR — no extra dependency)
// ---------------------------------------------------------------------------

/// Encode a P-256 public key as a CBOR COSE_Key map (RFC 8152 §13.1.1).
pub fn encode_cose_public_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), 32, "P-256 x must be 32 bytes");
    assert_eq!(y.len(), 32, "P-256 y must be 32 bytes");

    let mut out = Vec::with_capacity(77);
    out.push(0xa5); // map(5)

    cbor_uint(&mut out, 1);     // 1: 2  (kty = EC2)
    cbor_uint(&mut out, 2);
    cbor_uint(&mut out, 3);     // 3: -7  (alg = ES256)
    cbor_neg_int(&mut out, 7);
    cbor_neg_int(&mut out, 1);  // -1: 1  (crv = P-256)
    cbor_uint(&mut out, 1);
    cbor_neg_int(&mut out, 2);  // -2: bstr(x)
    cbor_bytes(&mut out, x);
    cbor_neg_int(&mut out, 3);  // -3: bstr(y)
    cbor_bytes(&mut out, y);

    out
}

/// Encode a "none" attestation object wrapping authenticatorData.
pub fn encode_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa3); // map(3)
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    out.push(0xa0); // map(0) — empty
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("base64url decode error: {e}"))
}

// ---------------------------------------------------------------------------
// CBOR primitives
// ---------------------------------------------------------------------------

fn cbor_head(out: &mut Vec<u8>, major: u8, value: usize) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value < 0x100 {
        out.push(m | 24);
        out.push(value as u8);
    } else if value < 0x10000 {
        out.push(m | 25);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(m | 26);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

fn cbor_uint(out: &mut Vec<u8>, v: usize) {
    cbor_head(out, 0, v);
}

fn cbor_neg_int(out: &mut Vec<u8>, n: usize) {
    cbor_head(out, 1, n - 1);
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}
