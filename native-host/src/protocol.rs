// protocol.rs — Serde types for the Chrome Native Messaging wire format.
//
// All binary WebAuthn fields (challenges, credential IDs, keys, signatures)
// are carried as base64url strings.  The native host and extension both
// agree on camelCase field names to match the WebAuthn JS API.

use serde::{Deserialize, Serialize};

mod string_or_int {
    use serde::{self, Deserialize, Deserializer};
    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            String(String),
            Int(i64),
        }
        match StringOrInt::deserialize(deserializer)? {
            StringOrInt::String(s) => Ok(s),
            StringOrInt::Int(i) => Ok(i.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Registration (create)
// ---------------------------------------------------------------------------

/// Incoming registration request forwarded from the extension.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    #[serde(deserialize_with = "string_or_int::deserialize")]
    pub request_id:      String,
    pub rp_id:           String,
    #[serde(default)]
    pub rp_name:         String,
    pub challenge:       String,         // base64url
    #[serde(default)]
    pub user_id:         String,         // base64url
    #[serde(default)]
    pub user_name:       String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,        // raw JSON string from extension
}

/// Full create response — the `response` field is returned to the extension
/// and stringified as the `responseJson` argument to completeCreateRequest.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateResponse {
    pub response: PublicKeyCredentialCreate,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreate {
    pub id:                       String,   // base64url credential ID
    pub raw_id:                   String,   // base64url credential ID (WebAuthn duplicate)
    #[serde(rename = "type")]
    pub type_:                    String,   // "public-key"
    pub response:                 AttestationResponse,
    pub authenticator_attachment: String,   // "platform"
    pub client_extension_results: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json:   String,         // base64url
    pub attestation_object: String,         // base64url CBOR-encoded attObj
    pub transports:         Vec<String>,    // ["internal"]
}

// ---------------------------------------------------------------------------
// Authentication (get)
// ---------------------------------------------------------------------------

/// Incoming authentication request forwarded from the extension.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    #[serde(deserialize_with = "string_or_int::deserialize")]
    pub request_id:        String,
    pub rp_id:             String,
    pub challenge:         String,          // base64url
    #[serde(rename = "clientDataJSON")]
    pub client_data_json:  String,          // raw JSON string from extension
    #[serde(default)]
    pub allow_credentials: Vec<AllowCredential>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    pub id:    String,   // base64url
    #[serde(rename = "type", default)]
    pub type_: String,   // "public-key"
}

/// Full get response — the `response` field is stringified as `responseJson`
/// for completeGetRequest.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetResponse {
    pub response: PublicKeyCredentialGet,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialGet {
    pub id:                       String,   // base64url credential ID
    pub raw_id:                   String,
    #[serde(rename = "type")]
    pub type_:                    String,   // "public-key"
    pub response:                 AssertionResponse,
    pub authenticator_attachment: String,   // "platform"
    pub client_extension_results: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json:    String,         // base64url
    pub authenticator_data:  String,         // base64url
    pub signature:           String,         // base64url DER-encoded ECDSA P-256
    pub user_handle:         Option<String>, // base64url (may be absent)
}

// ---------------------------------------------------------------------------
// On-disk credential metadata (no private key material)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub credential_id: String,   // hex
    pub rp_id:         String,
    pub user_id:       String,   // base64url
    pub user_name:     String,
    pub sign_count:    u32,
    pub created_at:    u64,      // Unix timestamp (seconds)
}
