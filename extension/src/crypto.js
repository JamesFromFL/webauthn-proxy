// crypto.js — WebAuthn binary encoding helpers used by the extension layer.
// Private keys never pass through here; this file only handles public-facing
// data structures (clientDataJSON, rpIdHash, base64url encoding).

// ---------------------------------------------------------------------------
// Base64url
// ---------------------------------------------------------------------------

/**
 * Encode an ArrayBuffer or Uint8Array to a base64url string (no padding).
 *
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function encodeBase64Url(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string (with or without padding) to a Uint8Array.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function decodeBase64Url(str) {
  // Normalise: base64url → base64
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + ((4 - (str.length % 4)) % 4), '=');

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// clientDataJSON
// ---------------------------------------------------------------------------

/**
 * Build a minimal clientDataJSON object conforming to the WebAuthn spec
 * (https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata).
 *
 * The result is the UTF-8 string that the native host must include verbatim
 * in its authenticator response so that relying parties can verify it.
 *
 * @param {'webauthn.create'|'webauthn.get'} type
 * @param {string} challengeBase64Url  — the raw challenge value, base64url-encoded
 * @param {string} origin              — the RP origin (e.g. "https://example.com")
 * @returns {string}  JSON string
 */
export function buildClientDataJSON(type, challengeBase64Url, origin) {
  const clientData = {
    type,
    challenge: challengeBase64Url,
    origin: origin.startsWith('http') ? origin : `https://${origin}`,
    crossOrigin: false,
  };
  return JSON.stringify(clientData);
}

// ---------------------------------------------------------------------------
// rpIdHash
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hash of an RP ID string and return it as a Uint8Array.
 *
 * This value is included in the authenticatorData and must match what the
 * native host computes when it assembles the authenticator response.
 *
 * @param {string} rpId  — e.g. "example.com"
 * @returns {Promise<Uint8Array>}
 */
export async function computeRpIdHash(rpId) {
  const encoded = new TextEncoder().encode(rpId);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Convenience wrapper: compute rpIdHash and return it as a base64url string.
 *
 * @param {string} rpId
 * @returns {Promise<string>}
 */
export async function computeRpIdHashBase64Url(rpId) {
  const hash = await computeRpIdHash(rpId);
  return encodeBase64Url(hash);
}

// ---------------------------------------------------------------------------
// attestationObject CBOR decoding
// ---------------------------------------------------------------------------

/**
 * Decode a base64url-encoded attestationObject and extract the authData field.
 *
 * The attestationObject is CBOR-encoded: a map of {fmt, attStmt, authData}.
 * Returns the authData bytes as a base64url string.
 *
 * @param {string} attestationObjectB64  — base64url-encoded attestationObject
 * @returns {string|null}  base64url authData, or null if extraction fails
 */
export function extractFromAttestationObject(attestationObjectB64) {
  const bytes = decodeBase64Url(attestationObjectB64);
  return extractAuthData(bytes);
}

/**
 * Extract the COSE-encoded public key from a base64url-encoded authData blob.
 *
 * authData layout:
 *   32 bytes  rpIdHash
 *    1 byte   flags
 *    4 bytes  signCount
 *   16 bytes  aaguid
 *    2 bytes  credentialIdLength (big-endian)
 *    N bytes  credentialId
 *   remaining COSE-encoded public key
 *
 * @param {string} authDataB64  — base64url authData
 * @returns {string}  base64url COSE public key
 */
export function extractPublicKeyFromAuthData(authDataB64) {
  const bytes = decodeBase64Url(authDataB64);
  let pos = 32 + 1 + 4 + 16; // rpIdHash + flags + signCount + aaguid
  const credIdLen = (bytes[pos] << 8) | bytes[pos + 1];
  pos += 2 + credIdLen;
  return encodeBase64Url(bytes.slice(pos));
}

// ---------------------------------------------------------------------------
// COSE → SPKI/DER conversion
// ---------------------------------------------------------------------------

/**
 * Convert a COSE-encoded P-256 public key (base64url) to SPKI/DER (base64url).
 *
 * Chrome's webAuthenticationProxy requires publicKey in SubjectPublicKeyInfo
 * (SPKI) DER format, not raw COSE.
 *
 * @param {string} coseB64  — base64url COSE_Key map
 * @returns {string|null}   base64url SPKI, or null on parse failure
 */
export function coseToSpkiBase64Url(coseB64) {
  const cose = decodeBase64Url(coseB64);
  const x = extractCoseParam(cose, -2);
  const y = extractCoseParam(cose, -3);
  if (!x || !y) return null;

  // Uncompressed EC point: 0x04 || x || y
  const point = new Uint8Array([0x04, ...x, ...y]);

  // OID for ecPublicKey: 1.2.840.10045.2.1
  const ecOid   = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  // OID for P-256: 1.2.840.10045.3.1.7
  const p256Oid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

  // AlgorithmIdentifier SEQUENCE { ecPublicKey, P-256 }
  const algId = new Uint8Array([0x30, ecOid.length + p256Oid.length, ...ecOid, ...p256Oid]);

  // BIT STRING: unused-bits prefix (0x00) + uncompressed point
  const bitString = new Uint8Array([0x03, point.length + 1, 0x00, ...point]);

  // Outer SEQUENCE wrapping AlgorithmIdentifier + BIT STRING
  const spki = new Uint8Array([0x30, algId.length + bitString.length, ...algId, ...bitString]);

  return encodeBase64Url(spki);
}

/**
 * Extract the raw bytes for integer key `paramKey` from a COSE_Key CBOR map.
 *
 * @param {Uint8Array} coseBytes
 * @param {number}     paramKey   — e.g. -2 for x, -3 for y
 * @returns {Uint8Array|null}
 */
function extractCoseParam(coseBytes, paramKey) {
  let pos = 1; // skip map header byte
  const count = coseBytes[0] & 0x1f;

  for (let i = 0; i < count; i++) {
    // Read key (positive or negative integer)
    const keyByte  = coseBytes[pos];
    const majorType = (keyByte >> 5) & 0x7;
    const info      = keyByte & 0x1f;
    pos++;

    let key;
    if      (majorType === 0) { key = info; }          // positive int
    else if (majorType === 1) { key = -(1 + info); }   // negative int
    else                      { return null; }

    // Read value
    const valByte  = coseBytes[pos];
    const valMajor = (valByte >> 5) & 0x7;
    const valInfo  = valByte & 0x1f;
    pos++;

    if (valMajor === 2) {
      // Byte string
      let len;
      if      (valInfo === 24) { len = coseBytes[pos];                           pos += 1; }
      else if (valInfo === 25) { len = (coseBytes[pos] << 8) | coseBytes[pos+1]; pos += 2; }
      else                     { len = valInfo; }

      if (key === paramKey) return coseBytes.slice(pos, pos + len);
      pos += len;
    } else if (valMajor === 0) {
      // Positive int — no extra bytes consumed
      if (key === paramKey) return valInfo;
    } else if (valMajor === 1) {
      // Negative int — no extra bytes consumed
      if (key === paramKey) return -(1 + valInfo);
    } else {
      return null;
    }
  }
  return null;
}

/**
 * Walk a CBOR-encoded attestationObject map and return the authData value
 * as a base64url string.
 *
 * @param {Uint8Array} cborBytes
 * @returns {string|null}
 */
function extractAuthData(cborBytes) {
  // First byte: 0xa3 = CBOR map of 3 items
  let pos = 1;
  const view = new DataView(cborBytes.buffer, cborBytes.byteOffset);

  for (let i = 0; i < 3; i++) {
    // Read key (CBOR text string)
    const keyAdditional = cborBytes[pos] & 0x1f;
    pos += 1;
    const key = new TextDecoder().decode(cborBytes.slice(pos, pos + keyAdditional));
    pos += keyAdditional;

    // Read value
    const majorType    = (cborBytes[pos] >> 5) & 0x7;
    const additionalInfo = cborBytes[pos] & 0x1f;
    pos += 1;

    if (key === 'authData') {
      // Value is a CBOR byte string (major type 2)
      let len;
      if      (additionalInfo === 24) { len = cborBytes[pos];       pos += 1; }
      else if (additionalInfo === 25) { len = view.getUint16(pos);  pos += 2; }
      else                            { len = additionalInfo; }
      return encodeBase64Url(cborBytes.slice(pos, pos + len));
    } else {
      // Skip the value
      if (majorType === 2 || majorType === 3) {
        // Byte string or text string — skip length + content
        let len;
        if      (additionalInfo === 24) { len = cborBytes[pos];       pos += 1; }
        else if (additionalInfo === 25) { len = view.getUint16(pos);  pos += 2; }
        else                            { len = additionalInfo; }
        pos += len;
      }
      // majorType 5 (map) with additionalInfo 0 = empty map (0xa0 = attStmt) — nothing to skip
    }
  }
  return null;
}
