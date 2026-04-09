// storage.js — chrome.storage.local wrapper for credential metadata.
//
// IMPORTANT: Only credential metadata is stored here (rpId, credentialId,
// public key in COSE format). Private key material never leaves the TPM and
// must never be written to extension storage.

const STORAGE_KEY_PREFIX = 'credential:';
const INDEX_KEY = 'credential_index';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Returns the storage key for a given credentialId. */
function credentialKey(credentialId) {
  return `${STORAGE_KEY_PREFIX}${credentialId}`;
}

/** Read the credential index (array of credentialIds) from storage. */
async function readIndex() {
  const result = await chrome.storage.local.get(INDEX_KEY);
  return result[INDEX_KEY] ?? [];
}

/** Write an updated credential index back to storage. */
async function writeIndex(index) {
  await chrome.storage.local.set({ [INDEX_KEY]: index });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Persist credential metadata after a successful registration.
 *
 * @param {string} credentialId   — base64url credential ID as returned by the native host
 * @param {string} rpId           — relying party ID (e.g. "example.com")
 * @param {string} publicKey      — COSE-encoded public key, base64url
 * @param {object} [extra={}]     — any additional metadata (e.g. user handle, display name)
 * @returns {Promise<void>}
 */
export async function saveCredential(credentialId, rpId, publicKey, extra = {}) {
  const record = {
    credentialId,
    rpId,
    publicKey,
    createdAt: Date.now(),
    ...extra,
  };

  const index = await readIndex();
  if (!index.includes(credentialId)) {
    index.push(credentialId);
    await writeIndex(index);
  }

  await chrome.storage.local.set({ [credentialKey(credentialId)]: record });
}

/**
 * Retrieve stored metadata for all credentials associated with an rpId.
 *
 * @param {string} rpId
 * @returns {Promise<object[]>}  — array of credential metadata records (may be empty)
 */
export async function getCredentialsByRpId(rpId) {
  const index = await readIndex();
  if (index.length === 0) return [];

  const keys = index.map(credentialKey);
  const result = await chrome.storage.local.get(keys);

  return Object.values(result).filter((record) => record.rpId === rpId);
}

/**
 * Retrieve metadata for a single credential by its ID.
 *
 * @param {string} credentialId
 * @returns {Promise<object|null>}
 */
export async function getCredential(credentialId) {
  const result = await chrome.storage.local.get(credentialKey(credentialId));
  return result[credentialKey(credentialId)] ?? null;
}

/**
 * List metadata for every stored credential across all RPs.
 *
 * @returns {Promise<object[]>}
 */
export async function listCredentials() {
  const index = await readIndex();
  if (index.length === 0) return [];

  const keys = index.map(credentialKey);
  const result = await chrome.storage.local.get(keys);
  return Object.values(result);
}

/**
 * Remove a credential's metadata from storage.
 * Does not affect the TPM key blob (that is managed by the native host).
 *
 * @param {string} credentialId
 * @returns {Promise<void>}
 */
export async function deleteCredential(credentialId) {
  const index = await readIndex();
  const updated = index.filter((id) => id !== credentialId);

  await Promise.all([
    writeIndex(updated),
    chrome.storage.local.remove(credentialKey(credentialId)),
  ]);
}
