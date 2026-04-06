// background.js — service worker entry point; attaches the webAuthenticationProxy handler
// and routes all WebAuthn create/get requests to the native messaging host.

import { encodeBase64Url, decodeBase64Url, buildClientDataJSON, computeRpIdHash, extractFromAttestationObject, extractPublicKeyFromAuthData, coseToSpkiBase64Url } from './crypto.js';

const NATIVE_HOST = 'com.webauthnproxy.host';
const REQUEST_TIMEOUT_MS = 30_000;
const LOG_PREFIX = '[WebAuthn Proxy]';

function log(...args) {
  console.log(LOG_PREFIX, ...args);
}

function logError(...args) {
  console.error(LOG_PREFIX, ...args);
}

// ---------------------------------------------------------------------------
// Native host communication
// ---------------------------------------------------------------------------

/**
 * Send a message to the native host and return a Promise that resolves with
 * the host's response or rejects after REQUEST_TIMEOUT_MS.
 *
 * @param {object} message
 * @returns {Promise<object>}
 */
function sendToNativeHost(message) {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Native host request timed out after ${REQUEST_TIMEOUT_MS}ms`));
    }, REQUEST_TIMEOUT_MS);

    log('Sending to native host:', message.type, 'requestId:', message.requestId);

    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      clearTimeout(timeoutId);

      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      if (!response) {
        reject(new Error('Native host returned an empty response'));
        return;
      }

      log('Received from native host:', response.status, 'requestId:', response.requestId);
      resolve(response);
    });
  });
}

// ---------------------------------------------------------------------------
// Registration (create) handler
// ---------------------------------------------------------------------------

async function handleCreateRequest(requestInfo) {
  const { requestId, requestDetailsJson } = requestInfo;
  log('onCreateRequest fired, requestId:', requestId);

  let options;
  try {
    options = JSON.parse(requestDetailsJson);
  } catch (err) {
    logError('Failed to parse create requestDetailsJson:', err);
    chrome.webAuthenticationProxy.completeCreateRequest(
      { requestId, error: { name: 'UnknownError', message: 'Internal error: could not parse creation options' } },
      () => {}
    );
    return;
  }

  const rpId = options.rp?.id ?? new URL(options.rp?.id || '').hostname;
  const challenge = options.challenge; // base64url string as received
  log('Create request for rpId:', rpId);

  // Build the clientDataJSON the browser normally constructs.
  // The native host will echo it back inside the attestation response.
  const clientDataJSON = buildClientDataJSON('webauthn.create', challenge, rpId);

  const message = {
    type: 'create',
    requestId,
    rpId,
    challenge,
    clientDataJSON,
    options,
  };

  let response;
  try {
    response = await sendToNativeHost(message);
  } catch (err) {
    logError('Native host error during create:', err.message);
    chrome.webAuthenticationProxy.completeCreateRequest(
      { requestId, error: { name: 'UnknownError', message: `Native host error: ${err.message}` } },
      () => {}
    );
    return;
  }

  if (response.status !== 'ok') {
    logError('Native host returned error during create:', response.code, response.message);
    chrome.webAuthenticationProxy.completeCreateRequest(
      { requestId, error: { name: 'UnknownError', message: response.message ?? 'Authentication failed' } },
      () => {}
    );
    return;
  }

  log('Completing create request for requestId:', requestId);
  const attestationObject = response.response.response.attestationObject;
  const authData = extractFromAttestationObject(attestationObject);
  const coseKey = extractPublicKeyFromAuthData(authData);
  const publicKey = coseToSpkiBase64Url(coseKey);
  console.log('[DEBUG] authData:', authData);
  console.log('[DEBUG] coseKey:', coseKey);
  console.log('[DEBUG] publicKey (SPKI):', publicKey);
  console.log('[DEBUG] full responseJson:', JSON.stringify({
    ...response.response,
    response: {
      ...response.response.response,
      authenticatorData: authData,
      publicKeyAlgorithm: -7,
      publicKey: publicKey,
    }
  }, null, 2));
  await chrome.webAuthenticationProxy.completeCreateRequest({
    requestId,
    responseJson: JSON.stringify({
      ...response.response,
      response: {
        ...response.response.response,
        authenticatorData: authData,
        publicKeyAlgorithm: -7,
        publicKey,
      }
    }),
  });
}

// ---------------------------------------------------------------------------
// Authentication (get) handler
// ---------------------------------------------------------------------------

async function handleGetRequest(requestInfo) {
  const { requestId, requestDetailsJson } = requestInfo;
  log('onGetRequest fired, requestId:', requestId);

  let options;
  try {
    options = JSON.parse(requestDetailsJson);
  } catch (err) {
    logError('Failed to parse get requestDetailsJson:', err);
    chrome.webAuthenticationProxy.completeGetRequest(
      { requestId, error: { name: 'UnknownError', message: 'Internal error: could not parse assertion options' } },
      () => {}
    );
    return;
  }

  const rpId = options.rpId ?? '';
  const challenge = options.challenge; // base64url string
  const allowCredentials = options.allowCredentials ?? [];

  log('Get request for rpId:', rpId, '| allowCredentials count:', allowCredentials.length);

  const clientDataJSON = buildClientDataJSON('webauthn.get', challenge, rpId);

  const message = {
    type: 'get',
    requestId,
    rpId,
    challenge,
    clientDataJSON,
    allowCredentials,
    options,
  };

  let response;
  try {
    response = await sendToNativeHost(message);
  } catch (err) {
    logError('Native host error during get:', err.message);
    chrome.webAuthenticationProxy.completeGetRequest(
      { requestId, error: { name: 'UnknownError', message: `Native host error: ${err.message}` } },
      () => {}
    );
    return;
  }

  if (response.status !== 'ok') {
    logError('Native host returned error during get:', response.code, response.message);
    chrome.webAuthenticationProxy.completeGetRequest(
      { requestId, error: { name: 'UnknownError', message: response.message ?? 'Authentication failed' } },
      () => {}
    );
    return;
  }

  log('Completing get request for requestId:', requestId);
  await chrome.webAuthenticationProxy.completeGetRequest({
    requestId,
    responseJson: JSON.stringify(response.response),
  });
}

// ---------------------------------------------------------------------------
// Proxy attachment
// ---------------------------------------------------------------------------

// Attach the proxy immediately so Chrome routes WebAuthn calls to this extension.
chrome.webAuthenticationProxy.attach(() => {
  if (chrome.runtime.lastError) {
    logError('Failed to attach:', chrome.runtime.lastError.message);
  } else {
    log('Proxy attached successfully');
  }
});

function attachListeners() {
  if (chrome.webAuthenticationProxy.onCreateRequest.hasListeners()) {
    log('Listeners already registered, skipping.');
    return;
  }

  chrome.webAuthenticationProxy.onCreateRequest.addListener(handleCreateRequest);
  chrome.webAuthenticationProxy.onGetRequest.addListener(handleGetRequest);

  log('webAuthenticationProxy listeners attached.');
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener((details) => {
  log('Extension installed/updated, reason:', details.reason);
  attachListeners();
});

chrome.runtime.onStartup.addListener(() => {
  log('Browser startup detected, attaching listeners.');
  attachListeners();
});

// Register listeners immediately when the service worker first loads (covers unpacked reloads).
attachListeners();
