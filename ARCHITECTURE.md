# Architecture

webauthn-proxy is structured as five discrete layers. Each layer has a single responsibility and communicates only with the layers immediately above and below it.

---

## Layer 1 — Interception (`webAuthenticationProxy`)

The browser extension registers itself as a WebAuthn proxy using Chrome's experimental [`webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/webAuthenticationProxy/) API. This API allows the extension to:

- Intercept `navigator.credentials.create()` calls (registration).
- Intercept `navigator.credentials.get()` calls (authentication).
- Return a synthetic `AuthenticatorAttestationResponse` or `AuthenticatorAssertionResponse` to the calling page.

The page receives a standards-compliant WebAuthn response and requires no modification.

**Trust boundary:** The extension runs inside the browser's renderer sandbox. It sees the raw `PublicKeyCredentialCreationOptions` / `PublicKeyCredentialRequestOptions` but never touches key material.

---

## Layer 2 — Native Messaging Host protocol

When the extension intercepts a credential call it serialises the options and forwards them to the native host over [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

### Message format (extension → host)

```json
{
  "type": "create" | "get",
  "requestId": "<uuid>",
  "options": { /* JSON-serialised PublicKeyCredential*Options */ }
}
```

### Message format (host → extension)

On success:
```json
{
  "requestId": "<uuid>",
  "status": "ok",
  "response": { /* JSON-serialised authenticator response */ }
}
```

On failure:
```json
{
  "requestId": "<uuid>",
  "status": "error",
  "code": "user_cancelled" | "pam_failure" | "tpm_error" | "internal",
  "message": "<human-readable detail>"
}
```

The host process is a long-lived Rust binary registered in the Chrome native messaging manifest. It reads/writes length-prefixed JSON on stdin/stdout.

---

## Layer 3 — PAM user presence

Before performing any TPM operation the native host calls into PAM (Pluggable Authentication Modules) to verify user presence.

- The PAM service name is `webauthn-proxy` (configured in `/etc/pam.d/webauthn-proxy`).
- The host invokes the PAM conversation as the logged-in user.
- A successful PAM exchange (password, fingerprint, smartcard — whatever the local policy dictates) constitutes "user verification" in WebAuthn terms (`UV=true`).
- A cancelled or failed PAM challenge causes the host to return `user_cancelled` or `pam_failure` immediately.

This layer enforces that a human at the keyboard explicitly approves each credential operation.

---

## Layer 4 — TPM2 key sealing with PCR binding

All private key material lives inside the TPM2 chip and never leaves it in plaintext.

### Key creation (registration)

1. The host asks the TPM to generate an asymmetric key pair (ECDSA P-256 or EdDSA, depending on the RP's `pubKeyCredParams`).
2. The key is created under the TPM's Storage Root Key (SRK) and sealed to a **PCR policy** that captures the current boot chain state.
3. The TPM returns an encrypted key blob (the "credential"). The blob is stored on disk; it is useless without the same TPM and the same PCR values.

### PCR policy

By default the policy binds to:

| PCR | Content |
|-----|---------|
| 0 | BIOS/UEFI firmware |
| 7 | Secure Boot state |
| 11 | systemd-boot / bootloader measurements |

This means the credential is invalidated by firmware updates, Secure Boot changes, or OS loader swaps — by design.

### Signing (authentication)

1. The host loads the key blob back into the TPM.
2. The TPM verifies that the current PCR values match the policy.
3. If the policy passes, the TPM signs the authenticator data + client data hash internally.
4. The signature is returned; the private key never leaves the TPM boundary.

---

## Layer 5 — Credential lifecycle

### Registration flow

```
Browser page
  │  navigator.credentials.create(options)
  ▼
Extension (Layer 1)
  │  intercepts via webAuthenticationProxy.onCreateRequest
  │  serialises options → JSON
  ▼
Native host (Layer 2 — stdin)
  │  deserialises options
  ▼
PAM challenge (Layer 3)
  │  blocks until user approves
  ▼
TPM2 key generation (Layer 4)
  │  generates key pair, seals to PCR policy
  │  writes credential blob to ~/.local/share/webauthn-proxy/<rp_id>/<credential_id>
  │  returns public key + attestation data
  ▼
Native host (Layer 2 — stdout)
  │  serialises AuthenticatorAttestationResponse → JSON
  ▼
Extension (Layer 1)
  │  calls webAuthenticationProxy.completeCreateRequest(response)
  ▼
Browser page
     receives PublicKeyCredential (attestation)
```

### Authentication flow

```
Browser page
  │  navigator.credentials.get(options)
  ▼
Extension (Layer 1)
  │  intercepts via webAuthenticationProxy.onGetRequest
  │  serialises options → JSON
  ▼
Native host (Layer 2 — stdin)
  │  looks up matching credential blobs for allowedCredentials
  ▼
PAM challenge (Layer 3)
  │  blocks until user approves
  ▼
TPM2 signing (Layer 4)
  │  loads key blob, verifies PCR policy, signs authenticatorData+hash
  │  returns signature
  ▼
Native host (Layer 2 — stdout)
  │  serialises AuthenticatorAssertionResponse → JSON
  ▼
Extension (Layer 1)
  │  calls webAuthenticationProxy.completeGetRequest(response)
  ▼
Browser page
     receives PublicKeyCredential (assertion)
```

---

## Key invariants

- The native host never stores plaintext private key material.
- The extension never receives key material of any kind.
- Every credential operation requires a successful PAM challenge — there is no bypass path.
- PCR policy is evaluated inside the TPM; the host cannot forge a policy match.
