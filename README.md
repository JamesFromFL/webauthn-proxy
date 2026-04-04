# webauthn-proxy

<p align="center">
  <img src="assets/AuthnProxyLogoCircle.png" alt="AuthnProxy Logo" width="160" />
</p>

A local-first WebAuthn proxy that intercepts browser credential requests, enforces physical user presence via PAM, and seals credentials to the platform's TPM2 chip — so your passkeys can only be used on the exact machine they were created on, by a verified user.

---

## What it does

Modern browsers expose the [WebAuthn API](https://www.w3.org/TR/webauthn-2/) (`navigator.credentials.create` / `.get`) to allow passwordless authentication. By default, resident keys live in software or a roaming authenticator. **webauthn-proxy** sits between the browser and the authenticator and adds two hard guarantees:

1. **User presence** — every credential operation requires a real PAM authentication challenge on the local machine.
2. **Device binding** — credential material is sealed to TPM2 PCR values at the time of creation; it cannot be exported or used after a firmware/OS change.

---

## Architecture overview

webauthn-proxy is built in five layers:

| Layer | Name | Summary |
|-------|------|---------|
| 1 | **Interception** | Chrome extension uses the `webAuthenticationProxy` API to intercept all WebAuthn calls before they reach the platform authenticator. |
| 2 | **Native Messaging** | Extension forwards requests over the Chrome Native Messaging protocol to a local Rust host process. |
| 3 | **PAM User Presence** | Native host calls a PAM service to verify the user is physically present before proceeding. |
| 4 | **TPM2 Key Sealing** | Credential private keys are created inside the TPM and sealed to PCR values (boot chain, OS state). |
| 5 | **Credential Lifecycle** | Registration and authentication flows are handled end-to-end; the host returns a conformant authenticator response to the extension. |

See [ARCHITECTURE.md](ARCHITECTURE.md) for full detail including flow diagrams.

---

## Components

| Component | Language / Tech | Location |
|-----------|----------------|----------|
| Browser extension | JavaScript, Manifest V3 | `extension/` |
| Native messaging host | Rust | `native-host/` |
| Installer / setup scripts | Bash | `scripts/` |

---

## Getting started

> Setup instructions will be added once the initial implementation is complete.

For now, see [ARCHITECTURE.md](ARCHITECTURE.md) to understand the design, and [THREAT_MODEL.md](THREAT_MODEL.md) for the security scope.
