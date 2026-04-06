# Architecture — MyKey Proxy

## Overview

MyKey Proxy intercepts WebAuthn platform authenticator requests in Chrome and routes them through a secure local stack instead of letting them fail on Linux. When a site calls `navigator.credentials.create()` or `.get()`, the browser extension catches the call before it reaches the platform — which on Linux has no built-in authenticator — builds the required cryptographic structures, and coordinates with a persistent background daemon to verify the user and produce a valid signed response. The browser and the relying party receive a standards-compliant WebAuthn response and need no modification.

This architecture was chosen because each layer has a single responsibility and trust boundaries are explicit and enforced at every crossing. The extension cannot touch key material. The native host cannot talk directly to the TPM. The daemon is the only component with access to PAM and hardware — and it only responds to verified callers presenting a session token. The design is extensible: the daemon's authentication backend is structured to swap in a mobile bridge later without changing anything above it.

## Component Map

```
Chrome Browser
    └── webAuthenticationProxy API
         └── Extension (background.js)
              └── chrome.runtime.sendNativeMessage
                   └── Native Host (Rust binary)
                        └── D-Bus system bus (AES-256-GCM + HMAC)
                             └── Daemon (persistent Rust service)
                                  ├── PAM (user presence verification)
                                  ├── TPM2 (key sealing + signing)
                                  └── Credential store (/etc/mykey-proxy/)
```

## Layer 1 — Browser Extension

**File:** `extension/src/background.js`

Chrome MV3 service worker. Uses the `webAuthenticationProxy` API to intercept `navigator.credentials.create()` and `navigator.credentials.get()` calls before the browser can reject them for lacking a platform authenticator. Calls `chrome.webAuthenticationProxy.attach()` on startup to register as the active proxy. Builds `clientDataJSON`, extracts `rpId` and challenge, and forwards to the native host via `chrome.runtime.sendNativeMessage`. On success calls `completeCreateRequest` or `completeGetRequest`. On failure or 10-second timeout calls the same completion function with an error object. All events logged with `[MyKey Proxy]` prefix.

Supporting files:
- `crypto.js` — base64url encode/decode, rpIdHash computation, clientDataJSON builder
- `storage.js` — credential metadata only; private keys never stored here
- `ui.js` — placeholder for future popup

**Planned:** Firefox extension support. Firefox does not implement the `webAuthenticationProxy` API; a different interception mechanism will be required.

## Layer 2 — Native Host

**Files:** `native-host/src/`

Rust binary. Chrome spawns it on demand when the extension calls `sendNativeMessage`. Communicates with Chrome over stdin/stdout using the Native Messaging protocol — every message prefixed with a 4-byte little-endian length field. Stdout is exclusively the Chrome message channel — all logging goes to `/tmp/mykey-proxy-host.log`.

On startup connects to the daemon over the D-Bus system bus and establishes a session. The session token is received as raw bytes — no bootstrap key decryption needed, as the system bus itself is kernel-mediated and policy-controlled. All subsequent requests are serialized, wrapped in a signed and encrypted envelope, and forwarded to the daemon. Responses are decrypted and returned to Chrome.

Modules:
- `main.rs` — message framing loop, dispatch
- `protocol.rs` — serde types matching the WebAuthn JS API wire format
- `dbus_client.rs` — blocking D-Bus proxy for the daemon interface
- `session.rs` — session token storage, AES-256-GCM encrypt/decrypt, HMAC attachment, sequence counter
- `crypto.rs` — P-256 helpers, authenticatorData builder, COSE key encoding (retained for future local operations)
- `pam.rs` — PAM client stub (auth now handled by daemon)
- `tpm.rs` — TPM2 stub (key operations now handled by daemon)
- `registration.rs` — serializes CreateRequest, sends to daemon, returns CreateResponse
- `authentication.rs` — serializes GetRequest, sends to daemon, returns GetResponse

## Layer 3 — IPC Channel

**Transport:** D-Bus system bus

Every message between native host and daemon is:
1. Serialized to JSON
2. Wrapped in a `RequestEnvelope` with sequence number and Unix timestamp
3. HMAC-SHA256 signed with the session token
4. AES-256-GCM encrypted with the session token

The session token is issued by the daemon after process verification and returned as raw bytes over the D-Bus system bus. The system bus is mediated by the kernel and enforced by a D-Bus policy file — only authorised users and processes can reach `com.mykeyproxy.Daemon`, replacing the former bootstrap key encryption layer.

Wire format (outer envelope, JSON):
```
{
  "nonce":      <12 random bytes, base64>,
  "ciphertext": <AES-256-GCM encrypted RequestEnvelope, base64>
}
```

RequestEnvelope (plaintext after decryption, JSON):
```
{
  "sequence":       <u64 monotonic counter>,
  "timestamp_secs": <Unix seconds>,
  "hmac":           <HMAC-SHA256(session_token, payload), bytes>,
  "payload":        <serialized CreateRequest or GetRequest, bytes>
}
```

Replay protection: the daemon rejects any sequence number already seen and any timestamp outside a 30-second window.

## Layer 4 — Daemon

**Files:** `daemon/src/`

Persistent Rust service registered on the D-Bus system bus as `com.mykeyproxy.Daemon` at `/com/webauthnproxy/Daemon`. Runs as a dedicated system user (`mykey-proxy`) under a hardened systemd unit.

Startup sequence:
```
1. Initialize file logger
2. enforce_prereqs()
     ├── Secure Boot EFI variable check
     ├── TPM2 device presence check (/dev/tpm0, /dev/tpmrm0)
     ├── TPM2 responsiveness check (TPM2_GetCapability command)
     └── Binary SHA-256 hash verification against trusted-binaries.json
3. Register D-Bus service name and object
4. Enter tokio async event loop
```

D-Bus interface — `com.mykeyproxy.Daemon`:
- `Connect(pid)` — verify caller process ancestry, issue session token, return raw token bytes
- `Register(pid, encrypted_request)` — decrypt, replay check, HMAC verify, dispatch to registration handler, return encrypted response
- `Authenticate(pid, encrypted_request)` — same flow, dispatch to authentication handler
- `Disconnect(pid)` — revoke session token, zeroize

Modules:
- `prereqs.rs` — Secure Boot EFI var check, TPM2 device check, TPM2 command probe, binary SHA-256 verification
- `session.rs` — session token issuance, mlocked memory, zeroize on drop
- `validator.rs` — `/proc` ancestry verification, binary integrity check, HMAC verification
- `replay.rs` — sequence number cache, timestamp window enforcement, async mutex
- `crypto.rs` — AES-256-GCM encrypt/decrypt, HMAC-SHA256
- `dbus_interface.rs` — zbus interface definition, `DaemonState` (SessionStore + ReplayCache)
- `pam.rs` — async user presence via polkit pkcheck, 3-attempt retry with exponential cooldown brute-force protection
- `tpm.rs` — real TPM2 sealing under `--features tpm2`, software fallback for development/CI

## Layer 5 — Authentication Backend

### Polkit (User Presence)

Every registration and authentication request is gated by polkit before any key material is touched. The daemon calls `pkcheck` for the `com.mykeyproxy.authenticate` action, which triggers the desktop authentication agent to prompt the user with their system password or fingerprint. The daemon allows up to 3 attempts per session; if all fail a cooldown is imposed (1 min → 5 min → 15 min → 30 min → 1 h → 2 h → 5 h per consecutive failed session). A successful authentication resets the counter.

### TPM2 (Key Protection)

Keys are sealed to the TPM2 chip using PCR 0+7 policy binding. Build with `--features tpm2`.

```
Key generation:  TPM2_Create under the Owner SRK (RSA-2048 restricted decryption key)
Seal policy:     PCR 0  — firmware measurement
                 PCR 7  — Secure Boot state
Key material:    never leaves the TPM boundary
Unseal failure:  any changed PCR value causes hard failure (boot-time tampering detected)
Feature flag:    cargo build --features tpm2
```

## Registration Flow

```
User triggers registration request in browser
    │
    ▼
Extension intercepts navigator.credentials.create()
    │  builds clientDataJSON
    │  extracts rpId and challenge
    ▼
Native Host receives via sendNativeMessage
    │  serializes CreateRequest
    │  wraps in HMAC-signed, AES-256-GCM encrypted envelope
    ▼
Daemon receives Register() D-Bus call
    │  decrypts envelope
    │  checks replay cache (sequence number + timestamp)
    │  verifies HMAC
    │  calls polkit → desktop auth agent prompts user
    │  polkit approved
    │  generates P-256 keypair
    │  seals private key via TPM2 (PCR 0+7 policy binding)
    │  builds authenticatorData (AAGUID=zeros, AT flag set)
    │  encodes attestation object (format: none)
    │  encrypts response with session token
    ▼
Native Host decrypts response
    │  returns CreateResponse to Chrome
    ▼
Extension calls completeCreateRequest()
    │
    ▼
Browser submits credential to server — registration complete
```

## Authentication Flow

```
User triggers authentication request in browser
    │
    ▼
Extension intercepts navigator.credentials.get()
    │  builds clientDataJSON
    │  extracts rpId, challenge, and allowCredentials
    ▼
Native Host receives via sendNativeMessage
    │  serializes GetRequest
    │  wraps in HMAC-signed, AES-256-GCM encrypted envelope
    ▼
Daemon receives Authenticate() D-Bus call
    │  decrypts envelope
    │  checks replay cache
    │  verifies HMAC
    │  calls polkit → user presence confirmed
    │  resolves credential from allowCredentials or rpId scan
    │  unseals private key from TPM2
    │  verifies rpIdHash matches stored credential
    │  builds authenticatorData (UP+UV flags, incremented sign counter)
    │  signs authenticatorData || SHA-256(clientDataJSON) with P-256
    │  increments sign counter in credential metadata
    │  encrypts response with session token
    ▼
Native Host decrypts response
    │  returns GetResponse to Chrome
    ▼
Extension calls completeGetRequest()
    │
    ▼
Browser submits assertion to server — authentication complete
```

## Security Architecture

### Session Lifecycle

```
Native Host starts
    │  connects to D-Bus system bus
    │  calls Connect(pid)
    ▼
Daemon verifies caller
    │  reads /proc/{pid}/exe       — must be a recognised browser binary
    │                                (EPERM falls through to cmdline check)
    │  reads /proc/{pid}/cmdline   — confirmed browser invocation
    │  checks parent/grandparent cmdline — browser ancestry confirmed
    │  generates 32-byte CSPRNG session token
    │  mlocks token page in memory
    │  returns raw token bytes over kernel-mediated D-Bus system bus
    ▼
Native Host stores raw token in memory for session duration
    ▼
All subsequent requests encrypted + HMAC signed with session token
    ▼
Native Host exits
    └── calls Disconnect(pid)
         └── daemon zeroizes session token, removes from store
```

The D-Bus system bus is mediated by the kernel via a policy file
(`/etc/dbus-1/system.d/com.mykeyproxy.Daemon.conf`). Only the
`mykey-proxy` system user can own the service name, and only processes
matching the policy can call `Connect`. This replaces the former bootstrap
key encryption layer — the bus boundary itself provides the isolation.

### Trust Boundary Summary

| Boundary | Transport | Authentication | Encryption |
|---|---|---|---|
| Browser ↔ Extension | Chrome sandbox | Extension ID locked in NM manifest | Chrome internal |
| Extension ↔ Native Host | Chrome Native Messaging stdin/stdout | `allowed_origins` in host manifest | None (process isolation) |
| Native Host ↔ Daemon | D-Bus system bus | Kernel policy + process ancestry + session HMAC | AES-256-GCM |
| Daemon ↔ Hardware | Kernel syscalls | Polkit + TPM2 PCR policy | TPM2 hardware boundary |
| GUI Manager ↔ Daemon | D-Bus system bus | Kernel policy + polkit for destructive ops | None (metadata only; key material not exposed) |

## Planned: Daemon Broadcaster Pattern

Instead of request/response only, the daemon will emit D-Bus signals when authentication events occur. The extension will listen for these signals via the native host. This enables a system tray app, desktop notifications when an auth request is pending, and the auth prompt appearing on screen before the browser UI even updates.

```
Extension activates (intercept fires)
    └── sends request to daemon
Daemon receives request
    └── emits pending signal → system tray / desktop notification updates
    └── polkit prompts user via desktop auth agent
    └── user approves
    └── TPM2 signs
    └── emits completed signal with encrypted response
Extension catches response signal
    └── decrypts, submits completed WebAuthn assertion to Chrome
```

## Planned: Mobile Bridge

The daemon gains a fourth backend alongside PAM and TPM2. When the mobile backend is selected the daemon forwards the signing request to a paired phone instead of handling it locally.

```
Daemon receives auth request
    └── Mobile backend selected
    └── Encrypts request with ECDH pairing shared secret
    └── Sends to phone (local network first, encrypted relay as fallback)
Phone app receives request
    └── Displays site name and request details
    └── User approves with Face ID / fingerprint / PIN
    └── Phone signs with its own secure enclave key
    └── Encrypted response sent back
Daemon receives response
    └── Decrypts and validates
    └── Returns assertion up the stack to the native host
```

Planned `AuthBackend` trait:
```rust
trait AuthBackend {
    async fn register(&self, request: CreateRequest) -> Result<CreateResponse, Error>;
    async fn authenticate(&self, request: GetRequest) -> Result<GetResponse, Error>;
}
```

Implementations:
- `LocalBackend` — PAM + TPM2 (current)
- `MobileBackend` — phone bridge (planned)
- `HybridBackend` — try local first, fall back to mobile (planned)

## Planned: GTK4 Credential Manager

A separate native binary (`mykey-proxy-manager`) providing a graphical interface:

- **Credentials tab**: lists all registered credentials with key name, date/time created, origin type (website or extension), application name (parsed from rpId), and user-configurable nickname. Supports deletion with polkit re-authentication.
- **Secure Folders tab**: create and manage TPM-encrypted AES-256-GCM folders. All-or-nothing access — unlock the folder, add files, lock it. All contents encrypted on lock. Listed in credential manager.
- **Biometrics tab**: manage Howdy (face recognition) and fprintd (fingerprint) enrollments. Shows type, date, time, scan name, and user nickname. Enrollment delegates to system tools.
- **Mobile Pairing tab**: placeholder — planned feature.

The manager communicates with the daemon exclusively via D-Bus. The daemon will expose read-only credential listing methods accessible to local users, and destructive operations (delete, rename) will require polkit re-authentication. Key material never crosses the D-Bus boundary — only metadata is exposed.

## File Structure

```
mykey-proxy/
├── ARCHITECTURE.md               this document
├── THREAT_MODEL.md               attack surfaces and mitigations
├── CLAUDE.md                     project instructions for AI assistance
├── LICENSE                       MIT
├── README.md                     user-facing overview
│
├── assets/
│   ├── AuthnProxyLogoCircle.png  circular logo (used in README)
│   └── AuthnProxyLogoFull.png    full logo with text
│
├── extension/
│   ├── manifest.json             Chrome MV3 manifest, declares webAuthenticationProxy permission
│   ├── icons/
│   │   └── icon128.png           extension icon
│   └── src/
│       ├── background.js         service worker — intercept, forward, complete
│       ├── crypto.js             base64url, rpIdHash, clientDataJSON
│       ├── storage.js            chrome.storage.local wrapper for credential metadata
│       └── ui.js                 placeholder for future popup UI
│
├── native-host/
│   ├── Cargo.toml                dependencies: serde, zbus, aes-gcm, hmac, p256, pam, etc.
│   └── src/
│       ├── main.rs               stdin/stdout framing loop, dispatch
│       ├── protocol.rs           serde types for Chrome ↔ host wire format
│       ├── dbus_client.rs        blocking D-Bus proxy for daemon interface
│       ├── session.rs            session token, AES-256-GCM, HMAC, sequence counter
│       ├── registration.rs       CreateRequest → daemon → CreateResponse
│       ├── authentication.rs     GetRequest → daemon → GetResponse
│       ├── crypto.rs             P-256, authenticatorData, COSE key, base64url helpers
│       ├── pam.rs                PAM stub (auth delegated to daemon)
│       └── tpm.rs                TPM2 stub (key ops delegated to daemon)
│
├── daemon/
│   ├── Cargo.toml                dependencies: zbus, tokio, aes-gcm, hmac, pam, sha2, etc.
│   └── src/
│       ├── main.rs               startup, prereqs, D-Bus service registration, tokio runtime
│       ├── prereqs.rs            Secure Boot check, TPM2 check, binary hash check
│       ├── dbus_interface.rs     com.mykeyproxy.Daemon interface, DaemonState
│       ├── session.rs            session token issuance, mlocked storage
│       ├── validator.rs          /proc ancestry check, binary integrity, HMAC verify
│       ├── replay.rs             sequence number cache, 30-second timestamp window
│       ├── crypto.rs             AES-256-GCM, HMAC-SHA256, session token wrap/unwrap
│       ├── pam.rs                async polkit user presence, 3-attempt retry with exponential cooldown
│       └── tpm.rs                real TPM2 sealing (--features tpm2), software fallback for development
│
└── scripts/
    ├── install.sh                build, install, hash binaries, enable systemd service
    ├── com.mykeyproxy.host.json  Chrome Native Messaging host manifest
    └── mykey-proxy-daemon.service  systemd service unit with hardened permissions
```

## Configuration Files

| Path | Purpose |
|---|---|
| `/etc/mykey-proxy/trusted-binaries.json` | SHA-256 hashes of installed binaries, verified at daemon startup |
| `/etc/mykey-proxy/credentials/` | Credential metadata JSON files — no key material |
| `/etc/mykey-proxy/keys/` | TPM2 sealed key blobs (JSON: TPM2B_PUBLIC + TPM2B_PRIVATE, hex-encoded) |
| `/etc/pam.d/mykey-proxy` | PAM service configuration for user presence verification |
| `/etc/dbus-1/system.d/com.mykeyproxy.Daemon.conf` | D-Bus system bus policy — restricts who can own and call the daemon service |
| `scripts/com.mykeyproxy.host.json` | Chrome Native Messaging host manifest — declares binary path and allowed extension IDs |
| `scripts/mykey-proxy-daemon.service` | systemd service unit — runs as `mykey-proxy` user with strict sandboxing |
