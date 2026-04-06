# Threat Model — WebAuthn Proxy

## Scope

This threat model applies to the local authentication proxy running on a single Linux machine. It covers the attack surface between the browser, the native host, the daemon, and the hardware security components (PAM, TPM2). It does not cover network-level attacks, cloud infrastructure, or the security of third-party services like NordPass that consume the WebAuthn assertions this proxy produces.

## Trust Boundaries

The system has four trust boundaries, each with different guarantees:

1. **Browser ↔ Extension (Chrome sandbox)** — The extension runs inside Chrome's sandbox and can only communicate with the browser's WebAuthn proxy API. Chrome enforces this boundary; the extension cannot directly access the filesystem or system calls.

2. **Extension ↔ Native Host (Chrome Native Messaging, extension ID locked)** — Chrome launches the native host binary and connects it to the extension over stdin/stdout using a 4-byte length-prefixed JSON protocol. Only extensions whose ID matches the one registered in the installed host manifest can open this channel. Chrome enforces the ID check.

3. **Native Host ↔ Daemon (D-Bus system bus, encrypted + HMAC signed)** — The native host connects to the daemon over the D-Bus system bus. Every message is AES-256-GCM encrypted and HMAC-SHA256 signed using a session token issued only after the caller passes process verification. The system bus is kernel-mediated and policy-controlled — only processes authorised by the D-Bus policy file (`/etc/dbus-1/system.d/com.webauthnproxy.Daemon.conf`) can reach the daemon service.

4. **Daemon ↔ Hardware (PAM stack, TPM2 chip)** — The daemon calls into the PAM stack for user presence verification and communicates with the TPM2 resource manager for key sealing and signing. The daemon runs as a dedicated system user with no login shell and strict systemd confinement.

## System Requirements as Security Dependencies

TPM 2.0 and Secure Boot are hard requirements, not suggestions. Here is why:

- **Secure Boot** ensures every stage of the boot chain — firmware, bootloader, kernel — is signature-verified before the OS loads. Without it, an attacker with physical access can boot a live USB and tamper with the system undetected.
- **TPM 2.0 with PCR binding** means private keys are sealed to the measured boot state of the machine. The TPM will only release a key if the machine booted into the exact same verified state as when the key was created. A modified system — different bootloader, different kernel, Secure Boot disabled — produces different PCR values and the keys do not unseal.
- **Without both**, TPM key sealing collapses to software-only protection: keys sealed without Secure Boot can be extracted by booting alternate media; PCR binding without Secure Boot can be spoofed by manipulating what gets measured.
- The daemon checks both at startup and logs warnings if either is missing. Hard enforcement — refusing to operate — is planned and will be enabled once MOK binary signing is in place.

## Attack Surfaces and Mitigations

### 1. Fake Caller — IPC Spoofing

**Threat:** A malicious process on the machine pretends to be the native host and sends crafted requests to the daemon to trigger authentication without user involvement.

**Mitigations implemented:**
- Process ancestry verification: the daemon reads `/proc/{pid}/exe`, `/proc/{pid}/status` (PPid), and `/proc/{pid}/cmdline` — all three must resolve to a real Chrome/Chromium binary, and its parent must also be Chrome.
- Session tokens are issued only to verified processes, generated as 32 bytes from a CSPRNG, mlocked in memory, and zeroized on session end.
- HMAC-SHA256 is computed over every request payload using the session token — an attacker cannot forge a valid HMAC without the token.

### 2. IPC Eavesdropping — Passive Sniffing

**Threat:** A process monitors D-Bus traffic (e.g. via `dbus-monitor`) and reads messages in transit.

**Mitigations implemented:**
- All IPC payloads are encrypted with AES-256-GCM keyed on the session token.
- The D-Bus system bus is policy-controlled — unprivileged processes cannot monitor system bus traffic without explicit policy allowances.
- The session token is transmitted over the kernel-mediated system bus at session establishment; no additional bootstrap key encryption layer is needed or present.
- An eavesdropper sees only ciphertext they cannot decrypt without the session token.

### 3. Replay Attack

**Threat:** Attacker captures a legitimate request and replays it later to get another signed assertion without triggering PAM.

**Mitigations implemented:**
- Every request includes a monotonic sequence number and a Unix timestamp.
- The daemon maintains a replay cache and rejects any sequence number already seen.
- Timestamp window of 30 seconds — requests outside this window are rejected regardless of sequence number.
- Signed assertions are challenge-bound server-side — even a stolen assertion cannot be replayed to a different authentication session on the relying party.

### 4. Response Interception

**Threat:** Attacker lets a legitimate request go through, then intercepts the daemon's response containing the signed assertion before the native host receives it.

**Mitigations implemented:**
- The response is AES-256-GCM encrypted with the session token — only the native host that was issued that token can decrypt it.
- The signed assertion is bound to the specific server-issued challenge and is useless outside that authentication session.

### 5. Session Token Theft

**Threat:** Attacker targets the session token itself — with it they can forge requests and decrypt responses.

**Mitigations implemented:**
- Session token exists in memory only, never written to disk.
- The memory page is mlocked to prevent the token from being swapped to disk.
- Token is zeroized on session end via the `Zeroizing` wrapper.
- The daemon runs as a dedicated system user (`webauthn-proxy`) — a user-space attacker running as a different user cannot read daemon memory.
- The session token is transmitted over the kernel-mediated D-Bus system bus. The bus enforces the policy file before delivering the `Connect` response — the token is never present on a channel accessible to unprivileged user processes. The former bootstrap key encryption layer has been eliminated as an attack surface; D-Bus system bus isolation provides equivalent protection with a simpler trust model.

**Planned:**
- The daemon systemd unit includes `ProtectMemory=yes`, `MemoryDenyWriteExecute=yes`, and `NoNewPrivileges=yes` to further restrict memory access at the OS level.

### 6. Binary Substitution

**Threat:** Attacker replaces `/usr/local/bin/webauthn-proxy-host` or the daemon binary with a malicious version.

**Mitigations implemented:**
- The install script SHA-256 hashes both binaries and writes them to `/etc/webauthn-proxy/trusted-binaries.json`.
- The daemon verifies both hashes at startup and refuses to issue session tokens if either hash does not match.
- Both binaries are installed as root-owned and are not writable by the daemon user.

**Planned:**
- MOK (Machine Owner Key) signing of both binaries — Secure Boot will then verify them at the kernel module level before they can execute.
- An attacker cannot replace the binaries without the MOK private key even with root access.

### 7. Boot-Time Tampering

**Threat:** Attacker boots a live USB, modifies binaries or PAM configuration, reboots — and the modified system unseals keys normally.

**Mitigations:**
- **Secure Boot (required):** Rejects unsigned bootloaders and kernels — the live USB attack fails at boot before any modifications can take effect.
- **TPM2 PCR binding (planned full implementation):** Keys are sealed to PCR 0 (firmware measurement), PCR 7 (Secure Boot state), and PCR 11 (bootloader). Any modification changes the PCR values and the keys will not unseal.
- If Secure Boot is disabled since the last run, the daemon detects the state change and refuses to unseal keys pending re-enrollment.

### 8. PAM Stack Tampering

**Threat:** Attacker modifies PAM configuration or replaces a PAM module to make authentication always succeed without verifying credentials.

**Mitigations:**
- PAM config files are root-owned — the daemon user cannot modify anything under `/etc/pam.d/`.
- The systemd service unit includes `ProtectSystem=strict` and `ReadOnlyPaths=/etc`.
- Replacement of PAM modules can be caught by the binary hash manifest if the relevant modules are added to `trusted-binaries.json` (planned extension of the hash manifest scope).

### 9. Cross-Machine Key Theft

**Threat:** Attacker copies key material from disk and attempts to use it on a different machine.

**Mitigations:**
- TPM2 keys are physically bound to the TPM chip on this machine — they cannot be exported or used on any other hardware.
- Software fallback keys (current state) are not hardware-bound — this is the known gap the full TPM2 implementation closes. See [Current Known Gaps](#current-known-gaps).
- Warning-level log entries are emitted every time the software fallback is active so the gap is never silent.

### 10. Unauthorized Mobile Forwarding (Planned Feature)

**Threat:** Attacker intercepts or spoofs the mobile bridge to receive authentication requests or forge approvals.

**Planned mitigations:**
- QR-code based pairing with an ECDH key exchange — a shared secret is established at pairing time and is never transmitted after that.
- All mobile bridge traffic is encrypted end-to-end with the pairing shared secret.
- The relay server (if used) sees only ciphertext and cannot read or modify requests or responses.
- The phone app requires biometric or PIN approval for every request — passive interception cannot produce a valid approval.
- Pairing can be revoked from both the desktop and the phone app at any time.

## Hardware Attack Surface

TPM chip decapping, DMA attacks before OS load, and compromised UEFI firmware are acknowledged as theoretical attack surfaces. These require nation-state level resources or physical hardware access and are out of scope for this project. Enabling IOMMU/VT-d in BIOS settings mitigates DMA attacks at the kernel level and is recommended.

## Fully Compromised OS

If an attacker has kernel ring-0 access, all software security guarantees on the machine are void regardless of what this project does. This is out of scope and is the correct place to draw the boundary. The TPM provides some protection below this level through PCR-bound sealing, but a compromised kernel can still intercept unsealed key material at the point it enters user space.

## Coerced Authentication

If a user is physically forced to authenticate, no software solution can prevent it. Out of scope.

## What This Project Does Not Protect Against

- Remote attackers — no network surface is exposed by this project
- Kernel-level compromise
- Physical hardware attacks on the TPM chip itself
- Coerced user authentication
- Security of third-party services that consume the WebAuthn assertions this proxy produces

## Current Known Gaps

These are honest gaps in the current implementation, not omissions from the design:

- **TPM2 PCR key sealing is stubbed.** The software fallback stores keys as hex files on disk. They are protected by filesystem permissions (mode 0600, daemon user only) but are not hardware-bound. A root attacker can read them. This gap is closed when the full TPM2 implementation lands.
- **MOK binary signing is not yet implemented.** Binary substitution protection is detection-only at runtime via hash verification. It is not boot-time prevention. Until MOK signing is in place, a root attacker who modifies a binary before the daemon starts will not be caught until startup.
- **Secure Boot enforcement is currently a warning, not a hard exit.** The daemon checks the Secure Boot EFI variable at startup and logs a warning if it is disabled, but continues running. Hard enforcement will be enabled alongside MOK signing so the binaries can pass the check they require.
- **The mobile bridge does not exist yet.** The threat model for it in this document is speculative design intent. It will be updated when the feature is implemented.
