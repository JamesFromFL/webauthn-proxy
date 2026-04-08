# Threat Model — MyKey Proxy

## Scope

This threat model applies to the local authentication proxy running on a single Linux machine.

It covers the attack surface between:
- Browser
- Extension
- Native host
- Daemon
- Hardware-backed security components (PAM, TPM2)

It does **not** cover:
- Network-level attacks
- Cloud infrastructure
- Third-party services that consume WebAuthn assertions

---

## Security Assumptions

This design relies on the following assumptions:

- The operating system is not kernel-compromised
- Chromium/Chrome sandboxing and native messaging enforcement function correctly
- D-Bus policy is correctly installed and not modified by an attacker
- PAM and polkit are trusted and correctly configured
- TPM firmware and platform firmware are not already compromised
- The system boot chain is protected by Secure Boot

If these assumptions do not hold, the security guarantees of this system degrade accordingly.

---

## Security Requirements

The following are **hard requirements** of the system:

- TPM 2.0 must be present and functional  
- Secure Boot must be enabled and enforced  

These are foundational to the security model:

- Secure Boot ensures the boot chain (firmware → bootloader → kernel) is verified before execution
- TPM PCR binding ensures keys are only unsealed when the system is in a known-good measured state

Without both:
- Key sealing degrades to software-level protection
- Offline tampering and alternate boot attacks become viable

The daemon validates these requirements at startup. Systems not meeting these conditions are considered **unsupported and insecure by design**.

---

## Trust Boundaries

The system is divided into the following trust boundaries:

### 1. Browser ↔ Extension (Chrome sandbox)

- The extension runs inside the browser sandbox
- Cannot access the filesystem or make arbitrary system calls
- Communication is restricted to browser APIs

### 2. Extension ↔ Native Host (Native Messaging)

- Communication occurs over stdin/stdout using Chrome Native Messaging
- Access is restricted to registered extension IDs
- Browser enforces extension identity validation

### 3. Native Host ↔ Daemon (D-Bus system bus)

- Communication occurs over the system D-Bus
- Governed by a strict policy file:
  `/etc/dbus-1/system.d/com.mykeyproxy.Daemon.conf`
- All application-layer payloads are:
  - AES-256-GCM encrypted
  - HMAC-SHA256 signed
- Session tokens are issued only after process verification

### 4. Daemon ↔ Hardware (PAM + TPM2)

- PAM handles user presence verification
- TPM2 handles key sealing and signing
- Daemon runs under a dedicated system user with systemd confinement

---

## Attack Surfaces and Mitigations

### 1. Fake Caller — IPC Spoofing

**Threat:**  
A malicious process attempts to impersonate the native host and send forged authentication requests.

**Mitigations:**
- Process ancestry verification (`/proc/{pid}/exe`, `status`, `cmdline`)
- Parent process must resolve to a valid Chromium/Chrome binary
- Session tokens issued only after verification
- Tokens are:
  - CSPRNG-generated (32 bytes)
  - mlocked in memory
  - zeroized on session end
- All messages require a valid HMAC-SHA256

---

### 2. IPC Eavesdropping — Passive Monitoring

**Threat:**  
An attacker attempts to observe D-Bus traffic.

**Mitigations:**
- Payloads encrypted using AES-256-GCM
- D-Bus system bus enforces policy restrictions
- Observers without proper access should only see ciphertext

---

### 3. Replay Attack

**Threat:**  
Captured requests are replayed to bypass authentication.

**Mitigations:**
- Monotonic sequence numbers per session
- 30-second timestamp validity window
- Replay cache rejects previously seen sequence numbers
- WebAuthn assertions are challenge-bound server-side

---

### 4. Response Interception

**Threat:**  
An attacker intercepts daemon responses containing signed assertions.

**Mitigations:**
- Responses encrypted with session token
- Assertions bound to server-issued challenge
- Intercepted responses should not be reusable outside the original context

---

### 5. Session Token Theft

**Threat:**  
An attacker attempts to extract or reuse session tokens.

**Mitigations:**
- Tokens exist only in memory (never persisted)
- mlock prevents swapping
- Explicit zeroization on session end
- Daemon runs under an isolated system user
- D-Bus policy restricts exposure during transmission

---

### 6. Binary Substitution

**Threat:**  
System binaries are replaced with malicious versions.

**Mitigations:**
- SHA-256 hashes stored in `/etc/mykey-proxy/trusted-binaries.json`
- Verified at daemon startup
- Mismatch prevents session token issuance
- Binaries are root-owned and not writable by the daemon user

---

### 7. Boot-Time Tampering

**Threat:**  
Offline modification via alternate boot media.

**Mitigations:**
- Secure Boot enforces the signed boot chain
- TPM PCR 0 + 7 binding prevents key unsealing on modified systems
- System state changes invalidate sealed keys

---

### 8. PAM Stack Tampering

**Threat:**  
Attacker modifies PAM configuration to bypass authentication.

**Mitigations:**
- `/etc/pam.d/` is root-owned
- systemd service uses:
  - `ProtectSystem=strict`
  - `ReadOnlyPaths=/etc`
- Future: extend binary hash verification to PAM modules

---

### 9. Cross-Machine Key Theft

**Threat:**  
Key material copied to another machine.

**Mitigations:**
- TPM keys are hardware-bound
- PCR-bound sealing prevents reuse on different systems

---

### 10. Authentication Brute Force

**Threat:**  
Repeated authentication attempts to guess credentials.

**Mitigations:**
- Maximum 3 attempts per session (polkit)
- Progressive cooldown:
  1m → 5m → 15m → 30m → 1h → 2h → 5h
- Successful authentication resets the counter

---

### 11. Mobile Companion (Future Design)

**Threat:**  
Interception or spoofing of the mobile approval channel.

**Planned Mitigations:**
- QR-based pairing with ECDH key exchange
- End-to-end encrypted communication
- Relay server (if used) sees only ciphertext
- Per-request biometric/PIN approval on device
- Revocable pairing

---

## Out of Scope

The following are explicitly not addressed:

- Remote attackers (no network exposure)
- Kernel-level compromise (ring 0)
- Physical attacks on TPM hardware (e.g., decapping)
- Compromised firmware or UEFI
- Coerced user authentication
- Security of third-party relying parties

---

## Known Limitations

- Secure Boot enforcement is a design requirement, but not yet a hard runtime failure  
- Mobile companion functionality is not implemented; threat model reflects intended design  

---

## Hardware Attack Surface

Advanced attacks such as:
- DMA attacks before OS load
- TPM physical extraction
- Firmware compromise

are considered out of scope.

Enabling IOMMU/VT-d is recommended to reduce DMA attack surface.
