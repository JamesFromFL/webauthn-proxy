# Threat Model

## Assumptions

webauthn-proxy is designed for the following deployment context:

- A single-user Linux workstation or laptop.
- The TPM2 chip is present, enabled, and its PCR values reflect the actual boot state.
- The user's PAM configuration is controlled by the system owner (not the attacker).
- The attacker does **not** have root access at the time of a credential operation.
- The attacker does **not** have physical access to the machine.

---

## Trust boundaries

### Browser ↔ Extension

The extension runs in the browser's renderer process. It sees credential options and returns credential responses, but never handles key material. The browser's same-origin policy and extension sandbox are trusted to enforce this isolation.

**What we trust:** Chrome's `webAuthenticationProxy` API only delivers options from the page; it does not expose the TPM or PAM surfaces.

**What we do not trust:** JavaScript running on the page. The page can supply arbitrary `PublicKeyCredentialCreationOptions`, but the extension only forwards them — it cannot coerce the native host into producing a credential for an RP the user did not approve (PAM is the gate).

### Extension ↔ Native host

Chrome Native Messaging is a local IPC mechanism: the browser launches the host binary, identified by a registered manifest, and communicates over stdin/stdout. Only extensions whose ID is listed in the native messaging manifest can connect.

**What we trust:** The host binary path and the extension ID in the native messaging manifest are set at install time by a privileged installer. An attacker without write access to `/etc/opt/chrome/native-messaging-hosts/` cannot substitute a different binary.

**What we do not trust:** The content of messages. The native host validates all input and treats every message as potentially malformed.

### Native host ↔ PAM

The host calls PAM as the logged-in user. PAM policy is set by root. The host has no ability to pre-approve or cache a PAM result across requests.

**What we trust:** PAM's conversation mechanism correctly reflects local authentication policy (e.g., fingerprint reader, password, smartcard).

### Native host ↔ TPM2

The host communicates with the TPM via the kernel's `/dev/tpm0` or the resource manager (`/dev/tpmrm0`). It uses the `tss2` library and does not implement its own TPM command layer.

**What we trust:** The TPM hardware correctly enforces PCR policies and does not expose private key material.

---

## What TPM PCR sealing protects against

| Threat | Protection |
|--------|-----------|
| Credential blob stolen from disk | Blob is encrypted by the TPM SRK; useless without the same TPM. |
| Credential blob copied to another machine | PCR policy ties the blob to this specific TPM; other machines cannot load it. |
| Firmware/OS replaced after credential creation | PCR values change; the TPM refuses to unseal the key. |
| Cold-boot or offline attack against disk | No plaintext key material is ever written to disk. |

---

## What is explicitly out of scope

The following threats are **not** in scope for this project:

- **Remote attackers.** webauthn-proxy provides no network-facing surface. A remote attacker who has not already compromised the local machine cannot interact with the native host or TPM.
- **Compromised OS kernel.** A root-level attacker can tamper with the TPM resource manager, PAM modules, or the host binary itself. TPM PCR sealing deters offline attacks; it is not a substitute for OS integrity.
- **TPM firmware vulnerabilities.** We rely on the TPM vendor's firmware being correct. Known TPM vulnerabilities (e.g., TPM-FAIL, Infineon ROCA) are out of scope; users should apply firmware updates.
- **Compromised Chrome browser process.** If Chrome itself is backdoored, the `webAuthenticationProxy` interception can be subverted. Browser integrity is out of scope.
- **Side-channel attacks against the TPM.** Timing or power-analysis attacks against the TPM are academic-grade threats outside the deployment assumptions above.
- **Phishing / RP impersonation.** WebAuthn's origin-binding (the `rpId` check) is enforced by the browser, not by this proxy. We trust Chrome's origin enforcement.

---

## Residual risks

- A local attacker with the user's password (but not physical presence) can pass a password-based PAM challenge. Mitigate by configuring PAM to require a physical factor (fingerprint, hardware token).
- If PCR values are predictable or attacker-controlled (e.g., no Secure Boot), PCR sealing provides weaker guarantees. Mitigate by enabling Secure Boot and measuring the boot chain.
