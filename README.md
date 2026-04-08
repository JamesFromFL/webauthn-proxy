# MyKey Proxy
![MyKey Proxy](assets/AuthnProxyLogoStylized.png)

Designed around open standards and native Linux security components, MyKey Proxy enables secure, passwordless authentication across your system, browser, and applications.

**Secure by design. Simple by default. Built for Linux.**

## Features

- 🔐 TPM2-backed credential storage  
- 👆 Biometric authentication (fingerprint / face unlock)  
- 🧠 Encrypted secret management  
- 🌐 WebAuthn platform authenticator for Chromium and Firefox  
- 📁 Secure file management with encrypted storage  
- 🛡️ Simplified Secure Boot setup  

## Why MyKey Proxy?

Linux has powerful security primitives—but they’re often fragmented and difficult to use.

MyKey Proxy unifies them into a single, user-friendly experience:
- No passwords to remember  
- No scattered authentication tools  
- Just fast, secure access to your system and services

> Windows Hello–style authentication for Linux, built on TPM, biometrics, and open standards.

## How It Works

MyKey Proxy acts as a unified authentication layer for Linux, bridging hardware security, biometrics, and system services into a single, seamless experience.

When authentication is required—whether unlocking your system, accessing encrypted data, or approving a login—MyKey Proxy coordinates the process through a local background service:

1. **User Presence Verification**  
   You confirm your identity using biometrics (fingerprint/face) or your system credentials.
2. **Hardware-Backed Validation**  
   The request is securely processed using TPM2-backed keys, ensuring credentials never leave your machine.
3. **Secure Authorization**  
   The system signs or unlocks the requested resource (application, browser, or service) without exposing sensitive data.

All operations happen locally, leveraging Linux-native security components—no passwords transmitted, no external dependency on cloud authentication.

**One system. One identity. Fully under your control.**

## System Requirements

MyKey Proxy requires a modern Linux system with hardware-backed security features enabled.

### Required

- 🧩 Linux system with `systemd`, `D-Bus`, `PAM`, and `polkit`
- 🔐 TPM 2.0 enabled and accessible  
- 🛡️ Secure Boot enabled  
- 🌐 Chromium or Firefox-based browser  

> ⚠️ Systems without TPM 2.0 and Secure Boot are not supported.

## What's Inside

MyKey Proxy is composed of several components that work together to provide a seamless authentication experience on Linux:

- 🌐 **Browser Extension**  
  Integrates with Chromium and Firefox-based browsers to route authentication requests into MyKey Proxy.
- 🔌 **Native Host**  
  Acts as the bridge between the browser and the local system, translating authentication requests into secure system calls.
- ⚙️ **Daemon**  
  A background service responsible for authentication logic, TPM interactions, credential protection, and cryptographic operations.
- 🖥️ **System Tray**  
  Provides a lightweight interface for status, quick actions, and visibility into the running service.
- 🎛️ **GUI Manager (mykey-proxy-manager)** 
  A full desktop interface for managing credentials, biometrics, secure storage, and system security configuration.
- 📦 **Distribution**  
  Planned for AUR (Arch Linux) with potential future support for Flatpak and broader distributions.

## Disclaimer

MyKey Proxy was developed as a learning project by a cybersecurity student, focused on exploring platform security and authentication on Linux. It originated from a real-world problem that lacked a viable solution on the Linux desktop.

This project is in early development and has not undergone a formal security audit.

⚠️ **Do not rely on this software for production use.**  
Installation and daily use are not recommended at this stage. If you choose to use this software, you do so entirely at your own risk.

No guarantees are made regarding the safety, security, or integrity of credentials, platform keys, or authentication operations performed by this software. Hardware-backed authentication is a sensitive domain—evaluate and use accordingly.

Parts of this project were developed with the assistance of AI tools, including Claude by Anthropic. All architectural decisions and final implementations were reviewed and directed by a human. As with any security-sensitive software, you should review and understand the code before running it on your system.

If you discover a security vulnerability, please open a GitHub issue or contact me directly before disclosing it publicly.

## Project Roadmap

### ✅ Complete

- WebAuthn request interception via Chromium extension  
- Native host, daemon, and system tray (full multi-component architecture)  
- AES-256-GCM encrypted IPC with HMAC signing and replay protection  
- TPM2 hardware key sealing with PCR 0+7 policy binding  
- Polkit-based desktop authentication with brute-force cooldown protection  
- Process ancestry verification and binary integrity checks  
- Hardened systemd service 
- Secure Boot enforcement at daemon startup  

---

### 🚧 In Progress

- GTK4 Desktop Manager (`mykey-proxy-manager`)  

---

### 📦 Planned (Near Term)

- WebAuthn request interception via Firefox extension  
- Chrome Web Store and Firefox Add-ons submission  
- AUR package distribution  

---

### 🚀 Future

- Flatpak packaging  
- PAM module for PIN-based authentication (`mykeypin.so`)
- Mobile companion app (iOS & Android)  

## Installation

1. Clone the repository:  
   `git clone https://github.com/JamesFromFL/mykey-proxy`
2. Run the installer:  
   `./mykey-proxy/scripts/install.sh`
3. Follow the on-screen prompts — the installer handles building, installing, Secure Boot checks, TPM verification, extension setup, and a final health check automatically.

> ⚠️ Installation is under active development and may change in future releases.

## Logs and Troubleshooting

- Daemon logs: `journalctl -u mykey-proxy-daemon -f`
- Native host logs: `/tmp/mykey-proxy-host.log`
- Extension logs: Chrome DevTools on the background service worker at `chrome://extensions/`
- Tray logs: `journalctl --user -u mykey-proxy-tray -f`

## Testing

Current testing has been performed on browser extension–based authentication flows:

### WebAuthn (Extension)

- Visit [https://webauthn.io](https://webauthn.io)  
- Enter a username and click **Register**  
- Complete the authentication prompt (Linux password or PIN via Polkit)  
- Verify successful registration and sign-in  

### Extension Compatibility

- **NordPass (v7.5.7)**  
  - Enable biometric unlock in NordPass extension settings  
  - Authentication is handled via a Polkit prompt  
  - Biometric unlock functions successfully after approval  

> ⚠️ Testing coverage is currently limited and focused on core functionality.  
> Additional validation and edge-case testing will be expanded in future releases.

## License

MIT — JamesFromFL, 2026
