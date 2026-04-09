# MyKey
![MyKey](assets/mykey-logo-stylized-medium.png)

MyKey is a hardware-backed authentication and secret management platform for Linux.

Built on TPM2, Secure Boot, and native Linux security components, MyKey brings together passwordless authentication, encrypted secret storage, biometrics, and browser integration into a single, simple experience.

**Secure by design. Simple by default. Built for Linux.**

---

## ✨ Features

- 🔐 TPM2-backed credential storage  
- 🧠 Encrypted secret management  
- 🗝️ Secret Service API provider (replacement for KWallet / gnome-keyring)  
- 👆 Biometric authentication (fingerprint / face unlock)  
- 🌐 WebAuthn support for Chromium and Firefox  
- 📁 Secure file storage (encrypted folders)  
- 🛡️ Guided Secure Boot setup  

---

## 🧩 Components

MyKey is made up of several components that work together:

- ⚙️ **Daemon (mykey-daemon)**  
  Core background service handling authentication, TPM interaction, and security logic  

- 🎛️ **GUI Manager (mykey-manager)**  
  Desktop app for managing credentials, secrets, biometrics, and system security  

- 🖥️ **System Tray (mykey-tray)**  
  System tray interface for status and quick actions  

- 🗝️ **Secret Service API (mykey-secrets)**  
  Secret Service API provider — a hardware-backed, desktop-agnostic replacement for KWallet and gnome-keyring  

- 🔌 **Native Host (mykey-host)**  
  Native messaging bridge between the browser and the system  

- 🌐 **Browser Extension (mykey-proxy)**  
  Browser extension that enables WebAuthn authentication on Linux  

- 📦 **Distribution**  
  Planned for AUR (Arch Linux) with potential Flatpak support later  

---

## 🤔 Why MyKey?

Linux has powerful security tools — but they’re often fragmented, inconsistent, or difficult to use.

MyKey brings them together into one system:

- No passwords to remember  
- No juggling multiple tools  
- No guessing how your system is secured  

Just fast, secure authentication and encrypted storage — built directly on your system.

> Windows Hello–style authentication for Linux, built on open standards and real hardware security.

---

## ⚙️ How It Works

When authentication or secure data access is needed, MyKey handles everything locally:

1. 👆 **You verify your identity**  
   Using biometrics or your system credentials  

2. 🔐 **Your system validates securely**  
   TPM2 ensures keys never leave your machine  

3. ✅ **Access is granted safely**  
   Whether it's logging in, unlocking data, or approving a request  

Everything happens on your machine:
- No cloud dependency  
- No passwords sent over the network  
- No hidden background services  

**One system. One identity. Fully under your control.**

---

## 🖥️ Supported Platform

MyKey is designed for a **specific, security-focused Linux environment**.

### 🔐 Required Hardware

- TPM 2.0  
- UEFI firmware  
- Secure Boot enabled  

### ⚙️ Required System Stack

- systemd  
- systemd-boot  
- sbctl  
- UKI (Unified Kernel Image)  
- PAM  
- D-Bus  
- polkit  
- `/boot/EFI/` partition layout  

> ⚠️ MyKey relies on TPM PCR measurements tied to your boot process.  
> To guarantee security, the boot chain must be predictable and verifiable.  
> Unsupported configurations will cause sealed credentials to fail to unlock.

---

## ⚠️ Disclaimer

MyKey is an experimental project developed as part of a cybersecurity learning project.

This project:
- has **not been formally audited**
- is **still in active development**
- is **not recommended for production use**

Use at your own risk.

Hardware-backed authentication is serious — review and understand the system before relying on it.

Parts of this project were developed with the assistance of AI tools.  
All design decisions and implementations were reviewed and directed by a human.

If you discover a security issue, please report it responsibly.

---

## 🗺️ Project Roadmap

### ✅ Complete

- WebAuthn authentication via Chromium extension (`mykey-proxy`)  
- Native host (`mykey-host`), daemon (`mykey-daemon`), and system tray (`mykey-tray`) architecture  
- Encrypted IPC (AES-256-GCM + HMAC + replay protection)  
- TPM2 key sealing with PCR 0+7 binding
- Polkit authentication with brute-force protection  
- Process verification and binary integrity checks  
- Hardened systemd service  
- Secure Boot validation at startup  

---

### 🚧 In Progress

- GTK4 Desktop Manager (`mykey-manager`)  
- Secret Service API (`mykey-secrets`)  

---

### 📦 Planned (Near Term)

- Firefox extension support (`mykey-proxy`)  
- Chrome Web Store & Firefox Add-ons submission  
- AUR package  

---

### 🚀 Future

- PAM PIN module (`mykeypin.so`)
- Flatpak distribution  
- Mobile companion app  

---

## 📥 Installation

```bash
git clone https://github.com/JamesFromFL/mykey-proxy
cd mykey-proxy
./scripts/install.sh
```
Follow the on-screen prompts — the installer handles:

- TPM checks
- Secure Boot validation
- extension setup
- system configuration

> ⚠️ Installation is under active development and may change.

---

## 🗑️ Uninstall

```bash
git clone https://github.com/JamesFromFL/mykey-proxy
cd mykey-proxy
sudo ./scripts/uninstall.sh
```
> Removes all installed MyKey components from the system.

---

## 🧪 Testing

Current testing focuses on WebAuthn functionality via the browser extension.

### WebAuthn
- Visit https://webauthn.io
- Register a credential
- Authenticate using your Linux credentials

### Compatibility
- NordPass (v7.5.7) — biometric unlock confirmed working via polkit

> ⚠️ Testing is currently limited and will expand over time.

---

## 📜 License

MIT — JamesFromFL, 2026
