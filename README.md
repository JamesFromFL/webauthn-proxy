# WebAuthn Proxy
![WebAuthn Proxy](assets/AuthnProxyLogoStylized.png)

Linux has no built-in way to satisfy modern browser security checks that Windows and Mac handle automatically. This project fills that gap — it lets Chrome on Linux use your system's built-in security hardware to handle authentication requests that would otherwise just fail.

## How It Works

When a website or browser extension asks for secure authentication, the proxy intercepts that request before it fails. It passes the request to a background service running on your machine. That service verifies you are physically present using your Linux login credentials, then uses your machine's security chip to cryptographically sign the response. The approval goes back to the browser — no passwords sent over the network, everything stays on your machine.

## System Requirements

- Linux (any major distribution with systemd)
- Chrome or Chromium browser
- TPM 2.0 chip — required. Most computers made after 2016 have one. Check with: `cat /sys/class/tpm/tpm0/tpm_version_major`
- Secure Boot enabled in your BIOS/UEFI settings
- Rust toolchain — install from [rustup.rs](https://rustup.rs)
- tpm2-tools — install via your package manager (`pacman -S tpm2-tools` / `apt install tpm2-tools`)
- PAM development libraries — `libpam0g-dev` (Debian/Ubuntu) or `pam` (Arch)
- D-Bus — included in all major Linux distributions by default
- systemd — required for the background service

## What's Inside

- **Browser Extension** — watches for authentication requests in Chrome and routes them into the proxy instead of letting them fail
- **Native Host** — the bridge between the browser and your system, translates browser messages into system calls
- **Daemon** — the always-running background service that handles the actual security work: verifying you, protecting your keys, and signing responses
- **System Tray** — a status indicator that shows the proxy is running and visible from your desktop
- **Installer** — one script that builds everything, installs all components, handles Secure Boot and TPM checks, walks you through loading the extension, and runs a full health check automatically

## Disclaimer

This project was built by a cybersecurity student as a learning exercise in platform security and authentication. It was born out of a personal need — Linux had no working solution for a problem I ran into daily, so I built one.

This project is in early development. The code has not been audited.

Installation and daily use is not recommended at this stage. If you choose to install and use this software, you do so entirely at your own risk.

I do not guarantee the safety, security, or integrity of any platform keys, credentials, or authentication operations performed by this software. Platform key security is serious — treat it accordingly.

Parts of this project were developed with the assistance of AI tools including Claude by Anthropic. All architectural decisions, security design, and final implementation were reviewed and directed by a human. AI-assisted code should always be treated with the same scrutiny as any other untrusted code — read it, understand it, and verify it before running it on your system.

If you find a security issue please open a GitHub issue or contact me directly before disclosing publicly.

## Project Roadmap

### Complete
- ✅ WebAuthn request interception and proxy via Chrome MV3 extension
- ✅ Native host, daemon, and system tray — full five-layer architecture
- ✅ AES-256-GCM encrypted IPC with HMAC signing and replay protection
- ✅ TPM2 hardware key sealing with PCR 0+7 policy binding
- ✅ Polkit desktop authentication with brute-force cooldown protection
- ✅ Process ancestry verification and binary integrity checks
- ✅ Hardened systemd service, guided installer, and uninstall script

### In Progress
- ⏳ Hard Secure Boot enforcement at daemon startup

### To Do
- 🔵 Fingerprint (fprintd) and face recognition (Howdy) as polkit factors
- 🔵 GTK4 Credential Manager (`webauthn-proxy-manager`)
  - Credentials: key name, created date/time, type, application, nickname
  - Secure Folder: TPM-encrypted, all-or-nothing, password-locked
  - Biometrics: manage Howdy and fprintd enrollments with nicknames
  - Mobile Bridge: placeholder — planned feature
- 🔵 AUR package + Chrome Web Store submission
- 🔵 Firefox extension support

### Planned — 
- 🔵 Mobile Bridge
  - Pair phone via QR code, approve requests via Face ID/fingerprint/PIN
  - Local network with encrypted relay fallback
  - iOS and Android

## Installation

1. Clone the repo: `git clone https://github.com/JamesFromFL/webauthn-proxy`
2. Run the installer: `sudo ./scripts/install.sh`
3. Follow the on-screen prompts — the installer handles building, installing, Secure Boot checks, TPM verification, extension loading, and a final health check automatically.

## Logs and Troubleshooting

- Daemon logs: `journalctl -u webauthn-proxy-daemon -f`
- Native host logs: `/tmp/webauthn-proxy-host.log`
- Extension logs: Chrome DevTools on the background service worker at `chrome://extensions/`
- Tray logs: `journalctl --user -u webauthn-proxy-tray -f`

## Testing

Open [https://webauthn.io](https://webauthn.io), enter a username, click Register, and follow the prompts. You should be asked for your Linux password or PIN. Complete registration then test Sign In to confirm the full flow works.

NordPass compatibility: Toggle biometric unlock in NordPass settings. The polkit authentication dialog will appear. Enter your Linux password. NordPass biometrics will activate successfully. Verified working with NordPass v7.5.7.

## License

MIT — JamesFromFL, 2026
