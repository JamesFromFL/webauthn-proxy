# Claude Code — Project Instructions

## Project context

MyKey is a hardware-backed authentication and secret management platform for Linux. It provides WebAuthn platform authenticator support, TPM2-sealed credential storage, biometric management, encrypted secret storage via the Secret Service API, and a GTK4 credential manager — all backed by TPM2 and enforced Secure Boot.

MyKey is composed of the following components:

- **`mykey-proxy/chromium/`** — Chrome/Chromium browser extension (MV3, JavaScript)
- **`mykey-proxy/firefox/`** — Firefox extension (planned)
- **`mykey-host/`** — Native messaging host (Rust) bridging the browser to the daemon
- **`mykey-daemon/`** — Persistent D-Bus system service handling PAM, TPM2, and crypto
- **`mykey-tray/`** — System tray indicator (Rust, ksni)
- **`mykey-manager/`** — GTK4 credential management GUI (Rust)
- **`scripts/`** — Installer, uninstaller, systemd units, D-Bus policy, polkit policy
- **`assets/`** — Logos and icons
- **`docs/`** — Documentation (in progress)

---

## Coding conventions

### Rust components

These conventions apply to all four Rust crates: `mykey-host`, `mykey-daemon`, `mykey-tray`, and `mykey-manager`.

- Use the 2021 edition.
- Prefer `thiserror` for error types; avoid `Box<dyn Error>` in library code.
- Use `tss-esapi` (the Rust TSS2 ESAPI bindings) for all TPM2 operations.
- Use `pam` or `pam-sys` for PAM calls; do not shell out to `su` or `sudo`.
- Keep TPM and PAM logic in separate modules; the `main` message loop should only dispatch.
- All public functions must have doc comments.
- Run `cargo clippy -- -D warnings` before committing.

### Extension (JavaScript / Manifest V3)

Applies to `mykey-proxy/chromium/` (and `mykey-proxy/firefox/` when implemented).

- No build step unless genuinely required — keep it plain ES modules.
- Use the `webAuthenticationProxy` API exclusively; do not monkey-patch `navigator.credentials`.
- Keep `manifest.json` permissions minimal; request only what is used.
- No external npm dependencies without explicit discussion.

### General

- All new files get a comment header with a one-line description of the file's purpose.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, etc.).
- Branch names: `feat/<short-description>`, `fix/<short-description>`.

---

## Hard rules

- **Never commit secrets.** No tokens, passwords, private keys, or TPM handles. If a secret is accidentally staged, remove it and rotate it before pushing.
- **Never weaken PAM.** Do not add bypass paths, cached approvals, or fallback modes that skip the PAM challenge.
- **Never export key material.** TPM key blobs must stay sealed. Do not add debug modes that dump private keys.

---

## Architecture hygiene

- If you change where a layer boundary sits (e.g., move logic from the extension to the host, or add a new IPC surface), update **ARCHITECTURE.md** to reflect the new boundary.
- If you add a new threat surface or change an assumption, update **THREAT_MODEL.md**.
- Keep the five-layer model coherent: each layer should have one job.

---

## Testing

- All Rust components (`mykey-host`, `mykey-daemon`, `mykey-tray`, `mykey-manager`): use `cargo test` with integration tests that mock the PAM and TPM2 surfaces via trait objects — never call real PAM or TPM in CI.
- Extension: unit tests via a minimal test harness; no browser automation required for unit tests.
- A real end-to-end test (actual TPM + PAM) lives in `scripts/e2e-test.sh` and is only run manually on hardware.
