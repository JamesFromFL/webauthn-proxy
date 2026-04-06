# Claude Code — Project Instructions

## Project context

mykey-proxy is a local-first WebAuthn proxy for Linux. It intercepts browser passkey requests, enforces PAM user presence, and seals credential keys to the machine's TPM2 chip via PCR binding.

The repo has two main runtime components:

- **`extension/`** — A Chrome/Chromium browser extension (Manifest V3, JavaScript).
- **`native-host/`** — A native messaging host binary (Rust) that handles PAM and TPM2 operations.

Supporting directories:

- **`assets/`** — Project logos and static assets.
- **`docs/`** — Additional documentation beyond the top-level markdown files.
- **`scripts/`** — Install and setup shell scripts.

---

## Coding conventions

### Native host (Rust)

- Use the 2021 edition.
- Prefer `thiserror` for error types; avoid `Box<dyn Error>` in library code.
- Use `tss-esapi` (the Rust TSS2 ESAPI bindings) for all TPM2 operations.
- Use `pam` or `pam-sys` for PAM calls; do not shell out to `su` or `sudo`.
- Keep TPM and PAM logic in separate modules; the `main` message loop should only dispatch.
- All public functions must have doc comments.
- Run `cargo clippy -- -D warnings` before committing.

### Extension (JavaScript / Manifest V3)

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

- Native host: use `cargo test` with integration tests that mock the PAM and TPM2 surfaces via trait objects — never call real PAM or TPM in CI.
- Extension: unit tests via a minimal test harness; no browser automation required for unit tests.
- A real end-to-end test (actual TPM + PAM) lives in `scripts/e2e-test.sh` and is only run manually on hardware.
