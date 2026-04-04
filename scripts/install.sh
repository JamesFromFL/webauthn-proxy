#!/usr/bin/env bash
# install.sh — Build and install the WebAuthn Proxy native messaging host.
#
# Run as root (or with sudo) after loading the Chrome extension.
# Usage: sudo ./scripts/install.sh
#
# After running this script, replace EXTENSION_ID_PLACEHOLDER in the
# installed host manifest with your real extension ID (see instructions
# printed at the end of this script).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_NAME="webauthn-proxy-host"
BINARY_DEST="/usr/local/bin/${BINARY_NAME}"
HOST_MANIFEST_SRC="${REPO_ROOT}/scripts/com.webauthnproxy.host.json"
CREDENTIAL_DIR="/etc/webauthn-proxy/credentials"
KEY_DIR="/etc/webauthn-proxy/keys"
PAM_SERVICE="/etc/pam.d/webauthn-proxy"

# Chrome and Chromium native messaging host directories (system-wide)
CHROME_NMH_DIR="/etc/opt/chrome/native-messaging-hosts"
CHROMIUM_NMH_DIR="/etc/chromium/native-messaging-hosts"

# Per-user fallback (uncomment if you prefer user-level installation)
# CHROME_NMH_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts"
# CHROMIUM_NMH_DIR="${HOME}/.config/chromium/NativeMessagingHosts"

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
echo "==> Building ${BINARY_NAME} (release)..."
cd "${REPO_ROOT}/native-host"
cargo build --release
echo "    Build complete."

# ---------------------------------------------------------------------------
# 2. Install binary
# ---------------------------------------------------------------------------
echo "==> Installing binary to ${BINARY_DEST}..."
install -m 0755 "target/release/${BINARY_NAME}" "${BINARY_DEST}"
echo "    Installed."

# ---------------------------------------------------------------------------
# 3. Create credential and key directories
# ---------------------------------------------------------------------------
echo "==> Creating /etc/webauthn-proxy/ directories..."
install -d -m 0700 "${CREDENTIAL_DIR}"
install -d -m 0700 "${KEY_DIR}"
echo "    Directories ready."

# ---------------------------------------------------------------------------
# 4. Install PAM service configuration
# ---------------------------------------------------------------------------
if [[ ! -f "${PAM_SERVICE}" ]]; then
    echo "==> Installing PAM service config at ${PAM_SERVICE}..."
    cat > "${PAM_SERVICE}" <<'EOF'
# /etc/pam.d/webauthn-proxy
# PAM configuration for the WebAuthn Proxy user-presence check.
# Requires the logged-in user to authenticate before every WebAuthn operation.
#
# To use a hardware token (e.g. YubiKey via pam_u2f), replace the line below:
#   auth  required  pam_u2f.so
# To use fingerprint (fprintd), replace with:
#   auth  required  pam_fprintd.so

auth     required  pam_unix.so
account  required  pam_unix.so
EOF
    echo "    PAM service installed."
else
    echo "    PAM service already exists at ${PAM_SERVICE}, skipping."
fi

# ---------------------------------------------------------------------------
# 5. Install native messaging host manifest
# ---------------------------------------------------------------------------
install_manifest() {
    local dest_dir="$1"
    if [[ -d "${dest_dir}" || mkdir -p "${dest_dir}" ]]; then
        install -m 0644 "${HOST_MANIFEST_SRC}" "${dest_dir}/com.webauthnproxy.host.json"
        echo "    Manifest installed to ${dest_dir}/"
    fi
}

echo "==> Installing native messaging host manifests..."
mkdir -p "${CHROME_NMH_DIR}"    && install_manifest "${CHROME_NMH_DIR}"
mkdir -p "${CHROMIUM_NMH_DIR}"  && install_manifest "${CHROMIUM_NMH_DIR}"

# ---------------------------------------------------------------------------
# 6. Instructions: set real extension ID
# ---------------------------------------------------------------------------
cat <<'INSTRUCTIONS'

============================================================
 ACTION REQUIRED — Set your extension ID
============================================================

1. Load the extension in Chrome:
     chrome://extensions/ → Enable "Developer mode" → "Load unpacked"
     Select the extension/ directory in this repository.

2. Copy the Extension ID shown on the extensions page
   (a 32-character string like: abcdefghijklmnopabcdefghijklmnop)

3. Replace the placeholder in the installed host manifests:

     EXTENSION_ID="<paste your ID here>"

     for f in \
       /etc/opt/chrome/native-messaging-hosts/com.webauthnproxy.host.json \
       /etc/chromium/native-messaging-hosts/com.webauthnproxy.host.json; do
       [[ -f "$f" ]] && sudo sed -i \
         "s|EXTENSION_ID_PLACEHOLDER|${EXTENSION_ID}|g" "$f"
     done

4. Reload the extension (click the refresh icon on chrome://extensions/).

The host will log to /tmp/webauthn-proxy-host.log — check there if the
extension cannot connect.

============================================================
INSTRUCTIONS
