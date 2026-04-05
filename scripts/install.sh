#!/usr/bin/env bash
# install.sh — Build and install the WebAuthn Proxy native host and daemon.
#
# Run as root (or with sudo) after loading the Chrome extension.
# Usage: sudo ./scripts/install.sh
#
# After running this script, replace EXTENSION_ID_PLACEHOLDER in the
# installed host manifest with your real extension ID (see instructions
# printed at the end of this script).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_BINARY="webauthn-proxy-host"
DAEMON_BINARY="webauthn-proxy-daemon"
HOST_DEST="/usr/local/bin/${HOST_BINARY}"
DAEMON_DEST="/usr/local/bin/${DAEMON_BINARY}"
HOST_MANIFEST_SRC="${REPO_ROOT}/scripts/com.webauthnproxy.host.json"
SYSTEMD_UNIT_SRC="${REPO_ROOT}/scripts/webauthn-proxy-daemon.service"
TRAY_BINARY="webauthn-proxy-tray"
TRAY_DEST="/usr/local/bin/${TRAY_BINARY}"
TRAY_SERVICE_SRC="${REPO_ROOT}/scripts/webauthn-proxy-tray.service"
TRAY_SERVICE_DEST="${HOME}/.config/systemd/user/webauthn-proxy-tray.service"
WEBAUTHN_DIR="/etc/webauthn-proxy"
CREDENTIAL_DIR="${WEBAUTHN_DIR}/credentials"
KEY_DIR="${WEBAUTHN_DIR}/keys"
TRUSTED_HASHES="${WEBAUTHN_DIR}/trusted-binaries.json"
BOOTSTRAP_KEY="${WEBAUTHN_DIR}/bootstrap.key"
PAM_SERVICE="/etc/pam.d/webauthn-proxy"
SYSTEMD_UNIT="/etc/systemd/system/webauthn-proxy-daemon.service"
DAEMON_USER="webauthn-proxy"

# Chrome and Chromium native messaging host directories (system-wide)
CHROME_NMH_DIR="/etc/opt/chrome/native-messaging-hosts"
CHROMIUM_NMH_DIR="/etc/chromium/native-messaging-hosts"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
die() { echo "FATAL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Cargo detection — sudo resets PATH and loses the rustup shim
# ---------------------------------------------------------------------------
find_cargo() {
    if [[ -n "${SUDO_USER}" ]]; then
        local user_home
        user_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
        for candidate in \
            "${user_home}/.cargo/bin/cargo" \
            "${user_home}/.rustup/toolchains/"*/bin/cargo
        do
            if [[ -x "${candidate}" ]]; then
                echo "${candidate}"
                return 0
            fi
        done
    fi

    for home in /home/*/; do
        for candidate in \
            "${home}.cargo/bin/cargo" \
            "${home}.rustup/toolchains/"*/bin/cargo
        do
            if [[ -x "${candidate}" ]]; then
                echo "${candidate}"
                return 0
            fi
        done
    done

    for candidate in /usr/local/bin/cargo /usr/bin/cargo; do
        if [[ -x "${candidate}" ]]; then
            echo "${candidate}"
            return 0
        fi
    done

    return 1
}

CARGO="$(find_cargo)" || die "cargo not found. Install Rust from rustup.rs then re-run this script."
export PATH="$(dirname "${CARGO}"):${PATH}"
echo "    Using cargo: ${CARGO}"

# Resolve the real invoking user early — needed for builds and tray install
if [[ -n "${SUDO_USER}" ]]; then
    REAL_USER="${SUDO_USER}"
else
    REAL_USER="${USER}"
fi
REAL_USER_HOME=$(getent passwd "${REAL_USER}" | cut -d: -f6)

# ---------------------------------------------------------------------------
# 0. Preflight: Secure Boot + TPM2
# ---------------------------------------------------------------------------
echo "==> Checking hardware prerequisites..."

# Secure Boot
if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
    echo "    Secure Boot: enabled ✓"
else
    echo "    WARNING: Secure Boot does not appear to be enabled."
    echo "             TPM2 PCR binding provides weaker guarantees without Secure Boot."
    echo "             Continuing — set ProtectKernelModules=yes in the service unit"
    echo "             to limit exposure."
fi

# TPM2
if [[ -c /dev/tpm0 && -c /dev/tpmrm0 ]]; then
    echo "    TPM2: present ✓"
else
    echo "    WARNING: /dev/tpm0 or /dev/tpmrm0 not found."
    echo "             The software fallback (plaintext keys on disk) will be used."
    echo "             Do NOT use in production without a TPM2 chip."
fi

# ---------------------------------------------------------------------------
# 1. Create dedicated system user
# ---------------------------------------------------------------------------
echo "==> Ensuring system user '${DAEMON_USER}' exists..."
if id "${DAEMON_USER}" &>/dev/null; then
    echo "    User already exists."
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "${DAEMON_USER}"
    echo "    Created system user '${DAEMON_USER}'."
fi

# ---------------------------------------------------------------------------
# 2. Build native host
# ---------------------------------------------------------------------------
echo "==> Building ${HOST_BINARY} (release)..."
cd "${REPO_ROOT}/native-host"
sudo -u "${REAL_USER}" env PATH="$(dirname ${CARGO}):$PATH" HOME="${REAL_USER_HOME}" $CARGO build --release
echo "    Build complete."

# ---------------------------------------------------------------------------
# 3. Build daemon
# ---------------------------------------------------------------------------
echo "==> Building ${DAEMON_BINARY} (release)..."
cd "${REPO_ROOT}/daemon"
sudo -u "${REAL_USER}" env PATH="$(dirname ${CARGO}):$PATH" HOME="${REAL_USER_HOME}" $CARGO build --release
echo "    Build complete."

# ---------------------------------------------------------------------------
# 4. Install binaries
# ---------------------------------------------------------------------------
echo "==> Installing binaries..."
install -m 0755 "${REPO_ROOT}/native-host/target/release/${HOST_BINARY}"   "${HOST_DEST}"
install -m 0755 "${REPO_ROOT}/daemon/target/release/${DAEMON_BINARY}"       "${DAEMON_DEST}"
echo "    ${HOST_DEST}"
echo "    ${DAEMON_DEST}"

# ---------------------------------------------------------------------------
# 5. Create /etc/webauthn-proxy/ directory structure
# ---------------------------------------------------------------------------
echo "==> Creating ${WEBAUTHN_DIR}/ directories..."
install -d -m 0700 -o "${DAEMON_USER}" "${WEBAUTHN_DIR}"
install -d -m 0700 -o "${DAEMON_USER}" "${CREDENTIAL_DIR}"
install -d -m 0700 -o "${DAEMON_USER}" "${KEY_DIR}"
echo "    Directories ready."

# ---------------------------------------------------------------------------
# 6. Generate bootstrap key (if not already present)
# ---------------------------------------------------------------------------
if [[ ! -f "${BOOTSTRAP_KEY}" ]]; then
    echo "==> Generating bootstrap key at ${BOOTSTRAP_KEY}..."
    openssl rand -hex 32 > "${BOOTSTRAP_KEY}"
    chmod 0640 "${BOOTSTRAP_KEY}"
    chown "root:${DAEMON_USER}" "${BOOTSTRAP_KEY}"
    echo "    Bootstrap key generated."
else
    echo "    Bootstrap key already exists at ${BOOTSTRAP_KEY}, skipping."
fi

# ---------------------------------------------------------------------------
# 7. Hash both binaries and write trusted-binaries.json
# ---------------------------------------------------------------------------
echo "==> Writing trusted binary hashes to ${TRUSTED_HASHES}..."
HOST_HASH="$(sha256sum "${HOST_DEST}" | awk '{print $1}')"
DAEMON_HASH="$(sha256sum "${DAEMON_DEST}" | awk '{print $1}')"

cat > "${TRUSTED_HASHES}" <<EOF
[
  { "path": "${HOST_DEST}",   "sha256": "${HOST_HASH}" },
  { "path": "${DAEMON_DEST}", "sha256": "${DAEMON_HASH}" }
]
EOF
chmod 0644 "${TRUSTED_HASHES}"
echo "    native-host:  ${HOST_HASH}"
echo "    daemon:       ${DAEMON_HASH}"

# ---------------------------------------------------------------------------
# 8. Install PAM service configuration
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
# 9. Install D-Bus system policy
# ---------------------------------------------------------------------------
echo "==> Installing D-Bus system policy..."
install -m 0644 "${REPO_ROOT}/scripts/com.webauthnproxy.Daemon.conf" \
    "/etc/dbus-1/system.d/com.webauthnproxy.Daemon.conf"
echo "    D-Bus policy installed."

# ---------------------------------------------------------------------------
# 10. Install native messaging host manifest
# ---------------------------------------------------------------------------
install_manifest() {
    local dest_dir="$1"
    mkdir -p "${dest_dir}"
    install -m 0644 "${HOST_MANIFEST_SRC}" "${dest_dir}/com.webauthnproxy.host.json"
    echo "    Manifest installed to ${dest_dir}/"
}

echo "==> Installing native messaging host manifests..."
install_manifest "${CHROME_NMH_DIR}"
install_manifest "${CHROMIUM_NMH_DIR}"

# ---------------------------------------------------------------------------
# 10. Install and enable systemd service
# ---------------------------------------------------------------------------
echo "==> Installing systemd service unit..."
install -m 0644 "${SYSTEMD_UNIT_SRC}" "${SYSTEMD_UNIT}"
systemctl daemon-reload
systemctl enable webauthn-proxy-daemon
echo "    Service enabled. Start with: systemctl start webauthn-proxy-daemon"

# ---------------------------------------------------------------------------
# 11. Build and install system tray
# ---------------------------------------------------------------------------
echo "==> Building ${TRAY_BINARY} (release)..."
cd "${REPO_ROOT}/systray"
sudo -u "${REAL_USER}" env PATH="$(dirname ${CARGO}):$PATH" HOME="${REAL_USER_HOME}" $CARGO build --release
echo "    Build complete."

install -m 0755 "${REPO_ROOT}/systray/target/release/${TRAY_BINARY}" "${TRAY_DEST}"
echo "    ${TRAY_DEST}"

# ------------------------------------------------------------
# Install tray user service as the invoking user, not root
# ------------------------------------------------------------
echo "==> Installing tray user service..."

REAL_USER_ID=$(id -u "${REAL_USER}")
REAL_XDG_RUNTIME="/run/user/${REAL_USER_ID}"
REAL_DBUS="unix:path=${REAL_XDG_RUNTIME}/bus"
SYSTEMD_USER_DIR="${REAL_USER_HOME}/.config/systemd/user"

# Create the user systemd directory owned by the real user
mkdir -p "${SYSTEMD_USER_DIR}"
chown "${REAL_USER}:${REAL_USER}" "${SYSTEMD_USER_DIR}"

# Install the service file
cp "${REPO_ROOT}/scripts/webauthn-proxy-tray.service" "${SYSTEMD_USER_DIR}/webauthn-proxy-tray.service"
chmod 0644 "${SYSTEMD_USER_DIR}/webauthn-proxy-tray.service"
chown "${REAL_USER}:${REAL_USER}" "${SYSTEMD_USER_DIR}/webauthn-proxy-tray.service"

# Run systemctl --user as the real user with correct environment
sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user daemon-reload

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user enable webauthn-proxy-tray

# Symlink fallback to guarantee enable persists
AUTOSTART_DIR="${SYSTEMD_USER_DIR}/default.target.wants"
mkdir -p "${AUTOSTART_DIR}"
chown "${REAL_USER}:${REAL_USER}" "${AUTOSTART_DIR}"
ln -sf "${SYSTEMD_USER_DIR}/webauthn-proxy-tray.service" \
       "${AUTOSTART_DIR}/webauthn-proxy-tray.service"
chown -h "${REAL_USER}:${REAL_USER}" "${AUTOSTART_DIR}/webauthn-proxy-tray.service"

echo "    Tray service installed and enabled for user '${REAL_USER}'"
echo "    Start with: systemctl --user start webauthn-proxy-tray"

# ---------------------------------------------------------------------------
# 12. Instructions: set real extension ID
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

4. Start the daemon:  systemctl start webauthn-proxy-daemon

5. Reload the extension (click the refresh icon on chrome://extensions/).

Logs:
  Daemon:      journalctl -u webauthn-proxy-daemon  (or /tmp/webauthn-proxy-daemon.log)
  Native host: /tmp/webauthn-proxy-host.log

============================================================
INSTRUCTIONS
