#!/usr/bin/env bash
# uninstall.sh — Remove all WebAuthn Proxy components from the system.
# Run as root: sudo ./scripts/uninstall.sh

set -euo pipefail

die() { echo "FATAL: $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "This script must be run as root (sudo ./scripts/uninstall.sh)"

# Detect the real user
if [[ -n "${SUDO_USER}" ]]; then
    REAL_USER="${SUDO_USER}"
else
    REAL_USER="${USER}"
fi
REAL_USER_HOME=$(getent passwd "${REAL_USER}" | cut -d: -f6)
REAL_USER_ID=$(id -u "${REAL_USER}")
REAL_XDG_RUNTIME="/run/user/${REAL_USER_ID}"
REAL_DBUS="unix:path=${REAL_XDG_RUNTIME}/bus"

echo "==> Stopping services..."
systemctl stop webauthn-proxy-daemon 2>/dev/null || true
systemctl disable webauthn-proxy-daemon 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user stop webauthn-proxy-tray 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user disable webauthn-proxy-tray 2>/dev/null || true

echo "==> Removing binaries..."
rm -f /usr/local/bin/webauthn-proxy-host
rm -f /usr/local/bin/webauthn-proxy-daemon
rm -f /usr/local/bin/webauthn-proxy-tray

echo "==> Removing systemd units..."
rm -f /etc/systemd/system/webauthn-proxy-daemon.service
rm -f "${REAL_USER_HOME}/.config/systemd/user/webauthn-proxy-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/default.target.wants/webauthn-proxy-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/graphical-session.target.wants/webauthn-proxy-tray.service"
systemctl daemon-reload

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user daemon-reload 2>/dev/null || true

echo "==> Removing D-Bus policy..."
rm -f /etc/dbus-1/system.d/com.webauthnproxy.Daemon.conf

echo "==> Removing PAM config..."
rm -f /etc/pam.d/webauthn-proxy

echo "==> Removing native messaging manifests..."
rm -f /etc/opt/chrome/native-messaging-hosts/com.webauthnproxy.host.json
rm -f /etc/chromium/native-messaging-hosts/com.webauthnproxy.host.json

echo "==> Removing config directory..."
rm -rf /etc/webauthn-proxy/

echo "==> Removing system user..."
userdel webauthn-proxy 2>/dev/null || true

echo ""
echo "============================================================"
echo " WebAuthn Proxy has been uninstalled."
echo " Build artifacts in the source tree are untouched."
echo " To remove those: cargo clean in native-host/, daemon/, systray/"
echo "============================================================"
