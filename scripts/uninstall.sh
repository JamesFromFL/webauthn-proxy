#!/usr/bin/env bash
# uninstall.sh — Remove all MyKey Proxy components from the system.
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
systemctl stop mykey-proxy-daemon 2>/dev/null || true
systemctl disable mykey-proxy-daemon 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user stop mykey-proxy-tray 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user disable mykey-proxy-tray 2>/dev/null || true

echo "==> Removing binaries..."
rm -f /usr/local/bin/mykey-proxy-host
rm -f /usr/local/bin/mykey-proxy-daemon
rm -f /usr/local/bin/mykey-proxy-tray

echo "==> Removing systemd units..."
rm -f /etc/systemd/system/mykey-proxy-daemon.service
rm -f "${REAL_USER_HOME}/.config/systemd/user/mykey-proxy-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/default.target.wants/mykey-proxy-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/graphical-session.target.wants/mykey-proxy-tray.service"
systemctl daemon-reload

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user daemon-reload 2>/dev/null || true

echo "==> Removing D-Bus policy..."
rm -f /etc/dbus-1/system.d/com.mykeyproxy.Daemon.conf

echo "==> Removing sudoers rule..."
rm -f /etc/sudoers.d/mykey-proxy

echo "==> Removing polkit policy..."
rm -f /usr/share/polkit-1/actions/com.mykeyproxy.authenticate.policy

echo "==> Removing native messaging manifests..."
rm -f /etc/opt/chrome/native-messaging-hosts/com.mykeyproxy.host.json
rm -f /etc/chromium/native-messaging-hosts/com.mykeyproxy.host.json

echo "==> Removing config directory..."
rm -rf /etc/mykey-proxy/

echo "==> Removing system user..."
userdel mykey-proxy 2>/dev/null || true

echo ""
echo "============================================================"
echo " MyKey Proxy has been uninstalled."
echo " Build artifacts in the source tree are untouched."
echo " To remove those: cargo clean in native-host/, daemon/, systray/"
echo "============================================================"
