#!/usr/bin/env bash
# uninstall.sh — Remove all MyKey components from the system.
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

# ── Reverse migration (must succeed before anything is removed) ──
if [[ -f "/etc/mykey/provider/info.json" ]]; then
    echo "==> Secret Service provider detected — running unenroll..."
    if ! /usr/local/bin/mykey-migrate --unenroll; then
        echo ""
        echo "ERROR: Unenroll failed. Uninstall has been halted."
        echo "Your secrets are safe. Fix the error above and try again."
        echo "Run: mykey-migrate --unenroll"
        exit 1
    fi
    echo "✓ Unenroll complete."
fi

echo "==> Stopping services..."
sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user stop mykey-secrets 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user disable mykey-secrets 2>/dev/null || true

systemctl stop mykey-daemon 2>/dev/null || true
systemctl disable mykey-daemon 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user stop mykey-tray 2>/dev/null || true

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user disable mykey-tray 2>/dev/null || true

echo "==> Removing binaries..."
rm -f /usr/local/bin/mykey-host
rm -f /usr/local/bin/mykey-daemon
rm -f /usr/local/bin/mykey-tray
rm -f /usr/local/bin/mykey-secrets

echo "==> Removing systemd units..."
rm -f /etc/systemd/system/mykey-daemon.service
rm -f "${REAL_USER_HOME}/.config/systemd/user/mykey-secrets.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/default.target.wants/mykey-secrets.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/mykey-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/default.target.wants/mykey-tray.service"
rm -f "${REAL_USER_HOME}/.config/systemd/user/graphical-session.target.wants/mykey-tray.service"
systemctl daemon-reload

sudo -u "${REAL_USER}" \
    XDG_RUNTIME_DIR="${REAL_XDG_RUNTIME}" \
    DBUS_SESSION_BUS_ADDRESS="${REAL_DBUS}" \
    systemctl --user daemon-reload 2>/dev/null || true

echo "==> Removing D-Bus policy..."
rm -f /etc/dbus-1/system.d/com.mykey.Daemon.conf
rm -f /etc/dbus-1/session.d/org.freedesktop.secrets.conf

echo "==> Removing sudoers rule..."
rm -f /etc/sudoers.d/mykey

echo "==> Removing polkit policy..."
rm -f /usr/share/polkit-1/actions/com.mykey.authenticate.policy

echo "==> Removing native messaging manifests..."
rm -f /etc/opt/chrome/native-messaging-hosts/com.mykey.host.json
rm -f /etc/chromium/native-messaging-hosts/com.mykey.host.json

echo "==> Removing config directory..."
rm -rf /etc/mykey/

echo "==> Removing system user..."
userdel mykey 2>/dev/null || true

echo ""
echo "============================================================"
echo " MyKey has been uninstalled."
echo " Build artifacts in the source tree are untouched."
echo " To remove those: cargo clean in mykey-host/, mykey-daemon/, mykey-tray/"
echo "============================================================"
