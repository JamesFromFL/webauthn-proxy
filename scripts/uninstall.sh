#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " MyKey Uninstaller"
echo "============================================================"
echo ""

mykey-migrate --unenroll || {
    echo ""
    echo "FATAL: mykey-migrate --unenroll failed — uninstallation aborted." >&2
    echo "       Fix the error above and run ./scripts/uninstall.sh again." >&2
    exit 1
}

echo "==> Removing user services..."
systemctl --user stop mykey-tray 2>/dev/null || true
systemctl --user disable mykey-tray 2>/dev/null || true
rm -f "${HOME}/.config/systemd/user/mykey-secrets.service"
rm -f "${HOME}/.config/systemd/user/default.target.wants/mykey-secrets.service"
rm -f "${HOME}/.config/systemd/user/mykey-tray.service"
rm -f "${HOME}/.config/systemd/user/default.target.wants/mykey-tray.service"
rm -f "${HOME}/.config/systemd/user/graphical-session.target.wants/mykey-tray.service"
systemctl --user daemon-reload 2>/dev/null || true

echo "==> Removing system components..."
pkexec bash -c "
    systemctl stop mykey-daemon 2>/dev/null || true
    systemctl disable mykey-daemon 2>/dev/null || true
    rm -f /etc/systemd/system/mykey-daemon.service
    systemctl daemon-reload
    rm -f /usr/local/bin/mykey-host
    rm -f /usr/local/bin/mykey-daemon
    rm -f /usr/local/bin/mykey-tray
    rm -f /usr/local/bin/mykey-secrets
    rm -f /usr/local/bin/mykey-migrate
    rm -f /etc/dbus-1/system.d/com.mykey.Daemon.conf
    rm -f /etc/dbus-1/session.d/org.freedesktop.secrets.conf
    rm -f /etc/sudoers.d/mykey
    rm -f /usr/share/polkit-1/actions/com.mykey.authenticate.policy
    rm -f /etc/opt/chrome/native-messaging-hosts/com.mykey.host.json
    rm -f /etc/chromium/native-messaging-hosts/com.mykey.host.json
    rm -rf /etc/mykey/
    userdel mykey 2>/dev/null || true
"

echo ""
echo "============================================================"
echo " MyKey has been uninstalled."
echo "============================================================"

