#!/usr/bin/env bash
# uninstall.sh — MyKey full uninstaller
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "Do not run this script as root. Run as your normal user: ./scripts/uninstall.sh"
    exit 1
fi

die() { echo ""; echo "FATAL: $*" >&2; exit 1; }

echo "============================================================"
echo " MyKey Uninstaller"
echo "============================================================"
echo ""
echo "  This script requires sudo for system-level operations."
echo "  You may be prompted for your password once."
echo ""
sudo -v || die "sudo authentication failed — cannot continue"
# Keep sudo alive for the duration of the script
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
SUDO_KEEPALIVE_PID=$!
trap 'kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null' EXIT

echo ""
mykey-migrate --unenroll || die "mykey-migrate --unenroll failed — uninstallation aborted. Fix the error above and run ./scripts/uninstall.sh again."

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
sudo systemctl stop mykey-daemon 2>/dev/null || true
sudo systemctl disable mykey-daemon 2>/dev/null || true
sudo rm -f /etc/systemd/system/mykey-daemon.service
sudo systemctl daemon-reload

sudo rm -f /usr/local/bin/mykey-host
sudo rm -f /usr/local/bin/mykey-daemon
sudo rm -f /usr/local/bin/mykey-tray
sudo rm -f /usr/local/bin/mykey-secrets
sudo rm -f /usr/local/bin/mykey-migrate
sudo rm -f /usr/local/bin/mykey-pin
sudo rm -f /usr/lib/security/mykeypin.so
sudo rm -rf /etc/mykey/pin
sudo rm -f /etc/dbus-1/system.d/com.mykey.Daemon.conf
sudo rm -f /etc/dbus-1/session.d/org.freedesktop.secrets.conf
sudo rm -f /etc/sudoers.d/mykey
sudo rm -f /usr/share/polkit-1/actions/com.mykey.authenticate.policy
sudo rm -f /etc/opt/chrome/native-messaging-hosts/com.mykey.host.json
sudo rm -f /etc/chromium/native-messaging-hosts/com.mykey.host.json
sudo rm -rf /etc/mykey/
sudo userdel mykey 2>/dev/null || true

echo ""
echo "============================================================"
echo " MyKey has been uninstalled."
echo "============================================================"
