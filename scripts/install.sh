#!/usr/bin/env bash
# install.sh — MyKey full installer
# Handles: Secure Boot setup, TPM verification, build, install, extension setup, health check
# Run as normal user: ./scripts/install.sh (will prompt for sudo when needed)

if [[ $EUID -eq 0 ]]; then
    echo "Do not run this script as root. Run as your normal user: ./scripts/install.sh"
    exit 1
fi

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────
PASS="✓"; FAIL="✗"; WARN="⚠"; INFO="→"
ok()    { echo "  ${PASS} $*"; }
fail()  { echo "  ${FAIL} $*" >&2; }
warn()  { echo "  ${WARN} $*"; }
info()  { echo "  ${INFO} $*"; }
die()   { echo ""; echo "FATAL: $*" >&2; exit 1; }
confirm() {
    local prompt="$1"
    local reply
    echo ""
    read -rp "  ${prompt} [y/N] " reply
    echo ""
    [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FAILED=0

# ── Cargo discovery ───────────────────────────────────────────────────────────
find_cargo() {
    local user_home
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    else
        user_home="${HOME}"
    fi
    for candidate in \
        "${user_home}/.cargo/bin/cargo" \
        "${user_home}/.rustup/toolchains/"*/bin/cargo
    do
        [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
    done
    for home in /home/*/; do
        for candidate in \
            "${home}.cargo/bin/cargo" \
            "${home}.rustup/toolchains/"*/bin/cargo
        do
            [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
        done
    done
    for candidate in /usr/local/bin/cargo /usr/bin/cargo; do
        [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
    done
    return 1
}

CARGO="$(find_cargo)" || die "cargo not found. Install Rust from rustup.rs"
export PATH="$(dirname "${CARGO}"):${PATH}"
info "Using cargo: ${CARGO}"

# ── Real user (for tray service and home-dir operations) ─────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ── Distro detection ──────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}
DISTRO="$(detect_distro)"
info "Detected distribution: ${DISTRO}"

# ── Package manager helper ────────────────────────────────────────────────────
install_package() {
    local pkg="$1"
    case "${DISTRO}" in
        arch|manjaro|endeavouros)
            sudo pacman -S --noconfirm "${pkg}" ;;
        ubuntu|debian|linuxmint|pop)
            sudo apt-get install -y "${pkg}" ;;
        fedora)
            sudo dnf install -y "${pkg}" ;;
        opensuse*|sles)
            sudo zypper install -y "${pkg}" ;;
        *)
            die "Unknown distro '${DISTRO}' — please install '${pkg}' manually and re-run" ;;
    esac
}

echo ""
echo "  This installer requires sudo for system-level operations."
echo "  You may be prompted for your password."
echo ""
sudo -v || die "sudo authentication failed — cannot continue"
# Keep sudo alive in the background for the duration of the script
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
SUDO_KEEPALIVE_PID=$!
trap 'kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null' EXIT

# ════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SECURE BOOT
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 1 — Secure Boot"
echo "════════════════════════════════════════════════════════════"

detect_secure_boot_state() {
    # Primary: read raw EFI variable — most reliable across all tools
    local sb_var val
    sb_var="$(find /sys/firmware/efi/efivars -name 'SecureBoot-*' 2>/dev/null | head -1)"
    if [[ -n "${sb_var}" ]]; then
        # The EFI variable is 5 bytes: 4 attribute bytes + 1 value byte
        # Value byte: 1 = enabled, 0 = disabled
        val="$(od -An -tu1 "${sb_var}" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | tail -1)"
        if [[ "${val}" == "1" ]]; then
            echo "enabled"
            return
        fi
    fi

    # Check Setup Mode via EFI variable
    local sm_var sm_val
    sm_var="$(find /sys/firmware/efi/efivars -name 'SetupMode-*' 2>/dev/null | head -1)"
    if [[ -n "${sm_var}" ]]; then
        sm_val="$(od -An -tu1 "${sm_var}" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | tail -1)"
        if [[ "${sm_val}" == "1" ]]; then
            echo "setup_mode"
            return
        fi
    fi

    # Secondary: sbctl if available
    if command -v sbctl &>/dev/null; then
        local status
        status="$(sbctl status 2>/dev/null || true)"
        if echo "${status}" | grep -qiE "secure boot.*enabled|enabled.*secure boot"; then
            echo "enabled"; return
        elif echo "${status}" | grep -qiE "setup mode.*enabled|enabled.*setup mode"; then
            echo "setup_mode"; return
        elif echo "${status}" | grep -qiE "secure boot.*disabled|disabled.*secure boot"; then
            echo "disabled"; return
        fi
    fi

    # Tertiary: mokutil
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state="$(mokutil --sb-state 2>/dev/null || true)"
        echo "${sb_state}" | grep -q "SecureBoot enabled" && echo "enabled" && return
        echo "disabled"
        return
    fi

    echo "disabled"
}

SB_STATE="$(detect_secure_boot_state)"

case "${SB_STATE}" in
    enabled)
        ok "Secure Boot is enabled"
        ;;
    setup_mode)
        warn "Secure Boot is in Setup Mode — keys can be enrolled"
        ;;
    disabled)
        warn "Secure Boot is disabled"
        ;;
    unknown)
        warn "Could not determine Secure Boot state"
        ;;
esac

# Check if our binaries are already signed
ALREADY_SIGNED=0
if command -v sbctl &>/dev/null; then
    if sbctl list-files 2>/dev/null | grep -q "mykey"; then
        ok "MyKey binaries already enrolled in sbctl"
        ALREADY_SIGNED=1
    fi
fi

# Check if mokutil is managing things
USING_MOK=0
if command -v mokutil &>/dev/null && ! command -v sbctl &>/dev/null; then
    warn "mokutil detected — assuming user manages Secure Boot manually"
    USING_MOK=1
fi

if [[ "${SB_STATE}" == "enabled" && "${ALREADY_SIGNED}" -eq 1 ]]; then
    ok "Secure Boot fully configured — skipping setup"

elif [[ "${USING_MOK}" -eq 1 ]]; then
    echo ""
    echo "  ────────────────────────────────────────────────────────"
    echo "  mokutil detected — you are managing Secure Boot manually."
    echo ""
    echo "  This installer will not attempt to sign files with your"
    echo "  MOK keys. After installation completes you MUST sign"
    echo "  the following files with your own keys or the proxy"
    echo "  daemon will refuse to start:"
    echo ""
    echo "    /usr/local/bin/mykey-host"
    echo "    /usr/local/bin/mykey-daemon"
    echo "    /usr/local/bin/mykey-tray"
    echo ""
    echo "  Sign them with sbsign, pesign, or your preferred tool."
    echo "  Example with sbsign:"
    echo "    sudo sbsign --key /path/to/MOK.key --cert /path/to/MOK.crt \\"
    echo "      --output /usr/local/bin/mykey-daemon \\"
    echo "      /usr/local/bin/mykey-daemon"
    echo ""
    echo "  The proxy will not run without Secure Boot active and"
    echo "  all binaries signed."
    echo "  ────────────────────────────────────────────────────────"
    echo ""
    warn "Continuing installation — manual signing required before use"

elif [[ "${SB_STATE}" == "disabled" && "${ALREADY_SIGNED}" -eq 0 ]]; then
    echo ""
    echo "  Secure Boot is not enabled on this system."
    echo "  MyKey works best with Secure Boot enabled as it"
    echo "  provides hardware-level protection for your authentication keys."
    echo ""
    if confirm "Would you like this script to guide you through Secure Boot setup?"; then

        echo ""
        echo "════════════════════════════════════════════════════════════"
        echo ""
        echo "  DISCLAIMER — PLEASE READ CAREFULLY"
        echo ""
        echo "  Secure Boot setup modifies your system firmware key database."
        echo "  Incorrect configuration can prevent your system from booting."
        echo ""
        echo "  By proceeding you acknowledge:"
        echo ""
        echo "  - I am not responsible for any issues, data loss, or"
        echo "    system failures that may result from this script."
        echo ""
        echo "  - It is strongly recommended that you research and"
        echo "    understand Secure Boot before allowing any script"
        echo "    to configure it on your behalf."
        echo ""
        echo "  - You should have a recovery method available before"
        echo "    proceeding (live USB, backup bootloader, etc.)"
        echo ""
        echo "  - This script will enroll new signing keys into your"
        echo "    firmware. This cannot be easily undone without"
        echo "    entering BIOS and clearing platform keys."
        echo ""
        echo "════════════════════════════════════════════════════════════"
        echo ""
        echo "  To confirm you have read and understood the above,"
        echo "  type the following exactly and press Enter:"
        echo ""
        echo '  Yes. I understand and agree. Continue with script secure-boot setup.'
        echo ""
        read -rp "  Your response: " SB_CONSENT
        echo ""

        if [[ "${SB_CONSENT}" != "Yes. I understand and agree. Continue with script secure-boot setup." ]]; then
            warn "Consent not confirmed — skipping Secure Boot setup"
            warn "You can set up Secure Boot manually and re-run this script"
            SB_STATE="skip"
        else
            ok "Consent confirmed — proceeding with Secure Boot setup"

            if ! command -v sbctl &>/dev/null; then
                info "Installing sbctl..."
                install_package sbctl
            fi

            SB_STATUS="$(sbctl status 2>/dev/null || true)"

            if echo "${SB_STATUS}" | grep -q "Setup Mode.*Enabled"; then
                ok "System is in Setup Mode — ready to enroll keys"

                echo ""
                info "Step 1: Generate Secure Boot signing keys"
                if confirm "Generate new Secure Boot keys now?"; then
                    sudo sbctl create-keys
                    ok "Keys generated"
                else
                    die "Cannot continue without Secure Boot keys"
                fi

                echo ""
                info "Step 2: Enroll keys into firmware"
                echo ""
                warn "Before enrolling keys, consider: if your hardware requires Microsoft's"
                warn "UEFI keys (common on dual-boot systems, some laptops, or if you plan to"
                warn "install Windows), you should include them."
                echo ""
                read -rp "Include Microsoft keys? (recommended for most hardware) [Y/n]: " ms_keys
                if [[ "${ms_keys,,}" != "n" ]]; then
                    sudo sbctl enroll-keys --microsoft
                else
                    sudo sbctl enroll-keys
                fi

            else
                echo ""
                echo "  ────────────────────────────────────────────────────"
                echo "  Your system is not in Secure Boot Setup Mode."
                echo ""
                echo "  To enable Secure Boot setup you need to:"
                echo "  1. Reboot your machine"
                echo "  2. Enter BIOS/UEFI firmware (usually F2, F12, DEL,"
                echo "     or ESC during boot — check your motherboard manual)"
                echo "  3. Find the Secure Boot settings"
                echo "  4. Clear existing Platform Keys or enable Setup Mode"
                echo "  5. Save and reboot"
                echo "  6. Run this installer again"
                echo ""
                echo "  WARNING: Clearing Platform Keys will disable Secure Boot"
                echo "  temporarily until new keys are enrolled. This is normal"
                echo "  and expected during the setup process."
                echo "  ────────────────────────────────────────────────────"
                echo ""
                warn "Secure Boot setup requires BIOS intervention — cannot continue with Secure Boot"
                warn "Continuing installation without Secure Boot — TPM key protection will be weaker"
            fi
        fi
    else
        warn "Skipping Secure Boot setup — continuing without it"
        warn "TPM key sealing will provide less protection without Secure Boot"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# PHASE 2 — TPM2
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 2 — TPM2"
echo "════════════════════════════════════════════════════════════"

if [[ -c /dev/tpm0 && -c /dev/tpmrm0 ]]; then
    ok "TPM2 device present"

    if ! command -v tpm2_getcap &>/dev/null; then
        warn "tpm2-tools not installed — installing..."
        install_package tpm2-tools
    fi

    if tpm2_getcap properties-fixed &>/dev/null; then
        ok "TPM2 is responsive"
    else
        warn "TPM2 device found but not responding — check tpm2-abrmd service"
    fi
else
    echo ""
    echo "  ────────────────────────────────────────────────────────"
    echo "  TPM2 is required but was not detected on this system."
    echo ""
    echo "  TPM2 is usually disabled in BIOS/UEFI by default."
    echo "  To enable it:"
    echo ""
    echo "  1. Reboot your machine"
    echo "  2. Enter BIOS/UEFI firmware (F2, F12, DEL, or ESC)"
    echo "  3. Find Security settings"
    echo "  4. Look for: TPM, TPM2, PTT (Intel), fTPM (AMD), or"
    echo "     Trusted Platform Module"
    echo "  5. Enable it"
    echo "  6. Save and reboot"
    echo "  7. Run this installer again"
    echo ""
    echo "  Note: Some older machines do not have a TPM2 chip."
    echo "  If TPM settings are not in your BIOS, your hardware"
    echo "  may not support it."
    echo "  ────────────────────────────────────────────────────────"
    echo ""
    die "TPM2 not found. Enable TPM2 in BIOS and run this script again."
fi

# ════════════════════════════════════════════════════════════════════════════
# PHASE 3 — DETECT BOOT ENVIRONMENT
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 3 — Boot Environment Detection"
echo "════════════════════════════════════════════════════════════"

detect_esp() {
    local esp
    esp="$(bootctl status 2>/dev/null | grep -i "ESP:" | awk '{print $2}' | head -1)"
    if [[ -n "${esp}" && -d "${esp}" ]]; then
        echo "${esp}"
        return 0
    fi
    for mp in /efi /boot/efi /boot; do
        if mountpoint -q "${mp}" 2>/dev/null; then
            if [[ -d "${mp}/EFI" ]]; then
                echo "${mp}"
                return 0
            fi
        fi
    done
    return 1
}

ESP="$(detect_esp)" || die "Cannot detect EFI System Partition. Is this a UEFI system?"
ok "EFI System Partition: ${ESP}"

BOOTLOADER="unknown"
if [[ -f "${ESP}/EFI/systemd/systemd-bootx64.efi" ]] || \
   [[ -f "${ESP}/EFI/systemd/systemd-bootaa64.efi" ]]; then
    BOOTLOADER="systemd-boot"
    ok "Bootloader: systemd-boot"
elif [[ -f "${ESP}/EFI/grub/grubx64.efi" ]] || \
     [[ -f "${ESP}/EFI/grub2/grubx64.efi" ]] || \
     command -v grub-install &>/dev/null || \
     command -v grub2-install &>/dev/null; then
    BOOTLOADER="grub"
    ok "Bootloader: GRUB"
else
    warn "Could not detect bootloader"
    BOOTLOADER="unknown"
fi

FILES_TO_SIGN=()

should_exclude() {
    local f="${1,,}"
    [[ "${f}" =~ /microsoft/ ]] && return 0
    [[ "${f}" =~ /windows/ ]] && return 0
    [[ "${f}" =~ bootmgr ]] && return 0
    [[ "${f}" =~ memtest ]] && return 0
    [[ "${f}" =~ recovery ]] && return 0
    return 1
}

detect_files_to_sign() {
    info "Scanning for files to sign..."

    if [[ "${BOOTLOADER}" == "systemd-boot" ]]; then
        for f in \
            "${ESP}/EFI/systemd/systemd-bootx64.efi" \
            "${ESP}/EFI/systemd/systemd-bootaa64.efi" \
            "${ESP}/EFI/BOOT/BOOTX64.EFI" \
            "${ESP}/EFI/BOOT/bootx64.efi"
        do
            if [[ -f "${f}" ]]; then
                if should_exclude "${f}"; then
                    warn "Auto-excluded: ${f}"
                else
                    FILES_TO_SIGN+=("${f}")
                fi
            fi
        done

        for f in "${ESP}/EFI/Linux/"*.efi; do
            if [[ -f "${f}" ]]; then
                if should_exclude "${f}"; then
                    warn "Auto-excluded (Windows/Microsoft file): ${f}"
                else
                    FILES_TO_SIGN+=("${f}")
                fi
            fi
        done

        for dir in \
            "${ESP}/EFI/arch" \
            "${ESP}/EFI/ubuntu" \
            "${ESP}/EFI/fedora" \
            "${ESP}/EFI/opensuse"
        do
            for f in "${dir}/"*.efi; do
                if [[ -f "${f}" ]]; then
                    if should_exclude "${f}"; then
                        warn "Auto-excluded (Windows/Microsoft file): ${f}"
                    else
                        FILES_TO_SIGN+=("${f}")
                    fi
                fi
            done
        done

    elif [[ "${BOOTLOADER}" == "grub" ]]; then
        for f in \
            "${ESP}/EFI/grub/grubx64.efi" \
            "${ESP}/EFI/grub2/grubx64.efi" \
            "${ESP}/EFI/BOOT/BOOTX64.EFI" \
            "${ESP}/EFI/BOOT/bootx64.efi"
        do
            if [[ -f "${f}" ]]; then
                if should_exclude "${f}"; then
                    warn "Auto-excluded (Windows/Microsoft file): ${f}"
                else
                    FILES_TO_SIGN+=("${f}")
                fi
            fi
        done
        warn "GRUB detected: kernel signing depends on your shim setup"
        warn "If using shim, your distro manages kernel signing separately"
    else
        while IFS= read -r -d '' f; do
            if should_exclude "${f}"; then
                warn "Auto-excluded (Windows/Microsoft file): ${f}"
            else
                FILES_TO_SIGN+=("${f}")
            fi
        done < <(find "${ESP}" -name "*.efi" -print0 2>/dev/null)
    fi

    # Deduplicate
    local -A seen
    local deduped=()
    local f
    for f in "${FILES_TO_SIGN[@]:-}"; do
        if [[ -z "${seen[${f}]:-}" ]]; then
            seen["${f}"]=1
            deduped+=("${f}")
        fi
    done
    FILES_TO_SIGN=()
    for f in "${deduped[@]:-}"; do
        FILES_TO_SIGN+=("${f}")
    done
}

detect_files_to_sign

if [[ ${#FILES_TO_SIGN[@]} -gt 0 ]]; then
    info "Files that will be signed with Secure Boot keys:"
    for f in "${FILES_TO_SIGN[@]}"; do
        echo "      ${f}"
    done
else
    warn "No EFI files found to sign"
fi

# ════════════════════════════════════════════════════════════════════════════
# PHASE 4 — BUILD AND INSTALL
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 4 — Build and Install"
echo "════════════════════════════════════════════════════════════"

HOST_BINARY="mykey-host"
DAEMON_BINARY="mykey-daemon"
TRAY_BINARY="mykey-tray"
HOST_DEST="/usr/local/bin/${HOST_BINARY}"
DAEMON_DEST="/usr/local/bin/${DAEMON_BINARY}"
TRAY_DEST="/usr/local/bin/${TRAY_BINARY}"
HOST_MANIFEST_SRC="${REPO_ROOT}/scripts/com.mykey.host.json"
SYSTEMD_UNIT_SRC="${REPO_ROOT}/scripts/mykey-daemon.service"
TRAY_SERVICE_SRC="${REPO_ROOT}/scripts/mykey-tray.service"
WEBAUTHN_DIR="/etc/mykey"
CREDENTIAL_DIR="${WEBAUTHN_DIR}/credentials"
KEY_DIR="${WEBAUTHN_DIR}/keys"
TRUSTED_HASHES="${WEBAUTHN_DIR}/trusted-binaries.json"
POLKIT_POLICY="/usr/share/polkit-1/actions/com.mykey.authenticate.policy"
SYSTEMD_UNIT="/etc/systemd/system/mykey-daemon.service"
DAEMON_USER="mykey"
CHROME_NMH_DIR="/etc/opt/chrome/native-messaging-hosts"
CHROMIUM_NMH_DIR="/etc/chromium/native-messaging-hosts"

# ── 4.1 Create dedicated system user ─────────────────────────────────────
echo ""
info "Ensuring system user '${DAEMON_USER}' exists..."
if id "${DAEMON_USER}" &>/dev/null; then
    ok "User '${DAEMON_USER}' already exists."
else
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "${DAEMON_USER}"
    ok "Created system user '${DAEMON_USER}'."
fi
# Add to tss group so the daemon can access TPM2 device nodes
sudo usermod -aG tss "${DAEMON_USER}" 2>/dev/null || true

# Install sudoers rule so the daemon can run pkcheck as root (polkit
# cross-identity checks require uid 0)
echo "==> Installing sudoers rule for polkit check..."
sudo tee /etc/sudoers.d/mykey > /dev/null << 'EOF'
# Allow mykey daemon to run pkcheck as root for user presence verification
mykey ALL=(root) NOPASSWD: /usr/bin/pkcheck
EOF
sudo chmod 0440 /etc/sudoers.d/mykey
ok "Sudoers rule installed."

# ── 4.2 Build native host ─────────────────────────────────────────────────
echo ""
info "Building ${HOST_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-host"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: ${HOST_BINARY}"

# ── 4.3 Build daemon ──────────────────────────────────────────────────────
echo ""
info "Building ${DAEMON_BINARY} (release)..."
cd "${REPO_ROOT}/daemon"
RUSTFLAGS="-A warnings" "${CARGO}" build --features tpm2 --release
ok "Build complete: ${DAEMON_BINARY}"

# ── 4.4 Install binaries ──────────────────────────────────────────────────
echo ""
info "Installing binaries..."
sudo install -m 0755 "${REPO_ROOT}/mykey-host/target/release/${HOST_BINARY}" "${HOST_DEST}"
sudo install -m 0755 "${REPO_ROOT}/daemon/target/release/${DAEMON_BINARY}"    "${DAEMON_DEST}"
ok "${HOST_DEST}"
ok "${DAEMON_DEST}"

# ── 4.5 Create /etc/mykey/ directory structure ───────────────────
echo ""
info "Creating ${WEBAUTHN_DIR}/ directories..."
sudo install -d -m 0700 -o "${DAEMON_USER}" "${WEBAUTHN_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${CREDENTIAL_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${KEY_DIR}"
ok "Directories ready."

# ── 4.7 Write initial trusted binary hashes ───────────────────────────────
echo ""
info "Writing trusted binary hashes to ${TRUSTED_HASHES}..."
HOST_HASH="$(sha256sum "${HOST_DEST}" | awk '{print $1}')"
DAEMON_HASH="$(sha256sum "${DAEMON_DEST}" | awk '{print $1}')"
sudo tee "${TRUSTED_HASHES}" > /dev/null << EOF
[
  { "path": "${HOST_DEST}",   "sha256": "${HOST_HASH}" },
  { "path": "${DAEMON_DEST}", "sha256": "${DAEMON_HASH}" }
]
EOF
sudo chmod 0644 "${TRUSTED_HASHES}"
ok "mykey-host:  ${HOST_HASH}"
ok "daemon:       ${DAEMON_HASH}"

# ── 4.8 Install D-Bus system policy ──────────────────────────────────────
echo ""
info "Installing D-Bus system policy..."
sudo install -m 0644 "${REPO_ROOT}/scripts/com.mykey.Daemon.conf" \
    "/etc/dbus-1/system.d/com.mykey.Daemon.conf"
ok "D-Bus policy installed."

# ── 4.9 Install polkit policy ─────────────────────────────────────────────
echo ""
info "Installing polkit policy..."
sudo install -m 0644 "${REPO_ROOT}/scripts/com.mykey.authenticate.policy" \
    "${POLKIT_POLICY}"
ok "Polkit policy installed."

# ── 4.10 Install native messaging host manifests ──────────────────────────
install_manifest() {
    local dest_dir="$1"
    sudo mkdir -p "${dest_dir}"
    sudo install -m 0644 "${HOST_MANIFEST_SRC}" "${dest_dir}/com.mykey.host.json"
    ok "Manifest installed to ${dest_dir}/"
}

echo ""
info "Installing native messaging host manifests..."
install_manifest "${CHROME_NMH_DIR}"
install_manifest "${CHROMIUM_NMH_DIR}"

# ── 4.11 Install and enable systemd daemon service ────────────────────────
echo ""
info "Installing systemd service unit..."
sudo install -m 0644 "${SYSTEMD_UNIT_SRC}" "${SYSTEMD_UNIT}"
sudo systemctl daemon-reload
sudo systemctl enable mykey-daemon
ok "Daemon service enabled."

# ── 4.12 Build mykey-tray ────────────────────────────────────────────────────
echo ""
info "Building ${TRAY_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-tray"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: ${TRAY_BINARY}"

# ── 4.13 Install mykey-tray binary ───────────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-tray/target/release/${TRAY_BINARY}" "${TRAY_DEST}"
ok "${TRAY_DEST}"

# ── 4.14 Install tray user service (as the real user, not root) ───────────
echo ""
info "Installing tray user service..."

REAL_USER_ID=$(id -u "${REAL_USER}")
REAL_XDG_RUNTIME="/run/user/${REAL_USER_ID}"
REAL_DBUS="unix:path=${REAL_XDG_RUNTIME}/bus"
SYSTEMD_USER_DIR="${REAL_HOME}/.config/systemd/user"

mkdir -p "${SYSTEMD_USER_DIR}"

cp "${TRAY_SERVICE_SRC}" "${SYSTEMD_USER_DIR}/mykey-tray.service"
chmod 0644 "${SYSTEMD_USER_DIR}/mykey-tray.service"

systemctl --user daemon-reload
systemctl --user enable --now mykey-tray

# Symlink fallback to guarantee enable persists
AUTOSTART_DIR="${SYSTEMD_USER_DIR}/default.target.wants"
mkdir -p "${AUTOSTART_DIR}"
ln -sf "${SYSTEMD_USER_DIR}/mykey-tray.service" \
       "${AUTOSTART_DIR}/mykey-tray.service"

ok "Tray service installed and enabled for user '${REAL_USER}'"

# ════════════════════════════════════════════════════════════════════════════
# PHASE 5 — SIGN BINARIES WITH SECURE BOOT KEYS
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 5 — Sign Binaries"
echo "════════════════════════════════════════════════════════════"

if command -v sbctl &>/dev/null && [[ "${SB_STATE:-}" != "skip" && "${SB_STATE:-}" != "disabled" && "${SB_STATE:-}" != "unknown" ]]; then

    # ── Per-file prompt for EFI boot files ───────────────────────
    if [[ ${#FILES_TO_SIGN[@]} -gt 0 ]]; then
        echo ""
        info "EFI boot file signing — you will be asked about each file."
        info "Only sign Linux bootloader and UKI files."
        info "Do NOT sign Windows files — they are already signed by Microsoft."
        echo ""

        for f in "${FILES_TO_SIGN[@]:-}"; do
            if [[ ! -f "${f}" ]]; then
                warn "File not found, skipping: ${f}"
                continue
            fi

            echo ""
            echo "  ──────────────────────────────────────────────────────"
            echo "  File: ${f}"
            echo ""
            echo "  Is this a Linux bootloader or UKI file that you want"
            echo "  protected by Secure Boot? If this is a Windows file,"
            echo "  choose S to skip."
            echo "  ──────────────────────────────────────────────────────"
            echo ""

            while true; do
                read -rp "  Sign this file? [Y]es / [S]kip / [Q]uit signing: " SIGN_CHOICE
                case "${SIGN_CHOICE,,}" in
                    y|yes)
                        sudo sbctl sign --save "${f}"
                        ok "Signed and saved: ${f}"
                        break
                        ;;
                    s|skip)
                        warn "Skipped: ${f}"
                        break
                        ;;
                    q|quit)
                        warn "Signing cancelled — remaining files not signed"
                        break 2
                        ;;
                    *)
                        echo "  Please type Y, S, or Q"
                        ;;
                esac
            done
        done
    fi

    # ── Verify and summarise ──────────────────────────────────────
    echo ""
    info "Verifying signatures..."
    VERIFY_OUT="$(sudo sbctl verify 2>&1 || true)"
    SIGNED=$(echo "${VERIFY_OUT}" | grep -c "✓" || true)
    UNSIGNED=$(echo "${VERIFY_OUT}" | grep -c "✗" || true)
    ok "Signature verification: ${SIGNED} signed, ${UNSIGNED} not signed"
    info "(Unsigned Microsoft/Windows files are expected and normal)"

else
    info "Skipping binary signing (Secure Boot not active or sbctl not available)"
    # Still add our binaries to sbctl database if sbctl exists
    # so they get signed when Secure Boot is later enabled
    if command -v sbctl &>/dev/null; then
        info "Registering binaries with sbctl for future signing..."
        for bin in "${HOST_DEST}" "${DAEMON_DEST}" "${TRAY_DEST}"; do
            [[ -f "${bin}" ]] && sudo sbctl sign --save "${bin}" 2>/dev/null || true
        done
    fi
fi

# Update binary hashes AFTER signing — signing changes the file and its SHA-256
echo ""
info "Updating trusted binary hashes..."
HOST_HASH="$(sha256sum "${HOST_DEST}" | awk '{print $1}')"
DAEMON_HASH="$(sha256sum "${DAEMON_DEST}" | awk '{print $1}')"
sudo tee "${TRUSTED_HASHES}" > /dev/null << EOF
[
  { "path": "${HOST_DEST}",   "sha256": "${HOST_HASH}" },
  { "path": "${DAEMON_DEST}", "sha256": "${DAEMON_HASH}" }
]
EOF
ok "Binary hashes updated"

# ════════════════════════════════════════════════════════════════════════════
# PHASE 6 — START SERVICES
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 6 — Start Services"
echo "════════════════════════════════════════════════════════════"

echo ""
info "Starting mykey-daemon..."
sudo systemctl start mykey-daemon
sleep 2
if systemctl is-active --quiet mykey-daemon; then
    ok "mykey-daemon is running"
else
    fail "mykey-daemon failed to start"
    fail "Check: journalctl -u mykey-daemon -n 20"
    FAILED=1
fi

info "Starting mykey-tray..."
systemctl --user start mykey-tray 2>/dev/null || true
sleep 1
if systemctl --user is-active --quiet mykey-tray 2>/dev/null; then
    ok "mykey-tray is running"
else
    warn "mykey-tray did not start — you can start it manually:"
    warn "systemctl --user start mykey-tray"
fi

# ════════════════════════════════════════════════════════════════════════════
# PHASE 7 — EXTENSION SETUP
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 7 — Browser Extension Setup"
echo "════════════════════════════════════════════════════════════"

declare -A BROWSERS
BROWSER_NAMES=()

check_browser() {
    local name="$1"
    local binary="$2"
    if command -v "${binary}" &>/dev/null; then
        # Only add name once (first binary wins for each name)
        if [[ -z "${BROWSERS[${name}]:-}" ]]; then
            BROWSERS["${name}"]="${binary}"
            BROWSER_NAMES+=("${name}")
        fi
    fi
}

check_browser "Google Chrome"       google-chrome-stable
check_browser "Google Chrome"       google-chrome
check_browser "Chromium"            chromium
check_browser "Chromium"            chromium-browser
check_browser "Ungoogled Chromium"  ungoogled-chromium
check_browser "Brave"               brave-browser
check_browser "Microsoft Edge"      microsoft-edge-stable
check_browser "Microsoft Edge"      microsoft-edge
check_browser "Vivaldi"             vivaldi-stable
check_browser "Vivaldi"             vivaldi

SELECTED_BROWSER=""
SELECTED_BINARY=""

if [[ ${#BROWSER_NAMES[@]} -eq 0 ]]; then
    echo ""
    warn "No supported Chromium-based browser detected"
    warn "Install one of: Google Chrome, Chromium, Brave, Edge, Vivaldi"
    warn "The webAuthenticationProxy API is Chromium-only — Firefox is not supported"
    warn "You will need to open your browser manually for the steps below"
    FAILED=1
else
    echo ""
    info "Found ${#BROWSER_NAMES[@]} supported browser(s):"
    for name in "${BROWSER_NAMES[@]}"; do
        echo "      - ${name} (${BROWSERS[${name}]})"
    done

    if [[ ${#BROWSER_NAMES[@]} -eq 1 ]]; then
        SELECTED_BROWSER="${BROWSER_NAMES[0]}"
        SELECTED_BINARY="${BROWSERS[${SELECTED_BROWSER}]}"
        info "Using: ${SELECTED_BROWSER}"
    else
        echo ""
        echo "  Multiple browsers detected. Which would you like to use?"
        select choice in "${BROWSER_NAMES[@]}"; do
            if [[ -n "${choice}" ]]; then
                SELECTED_BROWSER="${choice}"
                SELECTED_BINARY="${BROWSERS[${choice}]}"
                break
            fi
        done
    fi
fi

echo ""
echo "  ────────────────────────────────────────────────────────"
echo "  Load the MyKey Proxy extension in your browser."
echo "  Follow each step carefully."
echo "  ────────────────────────────────────────────────────────"
echo ""
read -rp "  Press Enter when you are ready to continue..."

# Step 1 — Open browser to extensions page
echo ""
info "Step 1: Open your browser to chrome://extensions"
info "Enable Developer Mode, then click 'Load unpacked' and select: ${REPO_ROOT}/mykey-proxy/chromium"
echo ""
if [[ -n "${SELECTED_BINARY:-}" ]]; then
    info "Opening ${SELECTED_BROWSER} now..."
    "${SELECTED_BINARY}" "chrome://extensions" &
fi
echo ""
read -rp "  Press Enter once the browser is open and you can see chrome://extensions/..."

# Step 2 — Developer mode
echo ""
echo "  Step 2: Enable Developer Mode"
echo "  Look for the 'Developer mode' toggle in the top right corner"
echo "  of the extensions page and turn it ON."
echo ""
read -rp "  Press Enter once Developer Mode is enabled..."

# Step 3 — Load unpacked
echo ""
echo "  Step 3: Load the extension"
echo "  Click the 'Load unpacked' button that appeared after enabling"
echo "  Developer Mode."
echo ""
echo "  When the folder picker opens, navigate to:"
echo "      ${REPO_ROOT}/mykey-proxy/chromium"
echo ""
read -rp "  Press Enter once you have selected the extension folder..."

# Step 4 — Get extension ID
echo ""
echo "  Step 4: Copy your Extension ID"
echo "  The MyKey Proxy extension should now appear on the page."
echo "  Under the extension name you will see an ID that looks like:"
echo "      abcdefghijklmnopabcdefghijklmnop"
echo "  (32 characters, lowercase letters a through p only)"
echo ""

EXTENSION_ID=""
while true; do
    read -rp "  Paste your Extension ID here: " EXTENSION_ID
    if [[ "${EXTENSION_ID}" =~ ^[a-p]{32}$ ]]; then
        ok "Valid Extension ID: ${EXTENSION_ID}"
        break
    else
        echo ""
        fail "Invalid format — must be exactly 32 characters using only letters a-p"
        echo "  Please check the ID and try again."
        echo ""
    fi
done

# Apply extension ID to all manifest files
UPDATED=0
for f in \
    "${CHROME_NMH_DIR}/com.mykey.host.json" \
    "${CHROMIUM_NMH_DIR}/com.mykey.host.json" \
    "${REAL_HOME}/.config/google-chrome/NativeMessagingHosts/com.mykey.host.json" \
    "${REAL_HOME}/.config/chromium/NativeMessagingHosts/com.mykey.host.json"
do
    if [[ -f "${f}" ]]; then
        sudo sed -i "s|EXTENSION_ID_PLACEHOLDER|${EXTENSION_ID}|g" "${f}"
        ok "Updated: ${f}"
        UPDATED=1
    fi
done

if [[ "${UPDATED}" -eq 0 ]]; then
    fail "No manifest files found to update"
    FAILED=1
fi

# Step 5 — Reload extension
echo ""
echo "  Step 5: Reload the extension"
echo "  Go back to chrome://extensions/ and click the"
echo "  refresh/reload icon on the MyKey Proxy extension card."
echo ""
read -rp "  Press Enter once you have reloaded the extension..."

# ════════════════════════════════════════════════════════════════════════════
# PHASE 8 — FINAL HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 8 — Final Health Check"
echo "════════════════════════════════════════════════════════════"
echo ""

# [1/8] Secure Boot
echo "[1/8] Secure Boot..."
SB_FINAL="$(detect_secure_boot_state)"
case "${SB_FINAL}" in
    enabled) ok "Secure Boot is enabled" ;;
    *)       warn "Secure Boot is not enabled — key protection is reduced" ;;
esac

# [2/8] TPM2
echo "[2/8] TPM2..."
if [[ -c /dev/tpm0 && -c /dev/tpmrm0 ]]; then
    ok "TPM2 present"
else
    fail "TPM2 not found"
    FAILED=1
fi

# [3/8] Binaries
echo "[3/8] Binaries..."
for bin in "${HOST_BINARY}" "${DAEMON_BINARY}" "${TRAY_BINARY}"; do
    if [[ -x "/usr/local/bin/${bin}" ]]; then
        ok "/usr/local/bin/${bin}"
    else
        fail "/usr/local/bin/${bin} missing"
        FAILED=1
    fi
done

# [4/8] Configuration files
echo "[4/8] Configuration..."
for f in \
    "${TRUSTED_HASHES}" \
    "${POLKIT_POLICY}" \
    "/etc/dbus-1/system.d/com.mykey.Daemon.conf"
do
    if sudo test -f "${f}"; then
        ok "${f}"
    else
        fail "${f} missing"
        FAILED=1
    fi
done

# [5/8] Extension ID
echo "[5/8] Extension ID..."
ID_SET=0
for f in \
    "${CHROME_NMH_DIR}/com.mykey.host.json" \
    "${CHROMIUM_NMH_DIR}/com.mykey.host.json"
do
    if [[ -f "${f}" ]] && ! grep -q "EXTENSION_ID_PLACEHOLDER" "${f}"; then
        ok "Extension ID configured in ${f}"
        ID_SET=1
    fi
done
if [[ "${ID_SET}" -eq 0 ]]; then
    fail "Extension ID not set in any manifest"
    FAILED=1
fi

# [6/8] Binary integrity
echo "[6/8] Binary integrity..."
if command -v python3 &>/dev/null; then
    sudo python3 - << 'PYEOF'
import json, hashlib, sys
try:
    with open("/etc/mykey/trusted-binaries.json") as f:
        entries = json.load(f)
    all_ok = True
    for entry in entries:
        with open(entry["path"], "rb") as bf:
            actual = hashlib.sha256(bf.read()).hexdigest()
        if actual == entry["sha256"]:
            print(f"  \u2713 {entry['path']}")
        else:
            print(f"  \u2717 {entry['path']} \u2014 hash mismatch", file=sys.stderr)
            all_ok = False
    sys.exit(0 if all_ok else 1)
except Exception as e:
    print(f"  ! Could not verify hashes: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    [[ $? -eq 0 ]] || FAILED=1
else
    warn "python3 not found — skipping hash verification"
fi

# [7/8] Daemon service
echo "[7/8] Daemon service..."
if systemctl is-active --quiet mykey-daemon; then
    ok "mykey-daemon is running"
else
    fail "mykey-daemon is not running"
    FAILED=1
fi

# [8/8] Tray service
echo "[8/8] Tray service..."
if systemctl --user is-active --quiet mykey-tray 2>/dev/null; then
    ok "mykey-tray is running"
else
    warn "mykey-tray is not running"
    warn "Start with: systemctl --user start mykey-tray"
fi

# ── Final summary ─────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
if [[ "${FAILED}" -eq 0 ]]; then
    echo " Installation complete — all checks passed."
    echo ""
    echo " Test the proxy:"
    echo "   1. Open https://webauthn.io in ${SELECTED_BROWSER:-your browser}"
    echo "   2. Enter a username and click Register"
    echo "   3. You will be prompted for your Linux password or PIN"
    echo "   4. Complete registration then test Sign In"
    echo ""
    echo " Live logs:"
    echo "   journalctl -u mykey-daemon -f"
    echo "   tail -f /tmp/mykey-host.log"
else
    echo " Installation completed with errors — review the output above."
    echo " Fix any failed checks and run ./scripts/install.sh again."
fi
echo "════════════════════════════════════════════════════════════"
echo ""
