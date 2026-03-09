#!/usr/bin/env bash
# =============================================================================
#  EctoLedger — Firecracker microVM Provisioning Script
#
#  Downloads the Firecracker binary, a minimal Linux kernel, and a busybox
#  rootfs, then configures the environment so the EctoLedger `sandbox-firecracker`
#  feature can isolate `run_command` intents inside ephemeral microVMs.
#
#  Prerequisites:
#    - Linux with KVM support (/dev/kvm must exist)
#    - curl, unzip/tar
#    - Root or sudo access (for /dev/kvm permissions and /opt/ectoledger/ setup)
#
#  Usage:
#    sudo ./scripts/provision-firecracker.sh [--prefix /opt/ectoledger]
#
#  After running, rebuild EctoLedger with:
#    cargo build --release --features sandbox-firecracker
#  Then set these environment variables before starting the server:
#    export ECTO_FC_BINARY=/opt/ectoledger/firecracker
#    export ECTO_FC_KERNEL=/opt/ectoledger/vmlinux
#    export ECTO_FC_ROOTFS=/opt/ectoledger/rootfs.ext4
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

# Firecracker release to download (see https://github.com/firecracker-microvm/firecracker/releases)
FC_VERSION="${FC_VERSION:-v1.10.1}"

# SHA-256 checksums for supply-chain integrity verification.
# Update these when bumping FC_VERSION.
FC_SHA256_x86_64="${FC_SHA256_x86_64:-e58161e6d89e0888e0cc1be4aa1bf16e57f6443ad4e7dd3e05d6ca3b0e2e0b30}"
FC_SHA256_aarch64="${FC_SHA256_aarch64:-f32de5dc0b50adbc7db8feabe6fa57b2a7a62ff78b0b3afe5fdc7c1e2e2d8ab8}"
KERNEL_SHA256_x86_64="${KERNEL_SHA256_x86_64:-c38b110dbb256ef57e79d3fafa80af31a57b5cb33e6fc1a79b284c1b4ee89ccc}"
KERNEL_SHA256_aarch64="${KERNEL_SHA256_aarch64:-a94d0f23b14cb54a51854fbc1a8ac0b68f21e89bfe6fd3b2ecbf53fb4fb2bd12}"

# Install prefix — all artefacts are placed here
INSTALL_PREFIX="${1:-/opt/ectoledger}"

# ── Colours ──────────────────────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"

info()    { echo -e "  ${CYAN}▶${RESET} $*"; }
success() { echo -e "  ${GREEN}✔${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "  ${RED}✘${RESET}  $*" >&2; }
step()    { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# ── SHA-256 verification helper ───────────────────────────────────────────────
verify_sha256() {
  local file="$1" expected="$2" label="$3"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum &>/dev/null; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    error "Neither sha256sum nor shasum found — cannot verify $label integrity."
    exit 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    error "SHA-256 checksum mismatch for $label!"
    error "  Expected: $expected"
    error "  Got:      $actual"
    error "The downloaded file may be corrupted or tampered with. Aborting."
    rm -f "$file"
    exit 1
  fi
  success "SHA-256 verified for $label"
}

# ── Detect architecture ───────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  FC_ARCH="x86_64" ;;
  aarch64) FC_ARCH="aarch64" ;;
  *)
    error "Unsupported architecture: $ARCH. Firecracker supports x86_64 and aarch64 only."
    exit 1
    ;;
esac

echo ""
echo -e "${BOLD}${CYAN}  EctoLedger — Firecracker microVM Provisioner${RESET}"
echo -e "  Version: ${FC_VERSION}  Architecture: ${FC_ARCH}  Prefix: ${INSTALL_PREFIX}"
echo ""

# ── 1. Verify KVM access ─────────────────────────────────────────────────────
step "Checking KVM"

if [[ ! -e /dev/kvm ]]; then
  error "/dev/kvm not found. Firecracker requires hardware virtualisation (KVM)."
  error "Enable nested virtualisation in your hypervisor, or use a bare-metal Linux host."
  exit 1
fi

if [[ ! -r /dev/kvm ]] || [[ ! -w /dev/kvm ]]; then
  warn "/dev/kvm exists but is not accessible to the current user."
  info "Adding current user to the 'kvm' group…"
  if id -nG "$USER" | grep -qw kvm; then
    warn "Already in 'kvm' group — a logout/login may be required to apply."
  else
    if command -v usermod &>/dev/null; then
      usermod -aG kvm "$USER"
      success "Added $USER to the 'kvm' group. Log out and back in, then re-run this script."
    else
      error "Could not add user to 'kvm' group automatically. Run: sudo usermod -aG kvm $USER"
      exit 1
    fi
    exit 0
  fi
else
  success "/dev/kvm is accessible"
fi

# ── 2. Create install directory ───────────────────────────────────────────────
step "Creating install directory"
mkdir -p "$INSTALL_PREFIX"
success "Directory ready: $INSTALL_PREFIX"

# ── 3. Download Firecracker binary ────────────────────────────────────────────
step "Downloading Firecracker ${FC_VERSION}"

FC_BINARY="${INSTALL_PREFIX}/firecracker"
if [[ -f "$FC_BINARY" ]]; then
  EXISTING_VER="$("$FC_BINARY" --version 2>/dev/null | head -1 || echo unknown)"
  warn "Firecracker already installed: $EXISTING_VER"
  warn "Delete ${FC_BINARY} and re-run to upgrade."
else
  RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${FC_ARCH}.tgz"
  TMP_TGZ="$(mktemp /tmp/firecracker-XXXX.tgz)"
  info "Downloading: $RELEASE_URL"
  curl --fail --location --progress-bar --output "$TMP_TGZ" "$RELEASE_URL"
  info "Extracting binary…"
  TMP_DIR="$(mktemp -d)"
  tar -xzf "$TMP_TGZ" -C "$TMP_DIR"
  # The release archive contains a versioned binary name — find it
  FC_BIN_SRC="$(find "$TMP_DIR" -name "firecracker-${FC_VERSION}-${FC_ARCH}" -type f | head -1)"
  if [[ -z "$FC_BIN_SRC" ]]; then
    # Fallback: any file named 'firecracker*' that is executable
    FC_BIN_SRC="$(find "$TMP_DIR" -name 'firecracker*' -type f | head -1)"
  fi
  if [[ -z "$FC_BIN_SRC" ]]; then
    error "Could not locate the Firecracker binary in the downloaded archive."
    exit 1
  fi
  # Verify downloaded binary integrity BEFORE installing to the destination.
  fc_expected_hash=""
  eval "fc_expected_hash=\$FC_SHA256_${FC_ARCH}"
  verify_sha256 "$FC_BIN_SRC" "$fc_expected_hash" "Firecracker ${FC_VERSION} (${FC_ARCH})"
  install -m 0755 "$FC_BIN_SRC" "$FC_BINARY"
  rm -rf "$TMP_TGZ" "$TMP_DIR"
  success "Firecracker installed → ${FC_BINARY}"
fi

# ── 4. Download kernel image ──────────────────────────────────────────────────
step "Downloading minimal Linux kernel"

KERNEL_PATH="${INSTALL_PREFIX}/vmlinux"
if [[ -f "$KERNEL_PATH" ]]; then
  success "Kernel already present: ${KERNEL_PATH}"
else
  # Use the Firecracker project's pre-built minimal kernel images
  KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${FC_ARCH}/vmlinux-5.10.225"
  info "Downloading kernel: $KERNEL_URL"
  curl --fail --location --progress-bar --output "$KERNEL_PATH" "$KERNEL_URL" || {
    warn "Primary kernel URL failed. Trying fallback…"
    KERNEL_URL_FB="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${FC_ARCH}/kernels/vmlinux.bin"
    curl --fail --location --progress-bar --output "$KERNEL_PATH" "$KERNEL_URL_FB" || {
      error "Could not download the kernel image. Check your internet connection."
      error "You can also supply your own kernel at ${KERNEL_PATH}."
      exit 1
    }
  }
  # Verify kernel image integrity
  kernel_expected_hash=""
  eval "kernel_expected_hash=\$KERNEL_SHA256_${FC_ARCH}"
  verify_sha256 "$KERNEL_PATH" "$kernel_expected_hash" "Linux kernel (${FC_ARCH})"
  success "Kernel installed → ${KERNEL_PATH}"
fi

# ── 5. Create rootfs image ────────────────────────────────────────────────────
step "Building minimal rootfs ext4 image"

ROOTFS_PATH="${INSTALL_PREFIX}/rootfs.ext4"
if [[ -f "$ROOTFS_PATH" ]]; then
  success "Rootfs already present: ${ROOTFS_PATH}"
else
  # Try to download Firecracker's official hello-rootfs first (smallest)
  ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${FC_ARCH}/ubuntu-22.04.ext4"
  info "Downloading rootfs: $ROOTFS_URL"
  curl --fail --location --progress-bar --output "$ROOTFS_PATH" "$ROOTFS_URL" || {
    warn "Official rootfs download failed. Building a minimal busybox rootfs locally…"

    if ! command -v mkfs.ext4 &>/dev/null; then
      error "mkfs.ext4 not found. Install e2fsprogs: apt install e2fsprogs"
      exit 1
    fi
    if ! command -v busybox &>/dev/null; then
      error "busybox not found. Install it: apt install busybox-static"
      exit 1
    fi

    TMP_ROOTFS="$(mktemp -d)"
    # Create minimal directory structure
    mkdir -p "${TMP_ROOTFS}"/{bin,sbin,etc,proc,sys,dev,tmp,opt/ectoledger}
    # Require jq for reliable JSON parsing in the guest init script
    if ! command -v jq &>/dev/null; then
      error "jq not found. Install it before proceeding."
      exit 1
    fi

    # Install busybox and jq, then create symlinks
    cp "$(command -v busybox)" "${TMP_ROOTFS}/bin/busybox"
    cp "$(command -v jq)" "${TMP_ROOTFS}/bin/jq"
    for tool in sh cat ls mount echo sleep; do
      ln -sf /bin/busybox "${TMP_ROOTFS}/bin/${tool}"
    done
    # Guest init: reads intent from /dev/vdb, runs the command, writes result to stdout
    cat > "${TMP_ROOTFS}/sbin/init" <<'INIT_SCRIPT'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || true

# Read intent JSON from the second block device (/dev/vdb)
INTENT=$(cat /dev/vdb 2>/dev/null)

# Build a safe argv from the JSON "args" array using jq @sh quoting.
# jq @sh single-quotes every element, so eval set -- will NOT undergo
# word-splitting or glob-expansion on the values.  This is the POSIX-safe
# way to convert a JSON array into shell positional parameters without
# allowing shell injection via crafted argument strings.
eval "set -- $(echo "$INTENT" | /bin/jq -r '[.args[]] | @sh' 2>/dev/null)"

if [ $# -eq 0 ]; then
  echo '{"error":"no args array found in intent"}'
  /sbin/reboot -f
fi

echo '{"status":"running"}'
# exec argv directly — no shell evaluation of argument values
"$@" 2>&1
echo '{"status":"complete"}'
/sbin/reboot -f
INIT_SCRIPT
    chmod +x "${TMP_ROOTFS}/sbin/init"

    # Create and populate ext4 image (64 MiB)
    dd if=/dev/zero bs=1M count=64 of="$ROOTFS_PATH" status=none
    mkfs.ext4 -q -F -L ectoledger-rootfs "$ROOTFS_PATH"

    TMP_MOUNT="$(mktemp -d)"
    mount -o loop "$ROOTFS_PATH" "$TMP_MOUNT"
    cp -a "${TMP_ROOTFS}/." "$TMP_MOUNT/"
    umount "$TMP_MOUNT"
    rmdir "$TMP_MOUNT"
    rm -rf "$TMP_ROOTFS"
    success "Minimal busybox rootfs created → ${ROOTFS_PATH}"
  }
fi

# ── 6. Write .env snippet ─────────────────────────────────────────────────────
step "Environment configuration"

ENV_SNIPPET="${INSTALL_PREFIX}/ectoledger-firecracker.env"
cat > "$ENV_SNIPPET" <<ENVEOF
# ─── EctoLedger Firecracker microVM configuration ───────────────────────────────
# Source this file or add these variables to your shell / .env before starting
# the EctoLedger server with --features sandbox-firecracker:
#
#   source ${ENV_SNIPPET}
#   cargo run --release --features sandbox-firecracker -- serve
#
export ECTO_FC_BINARY=${FC_BINARY}
export ECTO_FC_KERNEL=${KERNEL_PATH}
export ECTO_FC_ROOTFS=${ROOTFS_PATH}
export ECTO_FC_VCPUS=1
export ECTO_FC_MEM_MIB=128
export ECTO_FC_TIMEOUT_SECS=30
ENVEOF

success "Environment snippet written → ${ENV_SNIPPET}"

# ── 7. Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  ✔  Firecracker provisioning complete!${RESET}"
echo ""
echo -e "  ${BOLD}Firecracker binary:${RESET}  ${FC_BINARY}"
echo -e "  ${BOLD}Kernel image:${RESET}        ${KERNEL_PATH}"
echo -e "  ${BOLD}Root filesystem:${RESET}     ${ROOTFS_PATH}"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  1. Source the environment file:"
echo -e "     ${CYAN}source ${ENV_SNIPPET}${RESET}"
echo ""
echo -e "  2. Rebuild EctoLedger with the firecracker feature:"
echo -e "     ${CYAN}cargo build --release --features sandbox-firecracker${RESET}"
echo ""
echo -e "  3. Start the server:"
echo -e "     ${CYAN}./target/release/ectoledger serve${RESET}"
echo ""
echo -e "  See the README for full documentation on the Firecracker sandbox."
echo ""
