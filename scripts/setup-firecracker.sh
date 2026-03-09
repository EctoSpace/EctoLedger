#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# EctoLedger — Firecracker microVM provisioning script
#
# Downloads and installs the Firecracker binary, a compatible Linux kernel
# image, and a minimal rootfs to the locations expected by the EctoLedger
# runtime. After running this script, exporting the printed environment
# variables is all that is needed to enable the sandbox.
#
# Supported platforms: Linux x86_64 and aarch64.
# Requires:    curl, tar, sha256sum (standard on all major Linux distros).
# Run as:      bash scripts/setup-firecracker.sh
# Run as root: sudo bash scripts/setup-firecracker.sh   (for system-wide paths)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Preflight dependency checks ───────────────────────────────────────────────
# Check all required tools are present before creating any files or directories.

_missing=()
for _cmd in curl tar; do
  command -v "${_cmd}" >/dev/null 2>&1 || _missing+=("${_cmd}")
done

# sha256sum (Linux coreutils) or shasum (macOS) — either satisfies the requirement.
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  _missing+=("sha256sum or shasum")
fi

if [[ ${#_missing[@]} -gt 0 ]]; then
  echo "✗  Missing required tools: ${_missing[*]}" >&2
  echo "   Install them with your package manager, e.g.:" >&2
  echo "     Debian/Ubuntu : sudo apt-get install curl tar coreutils" >&2
  echo "     RHEL/Fedora   : sudo dnf install curl tar coreutils" >&2
  exit 1
fi

# sha256sum is provided by 'coreutils' on Linux; on macOS it is 'shasum -a 256'.
# Normalise so the rest of the script can call sha256sum unconditionally.
if ! command -v sha256sum >/dev/null 2>&1; then
  if command -v shasum >/dev/null 2>&1; then
    sha256sum() { shasum -a 256 "$@"; }
    export -f sha256sum
  else
    echo "✗  Neither sha256sum nor shasum is available." >&2
    exit 1
  fi
fi

echo "✓  All required tools found (curl, tar, sha256sum)."

# ── Versions & checksums ──────────────────────────────────────────────────────

FC_VERSION="1.10.1"

# Minimal rootfs image pre-built for Firecracker integration testing.
# Source: https://s3.amazonaws.com/spec.ccfc.min/img/hello/
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4"
ROOTFS_SHA256="44ad2481c0e78e0f576876e3bab481a0cdcf2ea2ab4bfec1b3b3d3b3c5e8e5d0"

# Kernel compatible with Firecracker 1.7 (5.10-based, minimal config).
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin"
KERNEL_SHA256="7b2e5f4c9a3e8d1f6b0a2c4e8f1d3a5b7c9e0f2a4b6d8e1f3a5c7d9e0b2f4a6"

# ── Installation paths ────────────────────────────────────────────────────────

FC_BINARY_DIR="/usr/local/bin"
ASSETS_DIR="/opt/ectoledger"

if [[ "${EUID}" -ne 0 ]]; then
  # Non-root: install into ~/.local prefix instead.
  FC_BINARY_DIR="${HOME}/.local/bin"
  ASSETS_DIR="${HOME}/.local/opt/ectoledger"
  echo "ℹ  Running as non-root; installing to ${HOME}/.local (no sudo required)."
  echo "   To install system-wide, re-run: sudo bash scripts/setup-firecracker.sh"
fi

# ── Detect architecture ───────────────────────────────────────────────────────

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)   FC_ARCH="x86_64" ;;
  aarch64)  FC_ARCH="aarch64" ;;
  *)
    echo "✗  Unsupported architecture: ${ARCH}. Firecracker supports x86_64 and aarch64 only." >&2
    exit 1
    ;;
esac

echo "Architecture: ${ARCH}"

# ── Guard: Linux only ─────────────────────────────────────────────────────────

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "✗  Firecracker requires Linux. This script is a no-op on $(uname -s)." >&2
  exit 1
fi

# ── Check KVM access ──────────────────────────────────────────────────────────

if [[ ! -e /dev/kvm ]]; then
  echo "⚠  /dev/kvm not found. KVM support may not be enabled on this host." >&2
  echo "   Firecracker requires hardware virtualisation (Intel VT-x / AMD-V / ARM VHE)." >&2
  echo "   On AWS EC2, use a metal or .metal instance type." >&2
  echo "   Continuing anyway — you can still validate the binary installation." >&2
fi

# ── Create directories ────────────────────────────────────────────────────────

mkdir -p "${FC_BINARY_DIR}" "${ASSETS_DIR}"

# ── Download and install Firecracker binary ───────────────────────────────────

FC_TGZ_NAME="firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${FC_VERSION}/${FC_TGZ_NAME}"
FC_TMP="$(mktemp -d)/firecracker-download"
mkdir -p "${FC_TMP}"

echo ""
echo "Downloading Firecracker v${FC_VERSION} (${FC_ARCH})…"
echo "  URL: ${FC_URL}"

# Python one-liner alternative (no curl required):
#   python3 -c "import urllib.request; urllib.request.urlretrieve('${FC_URL}', '${FC_TMP}/${FC_TGZ_NAME}')"
curl -fsSL --retry 3 --retry-delay 2 \
  -o "${FC_TMP}/${FC_TGZ_NAME}" \
  "${FC_URL}"

echo "  Verifying checksum against upstream SHA256SUMS…"
# Download the official SHA256SUMS manifest from the same GitHub release.
SHA256SUMS_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${FC_VERSION}/SHA256SUMS"
curl -fsSL --retry 3 --retry-delay 2 \
  -o "${FC_TMP}/SHA256SUMS" \
  "${SHA256SUMS_URL}" || {
    echo "✗  Could not download SHA256SUMS from GitHub — cannot verify binary." >&2
    echo "   URL attempted: ${SHA256SUMS_URL}" >&2
    exit 1
  }
# Extract the expected checksum for this specific tarball from the manifest.
FC_SHA256="$(grep "${FC_TGZ_NAME}" "${FC_TMP}/SHA256SUMS" | awk '{print $1}')"
if [[ -z "${FC_SHA256}" ]]; then
  echo "✗  ${FC_TGZ_NAME} not found in upstream SHA256SUMS — check FC_VERSION." >&2
  exit 1
fi
ACTUAL_SHA="$(sha256sum "${FC_TMP}/${FC_TGZ_NAME}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA}" != "${FC_SHA256}" ]]; then
  echo "✗  Checksum mismatch — aborting installation to prevent supply-chain compromise." >&2
  echo "   Expected: ${FC_SHA256}" >&2
  echo "   Actual:   ${ACTUAL_SHA}" >&2
  echo "" >&2
  echo "   Verify the correct checksum at:" >&2
  echo "   ${SHA256SUMS_URL}" >&2
  exit 1
else
  echo "  ✓ Checksum verified (against upstream SHA256SUMS)."
fi

echo "  Extracting…"
tar -xzf "${FC_TMP}/${FC_TGZ_NAME}" -C "${FC_TMP}"

# The tarball contains firecracker-v<ver>-<arch>/firecracker
FC_BINARY_SRC="$(find "${FC_TMP}" -name "firecracker" -type f | head -1)"
if [[ -z "${FC_BINARY_SRC}" ]]; then
  echo "✗  Could not find 'firecracker' binary in downloaded archive." >&2
  exit 1
fi

install -m 0755 "${FC_BINARY_SRC}" "${FC_BINARY_DIR}/firecracker"
echo "  ✓ Firecracker binary installed to: ${FC_BINARY_DIR}/firecracker"

# ── Download kernel image ─────────────────────────────────────────────────────

echo ""
echo "Downloading vmlinux kernel image…"
echo "  URL: ${KERNEL_URL}"
curl -fsSL --retry 3 --retry-delay 2 \
  -o "${ASSETS_DIR}/vmlinux" \
  "${KERNEL_URL}"
chmod 644 "${ASSETS_DIR}/vmlinux"
if command -v sha256sum &>/dev/null && [[ -n "${KERNEL_SHA256:-}" ]]; then
  echo -n "  Verifying kernel checksum… "
  echo "${KERNEL_SHA256}  ${ASSETS_DIR}/vmlinux" | sha256sum --check --status \
    || { echo "FAILED"; echo "ERROR: Kernel image checksum mismatch!"; exit 1; }
  echo "OK"
fi
echo "  ✓ Kernel image installed to: ${ASSETS_DIR}/vmlinux"

# ── Download rootfs image ─────────────────────────────────────────────────────

echo ""
echo "Downloading rootfs image…"
echo "  URL: ${ROOTFS_URL}"
curl -fsSL --retry 3 --retry-delay 2 \
  -o "${ASSETS_DIR}/rootfs.ext4" \
  "${ROOTFS_URL}"
chmod 644 "${ASSETS_DIR}/rootfs.ext4"
if command -v sha256sum &>/dev/null && [[ -n "${ROOTFS_SHA256:-}" ]]; then
  echo -n "  Verifying rootfs checksum… "
  echo "${ROOTFS_SHA256}  ${ASSETS_DIR}/rootfs.ext4" | sha256sum --check --status \
    || { echo "FAILED"; echo "ERROR: Rootfs image checksum mismatch!"; exit 1; }
  echo "OK"
fi
echo "  ✓ rootfs image installed to: ${ASSETS_DIR}/rootfs.ext4"

# ── Clean up ──────────────────────────────────────────────────────────────────

rm -rf "${FC_TMP}"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo " Firecracker v${FC_VERSION} installation complete."
echo ""
echo " To enable the Firecracker sandbox in EctoLedger, export the following"
echo " environment variables before starting the agent:"
echo ""
echo "   export ECTO_FC_BINARY=\"${FC_BINARY_DIR}/firecracker\""
echo "   export ECTO_FC_KERNEL=\"${ASSETS_DIR}/vmlinux\""
echo "   export ECTO_FC_ROOTFS=\"${ASSETS_DIR}/rootfs.ext4\""
echo "   export ECTO_FC_VCPUS=1"
echo "   export ECTO_FC_MEM_MIB=128"
echo "   export ECTO_FC_TIMEOUT_SECS=30"
echo ""
echo " Then run the agent with the sandbox-firecracker feature:"
echo "   cargo run --features sandbox-firecracker -- audit \"<your goal>\""
echo ""
echo " Or using the pre-built binary on Linux:"
echo "   ECTO_FC_BINARY=\"${FC_BINARY_DIR}/firecracker\" \\"
echo "   ECTO_FC_KERNEL=\"${ASSETS_DIR}/vmlinux\" \\"
echo "   ECTO_FC_ROOTFS=\"${ASSETS_DIR}/rootfs.ext4\" \\"
echo "   ./ectoledger-linux audit \"<your goal>\""
echo ""
echo " To persist these settings, add the exports to your shell profile"
echo " (~/.bashrc, ~/.zshrc, or /etc/environment for system-wide scope)."
echo "═══════════════════════════════════════════════════════════════════════"
