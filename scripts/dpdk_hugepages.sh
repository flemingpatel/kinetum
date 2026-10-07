#!/bin/bash -p
# scripts/dpdk_hugepages.sh
#
# Setup hugepages for DPDK (developer convenience).
# Adjust values for your system.
#
# Production Deployment Notes:
# - For production, configure hugepages via kernel parameters instead:
#   Add "hugepages=1024" to GRUB_CMDLINE_LINUX in /etc/default/grub
# - This script is for development/testing convenience only
#
# Exit Codes:
#   0 - Success
#   1 - Hugepage allocation failed (system doesn't have enough memory)
#   2 - Mount failed
#   3 - Platform not supported
[[ $- == *p* ]] || {
  printf '%s\n' '[dpdk] ERROR: helper requires /bin/bash -p' >&2
  exit 1
}
set -euo pipefail
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export LC_ALL=C
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GLOBIGNORE POSIXLY_CORRECT
for KINETUM_ENVIRONMENT_NAME in "${!LD_@}"; do
  unset "${KINETUM_ENVIRONMENT_NAME}"
done
unset KINETUM_ENVIRONMENT_NAME

# =============================================================================
# Signal Handlers
# =============================================================================

trap 'echo "[dpdk] Interrupted"; exit 130' INT TERM

# =============================================================================
# Help/Usage
# =============================================================================

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] [num_pages]

Setup hugepages for DPDK development/testing.

Arguments:
  num_pages    Number of hugepages to allocate (default: 1024)
               The host page size determines the maximum under a 32 GiB cap.

Options:
  -h, --help   Show this help message and exit

Examples:
  $0           # Allocate 1024 hugepages (default)
  $0 2048      # Allocate 2048 hugepages
  sudo $0 512  # Allocate 512 hugepages

Exit Codes:
  0 - Success
  1 - Hugepage allocation failed
  2 - Mount failed
  3 - Platform not supported
EOF
  exit 0
}

if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
  usage
fi

if [[ $# -gt 1 ]]; then
  echo "[dpdk] ERROR: too many arguments" >&2
  echo "[dpdk]        Use --help for usage." >&2
  exit 1
fi

# =============================================================================
# Platform Validation
# =============================================================================

if [[ "$(uname)" != "Linux" ]]; then
  echo "[dpdk] ERROR: This script is Linux-only (detected: $(uname))"
  exit 3
fi

if [[ ! -f /proc/meminfo ]]; then
  echo "[dpdk] ERROR: /proc/meminfo not found - is this a Linux system?"
  exit 3
fi

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "[dpdk] ERROR: This script requires root/sudo privileges"
  echo "[dpdk]        Run with: sudo $0 [num_pages]"
  exit 1
fi

SUDO=()
if [[ $EUID -ne 0 ]]; then
  SUDO=(sudo)
fi

# =============================================================================
# Configuration
# =============================================================================

PAGES="${1:-1024}"

# Validate PAGES before any shell arithmetic. The decimal spelling avoids
# octal interpretation and the width bound keeps arithmetic representable.
if ! [[ "$PAGES" =~ ^[1-9][0-9]{0,9}$ ]]; then
  echo "[dpdk] ERROR: Invalid page count: '$PAGES' (must be a positive decimal integer)"
  exit 1
fi

# Bound aggregate hugepage memory rather than assuming a 2 MiB host page.
HUGEPAGE_SIZE_KB=$(awk '/^Hugepagesize:/ {print $2}' /proc/meminfo)
if ! [[ "${HUGEPAGE_SIZE_KB}" =~ ^[1-9][0-9]*$ ]]; then
  echo "[dpdk] ERROR: Could not parse Hugepagesize from /proc/meminfo" >&2
  exit 1
fi
MAX_HUGEPAGE_MEMORY_KB=$((32 * 1024 * 1024))
MAX_PAGES=$((MAX_HUGEPAGE_MEMORY_KB / HUGEPAGE_SIZE_KB))
if (( MAX_PAGES == 0 )); then
  echo "[dpdk] ERROR: Host hugepage size exceeds the 32 GiB safety cap" >&2
  exit 1
fi
if (( 10#$PAGES > MAX_PAGES )); then
  echo "[dpdk] ERROR: Requested ${PAGES} hugepages exceeds maximum of ${MAX_PAGES}"
  echo "[dpdk]        Host Hugepagesize is ${HUGEPAGE_SIZE_KB} kB; the helper caps allocation at 32 GiB."
  exit 1
fi

# =============================================================================
# Hugepage Setup
# =============================================================================

echo "[dpdk] Setting vm.nr_hugepages=${PAGES}"
if ! "${SUDO[@]}" sysctl -w "vm.nr_hugepages=${PAGES}"; then
  echo "[dpdk] ERROR: Failed to set hugepages. Check kernel support and available memory."
  exit 1
fi

# Verify allocation succeeded (kernel may allocate fewer if memory is fragmented)
ALLOCATED=$(awk '/^HugePages_Total:/ {print $2}' /proc/meminfo)

# Validate that ALLOCATED is numeric before comparison
if ! [[ "$ALLOCATED" =~ ^[0-9]+$ ]]; then
  echo "[dpdk] ERROR: Could not parse HugePages_Total from /proc/meminfo" >&2
  exit 1
fi

if (( 10#$ALLOCATED < 10#$PAGES )); then
  echo "[dpdk] ERROR: Requested ${PAGES} hugepages but only ${ALLOCATED} allocated" >&2
  echo "[dpdk]        Reboot or reduce the requested count before validation." >&2
  exit 1
fi

# =============================================================================
# Mount hugetlbfs
# =============================================================================

echo "[dpdk] Mounting hugetlbfs at /mnt/huge (if not mounted)"
"${SUDO[@]}" mkdir -p /mnt/huge || { echo "[dpdk] Failed to create /mnt/huge"; exit 2; }
if ! findmnt -rn --target /mnt/huge --types hugetlbfs >/dev/null 2>&1; then
  if ! "${SUDO[@]}" mount -t hugetlbfs nodev /mnt/huge; then
    echo "[dpdk] ERROR: Failed to mount hugetlbfs"
    exit 2
  fi
fi
if ! findmnt -rn --target /mnt/huge --types hugetlbfs >/dev/null 2>&1; then
  echo "[dpdk] ERROR: /mnt/huge is not an admitted hugetlbfs mount" >&2
  exit 2
fi

# =============================================================================
# Status Report
# =============================================================================

echo "[dpdk] SUCCESS - Hugepage setup complete"
echo ""
grep -E 'HugePages|Hugepagesize' /proc/meminfo || true
mount | grep -i hugetlbfs || true
