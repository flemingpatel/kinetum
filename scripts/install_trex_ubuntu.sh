#!/bin/bash -p
# scripts/install_trex_ubuntu.sh
#
# Install Cisco TRex prebuilt Linux release tarballs on Ubuntu validation hosts.
# This helper downloads and extracts TRex only; it does not bind NICs, write a
# TRex port configuration, or start the stateless server.
#
# Exit Codes:
#   0 - Success
#   1 - Download, extraction, or package installation failed
#   2 - Invalid arguments
#   3 - Unsupported platform
#   4 - Insufficient privileges
[[ $- == *p* ]] || {
  printf '%s\n' '[trex] ERROR: helper requires /bin/bash -p' >&2
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

trap 'echo "[trex] Interrupted"; exit 130' INT TERM

DEFAULT_RELEASE_URL="https://trex-tgn.cisco.com/trex/release/latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Install Cisco TRex prebuilt release tarball for validation traffic generation.

Options:
  --prefix DIR       Installation directory (default: /opt/trex)
  --version VALUE    Release version such as v3.08, or latest (default: latest)
  --url URL          Explicit tarball URL; overrides --version
  --insecure-download
                    Disable TLS certificate verification for the TRex download
  --owner USER       Filesystem owner for extracted files
                    (default: SUDO_USER, then current user)
  -h, --help         Show this help message and exit

Examples:
  sudo $0
  sudo $0 --version v3.08
  sudo $0 --insecure-download
  sudo $0 --prefix /opt/trex --owner flemingp

Notes:
  - This script does not bind NICs or start TRex.
  - --insecure-download is only for lab hosts with broken CA chains.
  - Start TRex manually from the extracted directory:
      sudo ./t-rex-64 -i
EOF
  exit 0
}

PREFIX="/opt/trex"
TREX_RELEASE="latest"
URL=""
INSECURE_DOWNLOAD=0
OWNER="${SUDO_USER:-$(id -un)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { echo "[trex] ERROR: --prefix requires a value" >&2; exit 2; }
      PREFIX="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "[trex] ERROR: --version requires a value" >&2; exit 2; }
      TREX_RELEASE="$2"
      shift 2
      ;;
    --url)
      [[ $# -ge 2 ]] || { echo "[trex] ERROR: --url requires a value" >&2; exit 2; }
      URL="$2"
      shift 2
      ;;
    --insecure-download)
      INSECURE_DOWNLOAD=1
      shift
      ;;
    --owner)
      [[ $# -ge 2 ]] || { echo "[trex] ERROR: --owner requires a value" >&2; exit 2; }
      OWNER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "[trex] ERROR: unknown option: $1" >&2
      echo "[trex]        Use --help for usage." >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname)" != "Linux" ]]; then
  echo "[trex] ERROR: This script is Linux-only (detected: $(uname))"
  exit 3
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "[trex] ERROR: TRex prebuilt release helper requires x86_64"
  echo "[trex]        Detected architecture: $(uname -m)"
  exit 3
fi

if [[ ! -f /etc/os-release ]]; then
  echo "[trex] ERROR: /etc/os-release not found"
  exit 3
fi

source /etc/os-release
if [[ "${ID}" != "ubuntu" ]]; then
  echo "[trex] ERROR: This script is Ubuntu-only (detected: ${ID})"
  exit 3
fi

if [[ -z "${PREFIX}" || "${PREFIX}" != /* || "${PREFIX}" == "/" || \
      "${PREFIX}" == */ || "${PREFIX}" == *'/../'* || \
      "${PREFIX}" == *'/./'* || "${PREFIX}" == */.. || \
      "${PREFIX}" == */. || "${PREFIX}" == *'//'* ]]; then
  echo "[trex] ERROR: unsafe --prefix: ${PREFIX}" >&2
  exit 2
fi

if ! id -u -- "${OWNER}" >/dev/null 2>&1; then
  echo "[trex] ERROR: owner user does not exist: ${OWNER}" >&2
  exit 2
fi
GROUP="$(id -gn -- "${OWNER}")"

if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "[trex] ERROR: This script requires root/sudo privileges"
  echo "[trex]        Run with: sudo $0 [options]"
  exit 4
fi

SUDO=()
if [[ $EUID -ne 0 ]]; then
  SUDO=(sudo)
fi

if [[ -z "${URL}" ]]; then
  if [[ "${TREX_RELEASE}" == "latest" ]]; then
    # Cisco publishes the moving latest release at this extensionless URL.
    # The "latest.tar.gz" alias is not available on the public release host.
    URL="${DEFAULT_RELEASE_URL}"
  elif [[ "${TREX_RELEASE}" =~ ^https?:// ]]; then
    URL="${TREX_RELEASE}"
  else
    URL="https://trex-tgn.cisco.com/trex/release/${TREX_RELEASE}.tar.gz"
  fi
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

ARCHIVE="${TMP_DIR}/trex.tar.gz"

echo "[trex] Detected: ${PRETTY_NAME}"
echo "[trex] Installing prerequisite packages..."
if ! "${SUDO[@]}" apt-get update; then
  echo "[trex] ERROR: apt-get update failed"
  exit 1
fi

# TRex's NIC setup uses distutils, supplied by setuptools on Python 3.12.
required_packages=(build-essential ca-certificates curl tar python3 python3-setuptools pciutils zlib1g-dev)

if ! "${SUDO[@]}" apt-get install -y "${required_packages[@]}"; then
  echo "[trex] ERROR: prerequisite package installation failed"
  exit 1
fi

echo "[trex] Creating ${PREFIX}"
"${SUDO[@]}" mkdir -p "${PREFIX}"

curl_args=(-fL --retry 3 --connect-timeout 20)
if [[ "${INSECURE_DOWNLOAD}" -eq 1 ]]; then
  echo "[trex] WARNING: TLS certificate verification is disabled for this download"
  curl_args+=(-k)
fi

echo "[trex] Downloading ${URL}"
if ! curl "${curl_args[@]}" -o "${ARCHIVE}" --url "${URL}"; then
  echo "[trex] ERROR: failed to download TRex release"
  echo "[trex]        If this is a lab host with a broken CA chain, rerun with:"
  echo "[trex]          sudo $0 --insecure-download"
  exit 1
fi

echo "[trex] Extracting into ${PREFIX}"
if ! tar -tzf "${ARCHIVE}" >/dev/null; then
  echo "[trex] ERROR: downloaded file is not a readable gzip tar archive"
  echo "[trex]        URL: ${URL}"
  exit 1
fi

if ! "${SUDO[@]}" tar -xzf "${ARCHIVE}" -C "${PREFIX}"; then
  echo "[trex] ERROR: failed to extract TRex release"
  exit 1
fi

if ! TREX_BIN="$(
  "${SUDO[@]}" find "${PREFIX}" -maxdepth 3 -type f -name t-rex-64 |
    sort -V |
    tail -n1
)"; then
  echo "[trex] ERROR: failed to inspect the extracted TRex release" >&2
  exit 1
fi
if [[ -z "${TREX_BIN}" ]]; then
  echo "[trex] ERROR: extracted release does not contain t-rex-64"
  exit 1
fi
if [[ ! -x "${TREX_BIN}" ]]; then
  echo "[trex] ERROR: extracted t-rex-64 is not executable" >&2
  exit 1
fi

TREX_DIR="$(cd "$(dirname "${TREX_BIN}")" && pwd)"
API_PATH="${TREX_DIR}/automation/trex_control_plane/interactive"
if [[ ! -d "${API_PATH}" ]]; then
  echo "[trex] ERROR: extracted release omits the stateless Python API" >&2
  exit 1
fi

"${SUDO[@]}" chown -R "${OWNER}:${GROUP}" "${TREX_DIR}"

echo ""
echo "[trex] SUCCESS - TRex installed"
echo "  Directory: ${TREX_DIR}"
echo "  Binary:    ${TREX_BIN}"
echo "  Owner:     ${OWNER}:${GROUP}"
echo ""
if [[ -x "${SCRIPT_DIR}/dpdk_hugepages.sh" ]]; then
  echo "If hugepages are not configured yet:"
  echo "  sudo ${SCRIPT_DIR}/dpdk_hugepages.sh 4096"
  echo ""
fi
echo "Start the stateless server manually:"
echo "  cd ${TREX_DIR}"
echo "  sudo ./t-rex-64 -i"
echo ""
echo "Use this Kinetum validation API path:"
echo "  --trex-api-path ${API_PATH}"
