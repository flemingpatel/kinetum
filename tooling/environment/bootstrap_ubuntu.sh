#!/bin/bash -p
# tooling/environment/bootstrap_ubuntu.sh
#
# Installer for Ubuntu source-build, validation, and documentation dependencies
# (x86_64 / aarch64), including the fixed-output Kinetum DPDK package. This is
# a convenience script for local development; the producer independently
# verifies its exact builder and payload contract. The script does not bind
# NICs, configure hugepages, or start services.
#
# Required build host:
#   - Ubuntu 24.04 LTS (Noble), with its distro Python 3.12
#
# Exit Codes:
#   0 - Success
#   1 - Dependency installation or production failed
#   2 - Unsupported operating system or invalid arguments
#   3 - Insufficient privileges
[[ $- == *p* ]] || {
  printf '%s\n' '[bootstrap] ERROR: helper requires /bin/bash -p' >&2
  exit 1
}
set -euo pipefail
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export LC_ALL=C
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV GLOBIGNORE POSIXLY_CORRECT
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH GVBINDIR GV_FILE_PATH
for KINETUM_ENVIRONMENT_NAME in "${!LD_@}"; do
  unset "${KINETUM_ENVIRONMENT_NAME}"
done
unset KINETUM_ENVIRONMENT_NAME
for KINETUM_ENVIRONMENT_NAME in "${!PYTHON@}"; do
  unset "${KINETUM_ENVIRONMENT_NAME}"
done
unset KINETUM_ENVIRONMENT_NAME

# =============================================================================
# Signal Handlers
# =============================================================================

trap 'echo "[bootstrap] Interrupted"; exit 130' INT TERM

# =============================================================================
# Help/Usage
# =============================================================================

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Install Ubuntu 24.04 build, validation, and documentation dependencies for Kinetum.

Options:
  -h, --help   Show this help message and exit

Installed Packages:
  - build-essential, cmake, ninja-build, patch, pkg-config, git, ripgrep
  - ca-certificates, curl, wget, tar, gzip, xz-utils
  - distro python3 and python3-venv
  - locked Python development, packaging, and documentation dependencies
  - doxygen, Java 21, Graphviz, fonts-dejavu-core (website generation)
  - clang, clang-format, clang-tidy, libclang-rt-dev, strace
  - protobuf-compiler, libprotobuf-dev
  - protobuf-compiler-grpc, libgrpc++-dev
  - libgtest-dev
  - libssl-dev, libelf-dev, libnuma-dev
  - libarchive-dev, zlib1g-dev (native packaging codecs)
  - source-build headers required by the fixed DPDK producer policy
  - iproute2, pciutils, ethtool, tcpdump, jq, tmux
  - source-produced, fixed-output KinetumDPDK CONFIG package

Exit Codes:
  0 - Success
  1 - Dependency installation or production failed
  2 - Unsupported operating system or invalid arguments
  3 - Insufficient privileges
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      ;;
    *)
      echo "[bootstrap] ERROR: unknown option: $1" >&2
      echo "[bootstrap]        Use --help for usage." >&2
      exit 2
      ;;
  esac
done

# =============================================================================
# Platform Validation
# =============================================================================

# Check if running on Ubuntu
if [[ ! -f /etc/os-release ]]; then
  echo "[bootstrap] ERROR: /etc/os-release not found"
  exit 2
fi

source /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
  echo "[bootstrap] ERROR: This script is Ubuntu-only (detected: $ID)"
  exit 2
fi
if [[ "$VERSION_ID" != "24.04" ]]; then
  echo "[bootstrap] ERROR: exact dependency production requires Ubuntu 24.04"
  echo "[bootstrap]        Detected Ubuntu ${VERSION_ID}"
  exit 2
fi

echo "[bootstrap] Detected: $PRETTY_NAME"

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P -- "${SCRIPT_DIR}/../.." && pwd -P)"
PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python3"

if [[ ! -f "${SCRIPT_DIR}/build_kinetum_dpdk.py" ]]; then
  echo "[bootstrap] ERROR: exact DPDK producer is missing beside this script"
  exit 1
fi
if [[ ! -f "${SCRIPT_DIR}/../../third_party/dpdk/dependency_manifest.json" ]]; then
  echo "[bootstrap] ERROR: source-controlled DPDK dependency policy is missing"
  exit 1
fi
if [[ ! -f "${SCRIPT_DIR}/requirements.lock" || ! -s "${SCRIPT_DIR}/requirements.lock" ||
      -L "${SCRIPT_DIR}/requirements.lock" ]]; then
  echo "[bootstrap] ERROR: Python dependency lock is empty, missing, or indirect" >&2
  exit 1
fi

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "[bootstrap] ERROR: This script requires root/sudo privileges"
  echo "[bootstrap]        Run with: sudo $0"
  exit 3
fi

SUDO=()
if [[ $EUID -ne 0 ]]; then
  SUDO=(sudo)
fi

# =============================================================================
# Helpers
# =============================================================================

install_required_packages() {
  echo "[bootstrap] Installing $1..."
  shift
  if ! "${SUDO[@]}" apt-get install -y --no-install-recommends "$@"; then
    echo "[bootstrap] ERROR: Package installation failed"
    exit 1
  fi
}

print_required_tool_version() {
  local label="$1"
  local output
  shift

  if ! output=$("$@" 2>&1) || [[ -z "${output}" ]]; then
    echo "[bootstrap] ERROR: required tool probe failed: ${label}" >&2
    exit 1
  fi
  output="${output%%$'\n'*}"
  printf '  %-9s %s\n' "${label}:" "${output}"
}

# Install the selected Python dependencies as the original invoking user.
prepare_python_environment() {
  local owner_name owner_uid owner_home
  local environment_root="${PROJECT_ROOT}/.venv"
  local -a owner_command=()

  owner_name="$(id -un)"
  owner_uid="$EUID"
  if [[ $EUID -eq 0 && -n ${SUDO_UID+x} ]]; then
    if [[ ! "$SUDO_UID" =~ ^(0|[1-9][0-9]*)$ || -z ${SUDO_USER:-} ]]; then
      echo "[bootstrap] ERROR: original sudo caller is invalid" >&2
      exit 1
    fi
    owner_name="$SUDO_USER"
    owner_uid="$SUDO_UID"
    if [[ "$(id -u -- "$owner_name")" != "$owner_uid" ]]; then
      echo "[bootstrap] ERROR: original sudo caller identity disagrees" >&2
      exit 1
    fi
  fi
  owner_home="$(getent -- passwd "$owner_name" | cut -d: -f6)"
  if [[ "$owner_home" != /* ]]; then
    echo "[bootstrap] ERROR: Python environment owner has no absolute home" >&2
    exit 1
  fi
  if [[ $EUID -eq 0 && "$owner_uid" != 0 ]]; then
    owner_command=(/usr/sbin/runuser -u "$owner_name" --)
  fi
  owner_command+=(/usr/bin/env -i "HOME=$owner_home" "PATH=$PATH" LC_ALL=C PIP_CONFIG_FILE=/dev/null)

  if [[ -e "$environment_root" || -L "$environment_root" ]]; then
    if [[ ! -d "$environment_root" || -L "$environment_root" ||
          "$(stat -c %u -- "$environment_root")" != "$owner_uid" ||
          ! -f "$environment_root/pyvenv.cfg" || -L "$environment_root/pyvenv.cfg" ]]; then
      echo "[bootstrap] ERROR: .venv must be a direct virtual environment owned by $owner_name" >&2
      exit 1
    fi
  else
    "${owner_command[@]}" /usr/bin/python3 -I -B -m venv "$environment_root"
  fi
  if ! "${owner_command[@]}" "$PYTHON_BIN" -I -B -c \
    'import pathlib, site, sys
root = pathlib.Path(sys.argv[1])
sys.exit(sys.prefix != str(root) or sys.prefix == sys.base_prefix
         or sys.version_info[:2] != (3, 12)
         or any(not pathlib.Path(path).is_relative_to(root) for path in site.getsitepackages()))' \
    "$environment_root"; then
    echo "[bootstrap] ERROR: $environment_root must provide an isolated Python 3.12 interpreter" >&2
    exit 1
  fi

  # Install the source-only documentation extension's backend from the same lock.
  local backend_requirement
  backend_requirement="$(awk '
    /^setuptools==/ { selected = 1 }
    selected { print; if ($0 !~ /\\$/) exit }
    END { if (!selected) exit 1 }
  ' "${SCRIPT_DIR}/requirements.lock")"
  # pip reopens /dev/stdin, so its pipe must be created after the user switch.
  "${owner_command[@]}" /usr/bin/timeout --kill-after=5s 600s \
    /bin/bash -p -c '
    set -euo pipefail
    printf "%s\n" "$1" |
      "$2" -I -B -m pip --isolated install \
      --require-hashes --only-binary=:all: --no-deps --no-input --no-compile \
      --disable-pip-version-check --retries 0 --timeout 30 -r /dev/stdin
  ' kinetum-python-backend "$backend_requirement" "$PYTHON_BIN"
  "${owner_command[@]}" /usr/bin/timeout --kill-after=5s 600s \
    "$PYTHON_BIN" -I -B -m pip --isolated install \
    --require-hashes --only-binary=:all: --no-input --no-compile \
    --no-build-isolation --no-binary=sphinxcontrib-plantuml \
    --disable-pip-version-check --retries 0 --timeout 30 -r "${SCRIPT_DIR}/requirements.lock"
  "${owner_command[@]}" /usr/bin/timeout --kill-after=5s 600s \
    "$PYTHON_BIN" -I -B -m piptools sync --no-config \
    --pip-args='--require-hashes --only-binary=:all: --no-binary=sphinxcontrib-plantuml --no-build-isolation --no-input --no-compile --disable-pip-version-check --retries 0 --timeout 30' \
    "${SCRIPT_DIR}/requirements.lock"
  "${owner_command[@]}" /usr/bin/timeout --kill-after=5s 60s \
    "$PYTHON_BIN" -I -B -m pip --isolated check
}

# =============================================================================
# Package Installation
# =============================================================================

umask 022
exec {KINETUM_BOOTSTRAP_LOCK}< "$PROJECT_ROOT"
if ! /usr/bin/flock -n "$KINETUM_BOOTSTRAP_LOCK"; then
  echo "[bootstrap] ERROR: another bootstrap is using this source tree" >&2
  exit 1
fi

echo "[bootstrap] Updating package lists..."
if ! "${SUDO[@]}" apt-get update; then
  echo "[bootstrap] ERROR: apt-get update failed"
  exit 1
fi

install_required_packages "core dependencies" \
  build-essential cmake ninja-build patch pkg-config git ripgrep \
  ca-certificates curl wget tar gzip xz-utils \
  python3 python3-venv \
  doxygen openjdk-21-jre-headless graphviz fonts-dejavu-core \
  protobuf-compiler libprotobuf-dev \
  protobuf-compiler-grpc libgrpc++-dev \
  libgtest-dev \
  libssl-dev libelf-dev libnuma-dev libarchive-dev zlib1g-dev \
  libfdt-dev libpcap-dev \
  iproute2 pciutils ethtool tcpdump jq tmux \
  clang clang-format clang-tidy libclang-rt-dev strace

echo "[bootstrap] Preparing the project Python environment..."
prepare_python_environment

echo "[bootstrap] Producing exact KinetumDPDK dependency package..."
"${SUDO[@]}" "$PYTHON_BIN" -I -B "${SCRIPT_DIR}/build_kinetum_dpdk.py"

# =============================================================================
# Post-Installation Validation
# =============================================================================

echo ""
echo "[bootstrap] Verifying installed tools..."
print_required_tool_version cmake cmake --version
print_required_tool_version g++ g++ --version
print_required_tool_version protoc protoc --version
print_required_tool_version ninja ninja --version
print_required_tool_version python3 "$PYTHON_BIN" -I -B --version
print_required_tool_version doxygen doxygen --version
print_required_tool_version java java --version
print_required_tool_version graphviz dot -V
print_required_tool_version tar tar --version
print_required_tool_version gzip gzip --version
print_required_tool_version xz xz --version
print_required_tool_version libelf pkg-config --modversion libelf
echo "  dpdk:     source-produced fixed-output KinetumDPDK CONFIG package"
print_required_tool_version tcpdump tcpdump --version

echo ""
printf '[bootstrap] Activate Python tools with: source %q\n' "${PROJECT_ROOT}/.venv/bin/activate"
echo "[bootstrap] SUCCESS - Ubuntu dependencies installed"
