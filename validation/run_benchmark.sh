#!/bin/bash -p
# Launch Kinetum benchmarks from the source tree. Python owns the complete CLI,
# including explicit runtime selection for runs and independent report commands.

[[ $- == *p* ]] || {
    printf '%s\n' 'Error: benchmark runner requires direct /bin/bash -p execution' >&2
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
umask 027

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P -- "${SCRIPT_DIR}/.." && pwd -P)"
for KINETUM_ENVIRONMENT_NAME in "${!PYTHON@}"; do
    unset "${KINETUM_ENVIRONMENT_NAME}"
done
unset KINETUM_ENVIRONMENT_NAME
export PYTHONPATH="${SCRIPT_DIR}"
PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python3"

if ! "${PYTHON_BIN}" -I -B -c \
    'import sys; sys.exit(sys.version_info.major != 3 or sys.version_info.minor < 12)'; then
    printf 'Error: %s must provide Python 3.12 or newer\n' "${PYTHON_BIN}" >&2
    exit 1
fi

# -P excludes implicit working-directory imports. Only this exact package
# directory enters PYTHONPATH; the endpoint's remote interpreter is unrelated.
exec "${PYTHON_BIN}" -P -s -B -X utf8 -m kinetum_benchmark "$@"
