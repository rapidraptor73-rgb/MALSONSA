#!/usr/bin/env bash
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python 3.9+ is required. Install python3 with your OS package manager.' >&2
  exit 1
fi
exec python3 "$here/installer/install.py" "$@"
