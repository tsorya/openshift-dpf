#!/usr/bin/env bash
# Source user.env with auto-export so plain VAR=value lines are visible to
# child processes (e.g. make generate-env).
set -e

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
user_env="${1:-${repo_root}/user.env}"

if [ ! -f "$user_env" ]; then
    echo "No user.env at $user_env" >&2
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "$user_env"
set +a
