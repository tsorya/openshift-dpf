#!/bin/bash
# Keep argus-gtc-demo and argus-gtc-demo-v20 on the same commit (mirror follows primary).
set -e
set -o pipefail

PRIMARY_BRANCH=argus-gtc-demo
MIRROR_BRANCH=argus-gtc-demo-v20
REMOTE=${ARGUS_GTC_GIT_REMOTE:-origin}

usage() {
    echo "Usage: $0 [--push]"
    echo "  Align ${MIRROR_BRANCH} with ${PRIMARY_BRANCH} at the current HEAD."
    echo "  Commit on ${PRIMARY_BRANCH}, then run with --push to update both remotes."
    exit 1
}

do_push=false
if [[ "${1:-}" == "--push" ]]; then
    do_push=true
elif [[ -n "${1:-}" ]]; then
    usage
fi

current_branch=$(git branch --show-current)
if [[ "$current_branch" != "$PRIMARY_BRANCH" ]]; then
    echo "ERROR: Check out ${PRIMARY_BRANCH} first (on: ${current_branch})." >&2
    exit 1
fi

ref=$(git rev-parse HEAD)
git branch -f "$MIRROR_BRANCH" "$ref"

echo "Synced ${MIRROR_BRANCH} -> ${ref} ($(git log -1 --oneline))"
echo "${PRIMARY_BRANCH} is at the same commit."

if [[ "$do_push" == true ]]; then
    git push "$REMOTE" "$PRIMARY_BRANCH" "$MIRROR_BRANCH"
    echo "Pushed ${PRIMARY_BRANCH} and ${MIRROR_BRANCH} to ${REMOTE}."
fi
