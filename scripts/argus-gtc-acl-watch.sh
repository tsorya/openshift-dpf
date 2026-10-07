#!/usr/bin/env bash
# Stream only the demo agent's AdminNetworkPolicy drop records into its UI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${ARGUS_GTC_DEMO_URL:-}" ]]; then
    echo "Set ARGUS_GTC_DEMO_URL to the demo Route URL (for example https://argus-gtc-demo.example.com)." >&2
    exit 1
fi

ingest_token="${ARGUS_GTC_INGEST_TOKEN:-}"
token_file="${REPO_ROOT}/manifests/generated/argus-gtc-demo/.ingest-token"
if [[ -z "${ingest_token}" && -f "${token_file}" ]]; then
    ingest_token="$(<"${token_file}")"
fi
if [[ -z "${ingest_token}" ]]; then
    echo "ARGUS_GTC_INGEST_TOKEN is empty and the generated demo token file is missing." >&2
    exit 1
fi

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/kubeconfig}"
agent_node="$(oc get pods -n argus-gtc-demo -l app=argus-gtc-agent \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)"
if [[ -z "${agent_node}" ]]; then
    echo "The argus-gtc-agent pod is not scheduled; deploy it before starting the watcher." >&2
    exit 1
fi

ovn_pod="$(oc get pods -n openshift-ovn-kubernetes \
    -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName --no-headers 2>/dev/null \
    | awk -v node="${agent_node}" '$2 == node && $1 ~ /^ovnkube-node-/ { print $1; exit }')"
if [[ -z "${ovn_pod}" ]]; then
    echo "No ovnkube-node pod found for agent node ${agent_node}." >&2
    exit 1
fi

echo "Watching ${ovn_pod} on ${agent_node} for demo-agent ANP denies (canary TCP/31999 is allowed). Ctrl-C to stop."
oc exec -n openshift-ovn-kubernetes "${ovn_pod}" -c ovnkube-node -- \
    tail -n 0 -F /var/log/ovn/acl-audit-log.log |
    awk '/name="ANP:argus-gtc-agent-host-access:Egress:2"/ && /verdict="?drop"?/ && /direction=from-lport/ && /tcp,/ { print; fflush() }' |
    while IFS= read -r line; do
        payload="$(printf '%s' "${line}" | python3 -c 'import json, sys; print(json.dumps({"line": sys.stdin.read()}))')"
        curl --silent --show-error --fail --retry 3 --retry-delay 1 \
            --request POST \
            --url "${ARGUS_GTC_DEMO_URL%/}/api/agent-runs/policy-evidence" \
            --header "Content-Type: application/json" \
            --header "X-Ingest-Token: ${ingest_token}" \
            --data "${payload}"
        printf '\n'
    done
