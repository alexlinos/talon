#!/usr/bin/env bash
# Anonymizing CoPilot MCP proxy for NanoClaw
#
# Wraps copilot-mcp/copilot-mcp.sh with the same anonymizing proxy used for
# OpenSearch, so SearchEventsTool results are tokenized (USER_1, HOST_1,
# IP_INT_1, ...) before reaching the cloud model.
#
# Tokens are shared with anon-opensearch-mcp.sh via the one token map at
# /workspace/group/session_tokens.json, so a host seen through either server
# gets the same token and a single `deanonymize` call reverses both.
#
# Field definitions live in anon_proxy/fields.yaml — the same file governs
# both servers.
#
# Use this instead of the raw `copilot` server for event search. Write-back
# tools (SubmitAiAnalystReportTool and friends) should still go through the
# raw server: they take de-anonymized text by design, and anonymizing their
# results would obscure the job/report IDs the workflow needs.
#
# This script is called by Claude Code as the MCP server command.
# Do not run it directly — start NanoClaw normally.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/anon_proxy/anon_proxy.py"

# Resolves on the host (repo layout) and in the container, where siem/ and
# copilot-mcp/ are siblings under /workspace/extra.
export ANON_PROXY_CHILD="$SCRIPT_DIR/../copilot-mcp/copilot-mcp.sh"
export ANON_PROXY_LABEL="copilot"

LOCAL_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
SYSTEM_PYTHON="/opt/opensearch-mcp/bin/python3"

# The proxy itself only needs pyyaml, so any of these interpreters will do —
# it never imports the wrapped server's libraries.
#
# See anon-opensearch-mcp.sh for why pip is invoked as `python -m pip` (stale
# venv shebangs after an rsync) and why this uses if/then rather than `||`
# (set -e treats the command after a final `||` as terminating).
_is_native_exec() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    if [[ "$(uname -s)" == "Linux" ]]; then
        local magic
        magic=$(head -c 4 "$bin" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ "$magic" == "7f454c46" ]] || return 1
    fi
    return 0
}

_try_python() {
    local py="$1"
    [[ -x "$py" ]] || return 1
    if "$py" -c "import yaml" 2>/dev/null; then
        return 0
    fi
    "$py" -m pip install --quiet pyyaml >&2 2>/dev/null
}

if [[ ! -x "$ANON_PROXY_CHILD" ]]; then
    echo "[anon-copilot-mcp] ERROR: copilot-mcp.sh not found at $ANON_PROXY_CHILD" >&2
    exit 1
fi

if _is_native_exec "$LOCAL_PYTHON" && _try_python "$LOCAL_PYTHON"; then
    exec "$LOCAL_PYTHON" "$PROXY_SCRIPT"
fi

if [[ -x "$SYSTEM_PYTHON" ]] && _try_python "$SYSTEM_PYTHON"; then
    exec "$SYSTEM_PYTHON" "$PROXY_SCRIPT"
fi

echo "[anon-copilot-mcp] ERROR: no working python3 environment found." >&2
echo "[anon-copilot-mcp]   Tried: $LOCAL_PYTHON" >&2
echo "[anon-copilot-mcp]   Tried: $SYSTEM_PYTHON" >&2
echo "[anon-copilot-mcp]   In a container: rebuild the image (container/build.sh)" >&2
echo "[anon-copilot-mcp]   On the host: rerun siem/setup.sh to recreate the venv" >&2
exit 1
