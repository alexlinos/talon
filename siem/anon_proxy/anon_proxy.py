#!/usr/bin/env python3
"""
Anonymizing MCP proxy for SIEM tools.

Wraps a child MCP server and intercepts tool results, replacing sensitive
field values with consistent session tokens before they reach the cloud model.

The child is chosen by the ANON_PROXY_CHILD environment variable and defaults
to opensearch-mcp.sh, so the original OpenSearch behaviour is unchanged. The
CoPilot hunt tools are wrapped the same way via anon-copilot-mcp.sh.

Token map is persisted at /workspace/group/session_tokens.json so tokens
remain consistent across all tool calls within a session — and, because every
proxy instance shares that one file, across different wrapped servers too. A
host seen through OpenSearch and through CoPilot search gets the same token.
Concurrent instances coordinate with an exclusive file lock; see TokenMap.

Built-in tool: `deanonymize` — call this with a text block containing tokens
(USER_1, HOST_1, IP_INT_1, etc.) to get back the original values. Use it
when writing the final analyst report so names and IPs are accurate.

Usage:
  This script is invoked by anon-opensearch-mcp.sh (the MCP server command).
  It spawns opensearch-mcp.sh as a child and proxies all JSON-RPC messages,
  anonymizing tool results on the way through.
"""

import json
import os
import re
import sys
import ipaddress
import threading
import subprocess
import fcntl
import contextlib
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent
FIELDS_YAML = SCRIPT_DIR / "fields.yaml"

# The wrapped MCP server. Defaults to OpenSearch so existing deployments and
# anon-opensearch-mcp.sh keep working untouched.
CHILD_WRAPPER = Path(
    os.environ.get("ANON_PROXY_CHILD", str(SCRIPT_DIR.parent / "opensearch-mcp.sh"))
)

# Shared by every proxy instance in the group, which is what keeps tokens
# consistent across servers. Overridable so tests need no /workspace.
TOKEN_MAP_PATH = Path(
    os.environ.get("ANON_PROXY_TOKEN_MAP", "/workspace/group/session_tokens.json")
)

# Label used in diagnostics, e.g. "anon-proxy[copilot]".
PROXY_LABEL = os.environ.get("ANON_PROXY_LABEL", CHILD_WRAPPER.stem)

# ── Token map ─────────────────────────────────────────────────────────────────

class TokenMap:
    """Persistent map of original PII values to opaque tokens.

    Shared across proxy instances: the OpenSearch proxy and the CoPilot proxy
    both point at the same file so a hostname seen through either server gets
    the same token, and one `deanonymize` call reverses both.

    That sharing means two OS processes mutate one file, so every assignment is
    a read-modify-write under an exclusive `flock`. Without it, two proxies
    allocating tokens at once would clobber each other's entries — losing the
    mapping needed to de-anonymize the final report, and handing the same
    number to two different values.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.forward: dict[str, str] = {}   # original_value -> TOKEN_N
        self.counters: dict[str, int] = {}  # prefix -> last N assigned
        self._load()

    # -- disk -------------------------------------------------------------- #
    @contextlib.contextmanager
    def _locked_file(self):
        """Hold an exclusive cross-process lock for a read-modify-write.

        The lock is taken on a sidecar .lock file rather than the map itself:
        the map is replaced via atomic rename, so a lock on its inode would be
        dropped the moment we rewrite it.
        """
        lock_path = TOKEN_MAP_PATH.with_suffix(TOKEN_MAP_PATH.suffix + ".lock")
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Unwritable location — fall back to in-process locking only.
            yield False
            return
        try:
            with open(lock_path, "w") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield True
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            yield False

    def _read_unlocked(self) -> tuple[dict[str, str], dict[str, int]]:
        if not TOKEN_MAP_PATH.exists():
            return {}, {}
        try:
            data = json.loads(TOKEN_MAP_PATH.read_text())
            return data.get("forward", {}) or {}, data.get("counters", {}) or {}
        except Exception:
            return {}, {}

    def _write_unlocked(self):
        try:
            TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {"forward": self.forward, "counters": self.counters}, indent=2
            )
            # Atomic replace so a reader never sees a half-written map.
            tmp = TOKEN_MAP_PATH.with_suffix(TOKEN_MAP_PATH.suffix + ".tmp")
            tmp.write_text(payload)
            tmp.replace(TOKEN_MAP_PATH)
        except Exception:
            pass  # Token map is best-effort; don't crash the proxy

    def _load(self):
        with self._locked_file():
            self.forward, self.counters = self._read_unlocked()

    def _merge_from_disk(self):
        """Adopt entries a sibling proxy wrote since we last looked."""
        disk_forward, disk_counters = self._read_unlocked()
        for value, token in disk_forward.items():
            self.forward.setdefault(value, token)
        for prefix, n in disk_counters.items():
            # Never hand back a number a sibling already issued.
            self.counters[prefix] = max(self.counters.get(prefix, 0), n)

    # -- api --------------------------------------------------------------- #
    def get_or_create(self, value: str, prefix: str) -> str:
        """Return the token for *value* (creating one if needed)."""
        if not value or not value.strip():
            return value
        with self._lock:
            existing = self.forward.get(value)
            if existing:
                return existing
            with self._locked_file():
                # Re-read inside the lock: a sibling may have just assigned
                # this very value, in which case we must reuse its token.
                self._merge_from_disk()
                existing = self.forward.get(value)
                if existing:
                    return existing
                n = self.counters.get(prefix, 0) + 1
                self.counters[prefix] = n
                token = f"{prefix}_{n}"
                self.forward[value] = token
                self._write_unlocked()
                return token

    def reverse_all(self) -> dict[str, str]:
        """Return a token -> original_value mapping for de-anonymization."""
        with self._lock:
            with self._locked_file():
                # Pick up tokens issued by sibling proxies so a report written
                # after a CoPilot search still de-anonymizes fully.
                self._merge_from_disk()
            return {tok: orig for orig, tok in self.forward.items()}


# ── Field config ──────────────────────────────────────────────────────────────

def _load_fields() -> dict:
    if not FIELDS_YAML.exists():
        return {}
    if not HAS_YAML:
        sys.stderr.write(
            "[anon-proxy] WARNING: pyyaml not installed — field config unavailable, "
            "falling back to IP/path pattern scanning only.\n"
        )
        return {}
    try:
        with open(FIELDS_YAML) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        sys.stderr.write(f"[anon-proxy] WARNING: could not load fields.yaml: {e}\n")
        return {}


# ── Anonymizer ────────────────────────────────────────────────────────────────

# Regex: IPv4 addresses
_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Regex: Windows user path component   C:\Users\<name>\
_WIN_USER_PATH_RE = re.compile(r'(?i)(C:\\Users\\)([^\\]+)(\\)')

# Regex: Linux home directory path   /home/<name>/
_LINUX_HOME_RE = re.compile(r'(/home/)([^/]+)(/)')


def _is_internal_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class Anonymizer:
    def __init__(self, token_map: TokenMap):
        self.token_map = token_map
        config = _load_fields()

        # field_name (and field_name.lower()) -> token_prefix
        self._field_index: dict[str, str] = {}
        # fields that must never be touched
        self._preserve: set[str] = set()

        for cat_name, cat in config.get("categories", {}).items():
            prefix = cat.get("token_prefix", cat_name.upper())
            for field in cat.get("fields", []):
                self._field_index[field] = prefix
                self._field_index[field.lower()] = prefix

        for field in config.get("preserve_fields", []):
            self._preserve.add(field)
            self._preserve.add(field.lower())

        self._internal_ip_prefix: str = config.get("internal_ip_token_prefix", "IP_INT")
        self._scan_user_paths: bool = config.get("scan_user_paths", True)
        self._scan_inline_ips: bool = config.get("scan_inline_ips", True)

    #: Guard against pathological nesting while still reaching real payloads.
    _MAX_JSON_DEPTH = 6

    def _anonymize_string(self, field_name: str, value: str, depth: int = 0) -> str:
        """Anonymize a single string value for a given field."""
        if not value:
            return value

        fname_lower = field_name.lower()

        # Preserve fields: return unchanged
        if field_name in self._preserve or fname_lower in self._preserve:
            return value

        # Direct field mapping: replace entire value
        prefix = self._field_index.get(field_name) or self._field_index.get(fname_lower)
        if prefix:
            return self.token_map.get_or_create(value, prefix)

        # A string that is itself JSON must be walked, not pattern-scanned.
        #
        # Field-name mapping is the only thing that catches a hostname or
        # username; pattern scanning finds just IPs and user paths. So a nested
        # document treated as an opaque string silently loses most of its
        # anonymization. This is not hypothetical: FastMCP serializes the
        # CoPilot tools' content blocks as an ordinary return value, so their
        # results arrive double-wrapped and the real event sits one layer
        # deeper than the transport content.
        nested = self._maybe_json(value, depth)
        if nested is not None:
            return nested

        # No direct mapping — apply pattern-based scanning
        return self._scan_patterns(value)

    def _maybe_json(self, value: str, depth: int):
        """If *value* is a JSON object/array, anonymize inside it and re-encode."""
        if depth >= self._MAX_JSON_DEPTH:
            return None
        stripped = value.lstrip()
        if not stripped.startswith(("{", "[")):
            return None
        try:
            # strict=False: log payloads routinely carry raw control characters.
            parsed = json.loads(value, strict=False)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None
        if not isinstance(parsed, (dict, list)):
            return None
        return json.dumps(
            self.anonymize_obj(parsed, depth=depth + 1), ensure_ascii=False
        )

    def _scan_patterns(self, text: str) -> str:
        """Apply pattern-based anonymization to an arbitrary text string."""
        if self._scan_inline_ips:
            def _replace_ip(m: re.Match) -> str:
                ip = m.group(0)
                if _is_internal_ip(ip):
                    return self.token_map.get_or_create(ip, self._internal_ip_prefix)
                return ip
            text = _IP_RE.sub(_replace_ip, text)

        if self._scan_user_paths:
            # Windows: C:\Users\john.doe\  →  C:\Users\USER_1\
            def _replace_win(m: re.Match) -> str:
                username = m.group(2)
                token = self.token_map.get_or_create(username, "USER")
                return m.group(1) + token + m.group(3)
            text = _WIN_USER_PATH_RE.sub(_replace_win, text)

            # Linux: /home/john.doe/  →  /home/USER_1/
            def _replace_linux(m: re.Match) -> str:
                username = m.group(2)
                token = self.token_map.get_or_create(username, "USER")
                return m.group(1) + token + m.group(3)
            text = _LINUX_HOME_RE.sub(_replace_linux, text)

        return text

    def anonymize_obj(self, obj: Any, parent_key: str = "", depth: int = 0) -> Any:
        """Recursively walk a deserialized JSON object and anonymize PII values."""
        if isinstance(obj, dict):
            return {k: self._anonymize_value(k, v, depth) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.anonymize_obj(item, parent_key, depth) for item in obj]
        elif isinstance(obj, str):
            return self._scan_patterns(obj)
        else:
            return obj

    def _anonymize_value(self, key: str, value: Any, depth: int = 0) -> Any:
        if isinstance(value, str):
            return self._anonymize_string(key, value, depth)
        return self.anonymize_obj(value, key, depth)

    def anonymize_content_blocks(self, content: list) -> list:
        """Anonymize MCP tool-result content blocks (list of {type, text})."""
        result = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text":
                result.append(block)
                continue
            text = block.get("text", "")
            try:
                parsed = json.loads(text, strict=False)
                anon = self.anonymize_obj(parsed)
                text = json.dumps(anon, ensure_ascii=False)
            except (json.JSONDecodeError, ValueError):
                text = self._scan_patterns(text)
            result.append({**block, "text": text})
        return result


# ── De-anonymize tool definition ──────────────────────────────────────────────

_DEANONYMIZE_TOOL = {
    "name": "deanonymize",
    "description": (
        "Reverse the anonymization applied to SIEM data during this session. "
        "Pass any text containing tokens like USER_1, HOST_2, IP_INT_3, EMAIL_1, etc., "
        "and receive the original values substituted back in. "
        "Always call this before writing the final analyst report so that usernames, "
        "hostnames, and internal IPs are accurate and meaningful to the analyst."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Text containing anonymization tokens to de-anonymize."
            }
        },
        "required": ["text"]
    }
}


# ── Proxy core ────────────────────────────────────────────────────────────────

class Proxy:
    """
    Bidirectional JSON-RPC proxy over stdin/stdout.

    Two threads run concurrently:
      • _client_to_child: reads from our stdin → forwards to child stdin
      • _child_to_client: reads from child stdout → anonymizes → writes to our stdout
    """

    def __init__(self):
        self.token_map = TokenMap()
        self.anonymizer = Anonymizer(self.token_map)

        # id → method for in-flight requests
        self._pending: dict[Any, str] = {}
        self._pending_lock = threading.Lock()

        # Protects writes to sys.stdout so both threads don't interleave
        self._stdout_lock = threading.Lock()

    def _write(self, msg: dict):
        line = json.dumps(msg, ensure_ascii=False) + "\n"
        with self._stdout_lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    def _client_to_child(self, child_stdin):
        for raw_line in sys.stdin:
            try:
                msg = json.loads(raw_line)
            except json.JSONDecodeError:
                child_stdin.write(raw_line.encode())
                child_stdin.flush()
                continue

            method = msg.get("method", "")
            msg_id = msg.get("id")

            # Track this request so we can recognise the response
            if msg_id is not None and method:
                with self._pending_lock:
                    self._pending[msg_id] = method

            # Handle deanonymize locally — do not forward to child
            if method == "tools/call":
                tool_name = (msg.get("params") or {}).get("name", "")
                if tool_name == "deanonymize":
                    response = self._handle_deanonymize(msg)
                    self._write(response)
                    with self._pending_lock:
                        self._pending.pop(msg_id, None)
                    continue

            child_stdin.write(raw_line.encode())
            child_stdin.flush()

    def _child_to_client(self, child_stdout):
        for raw_line in child_stdout:
            try:
                msg = json.loads(raw_line)
            except (json.JSONDecodeError, ValueError):
                with self._stdout_lock:
                    sys.stdout.buffer.write(raw_line)
                    sys.stdout.flush()
                continue

            msg_id = msg.get("id")
            with self._pending_lock:
                method = self._pending.pop(msg_id, None) if msg_id is not None else None

            # Inject deanonymize into tools/list results
            if method == "tools/list" and "result" in msg:
                tools = msg["result"].get("tools", [])
                if not any(t.get("name") == "deanonymize" for t in tools):
                    tools.append(_DEANONYMIZE_TOOL)
                msg["result"]["tools"] = tools

            # Anonymize tools/call results
            elif method == "tools/call" and "result" in msg:
                content = msg["result"].get("content")
                if isinstance(content, list):
                    msg["result"]["content"] = self.anonymizer.anonymize_content_blocks(content)

            self._write(msg)

    def _handle_deanonymize(self, request: dict) -> dict:
        args = (request.get("params") or {}).get("arguments") or {}
        text = args.get("text", "")
        reverse = self.token_map.reverse_all()

        # Replace longest tokens first to avoid partial substitutions
        for token in sorted(reverse, key=len, reverse=True):
            text = text.replace(token, reverse[token])

        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }

    def run(self):
        if not CHILD_WRAPPER.exists():
            sys.stderr.write(
                f"[anon-proxy:{PROXY_LABEL}] ERROR: wrapped MCP server not found at "
                f"{CHILD_WRAPPER}. Set ANON_PROXY_CHILD to the wrapper to proxy.\n"
            )
            sys.exit(1)

        child = subprocess.Popen(
            [str(CHILD_WRAPPER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )

        t_in = threading.Thread(
            target=self._client_to_child,
            args=(child.stdin,),
            daemon=True,
        )
        t_out = threading.Thread(
            target=self._child_to_client,
            args=(child.stdout,),
            daemon=True,
        )
        t_in.start()
        t_out.start()

        t_in.join()
        child.stdin.close()
        t_out.join()
        child.wait()


if __name__ == "__main__":
    Proxy().run()
