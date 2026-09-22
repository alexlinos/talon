"""Tests for the anonymizing MCP proxy.

Two things must hold for the CoPilot hunt tools to be safe to use:

1. Every key carrying PII is tokenized — including the synthetic `host` and
   `user` keys that the hunt tools' normalize_hit() emits, which are not raw
   Wazuh field names and so are easy to miss.
2. Tokens stay consistent across proxy instances. The OpenSearch proxy and the
   CoPilot proxy are separate OS processes sharing one token map file, so a
   hostname seen through either must get the same token and a single
   `deanonymize` call must reverse both.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def _fresh_module(token_map: Path):
    """Import anon_proxy with TOKEN_MAP_PATH pointed at a temp file.

    The path is a module-level constant read from the environment at import
    time, so each test needs a fresh import rather than a monkeypatched attr.
    """
    os.environ["ANON_PROXY_TOKEN_MAP"] = str(token_map)
    if "anon_proxy" in sys.modules:
        del sys.modules["anon_proxy"]
    return importlib.import_module("anon_proxy")


@pytest.fixture()
def mod(tmp_path):
    return _fresh_module(tmp_path / "session_tokens.json")


# --------------------------------------------------------------------------- #
# Field coverage
# --------------------------------------------------------------------------- #
def test_synthetic_hunt_keys_are_tokenized(mod):
    """`host` and `user` come from normalize_hit(), not from Wazuh."""
    anon = mod.Anonymizer(mod.TokenMap())
    shaped = {
        "host": "WIN-DC01",
        "user": "svc_backup",
        "rule_id": "92052",
        "raw_fields": {"agent_name": "WIN-DC01", "data_win_eventdata_user": "svc_backup"},
    }
    out = anon.anonymize_obj(shaped)

    assert out["host"].startswith("HOST_")
    assert out["user"].startswith("USER_")
    # Rule metadata is preserved — it drives MITRE/threat-intel correlation.
    assert out["rule_id"] == "92052"


def test_shaped_and_raw_views_get_the_same_token(mod):
    """The same host must not appear tokenized in one key and clear in another.

    This is the specific leak that adding `host`/`user` to fields.yaml closes:
    normalize_hit copies agent_name into `host`, so missing the synthetic key
    would expose the very value raw_fields tokenizes.
    """
    anon = mod.Anonymizer(mod.TokenMap())
    out = anon.anonymize_obj({"host": "WIN-DC01", "raw_fields": {"agent_name": "WIN-DC01"}})

    assert out["host"] == out["raw_fields"]["agent_name"]
    assert "WIN-DC01" not in json.dumps(out)


def test_internal_ips_tokenized_external_preserved(mod):
    anon = mod.Anonymizer(mod.TokenMap())
    out = anon.anonymize_obj({"full_log": "conn from 10.1.2.3 to 8.8.8.8"})

    assert "10.1.2.3" not in out["full_log"]
    assert "IP_INT_1" in out["full_log"]
    # External IPs must survive for VirusTotal / Shodan lookups.
    assert "8.8.8.8" in out["full_log"]


# --------------------------------------------------------------------------- #
# Cross-instance token sharing
# --------------------------------------------------------------------------- #
def test_two_instances_share_tokens(tmp_path):
    """Mirrors the OpenSearch proxy and the CoPilot proxy running side by side."""
    path = tmp_path / "session_tokens.json"
    mod = _fresh_module(path)

    opensearch_side = mod.TokenMap()
    token = opensearch_side.get_or_create("WIN-DC01", "HOST")

    # A second process starting later must reuse, not reassign.
    copilot_side = mod.TokenMap()
    assert copilot_side.get_or_create("WIN-DC01", "HOST") == token


def test_live_instance_picks_up_a_siblings_token(tmp_path):
    """Both instances are already running when the sibling assigns a token."""
    path = tmp_path / "session_tokens.json"
    mod = _fresh_module(path)

    first, second = mod.TokenMap(), mod.TokenMap()
    token = first.get_or_create("WIN-DC01", "HOST")

    # `second` was constructed before the assignment, so it must re-read.
    assert second.get_or_create("WIN-DC01", "HOST") == token


def test_concurrent_instances_never_reuse_a_number(tmp_path):
    """Distinct values must never collide onto one token.

    Without the read-modify-write under flock, two instances each starting from
    counter 0 would both mint HOST_1 for different hosts.
    """
    path = tmp_path / "session_tokens.json"
    mod = _fresh_module(path)

    a, b = mod.TokenMap(), mod.TokenMap()
    tokens = {
        a.get_or_create("host-a", "HOST"),
        b.get_or_create("host-b", "HOST"),
        a.get_or_create("host-c", "HOST"),
    }
    assert len(tokens) == 3, f"tokens collided: {tokens}"


def test_deanonymize_reverses_tokens_from_both_servers(tmp_path):
    """A report written after a CoPilot search must de-anonymize fully."""
    path = tmp_path / "session_tokens.json"
    mod = _fresh_module(path)

    opensearch_side = mod.TokenMap()
    host_token = opensearch_side.get_or_create("WIN-DC01", "HOST")

    copilot_side = mod.TokenMap()
    user_token = copilot_side.get_or_create("svc_backup", "USER")

    # Whichever proxy handles the deanonymize call must see both.
    reverse = opensearch_side.reverse_all()
    assert reverse[host_token] == "WIN-DC01"
    assert reverse[user_token] == "svc_backup"


def test_token_map_survives_a_restart(tmp_path):
    path = tmp_path / "session_tokens.json"
    mod = _fresh_module(path)

    token = mod.TokenMap().get_or_create("WIN-DC01", "HOST")
    assert json.loads(path.read_text())["forward"]["WIN-DC01"] == token
    assert mod.TokenMap().get_or_create("WIN-DC01", "HOST") == token


def test_unwritable_token_map_does_not_crash(tmp_path):
    """Anonymization must still happen even if the map cannot be persisted."""
    mod = _fresh_module(tmp_path / "nope" / "deep" / "session_tokens.json")
    anon = mod.Anonymizer(mod.TokenMap())
    out = anon.anonymize_obj({"host": "WIN-DC01"})
    assert out["host"].startswith("HOST_")


# --------------------------------------------------------------------------- #
# Child selection
# --------------------------------------------------------------------------- #
def test_child_defaults_to_opensearch(tmp_path, monkeypatch):
    """Existing deployments must be unaffected by the parameterization."""
    monkeypatch.delenv("ANON_PROXY_CHILD", raising=False)
    mod = _fresh_module(tmp_path / "t.json")
    assert mod.CHILD_WRAPPER.name == "opensearch-mcp.sh"


def test_child_is_overridable(tmp_path, monkeypatch):
    monkeypatch.setenv("ANON_PROXY_CHILD", "/workspace/extra/copilot-mcp/copilot-mcp.sh")
    mod = _fresh_module(tmp_path / "t.json")
    assert mod.CHILD_WRAPPER.name == "copilot-mcp.sh"
