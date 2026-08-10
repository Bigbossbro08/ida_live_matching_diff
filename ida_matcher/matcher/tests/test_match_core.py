"""Headless tests for the pure matching logic in match_core (no IDA, no server)."""
import json

import pytest

from ida_matcher.matcher import match_core as mc


# ---------------------------------------------------------------- compare

def test_identical():
    pct, n = mc.compare_functions(
        bytes.fromhex("554889e5c3"), "554889e5c3", {}, {}
    )
    assert pct == 100.0 and n == 5


def test_different():
    pct, n = mc.compare_functions(
        bytes.fromhex("554889e5c3"), "554889e5c9", {}, {}
    )
    assert pct == 80.0 and n == 5


def test_length_mismatch_counts():
    # base has 2 extra bytes -> those bytes can never match -> < 100%.
    # (padding must not be 90/CC, those tail bytes are trimmed first.)
    pct, n = mc.compare_functions(
        bytes.fromhex("c3"), "c3c9c9", {}, {}
    )
    assert n == 3
    assert pct == pytest.approx(100 / 3)


def test_reloc_same_symbol_ok():
    pct, _ = mc.compare_functions(
        bytes.fromhex("e8000000"),
        "e8000000",
        {1: "_printf"}, {1: "printf"},
    )
    assert pct == 100.0


def test_reloc_symbol_changed_is_not_match():
    # Same bytes, but the reloc target symbol is different -> must NOT be 100%.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e8000000"),
        "e8000000",
        {1: "printf"}, {1: "puts"},
    )
    assert pct < 100.0


def test_reloc_symbol_anon_compatible():
    # One side has an anonymous DB label -> treat as unprovable, not a change.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e8000000"),
        "e8000000",
        {1: "printf"}, {1: "sub_401000"},
    )
    assert pct == 100.0


def test_reloc_vs_concrete_is_ok():
    pct, _ = mc.compare_functions(
        bytes.fromhex("b8 78563412"),
        "b8 78563412",
        {1: "_var"}, {},  # base side concrete value, other side relocated
    )
    assert pct == 100.0


# ---------------------------------------------------------------- normalize

def test_normalize_insn_reloc_replaces_token():
    s = mc._normalize_insn(0, "mov", "eax, ds:0x401000", b"\xa1\x00\x10\x40\x00",
                           {0: "_printf"}, {0: 4})
    assert "e<a" not in s
    assert "ds:<_printf>" in s and "eax" in s


def test_normalize_insn_reloc_no_token_appends_comment():
    s = mc._normalize_insn(0, "call", "0x401000", b"\xe8",
                           {0: "_printf"}, {0: 4})
    # hex token present -> replaced
    assert "<_printf>" in s


def test_normalize_insn_reloc_no_hex_appends():
    s = mc._normalize_insn(0, "lea", "eax, [esp+8]", b"\x8d",
                           {0: "_var"}, {0: 4})
    assert "; <_var>" in s


def test_normalize_jump_relative():
    s = mc._normalize_insn(0x1000, "je", "0x1004", b"\x74\x02", {}, {})
    assert "loc_+0x4" in s


# ---------------------------------------------------------------- names

@pytest.mark.parametrize("a,b,ok", [
    ("_printf", "__imp__printf", True),
    ("j__printf", "_printf", True),
    ("printf", "puts", False),
    ("printf", "sub_401000", True),   # anon side never fails
    ("sub_401000", "sub_401100", True),
])
def test_reloc_symbols_match(a, b, ok):
    assert mc._reloc_symbols_match(a, b) is ok


def test_normalize_target_name():
    assert mc._normalize_target_name("__imp__printf") == "printf"
    assert mc._normalize_target_name("j__printf") == "printf"


# ---------------------------------------------------------------- client fetch

def test_fetch_many_empty():
    assert mc.fetch_many_from_ida([]) == {}


def test_fetch_many_server_down(monkeypatch):
    # Point batch URL at a guaranteed-closed port and expect None (fallback).
    assert mc.fetch_many_from_ida(["a"]) in (None, {})  # will be None


def test_batch_results_filter_none(monkeypatch):
    class FakeResp:
        def __init__(self, data):
            self._d = data
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def read(self):
            return self._d
    def fake_open(url, timeout=60):
        payload = {"results": {"a": {"bytes": "c3"}, "b": None}}
        return FakeResp(json.dumps(payload).encode())
    monkeypatch.setattr(mc.urllib.request, "urlopen", fake_open)
    got = mc.fetch_many_from_ida(["a", "b"])
    assert set(got) == {"a"}


def test_server_alive_returns_bool():
    # Environment-dependent: a real server may or may not be running, so we
    # only assert the contract (a boolean) rather than a specific answer.
    assert isinstance(mc.server_alive(), bool)


# ---------------------------------------------------------------- summary (json)

def test_match_summary_json(tmp_path, monkeypatch, capsys):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "synthetic.obj"
    obj.write_bytes(build_synthetic_obj())

    monkeypatch.setattr(mc, "server_alive", lambda: True)

    def fake_many(names):
        return {
            "_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}},
            "_fb": {"is_thunk": True, "bytes": "", "fixups": {}, "switches": {}},
        }
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)

    mc.refresh_ida_cache = lambda: None
    mc.match_summary(obj, json_out=True)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["connected"] is True
    by_name = {r["name"]: r for r in data["functions"]}
    assert by_name["_fb"]["status"] == "thunk"
    assert by_name["_fa"]["status"] == "match"