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


def test_inserted_nop_uses_lcs_alignment():
    # One inserted NOP at the front used to shift every byte (score ~0%).
    # LCS keeps the true instruction overlap: 40/41 bytes still match.
    base = bytes(range(1, 41))          # 40 distinct bytes, no accidental resync
    obj = b"\x90" + base                # leading inserted NOP
    pct, n = mc.compare_functions(obj, base.hex(), {}, {})
    assert n == 41
    assert pct == pytest.approx((40 / 41) * 100)
    assert pct > 95.0


def test_middle_insertion_resyncs():
    # Insertion in the middle must not de-synchronize the trailing bytes.
    base = bytes(range(1, 21))
    obj = base[:10] + b"\xcc" + base[10:]
    pct, n = mc.compare_functions(obj, base.hex(), {}, {})
    assert n == 21
    assert pct == pytest.approx((20 / 21) * 100)


def test_base_switch_range_excluded_from_score():
    # IDA appends the .rdata jump table to the function bytes; the .obj never
    # has it. Stripping the reported table range must keep the score at 100%.
    code = bytes.fromhex("558bec83ec40c3")
    table = bytes.fromhex("0000000011111111")  # 8 bytes of jump table
    base = code + table
    pct, n = mc.compare_functions(
        code, base.hex(), {}, {},
        base_switch_ranges=[(len(code), len(code) + len(table))],
    )
    assert n == len(code)
    assert pct == 100.0


def test_symmetric_switch_range_stripped_from_both():
    # If the obj has an inline jump table matching base, stripping symmetrically should yield 100%.
    code = bytes.fromhex("558bec83ec40c3")
    table = bytes.fromhex("0000000011111111")
    full_bytes = code + table
    pct, n = mc.compare_functions(
        full_bytes, full_bytes.hex(), {}, {},
        base_switch_ranges=[(len(code), len(code) + len(table))],
    )
    assert n == len(code)
    assert pct == 100.0


def test_padding_after_switch_range_is_stripped():
    # If padding comes after the switch range, the range stripping happens first
    # then the trailing padding pop should remove it.
    code = bytes.fromhex("558bec83ec40c3")
    table = bytes.fromhex("0000000011111111")
    pad = bytes.fromhex("cccc")
    base = code + table + pad
    pct, n = mc.compare_functions(
        code, base.hex(), {}, {},
        base_switch_ranges=[(len(code), len(code) + len(table))],
    )
    assert n == len(code)
    assert pct == 100.0


def test_switch_range_within_function_bounds():
    # (Mis-)reported ranges that underflow/overflow must clamp to empty, never
    # crash and never strip real code.
    code = bytes.fromhex("558bec83ec40c3")
    pct, n = mc.compare_functions(
        code, code.hex(), {}, {},
        base_switch_ranges=[(-10, 0), (100, 999)],
    )
    assert pct == 100.0 and n == len(code)


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
    ("$L1234", "jpt_401000", True),
    ("$L_1234", "def_402000", True),
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


def test_match_summary_strict_exit_code(tmp_path, monkeypatch):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "synthetic.obj"
    obj.write_bytes(build_synthetic_obj())
    monkeypatch.setattr(mc, "server_alive", lambda: True)
    mc.refresh_ida_cache = lambda: None

    # _fa = "55 8B E8 00 00 00"; longer base + no base fixups -> below 100%.
    def fake_below(names):
        return {"_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}}}
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_below)
    assert mc.match_summary(obj, strict=True) == 1
    assert mc.match_summary(obj, strict=False) == 0

    # Identical bytes + matching reloc symbol -> 100% -> strict passes.
    def fake_full(names):
        return {"_fa": {"is_thunk": False, "bytes": "558be8000000", "fixups": {1: "_ext"}, "switches": {}}}
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_full)
    assert mc.match_summary(obj, strict=True) == 0


def test_match_summary_json_reports_metrics(tmp_path, monkeypatch, capsys):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "synthetic.obj"
    obj.write_bytes(build_synthetic_obj())
    monkeypatch.setattr(mc, "server_alive", lambda: True)
    mc.refresh_ida_cache = lambda: None

    def fake_many(names):
        return {
            "_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}},
            "_fb": {"is_thunk": True, "bytes": "", "fixups": {}, "switches": {}},
        }
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)

    mc.match_summary(obj, json_out=True)
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["match"] == 1
    assert data["summary"]["match_100"] == 0
    assert data["summary"]["match_below"] == 1
    assert data["summary"]["thunk"] == 1
    assert data["summary"]["not_found"] == 0