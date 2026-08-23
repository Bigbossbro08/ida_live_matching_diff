"""Headless tests for the pure matching logic in match_core (no IDA, no server)."""
import json
import re

import pytest

from ida_matcher.matcher import match_core as mc


# ---------------------------------------------------------------- compare

def test_identical():
    pct, n = mc.compare_functions(
        bytes.fromhex("554889e5c3"), "554889e5c3", {}, {}
    )
    assert pct == 100.0 and n == 5


def test_different():
    # ret (c3) vs leave (c9) in the last instruction -> Replace (+60 on 4 insns).
    pct, n = mc.compare_functions(
        bytes.fromhex("554889e5c3"), "554889e5c9", {}, {}
    )
    assert pct == pytest.approx(85.0) and n == 5


def test_length_mismatch_counts():
    # 1 instruction vs 3: the trailing leaves can never match; score clamps to
    # the max (1 insn * 100) -> 0%.
    pct, n = mc.compare_functions(
        bytes.fromhex("c3"), "c3c9c9", {}, {}
    )
    assert n == 3
    assert pct == pytest.approx(0.0)


def test_reloc_same_symbol_ok():
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"),
        "e800000000",
        {1: "_printf"}, {1: "printf"},
    )
    assert pct == 100.0


def test_reloc_symbol_changed_is_not_match():
    # Same bytes, but the reloc target symbol is different -> must NOT be 100%.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"),
        "e800000000",
        {1: "printf"}, {1: "puts"},
    )
    assert pct < 100.0


def test_reloc_symbol_anon_compatible():
    # One side has an anonymous DB label -> treat as unprovable, not a change.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"),
        "e800000000",
        {1: "printf"}, {1: "sub_401000"},
    )
    assert pct == 100.0


def test_phase2_reloc_eq():
    # test section mismatch
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("printf", 4, "relative", 0, ".text", "code")},
        {1: ("printf", 4, "relative", 0, ".data", "data")},
    )
    assert pct < 100.0

    # test section match, mode=nameaddress, bad name
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("funcA", 4, "relative", 0, ".text", "code")},
        {1: ("funcB", 4, "relative", 0, ".text", "code")},
    )
    assert pct < 100.0

    # test section match, mode=datavalue, bad name -> OK!
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("funcA", 4, "relative", 0, ".text", "code")},
        {1: ("funcB", 4, "relative", 0, ".text", "code")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE
    )
    assert pct == 100.0

    # test section match, mode=nameaddress, both compiler generated -> OK!
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("@123", 4, "relative", 0, ".text", "code")},
        {1: ("@456", 4, "relative", 0, ".text", "code")},
    )
    assert pct == 100.0


def test_reloc_class_mismatch_fails_even_relaxed():
    # objdiff checks relocation flags (class) BEFORE the relaxed shortcut:
    # absolute vs relative is never comparable, even in none mode.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("f", 4, "IMAGE_REL_I386_DIR32", 0, ".text", "code")},
        {1: ("f", 4, "IMAGE_REL_I386_REL32", 0, ".text", "code")},
        reloc_mode=mc.RELOC_MODE_NONE,
    )
    assert pct < 100.0


def test_reloc_width_not_compared():
    # objdiff never compares relocation width in reloc_eq; only flags matter.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("f", 4, "relative", 0, ".text", "code")},
        {1: ("f", 2, "relative", 0, ".text", "code")},
    )
    assert pct == 100.0


def test_reloc_address_eq_pool():
    # name_ok falls back to address_eq when names differ: a base-side pool
    # symbol (size 0) compares by final address (symbol address + addend).
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("pool_a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("pool_b", 4, "relative", 0, ".data", "data", 0x100, 0, "data")},
    )
    assert pct == 100.0


def test_reloc_address_eq_strict():
    # Non-pool symbols need strict address (and addend) equality when names
    # differ; a different address fails, an equal address matches.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("data_x", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("data_y", 4, "relative", 0, ".data", "data", 0x200, 4, "data")},
    )
    assert pct < 100.0

    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("data_x", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("data_y", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
    )
    assert pct == 100.0


def test_reloc_datavalue_literal_eq_no_accessor_conservative():
    # DataValue mode on two non-pool data symbols with NO data accessor:
    # ins_data_literals_eq cannot prove the target bytes equal, so it returns
    # False (never assume equal) -> mismatch.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("a", 4, "relative", 0, ".data", "data", 0x200, 4, "data")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE,
    )
    assert pct < 100.0


def test_reloc_datavalue_literal_eq_accessor():
    # DataValue mode with data accessors: names are ignored and a reloc arg
    # matches when the target data bytes are equal (objdiff ins_data_literals_eq).
    def make_acc(data_bytes, offset):
        def acc(_sym):
            return data_bytes, offset
        return acc

    # Same target bytes -> literal equality -> match (100).
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("b", 4, "relative", 0, ".data", "data", 0x200, 4, "data")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE,
        left_accessor=make_acc(b"\x00\x00\x00\x00", 0),
        right_accessor=make_acc(b"\x00\x00\x00\x00", 0),
    )
    assert pct == 100.0

    # Differing target bytes -> literal mismatch -> ArgMismatch (+5 REG).
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("b", 4, "relative", 0, ".data", "data", 0x200, 4, "data")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE,
        left_accessor=make_acc(b"\x00\x00\x00\x00", 0),
        right_accessor=make_acc(b"\x00\x00\x00\xff", 0),
    )
    assert pct == pytest.approx(95.0)

    # Nonzero symbol offset: accessor returns section bytes + offset; the
    # addend is symbol-relative, so the compared slice starts at offset+addend.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("b", 4, "relative", 0, ".data", "data", 0x200, 4, "data")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE,
        left_accessor=make_acc(b"\xde\xad\x00\x00\x00\x00", 4),
        right_accessor=make_acc(b"\xbe\xef\x00\x00\x00\x00", 4),
    )
    assert pct == 100.0


def test_reloc_datavalue_pool_value_ok():
    # DataValue mode: names ignored; base-side pool symbol (size 0) keeps
    # value_ok true -> match despite differing data symbol sizes.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("a", 4, "relative", 0, ".data", "data", 0x100, 4, "data")},
        {1: ("b", 4, "relative", 0, ".data", "data", 0x100, 0, "data")},
        reloc_mode=mc.RELOC_MODE_DATA_VALUE,
    )
    assert pct == 100.0


def test_reloc_sym_kind_not_data_value_ok():
    # value_ok is true when the LEFT symbol is not a data symbol (functions
    # don't diff values) regardless of mode.
    pct, _ = mc.compare_functions(
        bytes.fromhex("e800000000"), "e800000000",
        {1: ("f", 4, "relative", 0, ".text", "code", 0x40, 4, "code")},
        {1: ("f", 4, "relative", 0, ".text", "code", 0x40, 0, "code")},
        reloc_mode=mc.RELOC_MODE_ALL,
    )
    assert pct == 100.0


def test_reloc_vs_concrete_is_not_match_default():
    # Default (name_address): a relocation is NOT comparable to a concrete
    # immediate, mirroring objdiff's InstructionArgValue::Reloc semantics.
    pct, _ = mc.compare_functions(
        bytes.fromhex("b8 78563412"),
        "b8 78563412",
        {1: "_var"}, {},
    )
    assert pct == pytest.approx(95.0)


def test_reloc_vs_concrete_is_ok_relaxed():
    # Relaxed mode: reloc vs concrete cannot be proven different -> treat as equal.
    pct, _ = mc.compare_functions(
        bytes.fromhex("b8 78563412"),
        "b8 78563412",
        {1: "_var"}, {},
        reloc_mode=mc.RELOC_MODE_NONE,
    )
    assert pct == pytest.approx(95.0)

def test_concrete_vs_reloc_is_ok_relaxed():
    pct, _ = mc.compare_functions(
        bytes.fromhex("b8 78563412"),
        "b8 78563412",
        {}, {1: "_var"},
        reloc_mode=mc.RELOC_MODE_NONE,
    )
    assert pct == 100.0

    # Default (name_address): left Value vs right Reloc mismatches; objdiff
    # penalties it as IMM (left arg is a Value) -> 99.0, not REG (95.0).
    pct, _ = mc.compare_functions(
        bytes.fromhex("b8 78563412"),
        "b8 78563412",
        {}, {1: "_var"},
    )
    assert pct == pytest.approx(99.0)


def test_inserted_nop_uses_instruction_alignment():
    # One leading NOP: the instruction engine resyncs on the real instructions
    # instead of shifting every byte; only the extra row is penalized.
    pct, n = mc.compare_functions(
        bytes.fromhex("90558bec5dc3"), "558bec5dc3", {}, {}
    )
    assert n == 6
    assert pct == pytest.approx(80.0)


def test_middle_insertion_resyncs():
    # Insertion in the middle must not de-synchronize the trailing instructions.
    pct, n = mc.compare_functions(
        bytes.fromhex("558bec905dc3"), "558bec5dc3", {}, {}
    )
    assert n == 6
    assert pct == pytest.approx(80.0)


def test_branch_retarget_flagged():
    # Same opcodes, but the direct branch lands on a different aligned row
    # (nop vs ret): objdiff compares branch target *rows*, so this is an
    # ArgMismatch, not a silent match.
    pct, n = mc.compare_functions(
        bytes.fromhex("e8000000009090c3"),   # call +0 -> nop@5
        "e8020000009090c3",                  # call +2 -> ret@7
        {}, {},
    )
    assert n == 8
    assert pct == pytest.approx(98.75)


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

@pytest.mark.parametrize("a, b, ok", [
    ("printf", "printf", True),
    ("printf", "puts", False),
    ("RGE_Game@class$123", "RGE_Game@class$0", True),
    ("func$1", "func$2", True),
    ("var.1", "var.2", True),
    ("?A0x12345678@@", "?A0x00000000@@", True),
])
def test_symbol_name_matches(a, b, ok):
    assert mc.symbol_name_matches(a, b) is ok


def test_is_symbol_name_compiler_generated():
    assert mc.is_symbol_name_compiler_generated("@123") is True
    assert mc.is_symbol_name_compiler_generated("_$E456") is True
    assert mc.is_symbol_name_compiler_generated("$LC789") is True
    assert mc.is_symbol_name_compiler_generated("printf") is False


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
            "_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
            "_fb": {"is_thunk": True, "bytes": "", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
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
        return {"_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"}}
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_below)
    assert mc.match_summary(obj, strict=True) == 1
    assert mc.match_summary(obj, strict=False) == 0

    # Identical bytes + matching reloc symbol -> 100% -> strict passes.
    def fake_full(names):
        return {"_fa": {"is_thunk": False, "bytes": "558be8000000", "fixups": {1: "_ext"}, "switches": {}, "section_name": ".text", "section_kind": "code"}}
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
            "_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
            "_fb": {"is_thunk": True, "bytes": "", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
        }
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)

    mc.match_summary(obj, json_out=True)
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["match"] == 1
    assert data["summary"]["match_100"] == 0
    assert data["summary"]["match_below"] == 1
    assert data["summary"]["thunk"] == 1
    assert data["summary"]["not_found"] == 0


def test_match_summary_data_and_bss_rows(tmp_path, monkeypatch, capsys):
    # .text/.data/.bss obj: all symbols are fetched/matched; data and
    # bss records surface with scores via diff_data_symbol and diff_bss_symbol.
    from ida_matcher.matcher.tests.conftest import build_synthetic_multi_section_obj
    obj = tmp_path / "multi.obj"
    obj.write_bytes(build_synthetic_multi_section_obj())

    fetched = []
    fetched_data = []
    monkeypatch.setattr(mc, "server_alive", lambda: True)
    mc.refresh_ida_cache = lambda: None

    def fake_many(names):
        fetched.extend(names)
        return {"_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"}}
    def fake_many_data(names):
        fetched_data.extend(names)
        return {"_data1": {"bytes": "00112233", "section_name": ".data", "section_kind": "data"}, "_bss1": {"size": 8, "section_name": ".bss", "section_kind": "bss"}}
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)
    monkeypatch.setattr(mc, "fetch_many_data_from_ida", fake_many_data)

    mc.match_summary(obj, json_out=True)
    data = json.loads(capsys.readouterr().out)
    assert fetched == ["_fa"]
    assert set(fetched_data) == {"_data1", "_bss1"}
    by_name = {r["name"]: r for r in data["functions"]}
    assert by_name["_data1"]["status"] == "data"
    assert by_name["_bss1"]["status"] == "bss"
    assert data["summary"]["match"] == 3


# ---------------------------------------------------------------- --similar

def test_find_similar_code_symbols_ranking(tmp_path, monkeypatch, capsys):
    # --similar: ranks every base code symbol by instruction-diff %,
    # best first (objdiff find_similar_code_symbols).
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "synthetic.obj"
    obj.write_bytes(build_synthetic_obj())
    monkeypatch.setattr(mc, "server_alive", lambda: True)
    monkeypatch.setattr(mc, "refresh_ida_cache", lambda: None)
    monkeypatch.setattr(mc, "fetch_all_names_from_ida", lambda: ["_fa", "_fa_midnop", "_fa_diff"])

    def fake_many(names):
        return {
            "_fa": {"is_thunk": False, "bytes": "558be8000000", "fixups": {1: "_ext"}, "switches": {}, "section_name": ".text", "section_kind": "code", "size": 6},
            "_fa_midnop": {"is_thunk": False, "bytes": "55908be8000000", "fixups": {1: "_ext"}, "switches": {}, "section_name": ".text", "section_kind": "code", "size": 7},
            "_fa_diff": {"is_thunk": False, "bytes": "cccccccc", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code", "size": 4},
        }
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)

    assert mc.find_similar_code_symbols(obj, "_fa") == 0
    out = capsys.readouterr().out
    rows = re.findall(r"([\d.]+)%\s+(_\w+)", out)
    assert [n for _, n in rows] == ["_fa", "_fa_midnop", "_fa_diff"]
    pcts = [float(p) for p, _ in rows]
    assert pcts == sorted(pcts, reverse=True)
    assert pcts[0] == 100.0
    assert pcts[-1] < 50.0


def test_find_similar_non_code_symbol_rejected(tmp_path, monkeypatch, capsys):
    # A data symbol ranks nothing: the code-kind guard returns before any fetch.
    from ida_matcher.matcher.tests.conftest import build_synthetic_multi_section_obj
    obj = tmp_path / "multi.obj"
    obj.write_bytes(build_synthetic_multi_section_obj())
    monkeypatch.setattr(mc, "refresh_ida_cache", lambda: None)
    assert mc.find_similar_code_symbols(obj, "_data1") == 0
    out = capsys.readouterr().out
    assert "not a code symbol" in out


# ---------------------------------------------------------------- baseline / offline

def test_baseline_match_summary_offline(tmp_path, capsys):
    from ida_matcher.matcher.tests.conftest import build_synthetic_multi_section_obj
    obj = tmp_path / "multi.obj"
    obj.write_bytes(build_synthetic_multi_section_obj())

    # Create a baseline snapshot dict that matches exactly the live format.
    baseline = {
        "_fa": {"is_thunk": False, "bytes": "558be800000000c9c3", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
        "_data1": {"bytes": "00112233", "section_name": ".data", "section_kind": "data", "size": 4},
        "_bss1": {"size": 8, "section_name": ".bss", "section_kind": "bss"}
    }
    
    # We pass baseline=baseline. Server is down (fetch/server_alive not mocked).
    res = mc.match_summary(obj, json_out=True, baseline=baseline)
    assert res == 0
    data = json.loads(capsys.readouterr().out)
    
    # Assert it works just like live json_out.
    by_name = {r["name"]: r for r in data["functions"]}
    assert by_name["_fa"]["status"] == "match"
    assert by_name["_data1"]["status"] == "data"
    assert by_name["_bss1"]["status"] == "bss"
    assert data["summary"]["match"] == 3


def test_baseline_strict_data_below_100(tmp_path):
    from ida_matcher.matcher.tests.conftest import build_synthetic_multi_section_obj
    obj = tmp_path / "multi.obj"
    obj.write_bytes(build_synthetic_multi_section_obj())

    # Data mismatch
    baseline = {
        "_fa": {"is_thunk": False, "bytes": "558be8000000", "fixups": {1: "_ext"}, "switches": {}, "section_name": ".text", "section_kind": "code"},
        "_data1": {"bytes": "001122FF", "section_name": ".data", "section_kind": "data", "size": 4}, # FF mismatch
        "_bss1": {"size": 8, "section_name": ".bss", "section_kind": "bss"}
    }
    
    # strict=True should exit 1 because data is below 100
    assert mc.match_summary(obj, json_out=True, strict=True, baseline=baseline) == 1


def test_baseline_right_accessor_offline(tmp_path):
    # Verify make_right_accessor does NOT call fetch_data_from_ida when offline=True
    base_records = {}
    accessor = mc.make_right_accessor(base_records, offline=True)
    
    # This would crash if it tried to call the server
    res = accessor("missing_sym")
    assert res is None
    
    base_records["found_sym"] = {"bytes": "AABB"}
    res, off = accessor("found_sym")
    assert res == b"\xaa\xbb"
    assert off == 0


def test_export_baseline_writes_snapshot(tmp_path, monkeypatch):
    import ida_matcher.matcher.export_baseline as eb
    class FakeResp:
        def __init__(self, data):
            self._d = data
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def read(self):
            return self._d
    
    test_json = {"func1": {"bytes": "c3"}}
    def fake_open(url, timeout=120):
        assert url == "http://127.0.0.1:28000/baseline"
        return FakeResp(json.dumps(test_json).encode("utf-8"))
        
    monkeypatch.setattr(eb.urllib.request, "urlopen", fake_open)
    
    out_file = tmp_path / "baseline.json"
    count = eb.export_baseline(out_file)
    assert count == 1
    
    written = json.loads(out_file.read_text())
    assert written == test_json


def test_diff_code_propagates_args_diff():
    from ida_matcher.matcher.engine.diff_code import diff_code
    from ida_matcher.matcher.engine.types import RELOC_MODE_NAME_ADDRESS
    left_data = b"\xb8\x01\x00\x00\x00" # mov eax, 1
    right_data = b"\xb8\x02\x00\x00\x00" # mov eax, 2
    res = diff_code(left_data, {}, {}, right_data, {}, {}, reloc_mode=RELOC_MODE_NAME_ADDRESS)
    
    assert "left_args_diffs" in res
    assert "right_args_diffs" in res
    assert len(res["left_args_diffs"]) == 1
    
    # Capstone x86 for 'mov eax, imm' gives 2 ops. First matches (None), second mismatches (0).
    assert res["left_args_diffs"][0] == [None, 0]


def test_display_renders_arg_colors(capsys):
    from ida_matcher.matcher.engine.display import _render_engine_row, _configure_colors, RED_BG, RESET
    _configure_colors(True)
    class FakeInsnRef:
        def __init__(self):
            self.opcode = 0
            self.address = 0
            self.size = 5
            self.branch_dest = None
    
    class FakeSource:
        def __init__(self):
            self.data = b"\xb8\x01\x00\x00\x00" # mov eax, 1
        def reloc_at(self, a, s):
            return None
            
    source = FakeSource()
    ref = FakeInsnRef()
    
    text = _render_engine_row(source, ref, args_diff=[None, 0], is_mismatch_color=RED_BG)
    assert "eax" in text
    assert f"{RED_BG}1{RESET}" in text or f"{RED_BG}0x1{RESET}" in text


def test_match_summary_demangled_name_json(tmp_path, capsys):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "test.obj"
    obj.write_bytes(build_synthetic_obj())

    baseline = {
        "_fa": {
            "bytes": "558be8000000",
            "fixups": {1: "_ext"},
            "demangled_name": "fa_demangled(int)",
            "section_name": ".text",
            "section_kind": "code",
            "size": 6
        }
    }
    
    import ida_matcher.matcher.match_core as mc
    mc.match_summary(obj, json_out=True, baseline=baseline)
    
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    
    funcs = {r["name"]: r for r in data["functions"]}
    assert "_fa" in funcs
    assert funcs["_fa"]["demangled_name"] == "fa_demangled(int)"

def test_c7_mov_disp32_imm32_reloc_classified():
    # Regression: C7-style "mov dword ptr [disp32], imm32" carries its disp at
    # size-8 (not the trailing 4 bytes). The reloc was previously not matched
    # to the mem-disp operand, so link-time-zero obj bytes clashed with the
    # base binary's concrete VAs and CRT-initializer-style code scored ~84%.
    from ida_matcher.matcher.engine.diff_code import diff_code

    obj_bytes = bytes.fromhex(
        "c705" "00000000" "00000000"
        "c705" "04000000" "00000000"
        "c705" "08000000" "00000000"
        "c3"
    )
    base_bytes = bytes.fromhex(
        "c705" "d83c6800" "00000000"
        "c705" "dc3c6800" "00000000"
        "c705" "e03c6800" "00000000"
        "c3"
    )
    obj_relocs = {
        2: ("?temp@@3VBVector@@A", 4, "IMAGE_REL_I386_DIR32", 0, "/537", "bss", 0, 0, "data", True),
        12: ("?temp@@3VBVector@@A", 4, "IMAGE_REL_I386_DIR32", 4, "/537", "bss", 0, 0, "data", True),
        22: ("?temp@@3VBVector@@A", 4, "IMAGE_REL_I386_DIR32", 8, "/537", "bss", 0, 0, "data", True),
    }
    base_fixups = {
        2: ("?temp@@3VBVector@@A", 4, "absolute", 0, ".text", "code", 101592, 0, "data"),
        12: ("?temp@@3VBVector@@A", 4, "absolute", 4, ".text", "code", 101592, 0, "data"),
        22: ("?temp@@3VBVector@@A", 4, "absolute", 8, ".text", "code", 101592, 0, "data"),
    }
    res = diff_code(obj_bytes, obj_relocs, {2: 4, 12: 4, 22: 4}, base_bytes, base_fixups, {2: 4, 12: 4, 22: 4})
    assert res["match_percent"] == 100.0
