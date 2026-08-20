"""Tests for the native objdiff_py PyO3 extension module."""
import pytest
import objdiff_py
from objdiff_py import ObjectBuilder, diff_objects
from ida_matcher.matcher.tests.conftest import (
    RAW,
    build_synthetic_obj,
    build_synthetic_obj_with_funcdef_aux,
    build_synthetic_thunk_obj,
    build_synthetic_multi_section_obj,
    build_synthetic_comdat_weak_obj,
)


def test_object_builder_roundtrip():
    """Replicate build_synthetic_obj with ObjectBuilder and ensure objdiff-core consumes it."""
    b = ObjectBuilder("x86")
    sec_text = b.add_section(".text", "", 0)
    b.write_bytes(sec_text, 0, RAW)

    # Add symbols: _ext (undefined), _fa, _fb
    sym_ext = b.add_symbol(0xFFFFFFFF, "_ext", 0, 0, 2, 0)
    sym_fa = b.add_symbol(sec_text, "_fa", 0, 6, 2, 0)
    sym_fb = b.add_symbol(sec_text, "_fb", 6, 11, 2, 0)

    # Relocs: offset 1 (DIR32 -> _ext), offset 8 (DIR16 -> _ext)
    b.add_relocation(sec_text, 1, sym_ext, 6, 4, 0)
    b.add_relocation(sec_text, 8, sym_ext, 1, 2, 0)

    built_bytes = b.finish()
    assert isinstance(built_bytes, bytes)
    assert len(built_bytes) > 0

    # Feed to diff_objects to confirm objdiff-core reads and diffs cleanly
    result = diff_objects(built_bytes, built_bytes)
    assert result["left"] is not None
    assert result["right"] is not None

    left_symbols = result["left"]["symbols"]
    assert len(left_symbols) >= 2
    assert left_symbols[0]["match_percent"] == 100.0
    assert left_symbols[0]["diff_score"] == [0, 300]
    assert left_symbols[1]["match_percent"] == 100.0
    assert left_symbols[1]["diff_score"] == [0, 800]


def test_diff_objects_match():
    """Verify diff_objects on identical synthetic .obj fixtures reports 100% match."""
    obj_bytes = build_synthetic_obj()
    result = diff_objects(obj_bytes, obj_bytes)

    assert result["left"] is not None
    assert result["right"] is not None

    syms = result["left"]["symbols"]
    # _fa and _fb should both match 100%
    assert syms[0]["match_percent"] == 100.0
    assert syms[0]["diff_score"] == [0, 300]
    assert syms[1]["match_percent"] == 100.0
    assert syms[1]["diff_score"] == [0, 800]


def test_diff_objects_thunk():
    """Verify diff_objects handles thunk stub objects."""
    thunk_obj = build_synthetic_thunk_obj()
    result = diff_objects(thunk_obj, thunk_obj)

    assert result["left"] is not None
    syms = result["left"]["symbols"]
    assert len(syms) == 1
    assert syms[0]["match_percent"] == 100.0
    assert syms[0]["diff_score"] == [0, 100]

    # Diffing against a completely different object results in unmatched symbols
    diff_other = diff_objects(thunk_obj, build_synthetic_obj())
    assert diff_other["left"]["symbols"][0]["target_symbol"] is None


def test_diff_objects_all_fixtures():
    """Verify diff_objects successfully parses all synthetic test fixtures."""
    fixtures = [
        build_synthetic_obj(),
        build_synthetic_obj_with_funcdef_aux(total_size=6),
        build_synthetic_thunk_obj(),
        build_synthetic_multi_section_obj(),
        build_synthetic_comdat_weak_obj(),
    ]
    for fix in fixtures:
        res = diff_objects(fix, fix)
        assert res["left"] is not None
        assert res["right"] is not None
        for sym in res["left"]["symbols"]:
            if sym["target_symbol"] is not None:
                assert sym["match_percent"] == 100.0


def test_object_builder_archs():
    """Verify ObjectBuilder supports supported architectures."""
    for arch in ["x86", "x86_64", "arm", "arm64", "ppc", "mips"]:
        builder = ObjectBuilder(arch)
        sec = builder.add_section(".text", "", 0)
        builder.write_bytes(sec, 0, b"\x90\x90")
        out = builder.finish()
        assert len(out) > 0

    with pytest.raises(ValueError, match="Unsupported arch"):
        ObjectBuilder("invalid_arch_name")


def test_synthetic_obj_from_record_pure_and_lief_roundtrip(tmp_path):
    """Verify that synthetic_obj_from_record produces valid COFF readable by coff_pure and coff_lief."""
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record
    from ida_matcher.matcher.coff_pure import load_obj_pure
    from ida_matcher.matcher.coff_lief import load_obj_lief, HAS_LIEF

    rec = {
        "bytes": "558bec83ec40e800000000ba0000e800000000c3",
        "size": 20,
        "fixups": {"7": "_printf", "12": "_helper", "15": "_other"},
        "fixup_widths": {"7": 4, "12": 2, "15": 4},
        "fixup_classes": {"7": "absolute", "12": "absolute", "15": "relative"},
        "fixup_addends": {"7": 0, "12": 0, "15": 0},
        "fixup_sym_kinds": {"7": "code", "12": "code", "15": "code"},
        "section_name": ".text",
        "section_kind": "code",
        "arch": "x86",
    }

    obj_bytes = synthetic_obj_from_record(rec, "_my_func")
    assert isinstance(obj_bytes, bytes)
    assert len(obj_bytes) > 0

    obj_file = tmp_path / "test_synth.obj"
    obj_file.write_bytes(obj_bytes)

    # 1. Pure COFF parser round-trip
    pure_map = load_obj_pure(str(obj_file))
    assert len(pure_map) == 1
    # Symbol name in COFF symbol table
    sym_name = list(pure_map.keys())[0]
    entry = pure_map[sym_name]
    assert entry["bytes"] == bytes.fromhex(rec["bytes"])
    assert 7 in entry["relocs"]
    assert entry["reloc_widths"][7] == 4
    assert 12 in entry["relocs"]
    assert entry["reloc_widths"][12] == 2
    assert 15 in entry["relocs"]
    assert entry["reloc_widths"][15] == 4

    # 2. LIEF COFF parser round-trip (if LIEF installed)
    if HAS_LIEF:
        lief_map = load_obj_lief(str(obj_file))
        assert len(lief_map) == 1
        lief_entry = list(lief_map.values())[0]
        assert lief_entry["bytes"] == bytes.fromhex(rec["bytes"])
        assert 7 in lief_entry["relocs"]
        assert lief_entry["reloc_widths"][7] == 4
        assert 12 in lief_entry["relocs"]
        assert lief_entry["reloc_widths"][12] == 2
        assert 15 in lief_entry["relocs"]
        assert lief_entry["reloc_widths"][15] == 4

    # 3. objdiff-core diff round-trip
    diff_res = diff_objects(obj_bytes, obj_bytes)
    assert diff_res["left"] is not None
    syms = diff_res["left"]["symbols"]
    assert syms[0]["match_percent"] == 100.0


def test_synthetic_obj_data_record_roundtrip(tmp_path):
    """Verify data record COFF generation and round-trip."""
    import struct
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record
    from ida_matcher.matcher.coff_pure import (
        IMAGE_FILE_HEADER_FMT,
        IMAGE_FILE_HEADER_SIZE,
        IMAGE_SECTION_HEADER_FMT,
        IMAGE_SECTION_HEADER_SIZE,
    )

    rec = {
        "bytes": "0102030400000000",
        "size": 8,
        "fixups": {"4": "_g_target"},
        "fixup_widths": {"4": 4},
        "fixup_classes": {"4": "absolute"},
        "fixup_addends": {"4": 0},
        "fixup_sym_kinds": {"4": "data"},
        "section_name": ".data",
        "section_kind": "data",
        "arch": "x86",
    }

    obj_bytes = synthetic_obj_from_record(rec, "_g_data")
    assert isinstance(obj_bytes, bytes)
    assert len(obj_bytes) > 0

    # 1. objdiff-core diff round-trip
    diff_res = diff_objects(obj_bytes, obj_bytes)
    assert diff_res["left"] is not None
    assert len(diff_res["left"]["sections"]) == 1
    assert diff_res["left"]["sections"][0]["match_percent"] == 100.0

    # 2. Check COFF header and .data section header
    machine, num_sections, _, sym_ptr, num_syms, opt_hdr, _ = struct.unpack_from(
        IMAGE_FILE_HEADER_FMT, obj_bytes, 0
    )
    assert num_sections >= 1
    sec_data = obj_bytes[IMAGE_FILE_HEADER_SIZE : IMAGE_FILE_HEADER_SIZE + IMAGE_SECTION_HEADER_SIZE]
    name_raw, _, _, raw_size, raw_ptr, reloc_ptr, _, num_relocs, _, _ = struct.unpack(
        IMAGE_SECTION_HEADER_FMT, sec_data
    )
    sec_name = name_raw.split(b"\x00", 1)[0].decode("latin1")
    assert sec_name == ".data"
    assert raw_size == 8
    assert num_relocs == 1


def test_compare_functions_objdiff_py_enabled(monkeypatch):
    """Verify compare_functions behaves properly when OBJDIFF_PY=1 vs OBJDIFF_PY=0."""
    from ida_matcher.matcher.match_core import compare_functions

    raw_bytes = bytes.fromhex("55b800000000c9c3")
    relocs = {2: "_ext"}
    fixups = {2: ("_ext", 4, "absolute", 0, ".text", "code", 0, 0, "code")}

    # 1. Default (OBJDIFF_PY not set)
    monkeypatch.delenv("OBJDIFF_PY", raising=False)
    pct_py, count_py, score_py = compare_functions(
        raw_bytes, raw_bytes.hex(), relocs, fixups, return_details=True
    )
    assert pct_py == 100.0
    assert count_py == len(raw_bytes)

    # 2. Rust path active (OBJDIFF_PY=1)
    monkeypatch.setenv("OBJDIFF_PY", "1")
    pct_rust, count_rust, score_rust = compare_functions(
        raw_bytes, raw_bytes.hex(), relocs, fixups, return_details=True
    )
    assert pct_rust == 100.0
    assert count_rust == len(raw_bytes)


def test_compare_functions_objdiff_py_mismatch(monkeypatch):
    """Verify compare_functions with OBJDIFF_PY=1 reports mismatch score on divergent bytes."""
    from ida_matcher.matcher.match_core import compare_functions

    left_bytes = bytes.fromhex("558bec83ec40c9c3")
    right_bytes = bytes.fromhex("558bec83ec20c9c3")  # imm mismatch

    monkeypatch.setenv("OBJDIFF_PY", "1")
    pct, count, score = compare_functions(
        left_bytes, right_bytes.hex(), {}, {}, return_details=True
    )
    assert pct < 100.0
    assert score[0] > 0  # non-zero diff penalty


def test_diff_direction_config_and_env(monkeypatch, tmp_path):
    """Verify right-to-left diff direction configuration."""
    from ida_matcher.matcher.config import load_config, Config
    from ida_matcher.matcher.match_core import get_diff_direction, compare_functions

    # 1. Config default
    cfg = Config()
    assert cfg.diff_direction == "left_to_right"

    # 2. Config parsed from json
    cfg_file = tmp_path / "ida_watch.json"
    cfg_file.write_text('{"diff_direction": "right_to_left"}', encoding="utf-8")
    loaded = load_config(str(cfg_file))
    assert loaded.diff_direction == "right_to_left"
    assert get_diff_direction(loaded) == "right_to_left"

    # 3. Env var override
    monkeypatch.setenv("OBJDIFF_DIFF_DIRECTION", "right_to_left")
    assert get_diff_direction() == "right_to_left"
    monkeypatch.setenv("OBJDIFF_DIFF_DIRECTION", "left_to_right")
    assert get_diff_direction() == "left_to_right"

    # 4. compare_functions with diff_direction
    monkeypatch.setenv("OBJDIFF_PY", "1")
    raw_bytes = bytes.fromhex("558bec83ec40c9c3")
    pct, count = compare_functions(
        raw_bytes, raw_bytes.hex(), {}, {}, diff_direction="right_to_left"
    )
    assert pct == 100.0


def test_match_summary_and_focus_with_objdiff_py(monkeypatch, tmp_path, capsys):
    """Verify match_summary and match_focus execute cleanly with OBJDIFF_PY=1 against baseline."""
    from ida_matcher.matcher.match_core import match_summary, match_focus

    obj_bytes = build_synthetic_obj()
    obj_file = tmp_path / "test_obj.obj"
    obj_file.write_bytes(obj_bytes)

    baseline = {
        "_fa": {
            "bytes": "558be8000000",
            "fixups": {1: "_ext"},
            "fixup_widths": {1: 4},
            "fixup_classes": {1: "absolute"},
            "fixup_addends": {1: 0},
            "section_name": ".text",
            "section_kind": "code",
            "size": 6,
        },
        "_fb": {
            "bytes": "558bec83ec40e800000000c3",
            "fixups": {7: "_ext"},
            "fixup_widths": {7: 4},
            "fixup_classes": {7: "relative"},
            "fixup_addends": {7: 0},
            "section_name": ".text",
            "section_kind": "code",
            "size": 12,
        },
    }

    monkeypatch.setenv("OBJDIFF_PY", "1")

    # Run match_summary
    code = match_summary(obj_file, baseline=baseline)
    assert code == 0

    # Run match_focus
    match_focus(obj_file, "_fa", baseline=baseline)
    out = capsys.readouterr().out
    assert "DIFF: _fa" in out
    assert "100.00%" in out


def _extract_all_coff_symbol_names(coff_bytes: bytes) -> list:
    import struct
    machine, nsec, _tds, symptr, nsyms, opthdr, chars = struct.unpack_from("<HHIIIHH", coff_bytes, 0)
    strtab_off = symptr + nsyms * 18
    strtab_size = struct.unpack_from("<I", coff_bytes, strtab_off)[0]
    strtab = coff_bytes[strtab_off:strtab_off + strtab_size]

    names = []
    si = 0
    while si < nsyms:
        base = symptr + si * 18
        name_field = coff_bytes[base:base + 8]
        aux = coff_bytes[base + 17]
        if name_field[:4] == b"\x00\x00\x00\x00":
            name_off = struct.unpack_from("<I", name_field, 4)[0]
            end = strtab.find(b"\x00", name_off)
            if end != -1:
                name = strtab[name_off:end].decode("latin1")
            else:
                name = strtab[name_off:].decode("latin1")
        else:
            name = name_field.rstrip(b"\x00").decode("latin1")
        names.append(name)
        si += 1 + aux
    return names


def test_object_builder_verbatim_symbol_names(tmp_path):
    """Verify ObjectBuilder(x86) stores symbol names verbatim without automatic '_' prefix."""
    from ida_matcher.matcher.coff_pure import load_obj_pure

    b = ObjectBuilder("x86")
    sec_text = b.add_section(".text", "", 0)
    b.write_bytes(sec_text, 0, b"\x55\x8b\xec\x5d\xc3")

    # One Text in-section, two undefined Data
    b.add_symbol(sec_text, "?Foo@@YAXXZ", 0, 5, 2, 0)
    b.add_symbol(0xFFFFFFFF, "_printf", 0, 0, 3, 0)
    b.add_symbol(0xFFFFFFFF, "__ftol2", 0, 0, 3, 0)

    built_bytes = b.finish()
    assert isinstance(built_bytes, bytes)
    assert len(built_bytes) > 0

    # 1. Parse raw COFF symbol table
    names = _extract_all_coff_symbol_names(built_bytes)
    assert "?Foo@@YAXXZ" in names
    assert "_?Foo@@YAXXZ" not in names

    assert "_printf" in names
    assert "__printf" not in names

    assert "__ftol2" in names
    assert "___ftol2" not in names

    # 2. Parse with coff_pure.load_obj_pure
    obj_path = tmp_path / "verbatim_x86.obj"
    obj_path.write_bytes(built_bytes)
    parsed = load_obj_pure(str(obj_path))
    assert "?Foo@@YAXXZ" in parsed
    assert "_?Foo@@YAXXZ" not in parsed


def test_object_builder_verbatim_x64(tmp_path):
    """Verify ObjectBuilder(x86_64) also stores symbol names verbatim."""
    b = ObjectBuilder("x86_64")
    sec_text = b.add_section(".text", "", 0)
    b.write_bytes(sec_text, 0, b"\x48\x83\xec\x28\x48\x83\xc4\x28\xc3")

    b.add_symbol(sec_text, "?Foo@@YAXXZ", 0, 9, 2, 0)
    b.add_symbol(0xFFFFFFFF, "_printf", 0, 0, 3, 0)
    b.add_symbol(0xFFFFFFFF, "__ftol2", 0, 0, 3, 0)

    built_bytes = b.finish()
    names = _extract_all_coff_symbol_names(built_bytes)
    assert "?Foo@@YAXXZ" in names
    assert "_?Foo@@YAXXZ" not in names

    assert "_printf" in names
    assert "__printf" not in names

    assert "__ftol2" in names
    assert "___ftol2" not in names


def _extract_section_data_raw(coff_bytes: bytes) -> bytes:
    import struct
    machine, nsec, _tds, symptr, nsyms, opthdr, chars = struct.unpack_from("<HHIIIHH", coff_bytes, 0)
    sec_hdr_off = 20 + opthdr
    name_raw, v_size, v_addr, raw_size, raw_ptr, reloc_ptr, line_ptr, num_relocs, num_lines, flags = \
        struct.unpack_from("<8sIIIIIIHHI", coff_bytes, sec_hdr_off)
    return coff_bytes[raw_ptr:raw_ptr + raw_size]


def test_synthetic_obj_reloc_site_bytes_zero():
    """Verify that a DIR32 reloc site with addend 0 has 00000000 placeholder bytes even if input carries VA."""
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record

    # Input image bytes contain absolute VA 0x00b7cb5c at offset 1: "e8" + "5ccbb700" + "c3"
    rec = {
        "bytes": "e85ccbb700c3",
        "size": 6,
        "fixups": {"1": "_printf"},
        "fixup_widths": {"1": 4},
        "fixup_classes": {"1": "absolute"},
        "fixup_addends": {"1": 0},
        "fixup_sym_kinds": {"1": "code"},
        "section_name": ".text",
        "section_kind": "code",
        "arch": "x86",
    }
    built_bytes = synthetic_obj_from_record(rec, "test_func")
    sec_data = _extract_section_data_raw(built_bytes)
    # Site bytes at [1:5] must be 0, NOT the original VA 5ccbb700
    assert sec_data[1:5] == b"\x00\x00\x00\x00"


def test_synthetic_obj_reloc_site_bytes_addend():
    """Verify that a DIR32 reloc site with addend 61 has 3d000000 placeholder bytes."""
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record

    # Input image bytes contain absolute VA 0x00b7cb5c at offset 2
    rec = {
        "bytes": "8b805ccbb700",
        "size": 6,
        "fixups": {"2": "TheCamera"},
        "fixup_widths": {"2": 4},
        "fixup_classes": {"2": "absolute"},
        "fixup_addends": {"2": 61},
        "fixup_sym_kinds": {"2": "data"},
        "section_name": ".text",
        "section_kind": "code",
        "arch": "x86",
    }
    built_bytes = synthetic_obj_from_record(rec, "test_func")
    sec_data = _extract_section_data_raw(built_bytes)
    # Site bytes at [2:6] must be 61 in little-endian (<i: 0x3d, 0x00, 0x00, 0x00)
    assert sec_data[2:6] == b"\x3d\x00\x00\x00"


def test_synthetic_obj_reloc_site_bytes_rel32():
    """Verify that a REL32 reloc site with addend 0 has 00000000 (NOT +4) placeholder bytes."""
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record

    # Input image bytes contain displacement at offset 1
    rec = {
        "bytes": "e812345678c3",
        "size": 6,
        "fixups": {"1": "?Foo@@YAXXZ"},
        "fixup_widths": {"1": 4},
        "fixup_classes": {"1": "relative"},
        "fixup_addends": {"1": 0},
        "fixup_sym_kinds": {"1": "code"},
        "section_name": ".text",
        "section_kind": "code",
        "arch": "x86",
    }
    built_bytes = synthetic_obj_from_record(rec, "test_func")
    sec_data = _extract_section_data_raw(built_bytes)
    # Site bytes at [1:5] must be 0, NOT 4
    assert sec_data[1:5] == b"\x00\x00\x00\x00"


def test_compare_functions_objdiff_py_rel32_addend(monkeypatch):
    """Verify compare_functions with OBJDIFF_PY=1 matches REL32 relocations with addend 0 despite VA at right site."""
    from ida_matcher.matcher.match_core import compare_functions

    monkeypatch.setenv("OBJDIFF_PY", "1")

    # Left: compiled obj bytes has call opcode e8 + 00000000 placeholder addend + c3
    left_bytes = bytes.fromhex("e800000000c3")
    # reloc tuple: (name, width, class, addend)
    obj_relocs = {1: ("?TargetFunc@@YAXXZ", 4, "relative", 0)}

    # Right: IDA bytes has call opcode e8 + image displacement (e.g. 0x00123456) + c3
    right_bytes_hex = "e856341200c3"
    base_fixups = {1: ("?TargetFunc@@YAXXZ", 4, "relative", 0)}

    pct, count, score = compare_functions(
        left_bytes, right_bytes_hex, obj_relocs, base_fixups, return_details=True
    )
    assert pct == 100.0
    assert score[0] == 0


def test_compare_functions_objdiff_py_dir32_addend(monkeypatch):
    """Verify compare_functions with OBJDIFF_PY=1 matches DIR32 member addends (e.g. +61) despite VA at right site."""
    from ida_matcher.matcher.match_core import compare_functions

    monkeypatch.setenv("OBJDIFF_PY", "1")

    # Left: compiled obj bytes has mov eax, [TheCamera + 0x3d] -> 8b80 + 3d000000 (addend 61)
    left_bytes = bytes.fromhex("8b803d000000c3")
    obj_relocs = {2: ("?TheCamera@@3VCCamera@@A", 4, "absolute", 61)}

    # Right: IDA image bytes has absolute VA at site (e.g. 0x00b7cb5c + 0x3d = 0x00b7cb99)
    right_bytes_hex = "8b8099cbb700c3"
    base_fixups = {2: ("?TheCamera@@3VCCamera@@A", 4, "absolute", 61)}

    pct, count, score = compare_functions(
        left_bytes, right_bytes_hex, obj_relocs, base_fixups, return_details=True
    )
    assert pct == 100.0
    assert score[0] == 0


def test_synthetic_obj_matches_real_msvc_obj():
    """Golden regression test: synthetic object built from process_record.json matches real MSVC process_target.o 100.0%."""
    import json
    from pathlib import Path
    from objdiff_py import diff_objects
    from ida_matcher.matcher.ida_logic import synthetic_obj_from_record

    fixture_dir = Path(__file__).parent / "fixtures"
    target_bytes = (fixture_dir / "process_target.o").read_bytes()
    record = json.loads((fixture_dir / "process_record.json").read_text(encoding="utf-8"))

    synth_bytes = synthetic_obj_from_record(record, "?Process@COnscreenTimerEntry@@QAEXXZ")
    assert isinstance(synth_bytes, bytes)
    assert len(synth_bytes) > 0

    diff_res = diff_objects(target_bytes, synth_bytes)
    assert diff_res["left"] is not None
    assert diff_res["right"] is not None

    # Check that ?Process@COnscreenTimerEntry@@QAEXXZ matched 100.0% with diff_score [0, 5600]
    right_symbols = diff_res["right"]["symbols"]
    matched = [s for s in right_symbols if s.get("target_symbol") is not None]
    assert len(matched) == 1
    assert matched[0]["match_percent"] == 100.0
    assert matched[0]["diff_score"] == [0, 5600]

    # Also check from left side
    target_sym = diff_res["left"]["symbols"][matched[0]["target_symbol"]]
    assert target_sym["match_percent"] == 100.0
    assert target_sym["diff_score"] == [0, 5600]






