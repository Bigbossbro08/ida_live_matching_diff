"""Headless tests for the LIEF-backed COFF parser (ida_matcher.matcher.coff_lief)."""
import pytest

from ida_matcher.matcher import coff_lief as cl
from ida_matcher.matcher import coff_pure as cp

from ida_matcher.matcher.tests.conftest import (
    build_synthetic_obj,
    build_synthetic_obj_with_funcdef_aux,
    build_synthetic_thunk_obj,
    build_synthetic_multi_section_obj,
    build_synthetic_comdat_weak_obj,
)

pytestmark = pytest.mark.skipif(not cl.HAS_LIEF, reason="lief not installed")


@pytest.fixture()
def synth_obj(tmp_path):
    p = tmp_path / "synth.obj"
    p.write_bytes(build_synthetic_obj())
    return p


# ---------------------------------------------------------------- parity with pure parser

def test_parity_with_pure_parser(synth_obj):
    lief_res = cl.load_obj_lief(synth_obj)
    pure_res = cp.load_obj_pure(synth_obj)
    assert list(lief_res) == list(pure_res)
    for name in pure_res:
        l, pr = lief_res[name], pure_res[name]
        assert bytes(l["bytes"]) == bytes(pr["bytes"])
        assert l["offset"] == pr["offset"]
        assert l["relocs"] == pr["relocs"]
        assert l["reloc_widths"] == pr["reloc_widths"]


def test_record_fields(synth_obj):
    res = cl.load_obj_lief(synth_obj)
    assert res["_fa"]["section_kind"] == "code"
    assert res["_fa"]["is_thunk"] is False
    assert res["_fa"]["is_weak"] is False


def test_duplicate_first_wins(synth_obj):
    # Pure parser keeps first occurrence of a duplicated mangled name; LIEF
    # parser must too (same key space, so the fixture simply has one entry).
    assert len(cl.load_obj_lief(synth_obj)) == 2


# ---------------------------------------------------------------- exact bounds via FUNC_DEF aux

def test_exact_bounds_from_aux():
    res = cl.load_obj_lief(build_synthetic_obj_with_funcdef_aux(total_size=6))
    assert list(res) == ["_f"]
    # aux total_size = 6, not the 9-byte section size.
    assert bytes(res["_f"]["bytes"]).hex() == "558be8000000"


def test_aux_absent_falls_back_to_gap(synth_obj):
    # No aux records in the synthetic fixture -> gap heuristic still works.
    res = cl.load_obj_lief(synth_obj)
    assert bytes(res["_fa"]["bytes"]).hex() == "558be8000000"


# ---------------------------------------------------------------- thunk detection

def test_thunk_detected():
    res = cl.load_obj_lief(build_synthetic_thunk_obj())
    assert res["_t"]["is_thunk"] is True


def test_is_thunk_bytes_heuristic():
    assert cl._is_thunk_bytes(bytes.fromhex("ff2500000000")) is True
    assert cl._is_thunk_bytes(bytes.fromhex("558bec8b45fcc3")) is False
    assert cl._is_thunk_bytes(bytes.fromhex("e900000000")) is False   # jmp rel32 is not a forwarder stub
    assert cl._is_thunk_bytes(bytes.fromhex("ff2500000000") * 2) is False  # too big


# ---------------------------------------------------------------- reloc widths

def test_width_by_name():
    assert cl.RELOC_WIDTH_BY_NAME["I386_DIR32"] == 4
    assert cl.RELOC_WIDTH_BY_NAME["I386_DIR16"] == 2
    assert cl.RELOC_WIDTH_BY_NAME["AMD64_ADDR64"] == 8
    assert cl.RELOC_WIDTH_BY_NAME["AMD64_REL32"] == 4
    assert cl.RELOC_WIDTH_BY_NAME["ARM_MOV32T"] == 4


def test_reloc_width_unknown_is_default():
    # 0x0003 is not a real I386 reloc type -> LIEF exposes it as a raw int;
    # width lookup must fall back to 4 without raising.
    assert cl._reloc_width(131075) == 4
    assert cl._reloc_width(0) == 4
    assert cl._reloc_width(cl.lief.COFF.Relocation.TYPE.I386_DIR32) == 4


@pytest.mark.parametrize("name,w", [
    # I386
    ("I386_DIR16", 2), ("I386_REL16", 2), ("I386_DIR32", 4), ("I386_DIR32NB", 4),
    ("I386_SEG12", 2), ("I386_REL32", 4), ("I386_SECREL", 4), ("I386_SECTION", 2),
    ("I386_SECREL7", 1),
    # AMD64
    ("AMD64_ADDR32", 4), ("AMD64_ADDR32NB", 4), ("AMD64_ADDR64", 8), ("AMD64_REL32", 4),
    ("AMD64_REL32_1", 5), ("AMD64_REL32_2", 6), ("AMD64_REL32_3", 7),
    ("AMD64_REL32_4", 8), ("AMD64_REL32_5", 9), ("AMD64_SECREL", 4),
    ("AMD64_SECTION", 2), ("AMD64_SECREL7", 1), ("AMD64_SREL32", 4),
    # ARM
    ("ARM_ADDR32", 4), ("ARM_ADDR32NB", 4), ("ARM_REL32", 4),
    ("ARM_MOV32A", 4), ("ARM_MOV32T", 4),
    # ARM64
    ("ARM64_ADDR32", 4), ("ARM64_ADDR32NB", 4), ("ARM64_ADDR64", 8), ("ARM64_REL32", 4),
    # MIPS
    ("MIPS_REFWORD", 4), ("MIPS_REFWORDNB", 4), ("MIPS_JMPADDR", 4), ("MIPS_REFHALF", 2),
    ("MIPS_SECREL", 4), ("MIPS_SECRELHI", 4), ("MIPS_SECRELLO", 4), ("MIPS_GPREL", 4),
])
def test_width_map(name, w):
    assert cl.RELOC_WIDTH_BY_NAME[name] == w


# ---------------------------------------------------------------- data / bss

def test_data_section_kind_and_relocs():
    res = cl.load_obj_lief(build_synthetic_multi_section_obj())
    assert res["_data1"]["section_kind"] == "data"
    assert bytes(res["_data1"]["bytes"]).hex() == "7856341200000000"
    # DIR32 reloc on the data pointer is kept with its width.
    assert res["_data1"]["relocs"] == {0: ("_ext", 4, "IMAGE_REL_I386_DIR32", 0, "", "unknown", 0, 0, "unknown")}
    assert res["_data1"]["reloc_widths"] == {0: 4}


def test_bss_section_kind_empty_bytes():
    res = cl.load_obj_lief(build_synthetic_multi_section_obj())
    assert res["_bss1"]["section_kind"] == "bss"
    assert bytes(res["_bss1"]["bytes"]) == b""
    assert res["_bss1"]["size"] > 0
    assert res["_bss1"]["relocs"] == {}


def test_multi_section_code_still_functions():
    res = cl.load_obj_lief(build_synthetic_multi_section_obj())
    assert set(res) == {"_fa", "_data1", "_bss1"}
    assert res["_fa"]["section_kind"] == "code"
    # _fa is the only .text symbol -> spans the whole 17-byte code section.
    assert bytes(res["_fa"]["bytes"]).hex() == "558be800000000c9c39090ba0000c39090"


# ---------------------------------------------------------------- comdat / weak

def test_comdat_weak_detected():
    res = cl.load_obj_lief(build_synthetic_comdat_weak_obj())
    assert list(res) == ["_weak_fn"]
    assert res["_weak_fn"]["is_weak"] is True
    assert res["_weak_fn"]["section_kind"] == "code"


def test_comdat_bounds_from_unit_size():
    # COMDAT section is a single unit; bounds come from the unit size (SEC_DEF
    # length in the extended build, raw data size in the community build).
    res = cl.load_obj_lief(build_synthetic_comdat_weak_obj())
    assert bytes(res["_weak_fn"]["bytes"]).hex() == "558be800000000c9c3"


def test_comdat_unit_size_helper():
    # Community LIEF has no comdat_info; the LNK_COMDAT characteristics flag
    # drives the sizeof_raw_data fallback.
    data = build_synthetic_comdat_weak_obj()
    coff = cl.lief.COFF.parse(data)
    assert cl._comdat_unit_size(coff.sections[0]) == 9


# ---------------------------------------------------------------- robustness

def test_missing_file_is_empty(tmp_path):
    assert cl.load_obj_lief(tmp_path / "nope.obj") == {}


def test_garbage_file_is_empty(tmp_path):
    p = tmp_path / "garbage.obj"
    p.write_bytes(b"this is definitely not a coff object file")
    assert cl.load_obj_lief(p) == {}


def test_truncated_section_does_not_overread(tmp_path):
    # Valid header/section table but raw data cut short -> must not raise
    # and must not read past the content LIEF parsed.
    data = build_synthetic_obj()[:20 + 40 + 5]  # header + section hdr + 5 bytes
    p = tmp_path / "trunc.obj"
    p.write_bytes(data)
    assert cl.load_obj_lief(p) == {}
