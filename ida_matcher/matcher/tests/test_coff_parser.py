"""Headless tests for ida_matcher.matcher.coff_parser (no IDA required)."""
import os
import tempfile

import pytest

from ida_matcher.matcher.coff_parser import load_obj, _reloc_width
from ida_matcher.matcher.coff_parser import (
    IMAGE_REL_I386_DIR32,
    IMAGE_REL_I386_DIR16,
)
from ida_matcher.matcher import coff_lief
from ida_matcher.matcher import coff_pure
from ida_matcher.matcher.coff_parser import resolve_parser

from ida_matcher.matcher.tests.conftest import build_synthetic_obj


@pytest.fixture()
def synthetic_obj(tmp_path):
    p = tmp_path / "synthetic.obj"
    p.write_bytes(build_synthetic_obj())
    return p


def test_extracts_function_keys(synthetic_obj):
    funcs = load_obj(synthetic_obj)
    assert list(funcs) == ["_fa", "_fb"]


def test_function_bytes(synthetic_obj):
    funcs = load_obj(synthetic_obj)
    assert bytes(funcs["_fa"]["bytes"]).hex() == "558be8000000"
    assert bytes(funcs["_fb"]["bytes"]).hex() == "00c9c39090ba0000c39090"


def test_relocs_resolved(synthetic_obj):
    funcs = load_obj(synthetic_obj)
    assert funcs["_fa"]["relocs"] == {1: ("_ext", 4, "IMAGE_REL_I386_DIR32", 0, "", "unknown", 0, 0, "unknown")}
    assert funcs["_fb"]["relocs"] == {2: ("_ext", 2, "IMAGE_REL_I386_DIR16", 0, "", "unknown", 0, 0, "unknown")}


def test_reloc_widths(synthetic_obj):
    funcs = load_obj(synthetic_obj)
    assert funcs["_fa"]["reloc_widths"] == {1: 4}   # DIR32
    assert funcs["_fb"]["reloc_widths"] == {2: 2}   # DIR16


def test_reloc_width_mapping():
    assert _reloc_width(IMAGE_REL_I386_DIR32) == 4
    assert _reloc_width(IMAGE_REL_I386_DIR16) == 2


def test_missing_file_is_empty(tmp_path):
    assert load_obj(tmp_path / "nope.obj") == {}


# ---------------------------------------------------------------- parser selection (facade)

def test_resolve_parser_explicit():
    assert resolve_parser("lief") == "lief"
    assert resolve_parser("pure") == "pure"


def test_resolve_parser_auto_uses_lief_when_installed():
    assert resolve_parser("auto") == ("lief" if coff_lief.HAS_LIEF else "pure")


def test_resolve_parser_env_var(monkeypatch):
    monkeypatch.setenv("IDA_MATCHER_PARSER", "pure")
    assert resolve_parser() == "pure"
    monkeypatch.setenv("IDA_MATCHER_PARSER", "lief")
    assert resolve_parser() == "lief"


def test_resolve_parser_invalid():
    with pytest.raises(ValueError):
        resolve_parser("bogus")


def test_load_obj_forces_pure(synthetic_obj):
    assert load_obj(synthetic_obj, parser="pure") == coff_pure.load_obj_pure(synthetic_obj)


@pytest.mark.skipif(not coff_lief.HAS_LIEF, reason="lief not installed")
def test_load_obj_forces_lief(synthetic_obj):
    assert load_obj(synthetic_obj, parser="lief") == coff_lief.load_obj_lief(synthetic_obj)


@pytest.mark.skipif(not coff_lief.HAS_LIEF, reason="lief not installed")
def test_load_obj_lief_and_pure_agree(synthetic_obj):
    lief_res = load_obj(synthetic_obj, parser="lief")
    pure_res = load_obj(synthetic_obj, parser="pure")
    assert set(lief_res) == set(pure_res)
    for name in pure_res:
        l, pr = lief_res[name], pure_res[name]
        assert bytes(l["bytes"]) == bytes(pr["bytes"])
        assert l["offset"] == pr["offset"]
        assert l["relocs"] == pr["relocs"]
        assert l["reloc_widths"] == pr["reloc_widths"]