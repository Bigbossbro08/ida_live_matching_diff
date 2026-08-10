"""Headless tests for ida_matcher.matcher.coff_parser (no IDA required)."""
import os
import tempfile

import pytest

from ida_matcher.matcher.coff_parser import load_obj, _reloc_width
from ida_matcher.matcher.coff_parser import (
    IMAGE_REL_I386_DIR32,
    IMAGE_REL_I386_DIR16,
)

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
    assert funcs["_fa"]["relocs"] == {1: "_ext"}
    assert funcs["_fb"]["relocs"] == {2: "_ext"}


def test_reloc_widths(synthetic_obj):
    funcs = load_obj(synthetic_obj)
    assert funcs["_fa"]["reloc_widths"] == {1: 4}   # DIR32
    assert funcs["_fb"]["reloc_widths"] == {2: 2}   # DIR16


def test_reloc_width_mapping():
    assert _reloc_width(IMAGE_REL_I386_DIR32) == 4
    assert _reloc_width(IMAGE_REL_I386_DIR16) == 2


def test_missing_file_is_empty(tmp_path):
    assert load_obj(tmp_path / "nope.obj") == {}