"""
ida_matcher.matcher.coff_parser
~~~~~~~~~~~~~~~~~~~~~~~~~
Facade over two COFF .obj parsers:

- `coff_lief.load_obj_lief`  — LIEF-backed (robust, multi-arch, exact bounds).
- `coff_pure.load_obj_pure`  — zero-dependency pure-Python fallback (x86-32).

Selection: `load_obj(path, parser=...)` where `parser` is ``"auto"`` (default),
``"lief"`` or ``"pure"``. ``auto`` uses LIEF when installed, else the pure
parser. The ``IDA_MATCHER_PARSER`` env var overrides the default.

Constants and ``_reloc_width`` are re-exported from `coff_pure` for backward
compatibility (existing tests/imports keep working).
"""
import os
from pathlib import Path
from typing import Dict

from ida_matcher.matcher import coff_lief
from ida_matcher.matcher import coff_pure

# Backward-compatible re-exports (constants + helpers used by tests/consumers).
from ida_matcher.matcher.coff_pure import (  # noqa: F401
    _reloc_width,
    IMAGE_FILE_HEADER_FMT,
    IMAGE_FILE_HEADER_SIZE,
    IMAGE_SECTION_HEADER_FMT,
    IMAGE_SECTION_HEADER_SIZE,
    IMAGE_SYMBOL_FMT,
    IMAGE_SYMBOL_SIZE,
    IMAGE_RELOCATION_FMT,
    IMAGE_RELOCATION_SIZE,
    IMAGE_SYM_CLASS_EXTERNAL,
    IMAGE_SYM_CLASS_STATIC,
    IMAGE_SYM_TYPE_FUNCTION,
    IMAGE_REL_I386_DIR16,
    IMAGE_REL_I386_REL16,
    IMAGE_REL_I386_DIR32,
    IMAGE_REL_I386_DIR32NB,
    IMAGE_REL_I386_SEG12,
    IMAGE_REL_I386_REL32,
    IMAGE_REL_I386_WIDTHS,
)

load_obj_pure = coff_pure.load_obj_pure
load_obj_lief = coff_lief.load_obj_lief

_SUPPORTED = ("auto", "lief", "pure")


def resolve_parser(parser=None) -> str:
    """Resolve a parser selection to ``lief`` or ``pure``."""
    p = (parser or os.environ.get("IDA_MATCHER_PARSER", "auto")).strip().lower()
    if p == "auto":
        return "lief" if coff_lief.HAS_LIEF else "pure"
    if p not in _SUPPORTED:
        raise ValueError(f"unknown parser: {parser!r} (expected one of {_SUPPORTED})")
    return p


def load_obj(obj_path: Path, parser="auto") -> Dict[str, Dict]:
    """
    Parse a COFF .obj file and extract function byte boundaries and relocations.

    Returns the same record shape from either backend:
        { mangled_name: {"bytes": bytearray, "offset": int, "relocs": {rel_off: symbol},
                         "reloc_widths": {rel_off: width}, ...} }
    A missing/unreadable/non-COFF file yields ``{}`` (never raises).
    """
    if resolve_parser(parser) == "lief":
        return coff_lief.load_obj_lief(obj_path)
    return coff_pure.load_obj_pure(obj_path)