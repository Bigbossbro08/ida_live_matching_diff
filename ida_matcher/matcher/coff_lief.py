"""
ida_matcher.matcher.coff_lief
~~~~~~~~~~~~~~~~~~~~~~~~~
LIEF-backed COFF .obj parser. Produces the same record contract as
`coff_pure.load_obj_pure` plus extra metadata (`is_thunk`, `is_weak`,
`section_kind`, `size`, `demangled_name`), with exact function bounds from
auxiliary symbols when available (falling back to the gap heuristic
otherwise) and data/BSS extraction from non-code sections.

LIEF encodes COFF relocation types with a machine prefix (e.g. `I386_DIR32 ==
131078`), so width lookup keys on the enum member name, not raw COFF type
numbers.

Note on the free ("community") LIEF wheel: `section.comdat_info`, SEC_DEF
auxiliary records and `Symbol.demangled_name` are extended-build features and
return `None`/empty there. COMDAT bounds then fall back to the section's raw
data size (a COMDAT section is exactly one unit, so `sizeof_raw_data` equals
the SEC_DEF length in practice) and `demangled_name` is omitted.
"""
import warnings
from pathlib import Path
from typing import Dict

try:
    import lief
    HAS_LIEF = True
    LIEF_EXTENDED = bool(getattr(lief, "__extended__", False))
except ImportError:
    lief = None
    HAS_LIEF = False
    LIEF_EXTENDED = False

DEFAULT_RELOC_WIDTH = 4

# Width (in bytes) of the relocated field per LIEF relocation-type name.
# Unknown / absolute / non-address types fall back to the default.
RELOC_WIDTH_BY_NAME = {
    # I386
    "I386_DIR16": 2,
    "I386_REL16": 2,
    "I386_DIR32": 4,
    "I386_DIR32NB": 4,
    "I386_SEG12": 2,
    "I386_REL32": 4,
    "I386_SECREL": 4,
    "I386_SECTION": 2,
    "I386_SECREL7": 1,
    # AMD64
    "AMD64_ADDR32": 4,
    "AMD64_ADDR32NB": 4,
    "AMD64_ADDR64": 8,
    "AMD64_REL32": 4,
    "AMD64_REL32_1": 5,
    "AMD64_REL32_2": 6,
    "AMD64_REL32_3": 7,
    "AMD64_REL32_4": 8,
    "AMD64_REL32_5": 9,
    "AMD64_SECREL": 4,
    "AMD64_SECTION": 2,
    "AMD64_SECREL7": 1,
    "AMD64_SREL32": 4,
    # ARM
    "ARM_ADDR32": 4,
    "ARM_ADDR32NB": 4,
    "ARM_REL32": 4,
    "ARM_MOV32A": 4,
    "ARM_MOV32T": 4,
    # ARM64
    "ARM64_ADDR32": 4,
    "ARM64_ADDR32NB": 4,
    "ARM64_ADDR64": 8,
    "ARM64_REL32": 4,
    # MIPS
    "MIPS_REFWORD": 4,
    "MIPS_REFWORDNB": 4,
    "MIPS_JMPADDR": 4,
    "MIPS_REFHALF": 2,
    "MIPS_SECREL": 4,
    "MIPS_SECRELHI": 4,
    "MIPS_SECRELLO": 4,
    "MIPS_GPREL": 4,
}


# LIEF relocation-type int value -> enum member name. Built once so width
# lookup never has to construct the enum (invalid values would warn + raise).
_TYPE_NAME_BY_VALUE = {}
if HAS_LIEF:
    _TYPE_NAME_BY_VALUE = {int(m): m.name for m in lief.COFF.Relocation.TYPE}


def _reloc_type_value(reloc) -> int:
    """Raw int of a relocation type.

    Accessing `.type` on an unrecognized relocation triggers nanobind's
    invalid-enum RuntimeWarning; suppress it and read the raw value.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return int(reloc.type)


def _reloc_width(t) -> int:
    """Byte width of a LIEF relocation type (int or enum); 4 when unknown."""
    if not HAS_LIEF:
        return DEFAULT_RELOC_WIDTH
    name = _TYPE_NAME_BY_VALUE.get(int(t))
    return RELOC_WIDTH_BY_NAME.get(name, DEFAULT_RELOC_WIDTH)


def _section_kind(sec) -> str:
    """'code' | 'data' | 'bss' from the section characteristics."""
    cn = lief.PE.Section.CHARACTERISTICS
    if sec.has_characteristic(cn.CNT_CODE):
        return "code"
    if sec.has_characteristic(cn.CNT_UNINITIALIZED_DATA):
        return "bss"
    return "data"


def _is_function_like(sym) -> bool:
    """Mirror the pure parser's symbol filter (code and data symbols)."""
    name = sym.name
    if not name:
        return False
    if name.startswith("$") and not name.startswith("$LC"):
        return False
    if sym.section_idx <= 0:
        return False
    if not (name.startswith("?") or name.startswith("_") or name.startswith("@") or name.startswith("$LC")):
        return False
    st = lief.COFF.Symbol.STORAGE_CLASS
    if sym.storage_class not in (st.EXTERNAL, st.STATIC, st.WEAK_EXTERNAL):
        return False
    if name.startswith("__imp_"):
        return False
    ct = lief.COFF.Symbol.COMPLEX_TYPE
    return sym.complex_type in (ct.NULL, ct.FUNCTION)


def _exact_size(sym) -> int | None:
    """Exact function code size from the FUNC_DEF auxiliary symbol, if present."""
    for aux in sym.auxiliary_symbols:
        try:
            if aux.type == lief.COFF.AuxiliarySymbol.TYPE.FUNC_DEF:
                return int(aux.total_size)
        except Exception:
            return None
    return None


def _comdat_unit_size(sec) -> int | None:
    """Exact size of a COMDAT section's single unit.

    In the extended LIEF build, `sec.comdat_info` carries the section's
    defining symbol whose SEC_DEF auxiliary symbol records the exact length.
    Community LIEF exposes neither (extended-only), so fall back to the raw
    data size -- a COMDAT section is exactly one unit, so `sizeof_raw_data`
    equals the SEC_DEF length in practice.
    """
    try:
        info = sec.comdat_info
        if info is not None and info.symbol is not None:
            for aux in info.symbol.auxiliary_symbols:
                try:
                    if aux.type == lief.COFF.AuxiliarySymbol.TYPE.SEC_DEF:
                        return int(aux.length)
                except Exception:
                    break
    except Exception:
        pass
    if sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.LNK_COMDAT):
        return int(sec.sizeof_raw_data)
    return None


def _is_thunk_bytes(data: bytes) -> bool:
    """Compiler-generated forwarder stub: tiny `jmp dword ptr [mem]` (FF 25)."""
    if len(data) > 8:
        return False
    return len(data) >= 6 and data[:2] == b"\xff\x25"


def is_compiler_generated(name: str) -> bool:
    if not name: return False
    return (name.startswith("@") and name[1:].isdigit()) or \
           (name.startswith("_$E") and name[3:].isdigit()) or \
           (name.startswith("$LC") and name[3:].isdigit())

def _extract_symbol_flags(sym) -> set:
    flags = set()
    st = lief.COFF.Symbol.STORAGE_CLASS
    if sym.storage_class == st.EXTERNAL:
        flags.add("Global")
    elif sym.storage_class == st.STATIC:
        flags.add("Local")
    elif sym.storage_class == st.WEAK_EXTERNAL:
        flags.add("Weak")
    
    if sym.section_idx == 0 and sym.value > 0:
        flags.add("Common")
        
    if is_compiler_generated(sym.name):
        flags.add("CompilerGenerated")
    
    return flags


def _collect_associative_children(coff) -> Dict[int, list]:
    """Deprecated: kept for compatibility; superseded by coff_pure.scan_coff_aux."""
    return {}


def _resolve_section_relocs(sec, section_by_idx) -> dict:
    """Resolve one section's relocations (same record shape as load loop)."""
    sec_relocs = {}
    content = None
    for reloc in sec.relocations:
        width = _reloc_width(_reloc_type_value(reloc))
        r_type = _TYPE_NAME_BY_VALUE.get(int(_reloc_type_value(reloc)))
        r_class = f"IMAGE_REL_{r_type}" if r_type else "unknown"

        t_name = f"unk_sym_{reloc.symbol_idx}"
        t_sec_name = ""
        t_sec_kind = "unknown"
        sym_addr = 0
        sym_size = 0
        sym_kind = "unknown"
        addend = 0

        if reloc.symbol is not None:
            t_name = reloc.symbol.name
            sym_addr = int(reloc.symbol.value)
            sym_size = _exact_size(reloc.symbol) or 0
            t_sec = section_by_idx.get(reloc.symbol.section_idx)
            if t_sec:
                t_sec_name = t_sec.name
                t_sec_kind = _section_kind(t_sec)
                sym_kind = "code" if t_sec_kind == "code" else "data"
                if width > 0:
                    try:
                        if content is None:
                            content = bytes(sec.content)
                        b = content[reloc.address : reloc.address + width]
                        if len(b) == width:
                            addend = int.from_bytes(b, "little")
                    except Exception:
                        pass

        sec_relocs[reloc.address] = (t_name, width, r_class, addend, t_sec_name, t_sec_kind,
                                     sym_addr, sym_size, sym_kind)
    return sec_relocs


def load_obj_lief(obj_path) -> Dict[str, Dict]:
    """
    Parse a COFF .obj file with LIEF and extract function/data boundaries and
    relocations. Accepts a path (`str`/`Path`) or raw file `bytes`.

    Returns:
        { mangled_name: {"bytes": bytearray, "offset": int, "relocs": {rel_off: symbol_name},
                         "reloc_widths": {rel_off: width}, "is_thunk": bool,
                         "is_weak": bool, "section_kind": "code"|"data"|"bss",
                         "size": int} }
    """
    if not HAS_LIEF:
        return {}

    if isinstance(obj_path, bytes):
        raw = obj_path
    else:
        path = Path(obj_path)
        if not path.exists():
            return {}
        try:
            raw = path.read_bytes()
        except OSError:
            return {}

    try:
        coff = lief.COFF.parse(raw)
    except Exception:
        return {}
    if coff is None:
        return {}

    arch = "x64" if coff.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64 else "x86"

    section_by_idx = {i + 1: sec for i, sec in enumerate(coff.sections)}

    # Community LIEF drops SECTION_DEF/FUNC_DEF auxiliary records, so walk the
    # raw COFF symbol table for COMDAT associations and exact function sizes.
    from .coff_pure import scan_coff_aux
    assoc_children, funcdef_sizes = scan_coff_aux(raw)
    consumed_children = set()

    funcs_out = {}
    for sec_idx, sec in section_by_idx.items():
        kind = _section_kind(sec)
        syms = [s for s in coff.symbols
                if s.section_idx == sec_idx and _is_function_like(s)]
        if not syms:
            continue
        syms.sort(key=lambda s: s.value)

        content = bytes(sec.content)
        content_len = len(content)
        if kind == "bss":
            # .bss carries no raw bytes but its SizeOfRawData gives the span
            # of zeroed data (pointerto_rawdata is 0 in object files).
            unit_end = int(sec.sizeof_raw_data) or None
        else:
            unit_end = _comdat_unit_size(sec)
            if unit_end is not None:
                unit_end = min(unit_end, content_len)
            else:
                unit_end = content_len

        sec_relocs = _resolve_section_relocs(sec, section_by_idx)

        for idx, sym in enumerate(syms):
            if sym.name in funcs_out:
                continue

            start = sym.value
            size = _exact_size(sym)
            if size is None:
                size = funcdef_sizes.get(sym.name)
            flags = _extract_symbol_flags(sym)
            if _exact_size(sym) is None and funcdef_sizes.get(sym.name) is None:
                flags.add("SizeInferred")
            if size is None:
                size = unit_end - start if unit_end is not None else None
                for nxt in syms[idx + 1:]:
                    if nxt.value > start:
                        if nxt.name.startswith("__unwind$") or nxt.name.startswith("__catch$"):
                            continue
                        gap = nxt.value - start
                        size = gap if size is None else min(size, gap)
                        break

            if size is None or size <= 0:
                continue

            if kind == "bss":
                # BSS has no raw bytes; the client compares against IDA's
                # zeroed page. Keep the reloc window from the computed span.
                func_bytes = bytearray()
            else:
                # Never over-read a truncated/corrupt section.
                size = min(size, max(0, content_len - start))
                if size <= 0:
                    continue
                func_bytes = bytearray(content[start:start + size])

            func_relocs = {}
            func_reloc_widths = {}
            for rel_off, desc in sec_relocs.items():
                if start <= rel_off < start + size:
                    func_relocs[rel_off - start] = desc
                    func_reloc_widths[rel_off - start] = desc[1]

            # Attach associated EH funclet/thunk sections (e.g. `.text$x`) so
            # the local window matches IDA functions carrying those bytes as
            # tail chunks. Only safe when the parent section is a single-
            # function COMDAT (VC6 /Gy), otherwise attribution is ambiguous.
            if kind == "code" and len(syms) == 1 and any(
                    child_idx not in consumed_children for child_idx in assoc_children.get(sec_idx, [])):
                # VC6 pads the body COMDAT with NOPs when the funclet is
                # externalized; the original binary splits the chunk at the
                # next function, so drop that tail padding before appending.
                trim = len(func_bytes)
                while trim > 0 and func_bytes[trim - 1] == 0x90:
                    trim -= 1
                if trim < len(func_bytes):
                    del func_bytes[trim:]
                    size = len(func_bytes)
                for child_idx in assoc_children.get(sec_idx, []):
                    if child_idx in consumed_children or child_idx == sec_idx:
                        continue
                    child_sec = section_by_idx.get(child_idx)
                    if child_sec is None or _section_kind(child_sec) != "code":
                        continue
                    child_content = bytes(child_sec.content)
                    if not child_content:
                        continue
                    append_at = len(func_bytes)
                    func_bytes.extend(child_content)
                    for rel_off, desc in _resolve_section_relocs(child_sec, section_by_idx).items():
                        func_relocs[append_at + rel_off] = desc
                        func_reloc_widths[append_at + rel_off] = desc[1]
                    consumed_children.add(child_idx)
                size = len(func_bytes)
            if kind != "bss":
                size = len(func_bytes)

            record = {
                "bytes": bytearray(func_bytes),
                "offset": start,
                "relocs": func_relocs,
                "reloc_widths": func_reloc_widths,
                "is_thunk": bool(_is_thunk_bytes(func_bytes)),
                "is_weak": bool(sym.is_weak_external),
                "flags": list(flags),
                "section_kind": kind,
                "size": size,
                "section_bytes": content,
                "section_name": sec.name,
                "arch": arch,
            }
            if LIEF_EXTENDED:
                try:
                    if sym.demangled_name:
                        record["demangled_name"] = sym.demangled_name
                except Exception:
                    pass
            funcs_out[sym.name] = record

    return funcs_out