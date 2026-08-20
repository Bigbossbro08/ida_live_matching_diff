"""
ida_matcher.matcher.coff_pure
~~~~~~~~~~~~~~~~~~~~~~~~~
Pure-Python COFF .obj parser (zero dependencies, x86 32-bit / MSVC 6 compatible).
Fallback behind `coff_parser.load_obj` when LIEF is unavailable or disabled.

Parses IMAGE_FILE_HEADER, sections, symbols, and relocations to
extract function bytes and relocation data directly from .obj files.
"""
import struct
from pathlib import Path
from typing import Dict, List, Tuple

# Struct formats (little-endian)
IMAGE_FILE_HEADER_FMT = "<HHIIIHH"
IMAGE_FILE_HEADER_SIZE = 20

IMAGE_SECTION_HEADER_FMT = "<8sIIIIIIHHI"
IMAGE_SECTION_HEADER_SIZE = 40

IMAGE_SYMBOL_FMT = "<8sIhHBB"
IMAGE_SYMBOL_SIZE = 18

IMAGE_RELOCATION_FMT = "<IIH"
IMAGE_RELOCATION_SIZE = 10

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_CLASS_LABEL = 6
IMAGE_SYM_TYPE_FUNCTION = 0x20

# IMAGE_REL_I386 relocation types (masking width depends on the type)
IMAGE_REL_I386_DIR16   = 0x0001
IMAGE_REL_I386_REL16   = 0x0002
IMAGE_REL_I386_DIR32   = 0x0006
IMAGE_REL_I386_DIR32NB = 0x0007
IMAGE_REL_I386_SEG12   = 0x0009
IMAGE_REL_I386_REL32   = 0x0014

IMAGE_REL_I386_WIDTHS = {
    IMAGE_REL_I386_DIR16:   2,
    IMAGE_REL_I386_REL16:   2,
    IMAGE_REL_I386_DIR32:   4,
    IMAGE_REL_I386_DIR32NB: 4,
    IMAGE_REL_I386_SEG12:   2,
    IMAGE_REL_I386_REL32:   4,
}

IMAGE_REL_I386_NAMES = {
    IMAGE_REL_I386_DIR16: "IMAGE_REL_I386_DIR16",
    IMAGE_REL_I386_REL16: "IMAGE_REL_I386_REL16",
    IMAGE_REL_I386_DIR32: "IMAGE_REL_I386_DIR32",
    IMAGE_REL_I386_DIR32NB: "IMAGE_REL_I386_DIR32NB",
    IMAGE_REL_I386_SEG12: "IMAGE_REL_I386_SEG12",
    IMAGE_REL_I386_REL32: "IMAGE_REL_I386_REL32",
}

def _reloc_width(r_type: int) -> int:
    return IMAGE_REL_I386_WIDTHS.get(r_type, 4)

def parse_string_table(f, offset: int) -> bytes:
    """Read the COFF string table located after the symbol table."""
    f.seek(offset)
    try:
        size_bytes = f.read(4)
        if len(size_bytes) < 4:
            return b""
        size = struct.unpack("<I", size_bytes)[0]
        if size <= 4:
            return b""
        return f.read(size - 4)
    except Exception:
        return b""

def load_obj_pure(obj_path: Path) -> Dict[str, Dict]:
    """
    Parse a COFF .obj file and extract function byte boundaries and relocations.
    
    Returns:
        { mangled_name: {"bytes": bytearray, "offset": int, "relocs": {rel_off: symbol_name}} }
    """
    funcs_out = {}
    
    try:
        fh = open(obj_path, "rb")
    except OSError:
        return funcs_out
    
    with fh as f:
        # 1. IMAGE_FILE_HEADER
        header_data = f.read(IMAGE_FILE_HEADER_SIZE)
        if len(header_data) < IMAGE_FILE_HEADER_SIZE:
            return funcs_out
            
        machine, num_sections, timestamp, sym_ptr, num_syms, opt_hdr, chars = \
            struct.unpack(IMAGE_FILE_HEADER_FMT, header_data)
            
        # 2. IMAGE_SECTION_HEADER[]
        f.seek(IMAGE_FILE_HEADER_SIZE + opt_hdr)
        sections = []
        for i in range(num_sections):
            sec_data = f.read(IMAGE_SECTION_HEADER_SIZE)
            name_raw, v_size, v_addr, raw_size, raw_ptr, reloc_ptr, line_ptr, num_relocs, num_lines, flags = \
                struct.unpack(IMAGE_SECTION_HEADER_FMT, sec_data)
            
            # Null-terminated string parsing
            name = name_raw.split(b"\x00", 1)[0].decode("latin1")
            
            sections.append({
                "index": i + 1,  # 1-based index in symbol table
                "name": name,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "reloc_ptr": reloc_ptr,
                "num_relocs": num_relocs,
                "relocs": {},
                "bytes": b"",
                "flags": flags
            })
            
        # 3. Read Section Raw Bytes and Relocations
        for sec in sections:
            if sec["raw_ptr"] > 0 and sec["raw_size"] > 0:
                f.seek(sec["raw_ptr"])
                sec["bytes"] = f.read(sec["raw_size"])
                
            if sec["reloc_ptr"] > 0 and sec["num_relocs"] > 0:
                f.seek(sec["reloc_ptr"])
                for _ in range(sec["num_relocs"]):
                    rel_data = f.read(IMAGE_RELOCATION_SIZE)
                    if len(rel_data) < IMAGE_RELOCATION_SIZE:
                        break
                    v_addr, sym_idx, r_type = struct.unpack(IMAGE_RELOCATION_FMT, rel_data)
                    sec["relocs"][v_addr] = {"sym": sym_idx, "type": r_type}

        # 4. Symbol Table & String Table
        str_table_offset = sym_ptr + (num_syms * IMAGE_SYMBOL_SIZE)
        str_table = parse_string_table(f, str_table_offset)
        
        f.seek(sym_ptr)
        symbols = []
        i = 0
        while i < num_syms:
            sym_data = f.read(IMAGE_SYMBOL_SIZE)
            if len(sym_data) < IMAGE_SYMBOL_SIZE:
                break
                
            name_bytes, val, sec_num, s_type, s_class, num_aux = struct.unpack(IMAGE_SYMBOL_FMT, sym_data)
            
            if name_bytes[:4] == b"\x00\x00\x00\x00":
                # Long name from string table
                str_offset = struct.unpack("<I", name_bytes[4:8])[0]
                actual_off = str_offset - 4
                if 0 <= actual_off < len(str_table):
                    end_idx = str_table.find(b"\x00", actual_off)
                    if end_idx != -1:
                        name = str_table[actual_off:end_idx].decode("latin1")
                    else:
                        name = str_table[actual_off:].decode("latin1")
                else:
                    name = f"unk_str_{str_offset}"
            else:
                name = name_bytes.split(b"\x00", 1)[0].decode("latin1")
                
            symbols.append({
                "name": name,
                "value": val,
                "section": sec_num,
                "type": s_type,
                "class": s_class,
                "index": i,
                "aux_count": num_aux
            })
            
            if num_aux > 0:
                f.seek(num_aux * IMAGE_SYMBOL_SIZE, 1)
                for _ in range(num_aux):
                    symbols.append(None)
            
            i += 1 + num_aux

        # Resolve relocations
        for sec in sections:
            resolved_relocs = {}
            for offset, info in sec["relocs"].items():
                r_type = info["type"]
                width = _reloc_width(r_type)
                r_class = IMAGE_REL_I386_NAMES.get(r_type, f"unknown_{r_type}")

                sym_idx = info["sym"]
                t_name = f"unk_sym_{sym_idx}"
                t_sec_name = ""
                t_sec_kind = "unknown"
                sym_addr = 0
                sym_size = 0
                sym_kind = "unknown"
                addend = 0

                if sym_idx < len(symbols) and symbols[sym_idx] is not None:
                    t_sym = symbols[sym_idx]
                    t_name = t_sym["name"]
                    sym_addr = t_sym["value"]
                    t_sec_idx = t_sym["section"]
                    if t_sec_idx > 0 and t_sec_idx <= len(sections):
                        t_sec = sections[t_sec_idx - 1]
                        t_sec_name = t_sec["name"]
                        if t_sec["flags"] & 0x00000020:
                            t_sec_kind = "code"
                        elif t_sec["flags"] & 0x00000080:
                            t_sec_kind = "bss"
                        else:
                            t_sec_kind = "data"
                        sym_kind = "code" if t_sec_kind == "code" else "data"
                        if width > 0:
                            try:
                                b = sec["bytes"][offset:offset+width]
                                if len(b) == width:
                                    addend = int.from_bytes(b, "little")
                            except Exception:
                                pass

                resolved_relocs[offset] = (t_name, width, r_class, addend, t_sec_name, t_sec_kind,
                                           sym_addr, sym_size, sym_kind)
            sec["relocs"] = resolved_relocs

        # 5. Extract Functions
        code_syms = []
        # IMAGE_SCN_CNT_CODE = 0x00000020
        for s in symbols:
            if s and s["section"] > 0:
                sec = sections[s["section"] - 1]
                # Only keep function-like symbols (derived type nibble: 0=none, 2=function).
                # Ignore internal MSVC labels (e.g. $L jump tables) which artificially truncate functions.
                if (sec["flags"] & 0x00000020) and (s["type"] & 0x00F0) in (0x00, IMAGE_SYM_TYPE_FUNCTION):
                    if not s["name"].startswith("$"):
                        code_syms.append(s)
                
        sec_to_syms = {}
        for s in code_syms:
            sec_to_syms.setdefault(s["section"], []).append(s)
            
        for sec_num, syms_in_sec in sec_to_syms.items():
            sec = sections[sec_num - 1]
            syms_in_sec.sort(key=lambda x: x["value"])
            
            for idx, sym in enumerate(syms_in_sec):
                if not (sym["name"].startswith("?") or sym["name"].startswith("_") or sym["name"].startswith("@")):
                    continue
                if sym["class"] not in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_LABEL):
                    continue
                if sym["name"].startswith("__imp_"):
                    continue
                    
                start = sym["value"]
                end = sec["raw_size"]
                for next_sym in syms_in_sec[idx+1:]:
                    if next_sym["value"] > start:
                        end = next_sym["value"]
                        break
                        
                size = end - start
                if size <= 0:
                    continue
                    
                func_bytes = sec["bytes"][start:start+size]
                
                func_relocs = {}
                func_reloc_widths = {}
                for offset, desc in sec["relocs"].items():
                    if start <= offset < end:
                        func_relocs[offset - start] = desc
                        func_reloc_widths[offset - start] = desc[1]

                if sym["name"] in funcs_out:
                    continue

                funcs_out[sym["name"]] = {
                    "bytes": bytearray(func_bytes),
                    "offset": start,
                    "relocs": func_relocs,
                    "reloc_widths": func_reloc_widths,
                    "section_bytes": sec["bytes"],
                    "section_name": sec["name"],
                }
                
    return funcs_out
