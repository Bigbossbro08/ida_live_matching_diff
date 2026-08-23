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

# IMAGE_COMDAT_SELECTION values (SEC_DEF auxiliary record)
IMAGE_COMDAT_SELECT_NODUPLICATES = 1
IMAGE_COMDAT_SELECT_ANY = 2
IMAGE_COMDAT_SELECT_SAME_SIZE = 3
IMAGE_COMDAT_SELECT_EXACT_SIZE = 4
IMAGE_COMDAT_SELECT_ASSOCIATIVE = 5
IMAGE_COMDAT_SELECT_LARGEST = 6
IMAGE_COMDAT_SELECT_NEWEST = 7

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

def _parse_sec_def_aux(aux: bytes):
    """Parse a SECTION DEFINITION auxiliary record.

    Returns (length, assoc_parent, selection) where assoc_parent is the
    1-based section number this COMDAT is associative to (0 if not).
    """
    if len(aux) < 18:
        return None
    length, num_relocs, num_lines, checksum, number, selection, _reserved, high_number = \
        struct.unpack("<IHHIhBBh", aux)
    parent = number
    if parent and high_number:
        parent += high_number * 65536
    return (length, parent if selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE else 0, selection)

def _parse_func_def_aux(aux: bytes):
    """Parse a FUNCTION DEFINITION auxiliary record; returns total_size or None."""
    if len(aux) < 8:
        return None
    length = struct.unpack("<I", aux[:4])[0]
    return length or None

def scan_coff_aux(data):
    """Walk the raw COFF symbol table of an unwrapped .obj image.

    Community LIEF builds drop SECTION_DEF/FUNC_DEF auxiliary records for
    regular symbols, so both parsers use this raw walk instead.

    Returns (assoc_children, funcdef_sizes):
      assoc_children: {parent_section_number: [child_section_number, ...]}
          from SECDEF records with IMAGE_COMDAT_SELECT_ASSOCIATIVE (MSVC 6
          puts each C++ EH funclet/thunk into a `.text$x` COMDAT associated
          with its parent function's code section).
      funcdef_sizes: {symbol_name: total_length} from FUNCDEF records.
    """
    assoc_children = {}
    funcdef_sizes = {}
    try:
        if len(data) < IMAGE_FILE_HEADER_SIZE:
            return assoc_children, funcdef_sizes
        machine, num_sections, _ts, sym_ptr, num_syms, opt_hdr, _chars = \
            struct.unpack(IMAGE_FILE_HEADER_FMT, data[:IMAGE_FILE_HEADER_SIZE])
        stroff = sym_ptr + num_syms * IMAGE_SYMBOL_SIZE
        size_field = data[stroff:stroff + 4]
        if len(size_field) < 4:
            return assoc_children, funcdef_sizes
        strsize = struct.unpack("<I", size_field)[0]
        strtab = data[stroff + 4:stroff + max(strsize, 4)]
        i = 0
        while i < num_syms:
            off = sym_ptr + i * IMAGE_SYMBOL_SIZE
            rec = data[off:off + IMAGE_SYMBOL_SIZE]
            if len(rec) < IMAGE_SYMBOL_SIZE:
                break
            name_bytes, val, sec_num, s_type, s_class, num_aux = struct.unpack(IMAGE_SYMBOL_FMT, rec)
            if name_bytes[:4] == b"\x00\x00\x00\x00":
                soff = struct.unpack("<I", name_bytes[4:8])[0] - 4
                if 0 <= soff < len(strtab):
                    end_idx = strtab.find(b"\x00", soff)
                    name = strtab[soff:end_idx].decode("latin1") if end_idx != -1 else strtab[soff:].decode("latin1")
                else:
                    name = f"unk_str_{soff}"
            else:
                name = name_bytes.split(b"\x00", 1)[0].decode("latin1")
            for k in range(num_aux):
                aoff = sym_ptr + (i + 1 + k) * IMAGE_SYMBOL_SIZE
                aux = data[aoff:aoff + IMAGE_SYMBOL_SIZE]
                if len(aux) < IMAGE_SYMBOL_SIZE:
                    break
                if s_class == IMAGE_SYM_CLASS_STATIC and name.startswith("."):
                    parsed = _parse_sec_def_aux(aux)
                    if parsed and parsed[1] > 0:
                        assoc_children.setdefault(parsed[1], []).append(sec_num)
                        break
                elif k == 0:
                    fsize = _parse_func_def_aux(aux)
                    if fsize and name not in funcdef_sizes:
                        funcdef_sizes[name] = fsize
            i += 1 + num_aux
    except Exception:
        pass
    return assoc_children, funcdef_sizes

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
                for _ in range(num_aux):
                    aux_data = f.read(IMAGE_SYMBOL_SIZE)
                    symbols.append(aux_data if len(aux_data) == IMAGE_SYMBOL_SIZE else None)
            
            i += 1 + num_aux

        # Auxiliary-derived metadata: COMDAT association (SEC_DEF) and exact
        # function sizes (FUNC_DEF).
        assoc_children = {}
        funcdef_sizes = {}
        for sym in symbols:
            if not isinstance(sym, dict) or sym["aux_count"] <= 0:
                continue
            aux_list = []
            j = sym["index"] + 1
            while j < len(symbols) and len(aux_list) < sym["aux_count"]:
                if isinstance(symbols[j], (bytes, bytearray)):
                    aux_list.append(bytes(symbols[j]))
                else:
                    break
                j += 1
            if sym["class"] == IMAGE_SYM_CLASS_STATIC and sym["name"].startswith("."):
                for aux in aux_list:
                    parsed = _parse_sec_def_aux(aux)
                    if parsed and parsed[1] > 0:
                        assoc_children.setdefault(parsed[1], []).append(sym["section"])
                        break
            else:
                for aux in aux_list:
                    fsize = _parse_func_def_aux(aux)
                    if fsize:
                        funcdef_sizes[sym["index"]] = fsize
                        break

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
            consumed_children = set()
            
            for idx, sym in enumerate(syms_in_sec):
                if not (sym["name"].startswith("?") or sym["name"].startswith("_") or sym["name"].startswith("@")):
                    continue
                if sym["class"] not in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_LABEL):
                    continue
                if sym["name"].startswith("__imp_"):
                    continue
                    
                start = sym["value"]
                exact = funcdef_sizes.get(sym["index"])
                end = sec["raw_size"] if exact is None else start + exact
                if exact is None:
                    for next_sym in syms_in_sec[idx+1:]:
                        if next_sym["value"] > start:
                            if next_sym["name"].startswith("__unwind$") or next_sym["name"].startswith("__catch$"):
                                continue
                            end = next_sym["value"]
                            break
                            
                size = end - start
                if size <= 0:
                    continue
                    
                func_bytes = bytearray(sec["bytes"][start:start+size])
                
                func_relocs = {}
                func_reloc_widths = {}
                for offset, desc in sec["relocs"].items():
                    if start <= offset < start + size:
                        func_relocs[offset - start] = desc
                        func_reloc_widths[offset - start] = desc[1]

                # Attach associated EH funclet/thunk COMDATs (e.g. `.text$x`),
                # matching IDA's tail-chunk windows. Only unambiguous for a
                # single-function (COMDAT) section.
                if len(syms_in_sec) == 1 and any(
                        child_idx not in consumed_children for child_idx in assoc_children.get(sec_num, [])):
                    # Drop VC6's externalized-funclet NOP padding, matching the
                    # original binary's chunk split at the next function.
                    trim = len(func_bytes)
                    while trim > 0 and func_bytes[trim - 1] == 0x90:
                        trim -= 1
                    if trim < len(func_bytes):
                        del func_bytes[trim:]
                        size = len(func_bytes)
                    for child_idx in assoc_children.get(sec_num, []):
                        if child_idx in consumed_children or child_idx == sec_num:
                            continue
                        child_sec = sections[child_idx - 1]
                        if not (child_sec["flags"] & 0x00000020):
                            continue
                        child_content = child_sec["bytes"]
                        if not child_content:
                            continue
                        append_at = len(func_bytes)
                        func_bytes.extend(child_content)
                        for offset, desc in child_sec["relocs"].items():
                            func_relocs[append_at + offset] = desc
                            func_reloc_widths[append_at + offset] = desc[1]
                        consumed_children.add(child_idx)
                    size = len(func_bytes)

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
