"""
ida_matcher.matcher.match_core
~~~~~~~~~~~~~~~~~~~~~~~~
All matching / diffing logic (Pure Binary).
"""

import sys
import os
import json
import re
import struct
import urllib.request
import urllib.parse
from pathlib import Path

try:
    import capstone
except ImportError:
    pass

from ida_matcher.matcher.coff_parser import load_obj
from ida_matcher.matcher.engine.types import (
    DEFAULT_RELOC_WIDTH, RELOC_MODE_NAME_ADDRESS, RELOC_MODE_NONE, RELOC_MODE_DATA_VALUE, RELOC_MODE_ALL,
    _DiffContext, _InsnSource, InsnRef
)
from ida_matcher.matcher.engine.diff_code import (
    diff_code, _strip_switch_ranges, reloc_eq, symbol_name_matches, is_symbol_name_compiler_generated
)
from ida_matcher.matcher.engine.display import (
    diff_function, _configure_colors, GREEN, RED, YELLOW, DIM, RESET
)
from ida_matcher.matcher.engine.data import (
    diff_data_symbol, diff_bss_symbol, diff_data_section, diff_bss_section
)

IDA_SERVER_URL = "http://127.0.0.1:28000/func?name="

def _disassemble(raw_bytes, base_offset=0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    insns = []
    for insn in md.disasm(bytes(raw_bytes), base_offset):
        insns.append((insn.address, insn.mnemonic, insn.op_str, bytes(insn.bytes)))
    return insns

def _normalize_insn(addr, mnemonic, op_str, insn_bytes, relocs, widths=None):
    intersecting_relocs = []
    for r_off, r_sym in relocs.items():
        w = (widths or {}).get(r_off, DEFAULT_RELOC_WIDTH)
        if r_off < addr + len(insn_bytes) and r_off + w > addr:
            intersecting_relocs.append(r_sym)

    if intersecting_relocs:
        target = intersecting_relocs[0]
        if re.search(r'0x[0-9a-fA-F]+', op_str):
            op_str = re.sub(r'0x[0-9a-fA-F]+', f'<{target}>', op_str)
        else:
            op_str += f" ; <{target}>"

    if not intersecting_relocs:
        jump_mnemonics = ("call", "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns")
        if mnemonic in jump_mnemonics:
            m = re.match(r'^(0x)?([0-9a-fA-F]+)$', op_str.strip())
            if m:
                try:
                    target_addr = int(m.group(2), 16)
                    rel = target_addr - addr
                    op_str = f"loc_{rel:+#x}"
                except ValueError:
                    pass

    return f"{mnemonic:<8} {op_str}"

def _insn_has_reloc(addr, insn_bytes, relocs, widths=None):
    for r_off in relocs.keys():
        w = (widths or {}).get(r_off, DEFAULT_RELOC_WIDTH)
        if r_off < addr + len(insn_bytes) and r_off + w > addr:
            return True
    return False

def is_objdiff_py_enabled() -> bool:
    """Return True if the native Rust objdiff_py diff engine is enabled via OBJDIFF_PY env var."""
    val = os.environ.get("OBJDIFF_PY", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def get_diff_direction(mappings_config=None, override=None) -> str:
    """Resolve diff direction: 'left_to_right' (default) or 'right_to_left'."""
    if override:
        return override
    env_dir = os.environ.get("OBJDIFF_DIFF_DIRECTION", "").strip().lower()
    if env_dir in ("right_to_left", "rtl", "objdiff"):
        return "right_to_left"
    if isinstance(mappings_config, dict):
        cfg_dir = str(mappings_config.get("diff_direction", "")).strip().lower()
        if cfg_dir in ("right_to_left", "rtl", "objdiff"):
            return "right_to_left"
    elif hasattr(mappings_config, "diff_direction"):
        cfg_dir = str(getattr(mappings_config, "diff_direction", "")).strip().lower()
        if cfg_dir in ("right_to_left", "rtl", "objdiff"):
            return "right_to_left"
    return "left_to_right"


def _apply_reloc_mappings(obj_relocs, reloc_mappings):
    """Rewrite reloc target names from the obj's naming scheme (MSVC mangled)
    to the IDA-side names (e.g. Itanium mangled) so reloc_eq matches them.

    obj_relocs values are either a bare symbol name (str) or a tuple whose
    first element is the target symbol name (rest = width/class/addend/...).

    Mapped relocs get a trailing True flag so reloc_eq knows the name match is
    authoritative: the IDA side records the resolved VA as its addend and its
    enclosing section, while the obj side records addend 0 and the target's
    real section, so those fields must not be compared for mapped names."""
    if not reloc_mappings:
        return obj_relocs
    out = {}
    for off, v in obj_relocs.items():
        if isinstance(v, tuple):
            name = v[0]
            if name in reloc_mappings:
                out[int(off)] = (reloc_mappings[name],) + tuple(v[1:]) + (True,)
            else:
                out[int(off)] = v
        else:
            out[int(off)] = reloc_mappings.get(str(v), v)
    return out


def fetch_synthetic_obj_from_ida(func_name: str) -> bytes | None:
    """Fetch raw synthetic COFF .obj bytes for a symbol from IDA server."""
    encoded_name = urllib.parse.quote(func_name)
    url = f"http://127.0.0.1:28000/synthetic_obj?name={encoded_name}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status == 200:
                return response.read()
    except Exception:
        return None
    return None


def _compare_functions_objdiff_py(obj_bytes, base_bytes, obj_relocs, base_fixups, obj_reloc_widths=None, arch="x86", diff_direction=None):
    from objdiff_py import ObjectBuilder, diff_objects

    b_left = ObjectBuilder(arch)
    sec_l = b_left.add_section(".text", "", 0)
    if obj_bytes:
        b_left.write_bytes(sec_l, 0, bytes(obj_bytes))
    sym_l = b_left.add_symbol(sec_l, "target_func", 0, len(obj_bytes), 2, 0)
    l_map = {}
    for r_off, r_target in obj_relocs.items():
        if isinstance(r_target, tuple):
            r_name = r_target[0]
            r_width = r_target[1]
            r_cls = r_target[2]
            r_addend = r_target[3] if len(r_target) > 3 else 0
        else:
            r_name = str(r_target)
            r_width = (obj_reloc_widths or {}).get(r_off, 4)
            r_cls = "absolute"
            r_addend = 0
        if r_name not in l_map:
            l_map[r_name] = b_left.add_symbol(0xFFFFFFFF, r_name, 0, 0, 3, 0)
        reloc_kind = 1 if r_cls == "relative" or r_width == 2 else 6
        writer_addend = int(r_addend) - 4 if r_cls == "relative" else (0 if r_width == 2 else int(r_addend))
        b_left.add_relocation(sec_l, int(r_off), l_map[r_name], reloc_kind, int(r_width), writer_addend)
    left_obj = b_left.finish()

    b_right = ObjectBuilder(arch)
    sec_r = b_right.add_section(".text", "", 0)
    r_data = bytearray(bytes(base_bytes)) if base_bytes else bytearray()
    for r_off, r_target in base_fixups.items():
        if isinstance(r_target, tuple):
            r_width = r_target[1]
            r_addend = r_target[3] if len(r_target) > 3 else 0
        else:
            r_width = 4
            r_addend = 0
        off = int(r_off)
        w = int(r_width)
        add = int(r_addend)
        if off + w <= len(r_data):
            if w == 4:
                r_data[off:off + 4] = struct.pack("<i", add)
            elif w == 2:
                r_data[off:off + 2] = struct.pack("<h", add)
            elif w == 8:
                r_data[off:off + 8] = struct.pack("<q", add)

    if r_data:
        b_right.write_bytes(sec_r, 0, bytes(r_data))
    sym_r = b_right.add_symbol(sec_r, "target_func", 0, len(r_data), 2, 0)
    r_map = {}
    for r_off, r_target in base_fixups.items():
        if isinstance(r_target, tuple):
            r_name = r_target[0]
            r_width = r_target[1]
            r_cls = r_target[2]
            r_addend = r_target[3] if len(r_target) > 3 else 0
        else:
            r_name = str(r_target)
            r_width = 4
            r_cls = "absolute"
            r_addend = 0
        if r_name not in r_map:
            r_map[r_name] = b_right.add_symbol(0xFFFFFFFF, r_name, 0, 0, 3, 0)
        reloc_kind = 1 if r_cls == "relative" or r_width == 2 else 6
        writer_addend = int(r_addend) - 4 if r_cls == "relative" else (0 if r_width == 2 else int(r_addend))
        b_right.add_relocation(sec_r, int(r_off), r_map[r_name], reloc_kind, int(r_width), writer_addend)
    right_obj = b_right.finish()

    direction = get_diff_direction(override=diff_direction)
    if direction == "right_to_left":
        diff_res = diff_objects(right_obj, left_obj)
    else:
        diff_res = diff_objects(left_obj, right_obj)

    syms = (diff_res.get("left") or {}).get("symbols", [])
    if syms and syms[0].get("match_percent") is not None:
        pct = float(syms[0]["match_percent"])
        diff_score = tuple(syms[0]["diff_score"]) if syms[0].get("diff_score") else (0, 0)
    else:
        pct = 0.0
        diff_score = (0, 0)
    return pct, diff_score


def compare_functions(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, obj_reloc_widths=None, base_switch_ranges=None,
                      reloc_mode=RELOC_MODE_NAME_ADDRESS, return_details=False, left_accessor=None, right_accessor=None, arch="x86",
                      diff_direction=None):
    """Instruction-level match of an .obj function against the IDA-served bytes."""
    base_bytes_hex = re.sub(r'[^0-9a-fA-F]', '', base_bytes_hex)
    if len(base_bytes_hex) % 2 != 0:
        base_bytes_hex = base_bytes_hex[:-1]

    base_bytes = bytearray.fromhex(base_bytes_hex)
    obj_bytes = bytearray(obj_bytes)

    if base_switch_ranges:
        base_bytes, base_fixups = _strip_switch_ranges(base_bytes, base_fixups, base_switch_ranges)
        obj_bytes, obj_relocs, obj_reloc_widths = _strip_switch_ranges(
            obj_bytes, obj_relocs, base_switch_ranges, obj_reloc_widths or {}
        )

    while obj_bytes and obj_bytes[-1] in (0x90, 0xCC):
        obj_bytes.pop()
    while base_bytes and base_bytes[-1] in (0x90, 0xCC):
        base_bytes.pop()

    total_count = max(len(obj_bytes), len(base_bytes))
    if total_count == 0:
        if return_details:
            return 0.0, 0, (0, 0)
        return 0.0, 0

    if is_objdiff_py_enabled():
        try:
            pct, diff_score = _compare_functions_objdiff_py(
                bytes(obj_bytes), bytes(base_bytes), obj_relocs, base_fixups,
                obj_reloc_widths=obj_reloc_widths, arch=arch, diff_direction=diff_direction
            )
            if return_details:
                return pct, total_count, diff_score
            return pct, total_count
        except Exception:
            pass

    result = diff_code(
        bytes(obj_bytes), obj_relocs, obj_reloc_widths or {},
        bytes(base_bytes), base_fixups, {k: DEFAULT_RELOC_WIDTH for k in base_fixups},
        reloc_mode=reloc_mode, left_data_accessor=left_accessor, right_data_accessor=right_accessor, arch=arch
    )
    if return_details:
        return result["match_percent"], total_count, (result["diff_score"], result["max_score"])
    return result["match_percent"], total_count

def find_symbol(left_name: str, obj_funcs: dict, all_base_records: dict, right_used: set, fuzzy_literals: bool) -> str:
    from .engine.diff_code import symbol_name_matches, is_symbol_name_compiler_generated
    left_sym = obj_funcs[left_name]
    section_kind = left_sym.get("section_kind", "code")
    section_name = left_sym.get("section_name", section_kind)
    left_flags = left_sym.get("flags", [])
    left_size = left_sym.get("size", 0)

    is_cg = "CompilerGenerated" in left_flags or is_symbol_name_compiler_generated(left_name)

    if is_cg and section_kind in ("code", "data", "bss"):
        closest_right_name = None
        closest_match_percent = 0.0

        for right_name, right_sym in all_base_records.items():
            if right_name in right_used:
                continue
            r_sec_name = right_sym.get("section_name", "")
            r_sec_kind = right_sym.get("section_kind", "unknown")
            r_cg = right_sym.get("compiler_generated", False) or is_symbol_name_compiler_generated(right_name)

            # Relink units place code in a custom section (.rogan2) while the
            # base binary's code lives in .text; code sections are equivalent
            # regardless of the exact section name.
            sec_name_ok = (r_sec_name == section_name) or (section_kind == "code" and r_sec_kind == "code")
            if not sec_name_ok or r_sec_kind != section_kind or not r_cg:
                continue

            if section_kind in ("code", "data"):
                pct = compare_for_pairing(left_name, right_name, obj_funcs, all_base_records)
                if pct == 100.0 or (fuzzy_literals and pct >= 50.0 and pct > closest_match_percent):
                    closest_right_name = right_name
                    closest_match_percent = pct
                    if pct == 100.0:
                        break
            elif section_kind == "bss":
                if left_size == right_sym.get("size", 0):
                    closest_right_name = right_name
                    break

        return closest_right_name

    for right_name, right_sym in all_base_records.items():
        if right_name in right_used:
            continue
        r_sec_name = right_sym.get("section_name", "")
        r_sec_kind = right_sym.get("section_kind", "unknown")

        sec_name_ok = (r_sec_name == section_name) or (section_kind == "code" and r_sec_kind == "code")
        if symbol_name_matches(left_name, right_name) and r_sec_kind == section_kind and sec_name_ok:
            return right_name

    return None

def compare_for_pairing(left_name, right_name, obj_funcs, all_base_records):
    left_sym = obj_funcs[left_name]
    right_sym = all_base_records[right_name]

    b_f_w = right_sym.get("fixup_widths", {})
    b_f_c = right_sym.get("fixup_classes", {})
    b_f_a = right_sym.get("fixup_addends", {})
    b_sym_a = right_sym.get("fixup_sym_addrs", {})
    b_sym_s = right_sym.get("fixup_sym_sizes", {})
    b_sym_k = right_sym.get("fixup_sym_kinds", {})
    base_fixups = {}
    for k, v in right_sym.get("fixups", {}).items():
        base_fixups[int(k)] = (v, b_f_w.get(str(k), 4), b_f_c.get(str(k), "absolute"), b_f_a.get(str(k), 0),
                               "", "unknown", b_sym_a.get(str(k), 0), b_sym_s.get(str(k), 0), b_sym_k.get(str(k), "unknown"))

    l_f_w = left_sym.get("reloc_widths", {})
    left_relocs = left_sym.get("relocs", {})

    left_bytes = left_sym.get("bytes", b"")
    right_bytes = bytes.fromhex(right_sym.get("bytes", "")) if right_sym.get("bytes") else b""

    pct, _ = diff_data_symbol(left_bytes, right_bytes, left_relocs, base_fixups, l_f_w, {int(k): v for k, v in b_f_w.items()})
    return pct

def apply_symbol_mappings(obj_funcs, all_base_records, mappings_config, left_used, right_used, matches):
    selecting_left = mappings_config.get("selecting_left")
    selecting_right = mappings_config.get("selecting_right")
    
    if selecting_left and selecting_left in obj_funcs:
        left_used.add(selecting_left)
    if selecting_right and selecting_right in all_base_records:
        right_used.add(selecting_right)
        
    mappings = mappings_config.get("mappings", {})
    for left_name, right_name in mappings.items():
        if left_name not in obj_funcs or left_name in left_used:
            continue
        if right_name not in all_base_records or right_name in right_used:
            continue
            
        l_sec_kind = obj_funcs[left_name].get("section_kind", "unknown")
        r_sec_kind = all_base_records[right_name].get("section_kind", "unknown")
        if l_sec_kind != r_sec_kind:
            continue
            
        matches.append((left_name, right_name))
        left_used.add(left_name)
        right_used.add(right_name)

def matching_symbols(obj_funcs: dict, all_base_records: dict, mappings_config: dict = None):
    matches = []
    left_used = set()
    right_used = set()

    if mappings_config:
        apply_symbol_mappings(obj_funcs, all_base_records, mappings_config, left_used, right_used, matches)

    for fuzzy in [False, True]:
        for left_name, left_sym in obj_funcs.items():
            if left_name in left_used:
                continue
            if left_sym.get("size", 0) == 0 or "Ignored" in left_sym.get("flags", []):
                continue
            
            right_name = find_symbol(left_name, obj_funcs, all_base_records, right_used, fuzzy)
            if right_name is not None:
                matches.append((left_name, right_name))
                left_used.add(left_name)
                right_used.add(right_name)

    for left_name, left_sym in obj_funcs.items():
        if left_name not in left_used and left_sym.get("size", 0) > 0 and "Ignored" not in left_sym.get("flags", []):
            matches.append((left_name, None))
            left_used.add(left_name)

    return matches

def find_similar_code_symbols(obj_path: Path, source_name: str, parser: str = "auto",
                              reloc_mode=RELOC_MODE_NAME_ADDRESS) -> int:
    """objdiff `find_similar_code_symbols` (diff/mod.rs:531): rank every
    right-side (IDA) code symbol by instruction-diff match_percent against a
    single .obj code symbol, best first. Returns an exit code."""
    refresh_ida_cache()
    obj_funcs = load_obj(obj_path, parser=parser)

    source = obj_funcs.get(source_name)
    if source is None:
        print(f"{RED}Symbol '{source_name}' not found in the .obj file.{RESET}")
        return 0
    if source.get("section_kind", "code") != "code":
        print(f"{YELLOW}Symbol '{source_name}' is not a code symbol; nothing to rank.{RESET}")
        return 0

    if not server_alive():
        print(
            f"{RED}Cannot connect to the live IDA server on 127.0.0.1:28000.{RESET}\n"
            f"{YELLOW}Ensure ida_server.py is running inside IDA, then retry.{RESET}"
        )
        return 0

    names = fetch_all_names_from_ida()
    records = (fetch_many_from_ida(names) if names else {}) or {}
    if not records:
        print("No symbols available from the live IDA server.")
        return 0

    all_base_records = {
        n: r for n, r in records.items()
        if r.get("section_kind", "unknown") == "code"
        and r.get("size", 0) > 0 and r.get("bytes")
        and not r.get("is_thunk")
    }

    left_accessor = make_left_accessor(obj_funcs)
    right_accessor = make_right_accessor(all_base_records)

    results = []
    for name, rec in all_base_records.items():
        b_f_w = rec.get("fixup_widths", {})
        b_f_c = rec.get("fixup_classes", {})
        b_f_a = rec.get("fixup_addends", {})
        b_sym_a = rec.get("fixup_sym_addrs", {})
        b_sym_s = rec.get("fixup_sym_sizes", {})
        b_sym_k = rec.get("fixup_sym_kinds", {})
        b_sec_name = rec.get("section_name", "")
        b_sec_kind = rec.get("section_kind", "code")
        base_fixups = {}
        for k, v in rec.get("fixups", {}).items():
            base_fixups[int(k)] = (v, b_f_w.get(str(k), 4), b_f_c.get(str(k), "absolute"),
                                   b_f_a.get(str(k), 0), b_sec_name, b_sec_kind,
                                   b_sym_a.get(str(k), 0), b_sym_s.get(str(k), 0),
                                   b_sym_k.get(str(k), "unknown"))
        pct, _ = compare_functions(
            source["bytes"], rec.get("bytes", ""), source.get("relocs", {}),
            base_fixups, source.get("reloc_widths", {}), rec.get("switch_ranges", []),
            reloc_mode=reloc_mode, left_accessor=left_accessor, right_accessor=right_accessor,
        )
        results.append((name, pct))

    results.sort(key=lambda r: r[1], reverse=True)

    print(f"{YELLOW}Similar code symbols in IDA for '{source_name}':{RESET}")
    for name, pct in results:
        line = f"{pct:5.1f}%  {name}"
        print(GREEN + line + RESET if pct == 100.0 else line)
    return 0

def fetch_all_names_from_ida():
    url = "http://127.0.0.1:28000/all_names"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
            return data.get("names", [])
    except Exception:
        return []

def fetch_from_ida(func_name):
    encoded_name = urllib.parse.quote(func_name)
    url = IDA_SERVER_URL + encoded_name
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
            if "bytes" in data:
                return data
    except Exception:
        return None
    return None

def fetch_many_from_ida(names):
    if not names:
        return {}
    url = "http://127.0.0.1:28000/funcs?names=" + urllib.parse.quote(",".join(names))
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = json.loads(response.read().decode())
        results = data.get("results") or {}
        return {k: v for k, v in results.items() if v is not None}
    except Exception:
        return None

def fetch_data_from_ida(func_name):
    encoded_name = urllib.parse.quote(func_name)
    url = "http://127.0.0.1:28000/data?name=" + encoded_name
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
            if "bytes" in data:
                return data
    except Exception:
        return None
    return None

def fetch_many_data_from_ida(names):
    if not names:
        return {}
    url = "http://127.0.0.1:28000/datas?names=" + urllib.parse.quote(",".join(names))
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = json.loads(response.read().decode())
        results = data.get("results") or {}
        return {k: v for k, v in results.items() if v is not None}
    except Exception:
        return None

def make_left_accessor(obj_funcs):
    def accessor(sym_name):
        if sym_name not in obj_funcs: return None
        func = obj_funcs[sym_name]
        return func.get("section_bytes", func.get("bytes")), func.get("offset", 0)
    return accessor

def make_right_accessor(base_records, offline=False):
    def accessor(sym_name):
        if sym_name not in base_records and not offline:
            res = fetch_data_from_ida(sym_name)
            if res:
                base_records[sym_name] = res
        rec = base_records.get(sym_name)
        if not rec: return None
        raw = bytes.fromhex(rec["bytes"]) if "bytes" in rec else b""
        return raw, 0
    return accessor


def _load_baseline(baseline):
    """Accept a baseline as a dict or a path to a JSON file; return the dict."""
    if isinstance(baseline, dict):
        return baseline
    import pathlib
    p = pathlib.Path(baseline)
    with open(p, "r") as f:
        return json.load(f)

def server_alive():
    """True when the live IDA server responds to GET /health."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:28000/health", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False

def refresh_ida_cache():
    """Ask the live IDA server to rebuild its name->address cache."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:28000/refresh", timeout=10) as response:
            response.read()
    except Exception:
        pass

def match_summary(obj_path: Path, json_out: bool = False, strict: bool = False, parser: str = "auto", reloc_mode=RELOC_MODE_NAME_ADDRESS, mappings_config=None, baseline=None, diff_direction=None) -> int:
    obj_funcs = load_obj(obj_path, parser=parser)

    if not obj_funcs:
        if not json_out: print("No functions found in the .obj file.")
        return 0

    reloc_mappings = (mappings_config or {}).get("reloc_mappings", {})
    if reloc_mappings:
        for name in list(obj_funcs):
            obj_funcs[name]["relocs"] = _apply_reloc_mappings(
                obj_funcs[name].get("relocs", {}), reloc_mappings)

    if baseline is not None:
        # Offline mode: load base records from baseline, skip all server calls
        all_base_records = dict(_load_baseline(baseline))
        left_accessor = make_left_accessor(obj_funcs)
        right_accessor = make_right_accessor(all_base_records, offline=True)
    else:
        # Live mode: unchanged
        refresh_ida_cache()

        if not server_alive():
            msg = (
                f"{RED}Cannot connect to the live IDA server on 127.0.0.1:28000.{RESET}\n"
                f"{YELLOW}Ensure ida_server.py is running inside IDA, then retry.{RESET}"
            )
            if json_out:
                print(json.dumps({"obj": str(obj_path), "connected": False}))
            else:
                print(msg)
            return 0

        code_syms = [n for n, d in obj_funcs.items() if d.get("section_kind", "code") == "code"]
        data_syms = [n for n, d in obj_funcs.items() if d.get("section_kind", "code") != "code"]

        records = fetch_many_from_ida(code_syms) or {n: rec for n in code_syms if (rec := fetch_from_ida(n)) is not None}
        data_records = fetch_many_data_from_ida(data_syms) or {n: rec for n in data_syms if (rec := fetch_data_from_ida(n)) is not None}

        all_base_records = dict(records)
        all_base_records.update(data_records)

        left_accessor = make_left_accessor(obj_funcs)
        right_accessor = make_right_accessor(all_base_records)

    rows = []
    sections_map = {}

    matches = matching_symbols(obj_funcs, all_base_records, mappings_config)
    direction = get_diff_direction(mappings_config, override=diff_direction)

    for left_name, right_name in matches:
        func_data = obj_funcs[left_name]
        kind = func_data.get("section_kind", "code")
        sec_name = func_data.get("section_name", kind)
        if sec_name not in sections_map:
            sections_map[sec_name] = {
                "name": sec_name, "kind": kind, "symbols": [],
                "obj_data": func_data.get("section_bytes", b""),
                "generic_weight": 0.0, "generic_total_size": 0,
                "right_data": bytearray(), "right_relocs": {}, "left_relocs": {},
                "right_reloc_widths": {}, "left_reloc_widths": {}
            }

        row = {"name": left_name, "status": None, "match_pct": None, "count": None, "diff_score": None, "section": sec_name, "size": 0}
        
        l_demangled = func_data.get("demangled_name")
        base_match = all_base_records.get(right_name) if right_name else None
        r_demangled = base_match.get("demangled_name") if base_match else None
        
        if l_demangled or r_demangled:
            row["demangled_name"] = l_demangled or r_demangled

        if base_match is None:
            row["status"] = "not_found"
            size = func_data.get("size", len(func_data["bytes"]))
            row["count"] = size
            row["size"] = size
            row["match_pct"] = 0.0
        elif kind == "code":
            if base_match.get("is_thunk"):
                row["status"] = "thunk"
                size = func_data.get("size", len(func_data["bytes"]))
                row["count"] = size
                row["size"] = size
            else:
                b_f_w = base_match.get("fixup_widths", {})
                b_f_c = base_match.get("fixup_classes", {})
                b_f_a = base_match.get("fixup_addends", {})
                b_sym_a = base_match.get("fixup_sym_addrs", {})
                b_sym_s = base_match.get("fixup_sym_sizes", {})
                b_sym_k = base_match.get("fixup_sym_kinds", {})
                b_sec_name = base_match.get("section_name", "")
                b_sec_kind = base_match.get("section_kind", "unknown")
                base_fixups = {}
                for k, v in base_match.get("fixups", {}).items():
                    base_fixups[int(k)] = (v, b_f_w.get(k, 4), b_f_c.get(k, "absolute"), b_f_a.get(k, 0),
                                           b_sec_name, b_sec_kind, b_sym_a.get(k, 0), b_sym_s.get(k, 0), b_sym_k.get(k, "unknown"))
                    
                l_arch = func_data.get("arch", "x86")
                r_arch = base_match.get("arch", "x86")
                arch = "x64" if l_arch == "x64" or r_arch == "x64" else "x86"
                
                pct, count, diff_score = compare_functions(
                    func_data["bytes"], base_match["bytes"], func_data["relocs"],
                    base_fixups, func_data.get("reloc_widths", {}),
                    base_match.get("switch_ranges", []),
                    reloc_mode=reloc_mode,
                    return_details=True,
                    left_accessor=left_accessor,
                    right_accessor=right_accessor,
                    arch=arch,
                    diff_direction=direction,
                )
                row.update(status="match", match_pct=pct, count=count, diff_score=list(diff_score), size=len(func_data["bytes"]))
        else:
            # Data/BSS symbols
            b_f_w = base_match.get("fixup_widths", {})
            b_f_c = base_match.get("fixup_classes", {})
            b_f_a = base_match.get("fixup_addends", {})
            b_sym_a = base_match.get("fixup_sym_addrs", {})
            b_sym_s = base_match.get("fixup_sym_sizes", {})
            b_sym_k = base_match.get("fixup_sym_kinds", {})
            base_fixups = {}
            for k, v in base_match.get("fixups", {}).items():
                base_fixups[int(k)] = (v, b_f_w.get(str(k), 4), b_f_c.get(str(k), "absolute"), b_f_a.get(str(k), 0),
                                       "", "unknown", b_sym_a.get(str(k), 0), b_sym_s.get(str(k), 0), b_sym_k.get(str(k), "unknown"))

            l_f_w = func_data.get("reloc_widths", {})
            left_relocs = func_data.get("relocs", {})
            
            left_bytes = func_data.get("bytes", "")
            right_bytes = bytes.fromhex(base_match.get("bytes", "")) if base_match.get("bytes") else b""
            
            size = func_data.get("size", len(left_bytes))
            
            if kind == "bss":
                pct = diff_bss_symbol(size, base_match.get("size", 0))
            else:
                pct = diff_data_symbol(left_bytes, right_bytes, left_relocs, base_fixups, l_f_w, {int(k): v for k, v in b_f_w.items()})
                
            row.update(status=kind, match_pct=pct, count=size, size=size, base_bytes=right_bytes.hex(), offset=func_data.get("offset", 0), base_relocs=base_fixups, obj_relocs=left_relocs, base_reloc_widths={int(k): v for k, v in b_f_w.items()}, obj_reloc_widths=l_f_w)
            
        rows.append(row)
        
        # Accumulate section stats
        if row["status"] not in ("thunk", "not_found"):
            sec = sections_map[sec_name]
            sec["symbols"].append(row)
            if row["match_pct"] is not None:
                sec["generic_weight"] += row["match_pct"] * row["size"]
                sec["generic_total_size"] += row["size"]
            if kind in ("data", "bss"):
                off = row.get("offset", 0)
                length = row.get("size", 0)
                if kind == "data" and row.get("base_bytes"):
                    bd = bytes.fromhex(row["base_bytes"])
                    if off + len(bd) > len(sec["right_data"]):
                        sec["right_data"].extend(b"\x00" * (off + len(bd) - len(sec["right_data"])))
                    sec["right_data"][off:off+len(bd)] = bd
                for k, v in row.get("base_relocs", {}).items():
                    sec["right_relocs"][k + off] = v
                for k, v in row.get("obj_relocs", {}).items():
                    sec["left_relocs"][k + off] = v
                for k, v in row.get("base_reloc_widths", {}).items():
                    sec["right_reloc_widths"][k + off] = v
                for k, v in row.get("obj_reloc_widths", {}).items():
                    sec["left_reloc_widths"][k + off] = v

    sections_out = []
    object_weight = 0.0
    object_total = 0

    for sec_name, sec in sections_map.items():
        if not sec["symbols"]: continue
        generic_match = 100.0 if sec["generic_total_size"] == 0 else sec["generic_weight"] / sec["generic_total_size"]
        section_match = generic_match
        
        if sec["kind"] == "data":
            left_max = max((r.get("offset", 0) + r.get("size", 0) for r in sec["symbols"]), default=0)
            left_data = sec["obj_data"][:left_max]
            right_data = bytes(sec["right_data"])
            symbols_diffs = [(r["size"], r["match_pct"]) for r in sec["symbols"]]
            data_score = diff_data_section(left_data, right_data, sec["left_relocs"], sec["right_relocs"], sec["left_reloc_widths"], sec["right_reloc_widths"], symbols_diffs)
            if data_score > generic_match:
                section_match = data_score
        elif sec["kind"] == "bss":
            symbols_diffs = [(r["size"], r["match_pct"]) for r in sec["symbols"]]
            left_tuples = []
            right_tuples = []
            for r in sec["symbols"]:
                left_tuples.append((r["offset"], r["size"]))
                if r["status"] != "not_found":
                    right_tuples.append((r["offset"], r["size"]))
            bss_score = diff_bss_section(symbols_diffs, left_tuples, right_tuples)
            section_match = max(generic_match, bss_score)

        sections_out.append({
            "name": sec_name,
            "match_percent": section_match,
            "size": sec["generic_total_size"],
            "kind": sec["kind"]
        })
        object_weight += section_match * sec["generic_total_size"]
        object_total += sec["generic_total_size"]

    object_match = 100.0 if object_total == 0 else object_weight / object_total

    matched_100 = sum(1 for r in rows if r["status"] in ("match", "data", "bss") and r["match_pct"] == 100.0)
    matched_below = sum(1 for r in rows if r["status"] in ("match", "data", "bss") and r["match_pct"] is not None and r["match_pct"] < 100.0)

    if json_out:
        out_data = {
            "obj": str(obj_path),
            "connected": True,
            "summary": {
                "match": matched_100 + matched_below,
                "match_100": matched_100,
                "match_below": matched_below,
                "thunk": sum(1 for r in rows if r["status"] == "thunk"),
                "not_found": sum(1 for r in rows if r["status"] == "not_found"),
            },
            "object": {
                "match_percent": object_match,
                "size": object_total,
            },
            "sections": sections_out,
            "functions": rows
        }
        print(json.dumps(out_data, indent=2))
        return 1 if (strict and matched_below) else 0

    print("\n" + "=" * 50 + "\nMATCHING RESULTS\n" + "=" * 50)
    for row in rows:
        dmngld = f" -> {row['demangled_name']}" if row.get("demangled_name") else ""
        if row["status"] == "not_found":
            print(f"{RED}[????] {row['name']}{dmngld} (Not found in Live IDA Database){RESET}")
        elif row["status"] == "thunk":
            print(f"{DIM}[THNK] {row['name']}{dmngld} (Thunk forwarder in IDA; skipped){RESET}")
        elif row["match_pct"] is not None:
            pct = row["match_pct"]
            tag = f"[{pct:5.1f}%]"
            if pct == 100.0:
                color = GREEN
            elif pct >= 80.0:
                color = YELLOW
            else:
                color = RED
            print(f"{color}{tag} {row['name']}{dmngld}{RESET}")

    obj_color = GREEN if object_match == 100.0 else (YELLOW if object_match >= 80.0 else RED)
    print("=" * 50)
    print(f"{obj_color}Total Object Match: {object_match:.2f}% ({matched_100}/{len(rows)} matching 100%){RESET}")
    if strict and matched_below:
        print(f"{RED}Strict mode: {matched_below} function(s) below 100% match.{RESET}")
        return 1
    return 0

def match_focus(obj_path: Path, func_name: str, parser: str = "auto", reloc_mode=RELOC_MODE_NAME_ADDRESS, mappings_config=None, baseline=None, diff_direction=None) -> None:
    obj_funcs = load_obj(obj_path, parser=parser)

    if func_name not in obj_funcs:
        print(f"Error: Function '{func_name}' not found in {obj_path}")
        sys.exit(1)

    if obj_funcs[func_name].get("section_kind", "code") != "code":
        kind = obj_funcs[func_name].get("section_kind", "code")
        print(f"Error: '{func_name}' is a {kind} symbol; data diffing is not supported yet.")
        sys.exit(1)

    obj_bytes = obj_funcs[func_name]["bytes"]
    obj_relocs = obj_funcs[func_name].get("relocs", {})
    obj_reloc_widths = obj_funcs[func_name].get("reloc_widths", {})

    reloc_mappings = (mappings_config or {}).get("reloc_mappings", {})
    obj_relocs = _apply_reloc_mappings(obj_relocs, reloc_mappings)
    
    right_name = func_name
    if mappings_config and "mappings" in mappings_config:
        if func_name in mappings_config["mappings"]:
            right_name = mappings_config["mappings"][func_name]
            print(f"Mapped {func_name} -> {right_name}")

    if baseline is not None:
        baseline_records = _load_baseline(baseline)
        base_match = baseline_records.get(right_name)
    else:
        refresh_ida_cache()

        if not server_alive():
            print(f"{RED}Cannot connect to the live IDA server on 127.0.0.1:28000.{RESET}")
            print(f"{YELLOW}Ensure ida_server.py is running inside IDA, then retry.{RESET}")
            sys.exit(1)

        base_match = fetch_from_ida(right_name)

    if not base_match:
        print(f"{RED}[????] {right_name} (Not found in Live IDA Database){RESET}")
        sys.exit(1)

    if base_match.get("is_thunk"):
        print(f"{DIM}[THNK] {func_name} is an IDA thunk/forwarder; skipping.{RESET}")
        sys.exit(1)

    if is_objdiff_py_enabled():
        try:
            from objdiff_py import diff_objects
            from ida_matcher.matcher.ida_logic import synthetic_obj_from_record
            left_obj_bytes = Path(obj_path).read_bytes() if Path(obj_path).exists() else None
            right_obj_bytes = None
            if baseline is None:
                right_obj_bytes = fetch_synthetic_obj_from_ida(right_name)
            if right_obj_bytes is None and base_match:
                right_obj_bytes = synthetic_obj_from_record(base_match, right_name)

            if left_obj_bytes and right_obj_bytes:
                direction = get_diff_direction(mappings_config, override=diff_direction)
                if direction == "right_to_left":
                    diff_objects(right_obj_bytes, left_obj_bytes)
                else:
                    diff_objects(left_obj_bytes, right_obj_bytes)
        except Exception:
            pass

    b_f_w = base_match.get("fixup_widths", {})
    b_f_c = base_match.get("fixup_classes", {})
    b_f_a = base_match.get("fixup_addends", {})
    b_sym_a = base_match.get("fixup_sym_addrs", {})
    b_sym_s = base_match.get("fixup_sym_sizes", {})
    b_sym_k = base_match.get("fixup_sym_kinds", {})
    b_sec_name = base_match.get("section_name", "")
    b_sec_kind = base_match.get("section_kind", "unknown")
    base_fixups = {}
    for k, v in base_match.get("fixups", {}).items():
        base_fixups[int(k)] = (v, b_f_w.get(k, 4), b_f_c.get(k, "absolute"), b_f_a.get(k, 0),
                               b_sec_name, b_sec_kind, b_sym_a.get(k, 0), b_sym_s.get(k, 0), b_sym_k.get(k, "unknown"))

    left_demangled_name = obj_funcs[func_name].get("demangled_name")
    right_demangled_name = base_match.get("demangled_name")

    base_switches = base_match.get("switches", {})
    base_switch_ranges = base_match.get("switch_ranges", [])
    
    # Needs left/right accessors for literal matching in focus mode
    all_base_records = {func_name: base_match}
    left_accessor = make_left_accessor(obj_funcs)
    offline = baseline is not None
    right_accessor = make_right_accessor(all_base_records, offline=offline)

    left_arch = obj_funcs[func_name].get("arch", "x86")
    right_arch = base_match.get("arch", "x86")
    arch = "x64" if left_arch == "x64" or right_arch == "x64" else "x86"

    diff_function(obj_bytes, base_match["bytes"], obj_relocs, base_fixups, base_switches, obj_reloc_widths, base_switch_ranges, reloc_mode=reloc_mode, left_accessor=left_accessor, right_accessor=right_accessor, func_name=func_name, left_demangled_name=left_demangled_name, right_demangled_name=right_demangled_name, arch=arch)

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Match compiled .obj functions against IDA database",
    )
    parser.add_argument("obj_path", help="Path to the .obj file")
    parser.add_argument("--func", help="Target a single function for side-by-side diff (mangled name)")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON summary (summary mode only)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any recognized function is below 100%% (CI gate)")
    parser.add_argument("--parser", choices=["auto", "lief", "pure"], default="auto",
                        help="COFF .obj parser backend (auto = LIEF when available)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors (also honors NO_COLOR env)")
    parser.add_argument("--reloc-mode", choices=["none", "nameaddress", "datavalue", "all"], default="nameaddress",
                        help="Relocation comparison mode (default: nameaddress)")
    args = parser.parse_args()

    colors = not (args.no_color or os.environ.get("NO_COLOR"))
    _configure_colors(colors)

    reloc_mode_map = {
        "none": "none",
        "nameaddress": "name_address",
        "datavalue": "data_value",
        "all": "all"
    }
    reloc_mode = reloc_mode_map[args.reloc_mode]

    if args.func:
        match_focus(Path(args.obj_path), args.func, parser=args.parser, reloc_mode=reloc_mode)
        sys.exit(0)
    else:
        sys.exit(match_summary(Path(args.obj_path), json_out=args.json, strict=args.strict, parser=args.parser, reloc_mode=reloc_mode))

if __name__ == "__main__":
    main()