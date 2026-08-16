"""
ida_matcher.matcher.match_core
~~~~~~~~~~~~~~~~~~~~~~~~
All matching / diffing logic (Pure Binary).
"""

import sys
import os
import json
import re
import urllib.request
import urllib.parse
import difflib
from pathlib import Path

from ida_matcher.matcher.coff_parser import load_obj

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

IDA_SERVER_URL = "http://127.0.0.1:28000/func?name="

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RED_BG = "\033[41m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def _configure_colors(enabled):
    """Switch ANSI color codes on/off (NO_COLOR, --no-color, --json)."""
    global GREEN, RED, YELLOW, RED_BG, RESET, DIM
    if not enabled:
        GREEN = RED = YELLOW = RED_BG = RESET = DIM = ""

# Reloc/fixup windows are matched by byte offset; a 2-byte or 4-byte relocation
# masks the bytes it covers so absolute addresses don't cause false mismatches.
DEFAULT_RELOC_WIDTH = 4

_ANON_SYM_RE = re.compile(r'^(?:sub|unk|loc|off|byte|word|dword|qword|asc|jpt|def)_[0-9a-fA-F_]+$')
_MSVC_LOCAL_LABEL_RE = re.compile(r'^\$L_?\d+$')

def _reloc_byte_map(relocs, widths=None, default=DEFAULT_RELOC_WIDTH):
    """Flatten {reloc_offset: name} (+ optional per-reloc widths) into {byte_index: name}."""
    byte_map = {}
    for off, name in relocs.items():
        w = (widths or {}).get(off, default)
        for i in range(w):
            byte_map[off + i] = name
    return byte_map

def _normalize_target_name(name):
    """Make obj-symbol and IDA-name spellings comparable (C decl/import/thunk prefixes)."""
    n = str(name).strip()
    n = re.sub(r'^__imp_', '', n)
    n = re.sub(r'^j_', '', n)      # IDA jump-thunk stub names: j_printf / j_?Foo@@...
    n = re.sub(r'^_', '', n)
    return n

def _looks_anonymous(name):
    """Address-derived labels (sub_401000, unk_402000, ...) carry no symbol identity."""
    n = str(name).lstrip('@?')
    if _ANON_SYM_RE.match(n):
        return True
    if _MSVC_LOCAL_LABEL_RE.match(n):
        return True
    if n.startswith('0x'):
        return True
    # Bare hex like the tail of j_435BFD after prefix stripping.
    if re.fullmatch(r'(?=.*\d)[0-9a-fA-F]{4,}', n):
        return True
    return False

def _reloc_symbols_match(name_a, name_b):
    """True when two reloc targets are (probably) the same symbol.

    Both sides relocated => the underlying values differ by construction, so the
    only way to catch a *real* change (e.g. printf -> puts at a call site) is to
    compare the target names. Anonymous DB labels are treated as compatible.
    """
    a = _normalize_target_name(name_a)
    b = _normalize_target_name(name_b)
    if a == b:
        return True
    if _looks_anonymous(a) or _looks_anonymous(b):
        return True
    return False

def _sym_ref_in_line(line):
    m = re.search(r'<([^>]+)>', line)
    return m.group(1) if m else None

def _strip_switch_ranges(data_bytes, fixups, switch_ranges, reloc_widths=None):
    """Drop jump-table (.rdata) byte ranges so they don't penalize the
    match. Fixup offsets are remapped onto the stripped buffer.
    """
    if not switch_ranges:
        if reloc_widths is not None:
            return data_bytes, fixups, reloc_widths
        return data_bytes, fixups

    drop = [False] * len(data_bytes)
    for start, end in switch_ranges:
        for i in range(max(0, start), min(end, len(data_bytes))):
            drop[i] = True

    new_bytes = bytearray()
    new_fixups = {}
    new_widths = {}
    removed = 0
    for i, b in enumerate(data_bytes):
        if drop[i]:
            removed += 1
            continue
        new_bytes.append(b)
        if i in fixups:
            new_fixups[i - removed] = fixups[i]
        if reloc_widths is not None and i in reloc_widths:
            new_widths[i - removed] = reloc_widths[i]

    if reloc_widths is not None:
        return new_bytes, new_fixups, new_widths
    return new_bytes, new_fixups

def compare_functions(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, obj_reloc_widths=None, base_switch_ranges=None):
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

    obj_reloc_map = _reloc_byte_map(obj_relocs, obj_reloc_widths)
    base_fixup_map = _reloc_byte_map(base_fixups)

    total_count = max(len(obj_bytes), len(base_bytes))
    if total_count == 0:
        return 0.0, 0

    # LCS alignment via difflib: inserted/deleted bytes resync instead of
    # shifting every later byte out of phase (one leading NOP no longer
    # decimates the score). SequenceMatcher needs a *transitive* token space,
    # so we first align on (kind, value) tokens -- concrete bytes by value, any
    # relocated byte (own reloc OR other-side fixup window) as one reloc token.
    def align_tokens(data, reloc_map, other_reloc_map):
        return [
            ("r", 0) if (reloc_map.get(i) is not None or other_reloc_map.get(i) is not None) else ("b", data[i])
            for i in range(len(data))
        ]

    obj_tokens = align_tokens(obj_bytes, obj_reloc_map, base_fixup_map)
    base_tokens = align_tokens(base_bytes, base_fixup_map, obj_reloc_map)

    # Second pass: re-apply the exact per-byte semantics on the aligned pairs.
    # * both relocated -> match iff _reloc_symbols_match (symbols align)
    # * one side relocated, other concrete -> not comparable -> match
    # * both concrete -> match iff byte-equal
    match_count = 0
    for i, j, size in difflib.SequenceMatcher(None, obj_tokens, base_tokens, autojunk=False).get_matching_blocks():
        for k in range(size):
            o_sym = obj_reloc_map.get(i + k)
            b_sym = base_fixup_map.get(j + k)
            if o_sym is not None and b_sym is not None:
                if _reloc_symbols_match(o_sym, b_sym):
                    match_count += 1
            elif o_sym is not None or b_sym is not None:
                match_count += 1
            elif obj_bytes[i + k] == base_bytes[j + k]:
                match_count += 1

    return (match_count / total_count) * 100, total_count

def fetch_from_ida(func_name):
    """Fetch a single function record; returns None for 404 and any transport error."""
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
    """Fetch several functions in one round trip via GET /funcs?names=a,b,c.

    Returns {name: record} (thin funcs are absent) or None if the batch failed.
    Batch is the normal path for `match_summary`; without it, N functions cost
    N separate HTTP round trips (each scheduled on the 100 ms IDA timer).
    """
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

def server_alive():
    """True when the live IDA server responds to GET /health."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:28000/health", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False

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
            # Replace the address tokens only - keep registers ([eax], ds:...).
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

def highlight_diff_inline(base_text, obj_text):
    sm = difflib.SequenceMatcher(None, base_text, obj_text, autojunk=False)
    base_colored = ""
    obj_colored = ""

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        b_chunk = base_text[i1:i2]
        o_chunk = obj_text[j1:j2]

        if tag == 'equal':
            base_colored += b_chunk
            obj_colored += o_chunk
        else:
            if b_chunk:
                base_colored += f"{RED_BG}{b_chunk}{RESET}{RED}"
            if o_chunk:
                obj_colored += f"{RED_BG}{o_chunk}{RESET}{RED}"

    return base_colored, obj_colored

def print_hexdump_diff(obj_bytes, base_bytes, obj_relocs, base_fixups, obj_reloc_widths=None):
    COL_W = 48
    print(f"\n{'Base (IDA) Hex Dump':<{COL_W}} | {'Local (.obj) Hex Dump':<{COL_W}}")
    print("-" * COL_W + "+" + "-" * COL_W)

    max_len = max(len(obj_bytes), len(base_bytes))
    
    obj_reloc_indices = set()
    for r_off in obj_relocs.keys():
        w = (obj_reloc_widths or {}).get(r_off, DEFAULT_RELOC_WIDTH)
        for i in range(w): obj_reloc_indices.add(r_off + i)
            
    base_fixup_indices = set()
    for r_off in base_fixups.keys():
        for i in range(DEFAULT_RELOC_WIDTH): base_fixup_indices.add(r_off + i)

    for offset in range(0, max_len, 16):
        b_chunk = base_bytes[offset:offset+16]
        o_chunk = obj_bytes[offset:offset+16]
        
        b_str, o_str = "", ""
        for i in range(16):
            abs_i = offset + i
            
            b_val = f"{b_chunk[i]:02X}" if i < len(b_chunk) else "  "
            o_val = f"{o_chunk[i]:02X}" if i < len(o_chunk) else "  "
            
            is_o_reloc = abs_i in obj_reloc_indices
            is_b_reloc = abs_i in base_fixup_indices
            is_match = i < len(b_chunk) and i < len(o_chunk) and b_chunk[i] == o_chunk[i]
            
            if i >= len(b_chunk):
                b_str += "   "
            elif is_b_reloc:
                b_str += f"{YELLOW}{b_val}{RESET} "
            elif is_match:
                b_str += f"{GREEN}{b_val}{RESET} "
            else:
                b_str += f"{RED_BG}{b_val}{RESET} "
                
            if i >= len(o_chunk):
                o_str += "   "
            elif is_o_reloc:
                o_str += f"{YELLOW}{o_val}{RESET} "
            elif is_match:
                o_str += f"{GREEN}{o_val}{RESET} "
            else:
                o_str += f"{RED_BG}{o_val}{RESET} "
                
        print(f"{b_str} | {o_str}")

def diff_function(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, base_switches=None, obj_reloc_widths=None, base_switch_ranges=None):
    if not HAS_CAPSTONE:
        print(f"{RED}Error: capstone module not installed. Run: pip install capstone{RESET}")
        return 0.0

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

    print_hexdump_diff(obj_bytes, base_bytes, obj_relocs, base_fixups, obj_reloc_widths)

    base_insns = _disassemble(base_bytes, base_offset=0)
    obj_insns = _disassemble(obj_bytes, base_offset=0)

    base_fixup_widths = {k: DEFAULT_RELOC_WIDTH for k in base_fixups}
    obj_reloc_widths = obj_reloc_widths or {}

    base_lines, base_meta = [], []
    for addr, mn, op, ib in base_insns:
        base_lines.append(_normalize_insn(addr, mn, op, ib, base_fixups, base_fixup_widths))
        base_meta.append((addr, ib))

    obj_lines, obj_meta = [], []
    for addr, mn, op, ib in obj_insns:
        obj_lines.append(_normalize_insn(addr, mn, op, ib, obj_relocs, obj_reloc_widths))
        obj_meta.append((addr, ib))

    COL_W = 42
    print(f"\n{'Base (IDA Database)':<{COL_W}} | {'Local Compiled (.obj)':<{COL_W}}")
    print("-" * COL_W + "+" + "-" * COL_W)

    sm = difflib.SequenceMatcher(None, base_lines, obj_lines, autojunk=False)
    match_count = total_count = 0

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for bi in range(i1, i2):
                line = base_lines[bi]
                print(f"{GREEN}{line:<{COL_W}} | {obj_lines[bi + (j1 - i1)]:<{COL_W}}{RESET}")
                match_count += 1
                total_count += 1
        elif tag == 'replace':
            pairs = list(zip(range(i1, i2), range(j1, j2)))
            for bi, oi in pairs:
                total_count += 1
                b_has_reloc = _insn_has_reloc(base_meta[bi][0], base_meta[bi][1], base_fixups, base_fixup_widths)
                o_has_reloc = _insn_has_reloc(obj_meta[oi][0], obj_meta[oi][1], obj_relocs, obj_reloc_widths)

                if b_has_reloc or o_has_reloc:
                    b_sym = _sym_ref_in_line(base_lines[bi])
                    o_sym = _sym_ref_in_line(obj_lines[oi])
                    tag_str = ""
                    w = max(0, COL_W - len(tag_str))
                    if b_sym and o_sym and not _reloc_symbols_match(b_sym, o_sym):
                        tag_str = f" [RELOC!= {b_sym} != {o_sym}]"
                        w = max(0, COL_W - len(tag_str))
                        print(f"{RED}{base_lines[bi]:<{COL_W}} | {obj_lines[oi]:<{w}}{tag_str}{RESET}")
                    else:
                        tag_str = " [RELOC]"
                        w = max(0, COL_W - len(tag_str))
                        print(f"{YELLOW}{base_lines[bi]:<{COL_W}} | {obj_lines[oi]:<{w}}{tag_str}{RESET}")
                        match_count += 1
                else:
                    b_hl, o_hl = highlight_diff_inline(base_lines[bi], obj_lines[oi])
                    b_pad = " " * max(0, COL_W - len(base_lines[bi]))
                    o_pad = " " * max(0, COL_W - len(obj_lines[oi]))
                    print(f"{RED}{b_hl}{b_pad} | {o_hl}{o_pad}{RESET}")

            if i2 - i1 > j2 - j1:
                for bi in range(i1 + (j2 - j1), i2):
                    total_count += 1
                    print(f"{RED}{base_lines[bi]:<{COL_W}} | {'(missing)':<{COL_W}}{RESET}")
            elif j2 - j1 > i2 - i1:
                for oi in range(j1 + (i2 - i1), j2):
                    total_count += 1
                    print(f"{RED}{'(missing)':<{COL_W}} | {obj_lines[oi]:<{COL_W}}{RESET}")

        elif tag == 'delete':
            for bi in range(i1, i2):
                total_count += 1
                print(f"{RED}{base_lines[bi]:<{COL_W}} | {'(missing)':<{COL_W}}{RESET}")
        elif tag == 'insert':
            for oi in range(j1, j2):
                total_count += 1
                print(f"{RED}{'(missing)':<{COL_W}} | {obj_lines[oi]:<{COL_W}}{RESET}")

    if base_switches:
        print("-" * (COL_W * 2 + 1))
        print(f"Detected {len(base_switches)} Jump Table(s) in IDA Database:")
        for insn_offset, targets in base_switches.items():
            print(f"{DIM}  Indirect Jump at function offset {insn_offset}:{RESET}")
            for i, tgt in enumerate(targets):
                print(f"    Case {i:<3}: jumps to loc_{tgt}")

    pct = (match_count / total_count) * 100 if total_count > 0 else 0.0
    print("-" * (COL_W * 2 + 1))
    color = GREEN if pct == 100.0 else (YELLOW if pct >= 80.0 else RED)
    print(f"{color}Instruction match: {match_count}/{total_count} ({pct:.2f}%){RESET}")
    return pct

def refresh_ida_cache():
    """Ask the live IDA server to rebuild its name->address cache."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:28000/refresh", timeout=10) as response:
            response.read()
    except Exception:
        pass

def match_summary(obj_path: Path, json_out: bool = False, strict: bool = False) -> int:
    """Run a summary match against the live IDA server.

    Returns an exit code: 0 on success, 1 when `strict` is set and any
    recognized function scored below 100% (CI gate). Server-down / empty obj
    keep returning 0 for backward compatibility.
    """
    refresh_ida_cache()
    obj_funcs = load_obj(obj_path)

    if not obj_funcs:
        print("No functions found in the .obj file.")
        return 0

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

    records = fetch_many_from_ida(list(obj_funcs))
    if records is None:
        # Old server (no /funcs batch endpoint) - fall back to one call per name.
        records = {n: rec for n in obj_funcs if (rec := fetch_from_ida(n)) is not None}

    rows = []
    for func_name, func_data in obj_funcs.items():
        base_match = records.get(func_name)
        row = {"name": func_name, "status": None, "match_pct": None, "count": None}
        if base_match is None:
            row["status"] = "not_found"
        elif base_match.get("is_thunk"):
            row["status"] = "thunk"
        else:
            base_fixups = {int(k): v for k, v in base_match.get("fixups", {}).items()}
            pct, count = compare_functions(
                func_data["bytes"], base_match["bytes"], func_data["relocs"],
                base_fixups, func_data.get("reloc_widths", {}),
                base_match.get("switch_ranges", []),
            )
            row.update(status="match", match_pct=pct, count=count)
        rows.append(row)

    matched_100 = sum(1 for r in rows if r["status"] == "match" and r["match_pct"] == 100.0)
    matched_below = sum(1 for r in rows if r["status"] == "match" and r["match_pct"] < 100.0)
    summary = {
        "match": matched_100 + matched_below,
        "match_100": matched_100,
        "match_below": matched_below,
        "thunk": sum(1 for r in rows if r["status"] == "thunk"),
        "not_found": sum(1 for r in rows if r["status"] == "not_found"),
    }

    if json_out:
        print(json.dumps({"obj": str(obj_path), "connected": True, "summary": summary, "functions": rows}, indent=2))
        return 1 if (strict and matched_below) else 0

    print("\n" + "=" * 50 + "\nMATCHING RESULTS\n" + "=" * 50)
    for row in rows:
        if row["status"] == "not_found":
            print(f"{DIM}[????] {row['name']} (Not found in Live IDA Database){RESET}")
        elif row["status"] == "thunk":
            print(f"{DIM}[THNK] {row['name']} (IDA thunk/forwarder - skipped){RESET}")
        else:
            pct = row["match_pct"]
            color = GREEN if pct == 100.0 else (YELLOW if pct >= 80.0 else RED)
            print(f"{color}[{pct:>6.2f}%]{RESET} {row['name']} ({row['count']} bytes)")
    print(f"{DIM}{summary}{RESET}")

    if strict and matched_below:
        print(f"{RED}Strict mode: {matched_below} function(s) below 100% match.{RESET}")
        return 1
    return 0

def match_focus(obj_path: Path, func_name: str) -> None:
    refresh_ida_cache()
    obj_funcs = load_obj(obj_path)

    if func_name not in obj_funcs:
        print(f"Error: Function '{func_name}' not found in {obj_path}")
        sys.exit(1)

    if not server_alive():
        print(f"{RED}Cannot connect to the live IDA server on 127.0.0.1:28000.{RESET}")
        print(f"{YELLOW}Ensure ida_server.py is running inside IDA, then retry.{RESET}")
        sys.exit(1)

    obj_bytes = obj_funcs[func_name]["bytes"]
    obj_relocs = obj_funcs[func_name]["relocs"]
    obj_reloc_widths = obj_funcs[func_name].get("reloc_widths", {})
    base_match = fetch_from_ida(func_name)

    if not base_match:
        print(f"{RED}[????] {func_name} (Not found in Live IDA Database){RESET}")
        sys.exit(1)

    if base_match.get("is_thunk"):
        print(f"{DIM}[THNK] {func_name} is an IDA thunk/forwarder; skipping.{RESET}")
        sys.exit(1)

    base_fixups = {int(k): v for k, v in base_match.get("fixups", {}).items()}

    print(f"\n{'=' * 50}\nDIFF: {func_name}\n{'=' * 50}")

    base_switches = base_match.get("switches", {})
    base_switch_ranges = base_match.get("switch_ranges", [])
    diff_function(obj_bytes, base_match["bytes"], obj_relocs, base_fixups, base_switches, obj_reloc_widths, base_switch_ranges)

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Match compiled .obj functions against IDA database",
    )
    parser.add_argument("obj_path", help="Path to the .obj file")
    parser.add_argument("--func", help="Target a single function for side-by-side diff (mangled name)")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON summary (summary mode only)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any recognized function is below 100%% (CI gate)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors (also honors NO_COLOR env)")
    args = parser.parse_args()

    colors = not (args.no_color or os.environ.get("NO_COLOR"))
    _configure_colors(colors)

    if args.func:
        match_focus(Path(args.obj_path), args.func)
        sys.exit(0)
    else:
        sys.exit(match_summary(Path(args.obj_path), json_out=args.json, strict=args.strict))

if __name__ == "__main__":
    main()