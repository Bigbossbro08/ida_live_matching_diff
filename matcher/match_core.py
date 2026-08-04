"""
tools.matcher.match_core
~~~~~~~~~~~~~~~~~~~~~~~~
All matching / diffing logic.
"""

import sys
import os
import subprocess
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import difflib
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

def _find_dumpbin():
    vc6_path = os.environ.get("VC6_PATH", r"E:\repos\msvc6.3")
    candidates = [
        os.path.join(vc6_path, "Bin", "dumpbin.exe"),
        os.path.join(vc6_path, "bin", "dumpbin.exe"),
        os.path.join(vc6_path, "VC98", "Bin", "dumpbin.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    import shutil
    found = shutil.which("dumpbin.exe")
    if found:
        return found
    return os.path.join(vc6_path, "Bin", "dumpbin.exe")

DUMPBIN_PATH = _find_dumpbin()
IDA_SERVER_URL = "http://127.0.0.1:28000/func?name="

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RED_BG = "\033[41m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def run_dumpbin(obj_path, flag):
    try:
        result = subprocess.run(
            [DUMPBIN_PATH, flag, str(obj_path)],
            capture_output=True, text=True, check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running dumpbin {flag} on {obj_path}: {e.stderr}")
        return ""

def parse_disasm(disasm_output):
    functions = {}
    current_func = None
    current_bytes = []
    current_offset = None

    for line in disasm_output.splitlines():
        if line.endswith("):") or ("):" in line and " (" in line):
            if current_func and current_bytes:
                functions[current_func] = {
                    "bytes": "".join(current_bytes),
                    "offset": current_offset or 0,
                }

            parts = line.split(" (")
            current_func = parts[0].strip() if len(parts) > 1 else line.replace(":", "").strip()
            current_bytes = []
            current_offset = None
        else:
            if current_func:
                m = re.match(r"^\s*([0-9A-Fa-f]+):(.*)", line)
                if m:
                    addr_str = m.group(1)
                    rest = m.group(2).strip()

                    if current_offset is None:
                        current_offset = int(addr_str, 16)

                    tokens = rest.split()
                    for token in tokens:
                        if len(token) == 2 and all(c in "0123456789ABCDEFabcdef" for c in token):
                            current_bytes.append(token)
                        else:
                            break

    if current_func and current_bytes:
        functions[current_func] = {
            "bytes": "".join(current_bytes),
            "offset": current_offset or 0,
        }

    return functions

def parse_relocations(reloc_output):
    sections = []
    current_section = None
    in_reloc_block = False

    for line in reloc_output.splitlines():
        if "RELOCATIONS #" in line:
            current_section = {}
            sections.append(current_section)
            in_reloc_block = True
            continue

        if in_reloc_block:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 3 and all(c in "0123456789ABCDEFabcdef" for c in parts[0]):
                try:
                    offset = int(parts[0], 16)
                    symbol = parts[4] if len(parts) >= 5 else f"RELOC@{offset:#x}"
                    if current_section is not None:
                        current_section[offset] = symbol
                except (ValueError, IndexError):
                    pass
            elif "Symbol" not in line and "Offset" not in line and "----" not in line:
                if len(parts) > 0 and not all(c in "0123456789ABCDEFabcdef" for c in parts[0]):
                    in_reloc_block = False

    return sections

def map_relocations(obj_funcs, reloc_sections):
    mapped = {}
    func_names = list(obj_funcs.keys())

    if len(func_names) == len(reloc_sections) and len(reloc_sections) > 1:
        for i, name in enumerate(func_names):
            mapped[name] = reloc_sections[i]
    else:
        flat_relocs = {}
        for section in reloc_sections:
            flat_relocs.update(section)

        for name, data in obj_funcs.items():
            func_offset = data["offset"]
            func_relocs = {}
            for r_off, r_sym in flat_relocs.items():
                if r_off >= func_offset:
                    func_relocs[r_off - func_offset] = r_sym
            mapped[name] = func_relocs

    return mapped

def compare_functions(obj_bytes_hex, base_bytes_hex, relocs):
    obj_bytes_hex = re.sub(r'[^0-9a-fA-F]', '', obj_bytes_hex)
    base_bytes_hex = re.sub(r'[^0-9a-fA-F]', '', base_bytes_hex)

    if len(obj_bytes_hex) % 2 != 0:
        obj_bytes_hex = obj_bytes_hex[:-1]
    if len(base_bytes_hex) % 2 != 0:
        base_bytes_hex = base_bytes_hex[:-1]

    obj_bytes = bytearray.fromhex(obj_bytes_hex)
    base_bytes = bytearray.fromhex(base_bytes_hex)

    while obj_bytes and obj_bytes[-1] in (0x90, 0xCC):
        obj_bytes.pop()
    while base_bytes and base_bytes[-1] in (0x90, 0xCC):
        base_bytes.pop()

    match_count = 0
    total_count = min(len(obj_bytes), len(base_bytes))

    if total_count == 0:
        return 0.0, 0

    reloc_offsets = set(relocs.keys())
    for i in range(total_count):
        is_reloc = False
        for r in range(max(0, i - 3), i + 1):
            if r in reloc_offsets:
                is_reloc = True
                break

        if is_reloc or obj_bytes[i] == base_bytes[i]:
            match_count += 1

    return (match_count / total_count) * 100, total_count

def fetch_from_ida(func_name):
    encoded_name = urllib.parse.quote(func_name)
    url = IDA_SERVER_URL + encoded_name
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
            if "bytes" in data:
                return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print(f"{RED}HTTP Error {e.code} for {func_name}{RESET}")
    except Exception as e:
        print(f"{RED}IDA server error for {func_name}: {e}{RESET}")
    return None

def _disassemble(raw_bytes, base_offset=0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    insns = []
    for insn in md.disasm(bytes(raw_bytes), base_offset):
        insns.append((insn.address, insn.mnemonic, insn.op_str, bytes(insn.bytes)))
    return insns

def _normalize_insn(addr, mnemonic, op_str, insn_bytes, relocs, is_obj_side):
    reloc_sym = None
    for byte_pos in range(addr, addr + len(insn_bytes)):
        if byte_pos in relocs:
            reloc_sym = relocs[byte_pos]
            break
    
    jump_mnemonics = (
        "call", "jmp", "je", "jne", "jz", "jnz", "jg", "jge", 
        "jl", "jle", "ja", "jae", "jb", "jbe", "jo", "jno",
        "js", "jns", "jp", "jnp", "jcxz", "jecxz"
    )

    is_jump = mnemonic in jump_mnemonics
    is_indirect = is_jump and ("[" in op_str or "ptr" in op_str)

    if reloc_sym and is_obj_side:
        if is_jump and not is_indirect:
            op_str = f"<{reloc_sym}>"
        else:
            if is_indirect and not re.search(r'0x[0-9a-fA-F]+', op_str):
                op_str = op_str.replace("]", f" + <{reloc_sym}>]")
            else:
                op_str = re.sub(r'0x[0-9a-fA-F]+', f'<{reloc_sym}>', op_str, count=1)
                
            if '<' not in op_str:
                op_str = f"{op_str}  ; <{reloc_sym}>"
                
    elif reloc_sym and not is_obj_side:
        if is_jump and not is_indirect:
            op_str = f"<{reloc_sym}>"
        else:
            op_str = re.sub(r'0x[0-9a-fA-F]+', f'<{reloc_sym}>', op_str, count=1)
            
    elif not is_obj_side:
        if is_jump and not is_indirect:
            m = re.match(r'^(0x)?([0-9a-fA-F]+)$', op_str.strip())
            if m:
                try:
                    target = int(m.group(2), 16)
                    rel = target - addr
                    op_str = f"loc_{rel:+#x}"
                except ValueError:
                    pass
    
    return f"{mnemonic:<8} {op_str}"

def _insn_has_reloc(addr, insn_bytes, relocs):
    for byte_pos in range(addr, addr + len(insn_bytes)):
        if byte_pos in relocs:
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

def print_hexdump_diff(obj_bytes, base_bytes, relocs):
    """Outputs a 16-byte aligned side-by-side hexdump visualizing byte-level differences."""
    COL_W = 48
    print(f"\n{'Base (IDA) Hex Dump':<{COL_W}} | {'Local (.obj) Hex Dump':<{COL_W}}")
    print("─" * COL_W + "┼" + "─" * COL_W)

    max_len = max(len(obj_bytes), len(base_bytes))
    reloc_indices = set()
    for r_off in relocs.keys():
        for i in range(4): # Assume standard 32-bit relocs cover 4 bytes
            reloc_indices.add(r_off + i)

    for offset in range(0, max_len, 16):
        b_chunk = base_bytes[offset:offset+16]
        o_chunk = obj_bytes[offset:offset+16]
        
        b_str, o_str = "", ""
        for i in range(16):
            abs_i = offset + i
            
            b_val = f"{b_chunk[i]:02X}" if i < len(b_chunk) else "  "
            o_val = f"{o_chunk[i]:02X}" if i < len(o_chunk) else "  "
            
            is_reloc = abs_i in reloc_indices
            is_match = i < len(b_chunk) and i < len(o_chunk) and b_chunk[i] == o_chunk[i]
            
            # Format Base Hex
            if i >= len(b_chunk):
                b_str += "   "
            elif is_reloc:
                b_str += f"{YELLOW}{b_val}{RESET} "
            elif is_match:
                b_str += f"{GREEN}{b_val}{RESET} "
            else:
                b_str += f"{RED_BG}{b_val}{RESET} "
                
            # Format Obj Hex
            if i >= len(o_chunk):
                o_str += "   "
            elif is_reloc:
                o_str += f"{YELLOW}{o_val}{RESET} "
            elif is_match:
                o_str += f"{GREEN}{o_val}{RESET} "
            else:
                o_str += f"{RED_BG}{o_val}{RESET} "
                
        print(f"{b_str} | {o_str}")

def diff_function(obj_bytes_hex, base_bytes_hex, relocs, base_switches=None):
    if not HAS_CAPSTONE:
        print(f"{RED}Error: capstone module not installed. Run: pip install capstone{RESET}")
        return 0.0

    obj_bytes_hex = re.sub(r'[^0-9a-fA-F]', '', obj_bytes_hex)
    base_bytes_hex = re.sub(r'[^0-9a-fA-F]', '', base_bytes_hex)

    if len(obj_bytes_hex) % 2 != 0:
        obj_bytes_hex = obj_bytes_hex[:-1]
    if len(base_bytes_hex) % 2 != 0:
        base_bytes_hex = base_bytes_hex[:-1]

    obj_bytes = bytearray.fromhex(obj_bytes_hex)
    base_bytes = bytearray.fromhex(base_bytes_hex)

    while obj_bytes and obj_bytes[-1] in (0x90, 0xCC):
        obj_bytes.pop()
    while base_bytes and base_bytes[-1] in (0x90, 0xCC):
        base_bytes.pop()

    # Call the new side-by-side raw byte visualizer
    print_hexdump_diff(obj_bytes, base_bytes, relocs)

    base_insns = _disassemble(base_bytes, base_offset=0)
    obj_insns = _disassemble(obj_bytes, base_offset=0)

    base_lines, base_meta = [], []
    for addr, mn, op, ib in base_insns:
        base_lines.append(_normalize_insn(addr, mn, op, ib, relocs, is_obj_side=False))
        base_meta.append((addr, ib))

    obj_lines, obj_meta = [], []
    for addr, mn, op, ib in obj_insns:
        obj_lines.append(_normalize_insn(addr, mn, op, ib, relocs, is_obj_side=True))
        obj_meta.append((addr, ib))

    COL_W = 42
    print(f"\n{'Base (IDA Database)':<{COL_W}} | {'Local Compiled (.obj)':<{COL_W}}")
    print("─" * COL_W + "┼" + "─" * COL_W)

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
                b_has_reloc = _insn_has_reloc(base_meta[bi][0], base_meta[bi][1], relocs)
                o_has_reloc = _insn_has_reloc(obj_meta[oi][0], obj_meta[oi][1], relocs)

                if b_has_reloc or o_has_reloc:
                    tag_str = " [RELOC]"
                    print(f"{YELLOW}{base_lines[bi]:<{COL_W}} | {obj_lines[oi]:<{COL_W - len(tag_str)}}{tag_str}{RESET}")
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
        print("─" * (COL_W * 2 + 1))
        print(f"Detected {len(base_switches)} Jump Table(s) in IDA Database:")
        for insn_offset, targets in base_switches.items():
            print(f"{DIM}  Indirect Jump at function offset {insn_offset}:{RESET}")
            for i, tgt in enumerate(targets):
                print(f"    Case {i:<3}: jumps to loc_{tgt}")

    pct = (match_count / total_count) * 100 if total_count > 0 else 0.0
    print("─" * (COL_W * 2 + 1))
    color = GREEN if pct == 100.0 else (YELLOW if pct >= 80.0 else RED)
    print(f"{color}Instruction match: {match_count}/{total_count} ({pct:.2f}%){RESET}")
    return pct

def _load_obj(obj_path: Path):
    obj_path = Path(obj_path)
    if not obj_path.exists():
        print(f"Error: {obj_path} not found.")
        sys.exit(1)

    print(f"Reading {obj_path}...")
    disasm = run_dumpbin(str(obj_path), "/disasm")
    reloc_out = run_dumpbin(str(obj_path), "/RELOCATIONS")

    obj_funcs = parse_disasm(disasm)
    reloc_sections = parse_relocations(reloc_out)
    func_relocs = map_relocations(obj_funcs, reloc_sections)
    return obj_funcs, func_relocs

def match_summary(obj_path: Path) -> None:
    obj_funcs, func_relocs = _load_obj(obj_path)

    print("\n" + "=" * 50 + "\nMATCHING RESULTS\n" + "=" * 50)
    for func_name, func_data in obj_funcs.items():
        base_match = fetch_from_ida(func_name)

        if not base_match:
            print(f"{DIM}[????] {func_name} (Not found in Live IDA Database){RESET}")
            continue

        match_pct, count = compare_functions(
            func_data["bytes"], base_match["bytes"], func_relocs.get(func_name, {})
        )
        color = GREEN if match_pct == 100.0 else RED
        print(f"{color}[{match_pct:>6.2f}%]{RESET} {func_name} ({count} bytes)")

def match_focus(obj_path: Path, func_name: str) -> None:
    obj_funcs, func_relocs = _load_obj(obj_path)

    if func_name not in obj_funcs:
        print(f"Error: Function '{func_name}' not found in {obj_path}")
        sys.exit(1)

    obj_bytes_hex = obj_funcs[func_name]["bytes"]
    base_match = fetch_from_ida(func_name)

    if not base_match:
        print(f"{RED}[????] {func_name} (Not found in Live IDA Database){RESET}")
        sys.exit(1)

    print(f"\n{'=' * 50}\nDIFF: {func_name}\n{'=' * 50}")
    
    base_switches = base_match.get("switches", {})
    diff_function(obj_bytes_hex, base_match["bytes"], func_relocs.get(func_name, {}), base_switches)

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Match compiled .obj functions against IDA database",
    )
    parser.add_argument("obj_path", help="Path to the .obj file")
    parser.add_argument("--func", help="Target a single function for side-by-side diff (mangled name)")
    args = parser.parse_args()

    if args.func:
        match_focus(Path(args.obj_path), args.func)
    else:
        match_summary(Path(args.obj_path))

if __name__ == "__main__":
    main()