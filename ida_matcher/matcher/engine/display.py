"""
ida_matcher.matcher.engine.display
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Console formatting and diff rendering.
"""

import re
import difflib

from ida_matcher.matcher.engine.types import (
    KIND_NONE, KIND_OP_MISMATCH, KIND_ARG_MISMATCH, KIND_REPLACE, KIND_DELETE, KIND_INSERT,
    DEFAULT_RELOC_WIDTH, OPCODE_DATA, _read_le
)
from ida_matcher.matcher.engine.arch_x86 import _capstone_insn, HAS_CAPSTONE
from ida_matcher.matcher.engine.diff_code import diff_code

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RED_BG = "\033[41m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def _configure_colors(enabled):
    global GREEN, RED, YELLOW, RED_BG, RESET, DIM
    if not enabled:
        GREEN = RED = YELLOW = RED_BG = RESET = DIM = ""

def _strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)

def _sym_ref_in_line(line):
    m = re.search(r'<([^>]+)>', line)
    return m.group(1) if m else None

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

def _render_engine_row(source, ins_ref, args_diff=None, is_mismatch_color=None):
    if ins_ref.opcode == OPCODE_DATA:
        mnemonic = {1: ".byte", 2: ".word", 4: ".dword", 8: ".qword"}.get(ins_ref.size, ".byte")
        reloc = source.reloc_at(ins_ref.address, ins_ref.size)
        if reloc is not None:
            return f"{ins_ref.address:04x}: {mnemonic} <{reloc[1]}>"
        return f"{ins_ref.address:04x}: {mnemonic} 0x{_read_le(source.data, ins_ref.address, ins_ref.size):x}"
    
    insn = _capstone_insn(source, ins_ref.address)
    if insn:
        op_str = insn.op_str
        if args_diff and op_str:
            ops = op_str.split(", ")
            colored_ops = []
            for i, op in enumerate(ops):
                if i < len(args_diff) and args_diff[i] is not None and is_mismatch_color:
                    colored_ops.append(f"{is_mismatch_color}{op}{RESET}")
                else:
                    colored_ops.append(op)
            op_str = ", ".join(colored_ops)
        text = f"{ins_ref.address:04x}: {insn.mnemonic} {op_str}"
    else:
        text = f"{ins_ref.address:04x}: ??"
    reloc = source.reloc_at(ins_ref.address, ins_ref.size)
    if reloc is not None and reloc[1] is not None:
        text += f" ; <{reloc[1]}>"
    elif ins_ref.branch_dest is not None:
        text += f" ; loc_{ins_ref.branch_dest:x}"
    return text

def diff_function(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, base_switches=None, obj_reloc_widths=None, base_switch_ranges=None, reloc_mode="name_address", left_accessor=None, right_accessor=None, func_name=None, left_demangled_name=None, right_demangled_name=None, arch="x86"):
    from ida_matcher.matcher.engine.diff_code import _strip_switch_ranges

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

    if func_name:
        print(f"\n{'=' * 50}\nDIFF: {func_name}\n{'=' * 50}")
        if left_demangled_name or right_demangled_name:
            b_name = right_demangled_name or func_name
            o_name = left_demangled_name or func_name
            print(f"Base:  {b_name}")
            print(f"Local: {o_name}")

    print_hexdump_diff(obj_bytes, base_bytes, obj_relocs, base_fixups, obj_reloc_widths)

    result = diff_code(
        bytes(obj_bytes), obj_relocs, obj_reloc_widths or {},
        bytes(base_bytes), base_fixups, {k: DEFAULT_RELOC_WIDTH for k in base_fixups},
        reloc_mode=reloc_mode, left_data_accessor=left_accessor, right_data_accessor=right_accessor, arch=arch
    )

    COL_W = 44
    print(f"\n{'Base (IDA Database)':<{COL_W}} | {'Local Compiled (.obj)':<{COL_W}}")
    print("-" * COL_W + "+" + "-" * COL_W)

    tag_for = {
        KIND_NONE: ("", GREEN),
        KIND_OP_MISMATCH: (" [OP]", YELLOW),
        KIND_ARG_MISMATCH: (" [ARG]", YELLOW),
        KIND_REPLACE: (" [REPL]", RED),
        KIND_DELETE: (" [DEL]", RED),
        KIND_INSERT: (" [INS]", RED),
    }
    left_rows = result["left_rows"]
    right_rows = result["right_rows"]
    left_args_diffs = result.get("left_args_diffs", [])
    right_args_diffs = result.get("right_args_diffs", [])
    for i, kind in enumerate(result["kinds"]):
        l_ref = left_rows[i].ins_ref
        r_ref = right_rows[i].ins_ref
        tag, color = tag_for[kind]
        mismatch_color = f"{RED_BG}" if color != GREEN else None
        
        la_diff = left_args_diffs[i] if i < len(left_args_diffs) else None
        ra_diff = right_args_diffs[i] if i < len(right_args_diffs) else None
        
        b_text = _render_engine_row(result["right"], r_ref, ra_diff, mismatch_color) if r_ref is not None else "(missing)"
        o_text = _render_engine_row(result["left"], l_ref, la_diff, mismatch_color) if l_ref is not None else "(missing)"
        
        b_pad = " " * max(0, COL_W - len(_strip_ansi(b_text)))
        o_pad = " " * max(0, COL_W - len(_strip_ansi(o_text)) - len(tag))
        print(f"{color}{b_text}{b_pad} | {o_text}{o_pad}{tag}{RESET}")

    if base_switches:
        print("-" * (COL_W * 2 + 1))
        print(f"Detected {len(base_switches)} Jump Table(s) in IDA Database:")
        for insn_offset, targets in base_switches.items():
            print(f"{DIM}  Indirect Jump at function offset {insn_offset}:{RESET}")
            for i, tgt in enumerate(targets):
                print(f"    Case {i:<3}: jumps to loc_{tgt}")

    pct = result["match_percent"]
    match_count = result["diff_score"]
    total_count = result["max_score"]
    print("-" * (COL_W * 2 + 1))
    color = GREEN if pct == 100.0 else (YELLOW if pct >= 80.0 else RED)
    print(f"{color}Instruction match: {pct:.2f}% (penalty {match_count}/{total_count}){RESET}")
    return pct
