"""
ida_matcher.matcher.engine.diff_code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Core decision tree, arg equality, and scoring logic.
"""

import re
from ida_matcher.matcher.engine.types import (
    RELOC_MODE_NONE, RELOC_MODE_NAME_ADDRESS, RELOC_MODE_DATA_VALUE, RELOC_MODE_ALL,
    KIND_NONE, KIND_OP_MISMATCH, KIND_ARG_MISMATCH, KIND_REPLACE, KIND_DELETE, KIND_INSERT,
    PENALTY_IMM_DIFF, PENALTY_REG_DIFF, PENALTY_REPLACE, PENALTY_INSERT_DELETE,
    _InsnSource, _DiffContext, _ins_code
)
from ida_matcher.matcher.engine.align import insn_align
from ida_matcher.matcher.engine.arch_x86 import scan_instructions, resolve_branches, process_instruction

def _value_loose_eq(a, b):
    if a[0] == "opaque" or b[0] == "opaque":
        return a == b
    return a[1] == b[1]

def get_normalized_symbol_name(name: str) -> str:
    name = re.sub(r'^__imp_', '', name.strip())
    name = re.sub(r'^j_', '', name)
    name = re.sub(r'^_', '', name)
    
    if "@class$" in name:
        parts = name.split("@class$", 1)
        suffix = parts[1]
        m = re.match(r"^(\d+)(.*)$", suffix)
        if m:
            return f"{parts[0]}@class$0000{m.group(2)}"
        return name
    if "$" in name:
        parts = name.split("$", 1)
        if parts[1].isdigit():
            return f"{parts[0]}$0000"
    if "." in name:
        parts = name.split(".", 1)
        if parts[1].isdigit():
            return f"{parts[0]}.0000"
    if name.startswith("?") and "?A0x" in name:
        return re.sub(r"\?A0x[0-9a-fA-F]{8}@@", "?A0x00000000@@", name)
    return name

def is_symbol_name_compiler_generated(name: str) -> bool:
    if name.startswith("@") and name[1:].isdigit():
        return True
    if name.startswith("_$E") and name[3:].isdigit():
        return True
    if name.startswith("$LC") and name[3:].isdigit():
        return True
    return False

def _looks_anonymous(name: str) -> bool:
    n = str(name).strip()
    if re.match(r"^(sub|loc|unk|jpt|def|nullsub)_[0-9A-Fa-f]+", n):
        return True
    if re.match(r"^[0-9A-Fa-f]+$", n):
        return True
    return False

def symbol_name_matches(left_name: str, right_name: str) -> bool:
    left_norm = get_normalized_symbol_name(left_name)
    right_norm = get_normalized_symbol_name(right_name)
    return left_norm == right_norm

def _address_eq(left_reloc, right_reloc):
    if not (left_reloc[10] if len(left_reloc) > 10 else False):
        return False
    if not (right_reloc[10] if len(right_reloc) > 10 else False):
        return False
    left_sym_addr = left_reloc[7]
    right_sym_addr = right_reloc[7]
    left_sym_size = left_reloc[8]
    right_sym_size = right_reloc[8]
    left_addend = left_reloc[4]
    right_addend = right_reloc[4]
    if right_sym_size == 0 and left_sym_size != 0:
        return (left_sym_addr + left_addend) == (right_sym_addr + right_addend)
    return left_sym_addr == right_sym_addr and left_addend == right_addend

def _ins_data_literals_eq(ctx, left_ins, right_ins):
    left_reloc = ctx.left.reloc_at(left_ins.address, left_ins.size)
    right_reloc = ctx.right.reloc_at(right_ins.address, right_ins.size)
    if not left_reloc or not right_reloc:
        return False

    left_sym = left_reloc[1]
    right_sym = right_reloc[1]

    if not getattr(ctx.left, 'data_accessor', None) or not getattr(ctx.right, 'data_accessor', None):
        return False

    left_info = ctx.left.data_accessor(left_sym)
    right_info = ctx.right.data_accessor(right_sym)
    if not left_info or not right_info:
        return False

    left_data, left_offset = left_info
    right_data, right_offset = right_info

    left_addend = left_reloc[4] if len(left_reloc) > 4 else 0
    right_addend = right_reloc[4] if len(right_reloc) > 4 else 0

    # objdiff indexes symbol_data[addend..]; the accessor returns section bytes
    # plus the symbol's offset within it, so the byte index is offset + addend.
    left_idx = left_offset + left_addend
    right_idx = right_offset + right_addend

    if left_idx >= len(left_data) or right_idx >= len(right_data):
        return False

    left_slice = left_data[left_idx:]
    right_slice = right_data[right_idx:]
    cmp_len = min(len(left_slice), len(right_slice))
    if cmp_len == 0:
        return False
    return left_slice[:cmp_len] == right_slice[:cmp_len]

def reloc_eq(ctx, left_ins, right_ins):
    left_reloc = ctx.left.reloc_at(left_ins.address, left_ins.size)
    right_reloc = ctx.right.reloc_at(right_ins.address, right_ins.size)
    
    relax = ctx.reloc_mode == RELOC_MODE_NONE
    if left_reloc is None and right_reloc is None:
        return True
    if left_reloc is None and right_reloc is not None:
        return relax
    if left_reloc is not None and right_reloc is None:
        return False

    left_name = left_reloc[1]
    right_name = right_reloc[1]

    left_mapped = left_reloc[11] if len(left_reloc) > 11 else False
    right_mapped = right_reloc[11] if len(right_reloc) > 11 else False

    left_class = left_reloc[3] if len(left_reloc) > 3 else "absolute"
    right_class = right_reloc[3] if len(right_reloc) > 3 else "absolute"
    left_addend = left_reloc[4] if len(left_reloc) > 4 else 0
    right_addend = right_reloc[4] if len(right_reloc) > 4 else 0
    left_sec_name = left_reloc[5] if len(left_reloc) > 5 else ""
    right_sec_name = right_reloc[5] if len(right_reloc) > 5 else ""
    left_sym_size = left_reloc[8] if len(left_reloc) > 8 else 0
    right_sym_size = right_reloc[8] if len(right_reloc) > 8 else 0
    left_sym_kind = left_reloc[9] if len(left_reloc) > 9 else "unknown"

    if left_class != right_class:
        if left_class not in ("absolute", "relative", "unknown", "") and right_class not in ("absolute", "relative", "unknown", ""):
            return False

    if relax:
        return True

    if (left_mapped or right_mapped) and symbol_name_matches(left_name, right_name):
        # Explicit reloc_mapping declares these names equivalent; the IDA side
        # records the resolved VA as its addend and its enclosing section while
        # the obj side records addend 0 and the target's real section, so the
        # addend/section/address checks below would spuriously reject them.
        return True

    if _looks_anonymous(left_name) or _looks_anonymous(right_name):
        name_addend_ok = True
    else:
        name_addend_ok = symbol_name_matches(left_name, right_name) and (left_addend == right_addend)
    
    if left_sec_name and right_sec_name:
        # The IDA side records the enclosing function's section for every
        # fixup, while the obj side records each reloc target's own section.
        # An explicit reloc_mapping (mapped flag) declares the names equivalent,
        # so the section mismatch is a recording artifact and must be ignored.
        mapped_match = (left_mapped or right_mapped) and symbol_name_matches(left_name, right_name)
        section_name_eq = left_sec_name == right_sec_name or mapped_match
        
        name_ok = False
        if ctx.reloc_mode == RELOC_MODE_DATA_VALUE:
            name_ok = True
        elif is_symbol_name_compiler_generated(left_name) and is_symbol_name_compiler_generated(right_name):
            name_ok = True
        elif name_addend_ok or _address_eq(left_reloc, right_reloc):
            name_ok = True
            
        value_ok = False
        if ctx.reloc_mode == RELOC_MODE_NAME_ADDRESS:
            value_ok = True
        elif _ins_data_literals_eq(ctx, left_ins, right_ins):
            value_ok = True
        elif left_sym_kind != "data":
            value_ok = True
        elif right_sym_size == 0:
            value_ok = True
            
        return section_name_eq and name_ok and value_ok

    return name_addend_ok

def arg_eq(ctx, left_row, right_row, a, b, left_ins, right_ins):
    if a[0] in ("signed", "unsigned", "opaque"):
        if b[0] in ("signed", "unsigned", "opaque"):
            return _value_loose_eq(a, b)
        if b[0] == "reloc":
            # IDA records spurious fixups (e.g. struct-member disp treated as
            # a reference to unk_00000004) where the obj has a plain literal.
            # Anonymous targets are already relaxed by name, so allow the match.
            r_reloc = ctx.right.reloc_at(right_ins.address, right_ins.size) if right_ins else None
            if r_reloc and _looks_anonymous(r_reloc[1]):
                return True
            return ctx.reloc_mode == RELOC_MODE_NONE
        return False
    if a[0] == "reloc":
        if b[0] == "reloc":
            return reloc_eq(ctx, left_ins, right_ins)
        if b[0] in ("signed", "unsigned", "opaque"):
            l_reloc = ctx.left.reloc_at(left_ins.address, left_ins.size) if left_ins else None
            if l_reloc and _looks_anonymous(l_reloc[1]):
                return True
        return False
    if a[0] == "branch":
        if b[0] == "branch":
            return left_row.branch_to == right_row.branch_to
        if b[0] == "reloc":
            return ctx.reloc_mode == RELOC_MODE_NONE
        return False
    return False

def diff_instruction(ctx, left_row, right_row):
    left, right = left_row.ins_ref, right_row.ins_ref
    if left is None and right is None:
        return KIND_NONE, 0, [], []
    if left is None:
        return KIND_INSERT, PENALTY_INSERT_DELETE, [], []
    if right is None:
        return KIND_DELETE, PENALTY_INSERT_DELETE, [], []
    if left.opcode != right.opcode:
        return KIND_REPLACE, PENALTY_REPLACE, [], []

    left_code = _ins_code(ctx.left, left)
    right_code = _ins_code(ctx.right, right)
    if left_code == right_code and reloc_eq(ctx, left, right):
        return KIND_NONE, 0, [], []

    l_ins = process_instruction(ctx.left, left)
    r_ins = process_instruction(ctx.right, right)
    if len(l_ins.args) != len(r_ins.args):
        return KIND_REPLACE, PENALTY_REPLACE, [], []

    kind = KIND_NONE
    penalty = 0
    left_args_diff, right_args_diff = [], []
    if l_ins.mnemonic != r_ins.mnemonic:
        penalty += PENALTY_REG_DIFF
        kind = KIND_OP_MISMATCH
    for a, b in zip(l_ins.args, r_ins.args):
        if arg_eq(ctx, left_row, right_row, a, b, left, right):
            left_args_diff.append(None)
            right_args_diff.append(None)
        else:
            penalty += PENALTY_IMM_DIFF if a[0] in ("signed", "unsigned") else PENALTY_REG_DIFF
            if kind == KIND_NONE:
                kind = KIND_ARG_MISMATCH
            left_args_diff.append(0)
            right_args_diff.append(0)
    if kind == KIND_NONE and len(left_code) != len(right_code):
        kind = KIND_OP_MISMATCH
        penalty += PENALTY_REG_DIFF
    return kind, penalty, left_args_diff, right_args_diff

def diff_code(left_data, left_relocs, left_widths, right_data, right_relocs, right_widths,
              reloc_mode=RELOC_MODE_NAME_ADDRESS, left_data_accessor=None, right_data_accessor=None, arch="x86"):
    left = _InsnSource(left_data, left_relocs, left_widths, data_accessor=left_data_accessor, arch=arch)
    right = _InsnSource(right_data, right_relocs, right_widths, data_accessor=right_data_accessor, arch=arch)
    left_ops = scan_instructions(left)
    right_ops = scan_instructions(right)
    left_rows, right_rows = insn_align(left_ops, right_ops)
    resolve_branches(left_rows)
    resolve_branches(right_rows)
    ctx = _DiffContext(left, right, reloc_mode)
    kinds = []
    penalties = []
    left_args_diffs = []
    right_args_diffs = []
    for l_row, r_row in zip(left_rows, right_rows):
        kind, penalty, _la, _ra = diff_instruction(ctx, l_row, r_row)
        kinds.append(kind)
        penalties.append(penalty)
        left_args_diffs.append(_la)
        right_args_diffs.append(_ra)
    diff_score = min(sum(penalties), len(left_ops) * PENALTY_INSERT_DELETE)
    max_score = len(left_ops) * PENALTY_INSERT_DELETE
    match_percent = 100.0 if max_score == 0 else (1 - diff_score / max_score) * 100
    return {
        "left": left,
        "right": right,
        "left_rows": left_rows,
        "right_rows": right_rows,
        "left_ops": left_ops,
        "right_ops": right_ops,
        "kinds": kinds,
        "penalties": penalties,
        "left_args_diffs": left_args_diffs,
        "right_args_diffs": right_args_diffs,
        "diff_score": diff_score,
        "max_score": max_score,
        "match_percent": match_percent,
    }


def _strip_switch_ranges(data_bytes, fixups, switch_ranges, reloc_widths=None):
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
