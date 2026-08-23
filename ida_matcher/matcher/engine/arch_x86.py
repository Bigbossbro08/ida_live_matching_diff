"""
ida_matcher.matcher.engine.arch_x86
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Capstone decoding, scanning, and argument processing.
"""

import re
try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from ida_matcher.matcher.engine.types import (
    InsnRef, ParsedInsn, OPCODE_DATA, _SIZE_NAMES, _read_le
)

_INTERNAL_LABEL_RE = re.compile(
    r'^(?:loc|LAB|jpt|def|unk)_[0-9a-fA-F_]+$'
    r'|^\$L_?\d+$'
    r'|^[._]L\d+$'
    r'|^switchD_\d+$'
)

_MSVC_LOCAL_LABEL_RE = re.compile(r'^\$L_?\d+$')

if HAS_CAPSTONE:
    _CS32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    _CS32.detail = True
    _CS64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _CS64.detail = True

def _capstone_insn(source, address):
    cs = _CS64 if getattr(source, "arch", "x86") == "x64" else _CS32
    try:
        insns = list(cs.disasm(source.data[address:], address, 1))
    except capstone.CsError:
        return None
    return insns[0] if insns else None

def _looks_internal_label(name):
    return bool(_INTERNAL_LABEL_RE.match(str(name).lstrip("@?$")) or _MSVC_LOCAL_LABEL_RE.match(str(name).lstrip("_")))

def _decode_one(source, address):
    insn = _capstone_insn(source, address)
    if insn is None:
        return None
    branch_dest = None
    if capstone.CS_GRP_BRANCH_RELATIVE in insn.groups:
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                branch_dest = op.imm
                break
    return InsnRef(address, len(insn.bytes), insn.id, branch_dest)

def scan_instructions(source):
    data = source.data
    n = len(data)
    out = []
    r_idx = 0
    pos = 0
    while pos < n:
        while r_idx < len(source.reloc_offsets) and source.reloc_offsets[r_idx] < pos:
            r_idx += 1
        if r_idx < len(source.reloc_offsets) and source.reloc_offsets[r_idx] == pos:
            size = source.reloc_width(pos)
            if pos + size <= n:
                out.append(InsnRef(pos, size, OPCODE_DATA, None))
                r_idx += 1
                indirect_pos = pos + size
                max_size = n - indirect_pos
                next_reloc = source.reloc_offsets[r_idx] if r_idx < len(source.reloc_offsets) else n
                indirect_size = min(max(0, next_reloc - indirect_pos), max_size)
                if indirect_size > 0:
                    for i in range(indirect_size):
                        out.append(InsnRef(indirect_pos + i, 1, OPCODE_DATA, None))
                    pos = indirect_pos + indirect_size
                else:
                    pos = indirect_pos
                continue
        insn = _decode_one(source, pos)
        if insn is None:
            out.append(InsnRef(pos, 1, OPCODE_DATA, None))
            pos += 1
            continue
        out.append(insn)
        pos += insn.size

    for ins in out:
        if ins.branch_dest is not None and not (0 <= ins.branch_dest < n):
            ins.branch_dest = None

    for ins in out:
        if ins.branch_dest is None:
            continue
        reloc = source.reloc_at(ins.address, ins.size)
        if reloc is None:
            continue
        if _looks_internal_label(reloc[1]):
            continue
        ins.branch_dest = None

    return out

def resolve_branches(rows):
    addr_map = {}
    for i, row in enumerate(rows):
        if row.ins_ref is not None:
            addr_map[row.ins_ref.address] = i
    branches = {}
    branch_idx = 0
    for i, row in enumerate(rows):
        ins = row.ins_ref
        if ins is None or ins.branch_dest is None:
            continue
        target = addr_map.get(ins.branch_dest)
        if target is None:
            continue
        entry = branches.get(target)
        if entry is None:
            branches[target] = (branch_idx, [i])
            row.branch_to = target
            row.branch_idx = branch_idx
            branch_idx += 1
        else:
            b_idx, froms = entry
            row.branch_to = target
            row.branch_idx = b_idx
            froms.append(i)
    for target, (b_idx, froms) in branches.items():
        rows[target].branch_from = froms
        rows[target].branch_idx = b_idx

def _imm_fit_width(value):
    for w in (1, 2, 4):
        if value < (1 << (8 * w)):
            return w
    return 0

def _reloc_in_imm(ins_ref, reloc):
    size = ins_ref.size
    span_start = max(0, size - min(4, size))
    rel = reloc[0] - ins_ref.address
    return span_start <= rel < size

def _reloc_in_mem_disp(ins_ref, reloc):
    size = ins_ref.size
    span_start = max(0, size - min(4, size))
    rel = reloc[0] - ins_ref.address
    if span_start <= rel < size:
        return True
    # C7-style "mov r/m32, imm32" forms: opcode+ModRM, disp32, then imm32 -
    # the displacement is NOT the trailing 4 bytes but sits at size-8.
    return size >= 8 and rel == size - 8

def _mem_args(insn, mem_op, ins_ref, reloc, reloc_on_disp):
    args = []
    has_reg = any(op.type == capstone.x86.X86_OP_REG for op in insn.operands)
    if not has_reg:
        args.append(("opaque", _SIZE_NAMES.get(mem_op.size // 8, str(mem_op.size // 8))))
        args.append(("opaque", "ptr"))
    base = mem_op.mem.base
    index = mem_op.mem.index
    scale = mem_op.mem.scale
    disp = mem_op.mem.disp
    if base:
        args.append(("opaque", insn.reg_name(base)))
    if index:
        if base:
            args.append(("opaque", "+"))
        args.append(("opaque", insn.reg_name(index)))
        args.append(("opaque", "*"))
        args.append(("signed", scale))
    if reloc_on_disp:
        if base or index:
            args.append(("opaque", "+"))
        args.append(("reloc",))
    elif disp != 0:
        if base or index:
            args.append(("opaque", "+" if disp > 0 else "-"))
        args.append(("signed", abs(disp)))
    return args

def process_instruction(source, ins_ref):
    if ins_ref.opcode == OPCODE_DATA:
        size = ins_ref.size
        mnemonic = {1: ".byte", 2: ".word", 4: ".dword", 8: ".qword"}.get(size, ".byte")
        reloc = source.reloc_at(ins_ref.address, size)
        args = [("reloc",)] if reloc else [("unsigned", _read_le(source.data, ins_ref.address, size))]
        return ParsedInsn(ins_ref, mnemonic, args)

    insn = _capstone_insn(source, ins_ref.address)
    reloc = source.reloc_at(ins_ref.address, ins_ref.size)
    is_branch = False
    if insn is not None and capstone.CS_GRP_BRANCH_RELATIVE in insn.groups:
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                is_branch = True
                break
    args = []
    relocation_emitted = False
    if insn is not None:
        has_imm = any(op.type == capstone.x86.X86_OP_IMM for op in insn.operands)
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_REG:
                args.append(("opaque", insn.reg_name(op.reg)))
            elif op.type == capstone.x86.X86_OP_IMM:
                if is_branch:
                    relocation_emitted = True
                    if ins_ref.branch_dest is not None:
                        args.append(("branch", ins_ref.branch_dest))
                    elif reloc is not None:
                        args.append(("reloc",))
                    else:
                        w = _imm_fit_width(op.imm)
                        if op.imm < 0:
                            args.append(("opaque", "-"))
                            args.append(("signed", -op.imm))
                        elif w and op.imm >= (1 << (8 * w - 1)):
                            args.append(("opaque", "-"))
                            args.append(("signed", (1 << (8 * w)) - op.imm))
                        else:
                            args.append(("signed", op.imm))
                else:
                    if reloc is not None and _reloc_in_imm(ins_ref, reloc):
                        args.append(("reloc",))
                        relocation_emitted = True
                    else:
                        w = _imm_fit_width(op.imm)
                        if op.imm < 0:
                            args.append(("opaque", "-"))
                            args.append(("signed", -op.imm))
                        elif w and op.imm >= (1 << (8 * w - 1)):
                            args.append(("opaque", "-"))
                            args.append(("signed", (1 << (8 * w)) - op.imm))
                        else:
                            args.append(("signed", op.imm))
            elif op.type == capstone.x86.X86_OP_MEM:
                is_rip = op.mem.base == capstone.x86.X86_REG_RIP
                # Note: `has_imm` is deliberately not a gate here - C7-style
                # "mov r/m32, imm32" carries both a disp32 (relocated) and an
                # imm32; the span check in _reloc_in_mem_disp disambiguates.
                reloc_on_disp = (
                    reloc is not None
                    and not relocation_emitted
                    and (is_rip or _reloc_in_mem_disp(ins_ref, reloc))
                )
                args.extend(_mem_args(insn, op, ins_ref, reloc, reloc_on_disp))
                if reloc_on_disp:
                    relocation_emitted = True
    if reloc is not None and not relocation_emitted:
        args.append(("reloc",))
    return ParsedInsn(ins_ref, insn.mnemonic if insn is not None else "", args)

def _arg_to_str(arg, reloc_name=None):
    if arg[0] == "opaque":
        return arg[1]
    if arg[0] == "signed":
        return hex(arg[1])
    if arg[0] == "unsigned":
        return hex(arg[1])
    if arg[0] == "reloc":
        return reloc_name if reloc_name is not None else "<reloc>"
    if arg[0] == "branch":
        return f"loc_{arg[1]:x}"
    return str(arg)
