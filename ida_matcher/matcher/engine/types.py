"""
ida_matcher.matcher.engine.types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Core data classes and constants for the diff engine.
"""

import bisect

DEFAULT_RELOC_WIDTH = 4

PENALTY_IMM_DIFF = 1
PENALTY_REG_DIFF = 5
PENALTY_REPLACE = 60
PENALTY_INSERT_DELETE = 100

RELOC_MODE_NONE = "none"
RELOC_MODE_NAME_ADDRESS = "name_address"
RELOC_MODE_DATA_VALUE = "data_value"
RELOC_MODE_ALL = "all"

OPCODE_DATA = 0xFFFE

KIND_NONE = "None"
KIND_OP_MISMATCH = "OpMismatch"
KIND_ARG_MISMATCH = "ArgMismatch"
KIND_REPLACE = "Replace"
KIND_DELETE = "Delete"
KIND_INSERT = "Insert"

_SIZE_NAMES = {1: "byte", 2: "word", 4: "dword", 8: "qword"}

class InsnRef:
    """Mirror of objdiff's InstructionRef (address, size, opcode, branch_dest)."""
    __slots__ = ("address", "size", "opcode", "branch_dest")

    def __init__(self, address, size, opcode, branch_dest=None):
        self.address = address
        self.size = size
        self.opcode = opcode
        self.branch_dest = branch_dest

    def __repr__(self):
        return f"InsnRef(0x{self.address:x}, {self.size}, op={self.opcode}, bd={self.branch_dest})"


class ParsedInsn:
    """Mirror of objdiff's ParsedInstruction (mnemonic + args)."""
    __slots__ = ("ins_ref", "mnemonic", "args")

    def __init__(self, ins_ref, mnemonic, args):
        self.ins_ref = ins_ref
        self.mnemonic = mnemonic
        self.args = args


class InstructionDiffRow:
    """Mirror of objdiff's InstructionDiffRow (one side of the alignment)."""
    __slots__ = ("ins_ref", "branch_to", "branch_from", "branch_idx")

    def __init__(self, ins_ref=None):
        self.ins_ref = ins_ref
        self.branch_to = None      # row index this branch targets (ins_idx)
        self.branch_from = None    # list of row indices branching here
        self.branch_idx = None


class _InsnSource:
    """One side of a diff: raw code + relocations + per-reloc descriptors."""

    __slots__ = ("data", "relocs", "widths", "classes", "addends", "sec_names", "sec_kinds",
                 "sym_addrs", "sym_sizes", "sym_kinds", "sym_known", "mapped_offsets", "reloc_offsets", "data_accessor", "arch")

    def __init__(self, data, relocs, widths=None, classes=None, addends=None, sec_names=None,
                 sec_kinds=None, sym_addrs=None, sym_sizes=None, sym_kinds=None, data_accessor=None, arch="x86"):
        self.arch = arch
        self.data_accessor = data_accessor
        self.data = bytes(data)
        self.relocs = {}
        self.widths = {int(k): int(v) for k, v in (widths or {}).items()}
        self.classes = {int(k): str(v) for k, v in (classes or {}).items()}
        self.addends = {int(k): int(v) for k, v in (addends or {}).items()}
        self.sec_names = {int(k): str(v) for k, v in (sec_names or {}).items()}
        self.sec_kinds = {int(k): str(v) for k, v in (sec_kinds or {}).items()}
        self.sym_addrs = {int(k): int(v) for k, v in (sym_addrs or {}).items()}
        self.sym_sizes = {int(k): int(v) for k, v in (sym_sizes or {}).items()}
        self.sym_kinds = {int(k): str(v) for k, v in (sym_kinds or {}).items()}
        self.sym_known = set(self.sym_addrs) | set(self.sym_sizes) | set(self.sym_kinds)
        self.mapped_offsets = set()
        
        for k, v in relocs.items():
            k_int = int(k)
            if isinstance(v, tuple):
                self.relocs[k_int] = str(v[0])
                if len(v) > 1: self.widths[k_int] = v[1]
                if len(v) > 2: self.classes[k_int] = v[2]
                if len(v) > 3: self.addends[k_int] = v[3]
                if len(v) > 4: self.sec_names[k_int] = v[4]
                if len(v) > 5: self.sec_kinds[k_int] = v[5]
                if len(v) > 6: self.sym_addrs[k_int] = v[6]
                if len(v) > 7: self.sym_sizes[k_int] = v[7]
                if len(v) > 8: self.sym_kinds[k_int] = v[8]
                if len(v) > 6: self.sym_known.add(k_int)
                if len(v) > 9 and v[9] is True: self.mapped_offsets.add(k_int)
            else:
                self.relocs[k_int] = str(v)
                
        self.reloc_offsets = sorted(self.relocs)

    def reloc_width(self, offset):
        return self.widths.get(offset, DEFAULT_RELOC_WIDTH)

    def reloc_at(self, address, size):
        offsets = self.reloc_offsets
        i = bisect.bisect_left(offsets, address)
        if i < len(offsets) and (offsets[i] == address or offsets[i] < address + size):
            off = offsets[i]
            return (
                off,
                self.relocs[off],
                self.reloc_width(off),
                self.classes.get(off, "absolute"),
                self.addends.get(off, 0),
                self.sec_names.get(off, ""),
                self.sec_kinds.get(off, "unknown"),
                self.sym_addrs.get(off, 0),
                self.sym_sizes.get(off, 0),
                self.sym_kinds.get(off, "unknown"),
                off in self.sym_known,
                off in self.mapped_offsets,
            )
        return None


class _DiffContext:
    __slots__ = ("left", "right", "reloc_mode")

    def __init__(self, left, right, reloc_mode):
        self.left = left
        self.right = right
        self.reloc_mode = reloc_mode


def _read_le(data, address, size):
    return int.from_bytes(data[address:address + size], "little")


def _ins_code(source, ins_ref):
    return source.data[ins_ref.address:ins_ref.address + ins_ref.size]
