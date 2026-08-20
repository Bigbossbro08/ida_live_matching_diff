import pytest
import capstone
from ida_matcher.matcher.engine.arch_x86 import _decode_one
from ida_matcher.matcher.engine.types import _InsnSource

def test_arch_x86_64_mode():
    # 48 8b 05 34 12 00 00 : mov rax, qword ptr [rip + 0x1234]
    data = bytes.fromhex("488b0534120000")
    
    # 64-bit mode (arch="x64")
    source_64 = _InsnSource(data, {}, {}, arch="x64")
    insn_64 = _decode_one(source_64, 0)
    assert insn_64 is not None
    # 48 8b 05 34 12 00 00 is mov rax, ... Capstone opcode for mov is capstone.x86.X86_INS_MOV
    assert insn_64.opcode == capstone.x86.X86_INS_MOV
    
    # 32-bit mode (arch="x86")
    source_32 = _InsnSource(data, {}, {}, arch="x86")
    insn_32 = _decode_one(source_32, 0)
    assert insn_32 is not None
    # 48 is dec eax in 32-bit mode
    assert insn_32.opcode == capstone.x86.X86_INS_DEC


def test_x64_scan_addr64_data_literal():
    from ida_matcher.matcher.engine.arch_x86 import scan_instructions
    from ida_matcher.matcher.engine.types import OPCODE_DATA
    # 8-byte ADDR64 literal (e.g. a pointer)
    data = bytes.fromhex("0000000000000000")
    src = _InsnSource(data, {0: ("lit", 8)}, {0: 8}, arch="x64")
    ins = scan_instructions(src)
    assert len(ins) == 1
    assert ins[0].opcode == OPCODE_DATA
    assert ins[0].size == 8


def test_x64_diff_identical_with_addr64_literal():
    from ida_matcher.matcher.engine.diff_code import diff_code
    from ida_matcher.matcher.engine.types import OPCODE_DATA
    # 8-byte ADDR64 literal followed by `ret` (the ret becomes indirect data)
    data = bytes.fromhex("0000000000000000c3")
    relocs = {0: ("lit", 8)}
    widths = {0: 8}
    res = diff_code(data, relocs, widths, data, {0: ("lit", 8)}, {0: 8}, arch="x64")
    assert res["match_percent"] == 100.0
    assert res["left_ops"][0].opcode == OPCODE_DATA
    assert res["left_ops"][0].size == 8


def test_x64_rel32_branch_resolution():
    from ida_matcher.matcher.engine.arch_x86 import scan_instructions
    # e8 fb ff ff ff : call rel32 (5 + -5 = 0, in-range), then ret
    data = bytes.fromhex("e8fbffffffc3")
    src = _InsnSource(data, {}, {}, arch="x64")
    ins = scan_instructions(src)
    assert ins[0].opcode == capstone.x86.X86_INS_CALL
    assert ins[0].branch_dest == 0
    assert ins[1].opcode == capstone.x86.X86_INS_RET


def test_x64_data_mnemonic_qword():
    from ida_matcher.matcher.engine.arch_x86 import process_instruction, scan_instructions
    data = bytes.fromhex("0000000000000000")
    src = _InsnSource(data, {0: ("lit", 8)}, {0: 8}, arch="x64")
    ins_ref = scan_instructions(src)[0]
    p = process_instruction(src, ins_ref)
    assert p.mnemonic == ".qword"
    assert p.args == [("reloc",)]
