"""Shared builders for tests: a tiny synthetic COFF .obj file."""
import struct

RAW = bytes.fromhex("55 8B E8 00 00 00 00 C9 C3 90 90 BA 00 00 C3 90 90")


def sym(name8: bytes, value: int, sec: int, typ: int, cls: int) -> bytes:
    return struct.pack("<8sIhHBB", name8, value, sec, typ, cls, 0)


def build_synthetic_obj() -> bytes:
    """_.obj with .text section, two funcs (_fa, _fb) and one eeternal _ext.

    Layout:
      header(20) section_hdr(40) raw(17) relocs(20) syms(3*18) strtab(4)
    Reloc 1 (DIR32) at raw-offset 1 -> _ext  (width 4)
    Reloc 2 (DIR16) at raw-offset 8 -> _ext  (width 2)
    """
    raw_size = len(RAW)
    raw_ptr = 20 + 40
    relocs = [
        struct.pack("<IIH", 1, 2, 6),   # DIR32
        struct.pack("<IIH", 8, 2, 1),   # DIR16
    ]
    reloc_ptr = raw_ptr + raw_size
    sym_ptr = reloc_ptr + len(b"".join(relocs))
    syms = [
        sym(b"_fa\0\0\0\0\0", 0, 1, 0x20, 2),
        sym(b"_fb\0\0\0\0\0", 6, 1, 0x20, 2),
        sym(b"_ext\0\0\0\0", 0, 0, 0x20, 2),
    ]
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, sym_ptr, len(syms), 0, 0)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", 0, 0, raw_size, raw_ptr, reloc_ptr, 0, len(relocs), 0, 0x20,
    )
    strtab = struct.pack("<I", 4)
    return header + sec_hdr + RAW + b"".join(relocs) + b"".join(syms) + strtab


def build_synthetic_obj_with_funcdef_aux(total_size=6):
    """Single-function .text obj whose symbol carries a FUNC_DEF aux record.

    RAW is 9 bytes; the aux `total_size` (default 6) should win over the
    gap-heuristic/section-size bound, so the function extracts to exactly
    `total_size` bytes.
    """
    raw = bytes.fromhex("55 8B E8 00 00 00 00 C9 C3")
    raw_size = len(raw)
    raw_ptr = 20 + 40
    # IMAGE_AUX_SYMBOL (function definition, 18 bytes): TagIndex, TotalSize,
    # PtrToLinenumber, PtrToNextFunc, then a 2-byte unused field.
    aux = struct.pack("<IIIIH", 0, total_size, 0, 0, 0)
    sym_entry = struct.pack("<8sIhHBB", b"_f\0\0\0\0\0\0", 0, 1, 0x20, 2, 1)
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, raw_ptr + raw_size, 2, 0, 0)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", 0, 0, raw_size, raw_ptr, 0, 0, 0, 0, 0x20,
    )
    strtab = struct.pack("<I", 4)
    return header + sec_hdr + raw + sym_entry + aux + strtab


def build_synthetic_thunk_obj():
    """Single-function .text obj holding a 6-byte `jmp dword ptr [mem]` stub."""
    raw = bytes.fromhex("FF 25 78 56 34 12")
    raw_size = len(raw)
    raw_ptr = 20 + 40
    sym_entry = sym(b"_t\0\0\0\0\0\0", 0, 1, 0x20, 2)
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, raw_ptr + raw_size, 1, 0, 0)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", 0, 0, raw_size, raw_ptr, 0, 0, 0, 0, 0x20,
    )
    strtab = struct.pack("<I", 4)
    return header + sec_hdr + raw + sym_entry + strtab


def build_synthetic_multi_section_obj():
    """.obj with .text/.data/.bss: one code func, one initialized datum with a
    DIR32 reloc, and one BSS symbol (16 zeroed bytes, no raw data on disk).

    Layout:
      header(20) section_headers(3*40) .text(17) .data(8) .data_relocs(10)
      syms(4*18) strtab(4)
    """
    text_raw = bytes.fromhex("55 8B E8 00 00 00 00 C9 C3 90 90 BA 00 00 C3 90 90")
    data_raw = bytes.fromhex("78 56 34 12 00 00 00 00")  # first 4 bytes relocated
    bss_size = 16
    text_size, data_size = len(text_raw), len(data_raw)
    raw_ptr = 20 + 3 * 40
    data_ptr = raw_ptr + text_size
    reloc_ptr = data_ptr + data_size
    sym_ptr = reloc_ptr + 10

    relocs = [struct.pack("<IIH", 0, 3, 6)]  # DIR32 at data offset 0 -> sym 3 (_ext)
    syms = [
        sym(b"_fa\0\0\0\0\0", 0, 1, 0x20, 2),
        sym(b"_data1\0\0", 0, 2, 0, 2),
        sym(b"_bss1\0\0\0", 0, 3, 0, 2),
        sym(b"_ext\0\0\0\0\0", 0, 0, 0, 2),
    ]
    header = struct.pack("<HHIIIHH", 0x014C, 3, 0, sym_ptr, len(syms), 0, 0)

    def sec_hdr(name, raw_size, raw_ptr_, reloc_ptr_, num_relocs, flags):
        return struct.pack(
            "<8sIIIIIIHHI",
            name, 0, 0, raw_size, raw_ptr_, reloc_ptr_, 0, num_relocs, 0, flags,
        )

    sec_headers = b"".join([
        sec_hdr(b".text\0\0\0", text_size, raw_ptr, 0, 0, 0x60000020),
        sec_hdr(b".data\0\0\0", data_size, data_ptr, reloc_ptr, 1, 0xC0000040),
        sec_hdr(b".bss\0\0\0\0", bss_size, 0, 0, 0, 0xC0000080),
    ])
    strtab = struct.pack("<I", 4)
    return header + sec_headers + text_raw + data_raw + b"".join(relocs) + b"".join(syms) + strtab


def build_synthetic_comdat_weak_obj():
    """.text$mn COMDAT section (selection ANY) defining one WEAK_EXTERNAL
    function symbol; the section symbol carries a SEC_DEF aux whose length is
    the raw size. Exercises exact COMDAT bounds + weak classification.

    Symbols: .text$mn (SECTION + SEC_DEF aux), _weak_fn (WEAK_EXTERNAL + aux).
    """
    raw = bytes.fromhex("55 8B E8 00 00 00 00 C9 C3")
    raw_size = len(raw)
    raw_ptr = 20 + 40
    # IMAGE_AUX_SYMBOL_SECTION_DEFINITION: Length, NumReloc, NumLine, Checksum,
    # Number, Selection(ANY=2), Reserved, Unused.
    sec_def_aux = struct.pack("<IHHIHBBH", raw_size, 0, 0, 0, 0, 2, 0, 0)
    sec_sym = struct.pack("<8sIhHBB", b".text$mn\0", 0, 1, 0, 0x68, 1)  # SECTION=0x68
    # IMAGE_AUX_SYMBOL_WEAK_EXTERNAL: TagIndex(0 -> sec sym), Characteristics(0).
    weak_aux = struct.pack("<II", 0, 0) + b"\x00" * 10
    func_sym = struct.pack("<8sIhHBB", b"_weak_fn\0", 0, 1, 0x20, 0x69, 1)  # WEAK_EXTERNAL=0x69
    syms = sec_sym + sec_def_aux + func_sym + weak_aux
    sym_ptr = raw_ptr + raw_size
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, sym_ptr, 4, 0, 0x20)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text$mn\0", 0, 0, raw_size, raw_ptr, 0, 0, 0, 0, 0x60001020,  # CNT_CODE|LNK_COMDAT
    )
    strtab = struct.pack("<I", 4)
    return header + sec_hdr + raw + syms + strtab