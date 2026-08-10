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
        struct.pack("<IIH", 1, 2, 3),   # DIR32
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