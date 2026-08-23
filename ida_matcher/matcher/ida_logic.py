"""
ida_matcher.matcher.ida_logic
~~~~~~~~~~~~~~~~~~~~~~~
Runs inside the IDA Pro Python environment.
Handles extracting bytes, switch tables, and relocation (fixup) information
from a live IDB.
"""
import struct

try:
    import ida_funcs
    import ida_name
    import ida_bytes
    import idautils
    import ida_nalt
    import ida_idaapi
    import ida_ua
    import ida_fixup
    import ida_allins
    import ida_ida
    HAS_IDA = True
except ImportError:
    HAS_IDA = False

try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None

try:
    from objdiff_py import ObjectBuilder
except ImportError:
    ObjectBuilder = None

def _sync_read(fn):
    """Decorator to execute IDA API calls safely on IDA's main thread via execute_sync."""
    def wrapper(*args, **kwargs):
        if not HAS_IDA or ida_kernwin is None:
            return fn(*args, **kwargs)
        res = []
        err = []
        def runner():
            try:
                res.append(fn(*args, **kwargs))
            except Exception as e:
                err.append(e)
            return 1
        ida_kernwin.execute_sync(runner, ida_kernwin.MFF_READ)
        if err:
            raise err[0]
        return res[0] if res else None
    wrapper.__name__ = fn.__name__
    return wrapper

# A quick cache of names to EAs so we don't have to scan all names repeatedly
FUNC_CACHE = {}
DATA_CACHE = {}
# Sorted [(ea, name), ...] of every named address, used to resolve an operand
# target to its containing symbol (e.g. TheCamera.m_bWideScreenOn -> TheCamera).
NAME_EA_SORTED = []

@_sync_read
def build_cache():
    if not HAS_IDA:
        return
    global FUNC_CACHE
    FUNC_CACHE.clear()
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if name:
            FUNC_CACHE[name] = ea
    global DATA_CACHE
    DATA_CACHE.clear()
    global NAME_EA_SORTED
    NAME_EA_SORTED = sorted((ea, name) for ea, name in idautils.Names())
    import ida_segment
    for ea, name in idautils.Names():
        if name in FUNC_CACHE:
            continue
        seg = ida_segment.getseg(ea)
        if seg and seg.type != ida_segment.SEG_CODE:
            DATA_CACHE[name] = ea

def _resolve_target(ea):
    """
    Resolve a raw address to (name, addend, sym_ea) for fixup purposes.

    If `ea` is itself a named address, returns that name with addend 0. Otherwise
    falls back to the nearest named symbol at or below `ea` in the same segment
    (e.g. TheCamera.m_bWideScreenOn at TheCamera+0x3D -> ("TheCamera", 0x3D, TheCamera)).
    Returns (None, 0, 0) when no symbol can be associated, so callers skip the
    spurious fixup (struct-member displacements like [esi+39h]).
    """
    if not HAS_IDA or not NAME_EA_SORTED:
        return None, 0, 0
    name = ida_name.get_name(ea)
    if name:
        return name, 0, ea
    import bisect
    import ida_segment
    idx = bisect.bisect_right(NAME_EA_SORTED, (ea, "")) - 1
    if idx < 0:
        return None, 0, 0
    sym_ea, sym_name = NAME_EA_SORTED[idx]
    # The target must live in the same segment as its presumed container.
    seg = ida_segment.getseg(ea)
    sym_seg = ida_segment.getseg(sym_ea)
    if seg is None or sym_seg is None or seg.start_ea != sym_seg.start_ea:
        return None, 0, 0
    return sym_name, ea - sym_ea, sym_ea

def _collect_func_bytes(func):
    """
    Collect raw bytes for all chunks of a function.
    Returns (all_bytes: bytearray, chunks: list[(chunk_start_ea, offset_in_all, size)])
    """
    all_bytes = bytearray()
    chunks = []
    for chunk_start, chunk_end in idautils.Chunks(func.start_ea):
        size = chunk_end - chunk_start
        raw = ida_bytes.get_bytes(chunk_start, size)
        if raw:
            chunks.append((chunk_start, len(all_bytes), size))
            all_bytes.extend(raw)
    return all_bytes, chunks

def _target_sym_meta(ea):
    """(section_relative_addr, size, kind) for a fixup/operand target."""
    import ida_segment
    seg = ida_segment.getseg(ea)
    addr = 0
    kind = "unknown"
    if seg:
        addr = ea - seg.start_ea
        if seg.type == ida_segment.SEG_CODE:
            kind = "code"
        elif seg.type in (ida_segment.SEG_DATA, ida_segment.SEG_BSS):
            kind = "data"
    size = 0
    f = ida_funcs.get_func(ea)
    if f:
        size = f.size()
    return addr, size, kind


def _get_func_relocs_via_operands(func, chunks):
    """
    Primary method: walk every instruction in every chunk, decode it,
    and identify operands that reference external addresses.

    Returns {relative_byte_offset: symbol_name}
    """
    relocs = {}
    widths = {}
    classes = {}
    addends = {}
    sym_addrs = {}
    sym_sizes = {}
    sym_kinds = {}
    insn = ida_ua.insn_t()

    ADDR_OP_TYPES = {ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far}
    STACK_PHRASES = {4, 5}  # ESP=4, EBP=5

    # Bounds of the whole function (across chunks) so intra-function branch
    # targets can be excluded: a real COFF .obj never emits relocs for branches
    # that stay inside the function.
    if chunks:
        # Membership must be tested per chunk: a bounding box over distant
        # tail chunks (e.g. `.text$x` EH funclets far from the body) would
        # swallow unrelated externals located between them.
        def _in_func_chunks(addr):
            return any(c[0] <= addr < c[0] + c[2] for c in chunks)
    else:
        def _in_func_chunks(addr):
            return False

    for chunk_start, chunk_buf_offset, chunk_size in chunks:
        chunk_end = chunk_start + chunk_size
        ea = chunk_start

        while ea < chunk_end:
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                ea += 1
                continue

            _flags = ida_bytes.get_flags(ea)

            for op in insn.ops:
                if op.type == ida_ua.o_void:
                    break

                is_addr_op = op.type in ADDR_OP_TYPES
                # o_displ with non-stack base register can also be an address ref
                is_global_displ = (
                    op.type == ida_ua.o_displ
                    and op.phrase not in STACK_PHRASES
                    and op.addr != 0
                )
# Immediate operands that hold the address of a named symbol
                # (e.g. `mov edi, 0x97f680` referencing m_VehiclePoolConversion)
                # are reloc sites in the .obj; record them so the diff engine
                # sees a fixup at the same offset as the obj reloc.
                imm_val = op.value if op.type == ida_ua.o_imm else op.addr
                is_named_imm = (
                    op.type == ida_ua.o_imm
                    and imm_val != 0
                    and bool(ida_name.get_name(imm_val))
                )

                if not ((is_addr_op or is_global_displ or is_named_imm) and op.offb > 0):
                    continue

                # If the user/loader explicitly forced this operand to be a
                # plain number (is_numop), it is not a relocation site. This
                # mirrors unlinkerida's guard and avoids emitting fixups where
                # IDA itself says "this is just an immediate".
                if op.type != ida_ua.o_imm and ida_bytes.is_numop(_flags, op.n):
                    continue

                target_addr = imm_val if op.type == ida_ua.o_imm else op.addr

                # Exclude intra-function branch targets (no reloc in the .obj).
                if op.type in (ida_ua.o_near, ida_ua.o_far) and _in_func_chunks(target_addr):
                    continue

                # Resolve the target to its (possibly containing) named symbol.
                # Anonymous targets (struct-member displacements like [esi+39h],
                # tiny un-named offsets) get skipped, matching the .obj reloc set.
                target_name, addend, sym_ea = _resolve_target(target_addr)
                if not target_name:
                    continue
                if target_name.startswith("unk_") and addend == 0:
                    continue

                rel_off = chunk_buf_offset + (ea - chunk_start) + op.offb
                relocs[rel_off] = target_name

                is_64 = ida_ida.inf_is_64bit()
                if is_64:
                    if op.type in (ida_ua.o_near, ida_ua.o_far):
                        widths[rel_off] = 4
                        classes[rel_off] = "relative"
                    else:
                        is_qword = getattr(op, "dtype", 0) == ida_ua.dt_qword or ida_bytes.get_item_size(target_addr) == 8
                        widths[rel_off] = 8 if is_qword else 4
                        classes[rel_off] = "absolute"
                else:
                    widths[rel_off] = 4
                    # MSVC COFF: calls/jumps to an external function are
                    # IMAGE_REL_I386_REL32; data references are DIR32. Mirror
                    # what the compiler's .obj actually emits so objdiff-core's
                    # class equality passes.
                    classes[rel_off] = "relative" if op.type in (ida_ua.o_near, ida_ua.o_far) else "absolute"

                addends[rel_off] = addend
                sym_addrs[rel_off], sym_sizes[rel_off], sym_kinds[rel_off] = _target_sym_meta(sym_ea)

            ea += length

    return relocs, widths, classes, addends, sym_addrs, sym_sizes, sym_kinds

def _get_func_relocs_via_fixups(func, chunks):
    """
    Supplementary method: walk IDA's fixup table.
    """
    relocs = {}
    widths = {}
    classes = {}
    addends = {}
    sym_addrs = {}
    sym_sizes = {}
    sym_kinds = {}
    for chunk_start, chunk_buf_offset, chunk_size in chunks:
        chunk_end = chunk_start + chunk_size
        ea = ida_fixup.get_next_fixup_ea(chunk_start)
        while ea != ida_idaapi.BADADDR and ea < chunk_end:
            fi = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fi, ea):
                target_name, addend, sym_ea = _resolve_target(fi.off)
                if not target_name:
                    ea = ida_fixup.get_next_fixup_ea(ea + 1)
                    continue
                rel_off = chunk_buf_offset + (ea - chunk_start)
                if rel_off not in relocs:
                    relocs[rel_off] = target_name
                    
                    is_64 = ida_ida.inf_is_64bit()
                    if is_64:
                        if getattr(fi, "type", 0) == ida_fixup.FIXUP_OFF64:
                            widths[rel_off] = 8
                            classes[rel_off] = "absolute"
                        else:
                            # Typically FIXUP_OFF32 for relative or absolute 32-bit
                            widths[rel_off] = 4
                            classes[rel_off] = "relative" if (getattr(fi, "get_flags", lambda: 0)() & ida_fixup.FIXUPF_REL) else "absolute"
                    else:
                        widths[rel_off] = 4
                        # MSVC COFF: relative fixups (calls/jumps to externs) are
                        # IMAGE_REL_I386_REL32; everything else is DIR32.
                        classes[rel_off] = "relative" if (getattr(fi, "get_flags", lambda: 0)() & ida_fixup.FIXUPF_REL) else "absolute"
                        
                    addends[rel_off] = addend
                    sym_addrs[rel_off], sym_sizes[rel_off], sym_kinds[rel_off] = _target_sym_meta(sym_ea)
            ea = ida_fixup.get_next_fixup_ea(ea + 1)
    return relocs, widths, classes, addends, sym_addrs, sym_sizes, sym_kinds

def _is_thunk(func):
    """Return True for unambiguous compiler-generated forwarders (single leading
    direct `jmp mem`). Avoids misclassifying real small functions that tail-call.
    """
    if func.size() > 16:
        return False
    items = list(idautils.FuncItems(func.start_ea))
    if len(items) > 2:
        return False
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, func.start_ea) <= 0:
        return False
    if insn.itype == ida_allins.NN_jmp and insn.Op1.type == ida_ua.o_mem:
        return True
    return False

def is_compiler_generated(n):
    if not n: return False
    return (n.startswith("@") and n[1:].isdigit()) or \
           (n.startswith("_$E") and n[3:].isdigit()) or \
           (n.startswith("$LC") and n[3:].isdigit())

@_sync_read
def get_demangled_name(name):
    dmngld = ida_name.demangle_name(name, getattr(ida_name, "GN_DEMANGLED", 0))
    if dmngld:
        return dmngld
    import ida_idaapi
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea != ida_idaapi.BADADDR:
        short = ida_name.get_short_name(ea)
        if short and short != name:
            return short
    return ""

@_sync_read
def get_function_bytes(name):
    if not HAS_IDA:
        return None
    global FUNC_CACHE
    if not FUNC_CACHE:
        build_cache()

    ea = FUNC_CACHE.get(name)
    if ea is None:
        # The IDB may have gained/re-named functions since the cache was built.
        build_cache()
        ea = FUNC_CACHE.get(name)
    if ea is None or ea == ida_idaapi.BADADDR:
        return None

    func = ida_funcs.get_func(ea)
    if not func:
        return None

    if _is_thunk(func):
        return {
            "ea": hex(func.start_ea),
            "is_thunk": True,
            "size": func.size(),
            "bytes": "",
            "switches": {},
            "switch_ranges": [],
            "fixups": {},
            "demangled_name": get_demangled_name(name),
            "arch": "x64" if ida_ida.inf_is_64bit() else "x86",
        }

    all_bytes, chunks = _collect_func_bytes(func)
    if not all_bytes:
        return None

    r_op, w_op, c_op, a_op, sa_op, ss_op, sk_op = _get_func_relocs_via_operands(func, chunks)
    r_fx, w_fx, c_fx, a_fx, sa_fx, ss_fx, sk_fx = _get_func_relocs_via_fixups(func, chunks)
    
    relocs = {}
    widths = {}
    classes = {}
    addends = {}
    sym_addrs = {}
    sym_sizes = {}
    sym_kinds = {}
    for r, w, c, a, sa, ss, sk in [(r_op, w_op, c_op, a_op, sa_op, ss_op, sk_op),
                                   (r_fx, w_fx, c_fx, a_fx, sa_fx, ss_fx, sk_fx)]:
        for k, v in r.items():
            if k not in relocs:
                relocs[k] = v
                widths[k] = w[k]
                classes[k] = c[k]
                addends[k] = a[k]
                sym_addrs[k] = sa[k]
                sym_sizes[k] = ss[k]
                sym_kinds[k] = sk[k]

    switch_tables = {}
    switch_ranges = []
    for head in idautils.FuncItems(func.start_ea):
        si = ida_nalt.switch_info_t()
        if ida_nalt.get_switch_info(si, head):
            jtable_ea = si.jumps
            j_size = si.get_jtable_size()
            j_elemsize = si.get_jtable_element_size()
            targets = []
            if j_size > 0 and j_elemsize > 0:
                # The jump table lives in .rdata and is appended to the function
                # chunks; the .obj never contains it, so record its byte range
                # (function-relative) for the client to strip from the diff.
                table_start = jtable_ea - func.start_ea
                if table_start >= 0:
                    switch_ranges.append([table_start, table_start + j_size * j_elemsize])
                # Entries are either absolute VAs or offsets relative to the table
                # base when the SWI_ELBASE flag is set.
                elbase = bool(si.flags & getattr(ida_nalt, "SWI_ELBASE", 0))
                for i in range(j_size):
                    ptr_ea = jtable_ea + (i * j_elemsize)
                    raw = ida_bytes.get_dword(ptr_ea) if j_elemsize == 4 else ida_bytes.get_word(ptr_ea)
                    if raw == ida_idaapi.BADADDR:
                        continue
                    if elbase:
                        target_ea = jtable_ea + raw
                    else:
                        target_ea = raw
                    targets.append(hex(target_ea - func.start_ea))
            switch_tables[hex(head - func.start_ea)] = targets

    section_name = ""
    section_kind = "unknown"
    import ida_segment
    seg = ida_segment.getseg(func.start_ea)
    if seg:
        section_name = ida_segment.get_segm_name(seg)
        if seg.type == ida_segment.SEG_CODE: section_kind = "code"
        elif seg.type == ida_segment.SEG_DATA: section_kind = "data"
        elif seg.type == ida_segment.SEG_BSS: section_kind = "bss"

    return {
        "ea": hex(func.start_ea),
        "size": len(all_bytes),
        "bytes": all_bytes.hex(),
        "switches": switch_tables,
        "switch_ranges": switch_ranges,
        "fixups": {str(k): v for k, v in relocs.items()},
        "fixup_widths": {str(k): v for k, v in widths.items()},
        "fixup_classes": {str(k): v for k, v in classes.items()},
        "fixup_addends": {str(k): v for k, v in addends.items()},
        "fixup_sym_addrs": {str(k): v for k, v in sym_addrs.items()},
        "fixup_sym_sizes": {str(k): v for k, v in sym_sizes.items()},
        "fixup_sym_kinds": {str(k): v for k, v in sym_kinds.items()},
        "section_name": section_name,
        "section_kind": section_kind,
        "compiler_generated": is_compiler_generated(name),
        "demangled_name": get_demangled_name(name),
        "arch": "x64" if ida_ida.inf_is_64bit() else "x86",
    }

def refresh():
    build_cache()
    return {"status": "ok", "cached_functions": len(FUNC_CACHE)}

@_sync_read
def get_baseline():
    """Build a complete baseline snapshot: {name: record, ...} for all cached symbols."""
    global FUNC_CACHE, DATA_CACHE
    if not FUNC_CACHE:
        build_cache()
    result = {}
    for name in list(FUNC_CACHE.keys()):
        rec = get_function_bytes(name)
        if rec is not None:
            result[name] = rec
    for name in list(DATA_CACHE.keys()):
        rec = get_data_bytes(name)
        if rec is not None:
            result[name] = rec
    return result

@_sync_read
def get_data_bytes(name):
    if not HAS_IDA:
        return None
    global FUNC_CACHE
    if not FUNC_CACHE:
        build_cache()

    ea = FUNC_CACHE.get(name)
    if ea is None:
        build_cache()
        ea = FUNC_CACHE.get(name)
    if ea is None or ea == ida_idaapi.BADADDR:
        ea = DATA_CACHE.get(name)
        if ea is None:
            return None

    size = ida_bytes.get_item_size(ea)
    raw = ida_bytes.get_bytes(ea, size) if size > 0 else b""
    
    chunks = [(ea, 0, size)]
    r_fx, w_fx, c_fx, a_fx, sa_fx, ss_fx, sk_fx = _get_func_relocs_via_fixups(None, chunks)
    
    section_name = ""
    section_kind = "unknown"
    import ida_segment
    seg = ida_segment.getseg(ea)
    if seg:
        section_name = ida_segment.get_segm_name(seg)
        if seg.type == ida_segment.SEG_CODE: section_kind = "code"
        elif seg.type == ida_segment.SEG_DATA: section_kind = "data"
        elif seg.type == ida_segment.SEG_BSS: section_kind = "bss"
        
    return {
        "ea": hex(ea),
        "size": size,
        "bytes": raw.hex() if raw else "",
        "fixups": {str(k): v for k, v in r_fx.items()},
        "fixup_widths": {str(k): v for k, v in w_fx.items()},
        "fixup_classes": {str(k): v for k, v in c_fx.items()},
        "fixup_addends": {str(k): v for k, v in a_fx.items()},
        "fixup_sym_addrs": {str(k): v for k, v in sa_fx.items()},
        "fixup_sym_sizes": {str(k): v for k, v in ss_fx.items()},
        "fixup_sym_kinds": {str(k): v for k, v in sk_fx.items()},
        "section_name": section_name,
        "section_kind": section_kind,
        "compiler_generated": is_compiler_generated(name),
        "demangled_name": get_demangled_name(name),
        "arch": "x64" if ida_ida.inf_is_64bit() else "x86",
    }


def patch_reloc_site(data: bytearray, offset: int, width: int, addend: int):
    """
    Patch the COFF implicit addend directly into the section bytes at the relocation site.
    """
    if offset + width > len(data):
        return
    if width == 4:
        data[offset:offset+4] = struct.pack("<i", addend)
    elif width == 2:
        data[offset:offset+2] = struct.pack("<h", addend)
    elif width == 8:
        data[offset:offset+8] = struct.pack("<q", addend)


def synthetic_obj_from_record(rec, name=None):
    """
    Build a synthetic COFF .obj byte array from an extracted function or data record.
    """
    if not rec:
        return None
    if ObjectBuilder is None:
        raise RuntimeError("objdiff_py is not available; install objdiff_py to build synthetic objects")

    raw_hex = rec.get("bytes", "")
    raw_bytes = bytes.fromhex(raw_hex) if isinstance(raw_hex, str) else bytes(raw_hex)
    if not raw_bytes and rec.get("is_thunk"):
        raw_bytes = b"\x90"

    data = bytearray(raw_bytes)

    fixups = rec.get("fixups", {})
    widths = rec.get("fixup_widths", {})
    classes = rec.get("fixup_classes", {})
    addends = rec.get("fixup_addends", {})
    sym_kinds = rec.get("fixup_sym_kinds", {})

    # Patch reloc site bytes with MSVC placeholder addends before write_bytes
    for rel_off_str in fixups:
        rel_off = int(rel_off_str)
        width = int(widths.get(rel_off_str, 4))
        addend = int(addends.get(rel_off_str, 0))
        patch_reloc_site(data, rel_off, width, addend)

    arch = rec.get("arch", "x86")
    b = ObjectBuilder(arch)

    sec_name = rec.get("section_name") or ".text"
    sec_kind_str = rec.get("section_kind", "code")
    if sec_kind_str == "data":
        sec_kind = 1
    elif sec_kind_str == "bss":
        sec_kind = 3
    else:
        sec_kind = 0  # Text

    sec_id = b.add_section(sec_name, "", sec_kind)
    if data:
        b.write_bytes(sec_id, 0, bytes(data))

    sym_name = name or rec.get("name") or "func"
    sym_kind = 3 if sec_kind_str in ("data", "bss") else 2
    b.add_symbol(sec_id, sym_name, 0, len(data), sym_kind, 0)

    symbol_map = {}
    for rel_off_str, target_name in fixups.items():
        rel_off = int(rel_off_str)
        width = int(widths.get(rel_off_str, 4))
        cls = classes.get(rel_off_str, "absolute")
        addend = int(addends.get(rel_off_str, 0))
        target_kind_str = sym_kinds.get(rel_off_str, "unknown")
        # objdiff-core's ObjectBuilder refuses to serialize SymbolKind::Unknown,
        # so any fixup whose target kind was not classified (e.g. a spurious
        # unk_* reference) defaults to a data object symbol.
        target_sym_kind = 2 if target_kind_str == "code" else 3

        if target_name not in symbol_map:
            target_sym_id = b.add_symbol(0xFFFFFFFF, target_name, 0, 0, target_sym_kind, 0)
            symbol_map[target_name] = target_sym_id
        else:
            target_sym_id = symbol_map[target_name]

        if cls == "relative":
            writer_addend = addend - 4
            reloc_kind = 1
        elif width == 2:
            writer_addend = 0
            reloc_kind = 1
        else:
            writer_addend = addend
            reloc_kind = 6

        b.add_relocation(sec_id, rel_off, target_sym_id, reloc_kind, width, writer_addend)

    return b.finish()


def build_synthetic_obj(name):
    """
    Build a synthetic COFF .obj file for the given function (or data) name
    using ObjectBuilder.
    """
    rec = get_function_bytes(name)
    if rec is None:
        rec = get_data_bytes(name)
    if rec is None:
        return None
    return synthetic_obj_from_record(rec, name)