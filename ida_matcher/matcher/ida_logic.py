"""
ida_matcher.matcher.ida_logic
~~~~~~~~~~~~~~~~~~~~~~~
Runs inside the IDA Pro Python environment.
Handles extracting bytes, switch tables, and relocation (fixup) information
from a live IDB.
"""
import ida_funcs
import ida_name
import ida_bytes
import idautils
import ida_nalt
import ida_idaapi
import ida_ua
import ida_fixup
import ida_allins

# A quick cache of names to EAs so we don't have to scan all names repeatedly
FUNC_CACHE = {}

def build_cache():
    global FUNC_CACHE
    FUNC_CACHE.clear()
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if name:
            FUNC_CACHE[name] = ea

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

def _get_func_relocs_via_operands(func, chunks):
    """
    Primary method: walk every instruction in every chunk, decode it,
    and identify operands that reference external addresses.

    Returns {relative_byte_offset: symbol_name}
    """
    relocs = {}
    insn = ida_ua.insn_t()

    ADDR_OP_TYPES = {ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far}
    STACK_PHRASES = {4, 5}  # ESP=4, EBP=5

    for chunk_start, chunk_buf_offset, chunk_size in chunks:
        chunk_end = chunk_start + chunk_size
        ea = chunk_start

        while ea < chunk_end:
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                ea += 1
                continue

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

                if (is_addr_op or is_global_displ) and op.offb > 0:
                    target_name = ida_name.get_name(op.addr)
                    if not target_name:
                        target_name = f"unk_{op.addr:08X}"

                    # Compute relative offset
                    rel_off = chunk_buf_offset + (ea - chunk_start) + op.offb
                    relocs[rel_off] = target_name

            ea += length

    return relocs

def _get_func_relocs_via_fixups(func, chunks):
    """
    Supplementary method: walk IDA's fixup table.
    """
    relocs = {}
    for chunk_start, chunk_buf_offset, chunk_size in chunks:
        chunk_end = chunk_start + chunk_size
        ea = ida_fixup.get_next_fixup_ea(chunk_start)
        while ea != ida_idaapi.BADADDR and ea < chunk_end:
            fi = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fi, ea):
                target_name = ida_name.get_name(fi.off)
                if not target_name:
                    target_name = f"unk_{fi.off:08X}"
                rel_off = chunk_buf_offset + (ea - chunk_start)
                if rel_off not in relocs:
                    relocs[rel_off] = target_name
            ea = ida_fixup.get_next_fixup_ea(ea + 1)
    return relocs

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

def get_function_bytes(name):
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
        }

    all_bytes, chunks = _collect_func_bytes(func)
    if not all_bytes:
        return None

    relocs = _get_func_relocs_via_operands(func, chunks)
    relocs.update(_get_func_relocs_via_fixups(func, chunks))

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

    return {
        "ea": hex(func.start_ea),
        "size": len(all_bytes),
        "bytes": all_bytes.hex(),
        "switches": switch_tables,
        "switch_ranges": switch_ranges,
        "fixups": {str(k): v for k, v in relocs.items()},
    }

def refresh():
    build_cache()
    return {"status": "ok", "cached_functions": len(FUNC_CACHE)}