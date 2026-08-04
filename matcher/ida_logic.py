import ida_name
import ida_bytes
import ida_funcs
import ida_idaapi
import idautils
import ida_nalt

FUNC_CACHE = {}

def build_cache():
    global FUNC_CACHE
    cache = {}
    for f_ea in idautils.Functions():
        f_name = ida_name.get_name(f_ea)
        if f_name:
            # Store exact mangled name to avoid C++ overload collisions
            cache[f_name] = f_ea
            
    FUNC_CACHE = cache
    print(f"IDA Live Matcher: Cached {len(FUNC_CACHE)} function symbols.")

def get_function_bytes(name):
    global FUNC_CACHE
    if not FUNC_CACHE:
        build_cache()
        
    ea = FUNC_CACHE.get(name)
    
    if ea is None:
        print(f"[HOT-RELOAD DEBUG] Query: '{name}' NOT FOUND in cache!")
        return None
        
    if ea != ida_idaapi.BADADDR:
        func = ida_funcs.get_func(ea)
        if func:
            size = func.end_ea - func.start_ea
            raw_bytes = ida_bytes.get_bytes(func.start_ea, size)
            
            # --- Extract Jump Tables ---
            switch_tables = {}
            for head in idautils.FuncItems(func.start_ea):
                si = ida_nalt.switch_info_t()
                # FIX: Check for truthiness instead of '> 0' since it returns None on failure
                if ida_nalt.get_switch_info(si, head):
                    jtable_ea = si.jumps
                    j_size = si.get_jtable_size()
                    j_elemsize = si.get_jtable_element_size()
                    
                    targets = []
                    if j_size > 0 and j_elemsize > 0:
                        for i in range(j_size):
                            ptr_ea = jtable_ea + (i * j_elemsize)
                            target_ea = ida_bytes.get_dword(ptr_ea) if j_elemsize == 4 else ida_bytes.get_word(ptr_ea)
                            
                            # Store the relative offset from function start
                            targets.append(hex(target_ea - func.start_ea))
                            
                    switch_tables[hex(head - func.start_ea)] = targets

            if raw_bytes is not None:
                return {
                    "ea": hex(func.start_ea),
                    "size": size,
                    "bytes": raw_bytes.hex(),
                    "switches": switch_tables
                }
                
    return None