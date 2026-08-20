from ida_matcher.matcher.engine.types import RELOC_MODE_NAME_ADDRESS, _DiffContext, _InsnSource
from ida_matcher.matcher.engine.diff_code import reloc_eq
from ida_matcher.matcher.engine.align import patience_diff

class _FakeIns:
    def __init__(self, address, size):
        self.address = address
        self.size = size

def _patience_ratio(a, b):
    """Mirror of similar::diff_ratio over Patience ops: 2*equal/(len_a+len_b)."""
    if not a and not b:
        return 1.0
    ops = patience_diff(a, b)
    equal = sum(i2 - i1 for tag, i1, i2, j1, j2 in ops if tag == "equal")
    return (2.0 * equal) / (len(a) + len(b))

def diff_data_range(left_data, right_data):
    return _patience_ratio(left_data, right_data)

def diff_data_relocs_for_range(left_relocs, right_relocs, left_reloc_widths, right_reloc_widths, ctx):
    diffs = []
    # matched by relative offset within range
    # missing left->Delete, missing right->Insert, else None/Replace via reloc_eq
    left_relocs_list = sorted(left_relocs.items())
    right_relocs_list = sorted(right_relocs.items())
    
    matched_right = set()
    for l_off, l_reloc in left_relocs_list:
        l_size = left_reloc_widths.get(l_off, 4)
        r_reloc = None
        for r_off, r_reloc_val in right_relocs_list:
            if r_off == l_off:
                r_reloc = r_reloc_val
                matched_right.add(r_off)
                break
                
        if r_reloc is None:
            diffs.append(("Delete", l_off, None, l_size, 0))
        else:
            r_size = right_reloc_widths.get(l_off, 4)
            l_ins = _FakeIns(l_off, l_size)
            r_ins = _FakeIns(l_off, r_size)
            if reloc_eq(ctx, l_ins, r_ins):
                diffs.append(("None", l_off, l_off, l_size, r_size))
            else:
                diffs.append(("Replace", l_off, l_off, l_size, r_size))
                
    for r_off, r_reloc_val in right_relocs_list:
        if r_off not in matched_right:
            r_size = right_reloc_widths.get(r_off, 4)
            diffs.append(("Insert", None, r_off, 0, r_size))
            
    return diffs

def diff_data_symbol(left_data, right_data, left_relocs, right_relocs, left_reloc_widths, right_reloc_widths, reloc_mode=RELOC_MODE_NAME_ADDRESS):
    left_src = _InsnSource(left_data, left_relocs, left_reloc_widths)
    right_src = _InsnSource(right_data, right_relocs, right_reloc_widths)
    ctx = _DiffContext(left_src, right_src, reloc_mode)

    bytes_match_ratio = diff_data_range(left_data, right_data)

    reloc_diffs = diff_data_relocs_for_range(left_relocs, right_relocs, left_reloc_widths, right_reloc_widths, ctx)

    match_ratio = bytes_match_ratio
    if reloc_diffs:
        total_reloc_bytes = 0
        matching_reloc_bytes = 0
        for diff_kind, l_off, r_off, l_size, r_size in reloc_diffs:
            if diff_kind == "Insert":
                total_reloc_bytes += r_size
            elif diff_kind == "Delete":
                total_reloc_bytes += l_size
            else:
                total_reloc_bytes += l_size
                if diff_kind == "None":
                    matching_reloc_bytes += l_size

        if total_reloc_bytes > 0:
            relocs_match_ratio = matching_reloc_bytes / total_reloc_bytes
            match_ratio = ((bytes_match_ratio * len(left_data)) + (relocs_match_ratio * total_reloc_bytes)) / (len(left_data) + total_reloc_bytes)

    return match_ratio * 100.0

def diff_bss_symbol(left_size, right_size):
    return 100.0 if left_size == right_size else 50.0

def diff_generic_section(symbols_diffs):
    # symbols_diffs: list of (size, match_percent)
    total_size = sum(sz for sz, _ in symbols_diffs)
    if total_size == 0:
        return 100.0
    if all(pct == 100.0 for _, pct in symbols_diffs):
        return 100.0  # Avoid fp precision issues (objdiff diff_generic_section)
    matched = sum((sz * (pct or 0.0)) for sz, pct in symbols_diffs)
    return matched / total_size

def diff_data_section(left_data, right_data, left_relocs, right_relocs, left_reloc_widths, right_reloc_widths, symbols_diffs, reloc_mode=RELOC_MODE_NAME_ADDRESS):
    generic_pct = diff_generic_section(symbols_diffs)
    
    left_src = _InsnSource(left_data, left_relocs, left_reloc_widths)
    right_src = _InsnSource(right_data, right_relocs, right_reloc_widths)
    ctx = _DiffContext(left_src, right_src, reloc_mode)

    bytes_ratio = diff_data_range(left_data, right_data)
    data_pct = bytes_ratio * 100.0
    
    reloc_diffs = diff_data_relocs_for_range(left_relocs, right_relocs, left_reloc_widths, right_reloc_widths, ctx)
    all_left_relocs_match = True
    for diff_kind, l_off, r_off, l_size, r_size in reloc_diffs:
        if diff_kind in ("Delete", "Replace"):
            all_left_relocs_match = False
            break
            
    if all_left_relocs_match and data_pct > generic_pct:
        return data_pct
    return generic_pct

def diff_bss_section(symbols_diffs, left_sizes, right_sizes):
    # left_sizes, right_sizes: list of (offset, size)
    generic_pct = diff_generic_section(symbols_diffs)
    
    if not left_sizes and not right_sizes:
        pct = 100.0
    else:
        pct = _patience_ratio(left_sizes, right_sizes) * 100.0
        
    return max(pct, generic_pct)
