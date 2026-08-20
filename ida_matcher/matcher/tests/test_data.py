from ida_matcher.matcher.engine.data import diff_data_symbol, diff_bss_symbol, diff_data_section, diff_bss_section

def test_diff_data_identical():
    left_data = b"\x78\x56\x34\x12\x00\x00\x00\x00"
    right_data = b"\x78\x56\x34\x12\x00\x00\x00\x00"
    # one DIR32 reloc at offset 0
    relocs = {0: ("_ext", 4, "absolute", 0, "", "", 0, 0, "unknown")}
    widths = {0: 4}
    
    match_pct = diff_data_symbol(left_data, right_data, relocs, relocs, widths, widths)
    assert match_pct == 100.0

def test_diff_data_one_byte_change():
    left_data = b"\x78\x56\x34\x12\x00\x00\x00\x00"
    right_data = b"\x79\x56\x34\x12\x00\x00\x00\x00"
    match_pct = diff_data_symbol(left_data, right_data, {}, {}, {}, {})
    # 8 bytes, 7 match. ratio = 14 / 16 = 0.875
    assert abs(match_pct - 87.5) < 0.1

def test_diff_data_reloc_double_counting():
    left_data = b"\x00" * 8
    right_data = b"\x00" * 8
    
    # left and right data match completely (1.0 ratio).
    # left and right relocations mismatch.
    left_relocs = {0: ("_ext", 4, "absolute", 0, "", "", 0, 0, "unknown")}
    right_relocs = {0: ("_other", 4, "absolute", 0, "", "", 0, 0, "unknown")}
    widths = {0: 4}
    
    match_pct = diff_data_symbol(left_data, right_data, left_relocs, right_relocs, widths, widths)
    # bytes match: 8 * 1.0 = 8
    # relocs match: 4 * 0 = 0
    # ratio: 8 / (8 + 4) = 8 / 12 = 0.666
    assert abs(match_pct - 66.666) < 0.1

def test_diff_bss():
    assert diff_bss_symbol(16, 16) == 100.0
    assert diff_bss_symbol(16, 8) == 50.0

def test_diff_data_section():
    # Test diff_data_section replacing generic
    left_data = b"\x78\x56\x34\x12\x00\x00\x00\x00"
    right_data = b"\x78\x56\x34\x12\x00\x00\x00\x00"
    relocs = {0: ("_ext", 4, "absolute", 0, "", "", 0, 0, "unknown")}
    widths = {0: 4}
    
    # Let generic be 50%, but data and relocs match perfectly so it replaces it
    generic_pct = 50.0
    symbols_diffs = [(8, 50.0)]
    
    sec_pct = diff_data_section(left_data, right_data, relocs, relocs, widths, widths, symbols_diffs)
    assert sec_pct == 100.0
