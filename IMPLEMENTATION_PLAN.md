# IDA Live Matching Diff - API Map & Implementation Plan

## 1. API Map

### 1.1 Module Layout

```
ida_matcher/
  matcher/
    coff_parser.py   # Client-side: pure-Python COFF .obj parser
    match_core.py    # Client-side: matching / diffing engine + CLI entry
    run_match.py     # Client-side: one-shot CLI wrapper (executes match_core)
    watch.py         # Client-side: poll-for-changes CLI wrapper
    match.py         # Compatibility shim -> match_core
    ida_logic.py     # IDA-side: extracts bytes/fixups/switches from live IDB
    ida_server.py    # IDA-side: HTTP server inspecting via ida_logic
    export_baseline.py # IDA-side: offline baseline JSON export (not used by live flow)
```

### 1.2 Client <-> IDA Server HTTP Contract

| Endpoint      | Query   | Response                                       |
|---------------|---------|------------------------------------------------|
| `GET /func`   | `?name=<url-encoded mangled name>` | `200` with JSON function record (below), or `404 {"error":"not found"}`, or `500 {"error":...}` |
| `GET /funcs`  | `?names=a,b,c` | `200 {"results": {name: record-or-null}}` — batch lookup for `match_summary` (one round trip vs. N) |
| `GET /health` | —       | `200 {"status":"ok"}` — used by the client to detect a live server before matching |
| `GET /refresh`| —       | `200 {"status":"refreshed"}` — rebuilds the name→EA cache |

**Function record** produced by `ida_logic.get_function_bytes` and consumed by `match_core.fetch_from_ida`:

```jsonc
{
  "ea": "0x401000",            // function start VA (hex string)
  "size": 37,                  // total byte count across all chunks
  "bytes": "558bec83ec40...",  // hex string, concat of raw chunk bytes
  "is_thunk": false,           // added: true when IDA classifies it as a forwarder
  "switches": { "0x12": ["0x1a", "0x2c"] },  // jump-table: insn-offset -> target intra-function offsets
  "fixups": { "5": "_printf", "13": "unk_402100" }  // rel-byte-offset -> symbol label
}
```

Thunk responses carry `"bytes": ""` plus `"is_thunk": true` (was: `null`).

### 1.3 `.obj` Data Contract (`coff_parser.load_obj`)

```python
{ mangled_name: {
    "bytes": bytearray,            # raw function bytes (section-relative)
    "offset": int,                 # function start within its section
    "relocs": { rel_off: sym_name },       # reloc byte-offset -> target symbol
    "reloc_widths": { rel_off: width },    # NEW: per-reloc byte width (2 or 4)
} }
```

### 1.4 Key Function Signatures

**match_core.py (pure client)**
- `compare_functions(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, obj_reloc_widths=None) -> (float, int)`
- `fetch_from_ida(func_name) -> dict | None`
- `diff_function(obj_bytes, base_bytes_hex, obj_relocs, base_fixups, base_switches=None, obj_reloc_widths=None) -> float`
- `match_summary(obj_path)` / `match_focus(obj_path, func_name)`
- `_normalize_insn(addr, mnemonic, op_str, insn_bytes, relocs, widths=None) -> str`
- `_insn_has_reloc(addr, insn_bytes, relocs, widths=None) -> bool`
- `print_hexdump_diff(obj_bytes, base_bytes, obj_relocs, base_fixups, obj_reloc_widths=None)`
- NEW: `_reloc_byte_map(relocs, widths=None, default=4) -> {byte: sym}`
- NEW: `_reloc_symbols_match(name_a, name_b) -> bool` (normalizes `_`/`__imp_` prefixes, treats anonymous `sub_/unk_/loc_` as unprovable)

**ida_logic.py (Runs inside IDA Python)**
- `build_cache() -> None` (global `FUNC_CACHE` name→EA)
- `get_function_bytes(name) -> dict | None` (rebuilds cache on miss)
- `_is_thunk(func) -> bool` (now: single leading direct `jmp mem` only)
- `_get_func_relocs_via_operands(func, chunks)` / `_get_func_relocs_via_fixups(func, chunks)`

**ida_server.py**
- `start_server()` / `stop_server()` / `timer_callback()` / `handle_client(conn)` / `load_or_reload_logic()`

## 2. Implementation Plan

### 2.1 Bug fixes (correctness)

| # | Area | Problem | Fix |
|---|------|---------|-----|
| F1 | `match_core._normalize_insn` | Reloc operand without `[`/`ptr` replaced the *whole* op_str → `mov eax, ds:0x...` became `mov <sym>`, losing the destination register. Every `0x...` token was also rewritten. | Replace only `0x...` tokens; if none present, append a `; <sym>` comment instead of clobbering. |
| F2 | `match_core.compare_functions` / `diff_function` | A relocation/fixup byte is treated as a match even when the *symbol target* changed (e.g. `printf`→`puts`). | Compare normalized target names (`__imp_`/`_` stripped); anonymous `sub_/unk_/loc_` labels never fail the match. Mismatched reloc targets are counted as a difference and flagged `[RELOC≠ a != b]` in the diff. |
| F3 | `match_core.compare_functions` | Denominator uses `min(len)` → extra bytes on the longer side never count, so added code reports 100%. | Use `max(len)`; bytes beyond the other side are mismatches. |
| F4 | `ida_logic.get_function_bytes` + client | `FUNC_CACHE` built once; functions added/renamed in IDA after server start return `not found` forever. | Rebuild `FUNC_CACHE` on a cache miss before giving up; client also hits `GET /refresh` at the start of each match run. |
| F5 | `ida_logic` switch tables | Table entries always treated as absolute VAs; relative-entry tables (`SWI_ELBASE`) produce garbage offsets. | When `si.flags & SWI_ELBASE`, resolve as `jtable_ea + entry`. Skip `BADADDR` entries. |

### 2.2 Improvements

| # | Area | Change |
|---|------|--------|
| I1 | `coff_parser` | Record relocation type and derive per-reloc byte width (`reloc_widths`). Prevents 2-byte relocs (DIR16/REL16) from over-masking the next 2 bytes. |
| I2 | `coff_parser` | Skip non-function symbols in code sections (`(type & 0xF0) in (0, 0x20)`) and drop duplicate mangled names (first wins). |
| I3 | `ida_logic._is_thunk` | Only single direct `jmp mem` forwarders count as thunks (fewer false "not found" for real tiny tail-call funcs). Thunks now return a `is_thunk=true` record so the client prints `[THNK]` instead of `[????]`. |
| I4 | `ida_server` | Log `traceback` in `timer_callback` instead of silent `except: pass`; set a defensive `recv` timeout inside `handle_client`. |
| I5 | `match_core.match_summary` | Add YELLOW band (≥80%) between full-match green and `<80%` red. |
| I6 | `watch.py` | Trigger on `(mtime, size)` instead of mtime alone (survives same-second rebuilds). |
| I7 | Byte-compare semantics | **Kept strict by design**: summary % is byte-exact (one inserted byte = strong signal). Resync for *viewing* is already provided by the instruction-level `difflib` alignment in `diff_function`. Documented; not changing. |

### 2.3 Files Touched

- `ida_matcher/matcher/coff_parser.py` — I1, I2
- `ida_matcher/matcher/match_core.py` — F1, F2, F3, F4(client), I5, per-reloc widths
- `ida_matcher/matcher/ida_logic.py` — F4(server), F5, I3
- `ida_matcher/matcher/ida_server.py` — I4
- `ida_matcher/matcher/watch.py` — I6

### 2.4 Verification

- `python -m py_compile` on every changed file (client files run without IDA).
- Sanity-check pure-path functions headlessly:
  - `coff_parser.load_obj` on a synthetic/simplified COFF object (byte-toy fixture in a scratch script under the OS temp dir).
  - `compare_functions` unit-style calls with contrived bytes/relocs to confirm: symbol-change → not 100%; length mismatch → < 100%; equal reloc bytes → 100%.
- Provide a short `ida-match` run for the user to validate against a live IDA session (cannot be automated here).