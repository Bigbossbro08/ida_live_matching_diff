# IDA Live Matching Diff — Current State

> Snapshot of the matcher as of this session, including the fixes/improvements
> that have been implemented and verified, plus a prioritized list of what can
> be improved next.

## 1. What this tool is

Compares `*.obj` files produced by MSVC against the **live IDA Pro database**:

1. The IDA plugin (`ida_server.py`) runs an HTTP server on `127.0.0.1:28000`
   inside IDA and offers byte/fixup/switch data for every named function.
2. The pure-Python client (`ida-match` / `ida-watch`) parses a `.obj` directly
   (no `dumpbin`), looks each mangled name up on the server, and reports a
   byte-level match %, with a Capstone-based instruction diff for a single
   function.

## 2. Architecture

```
           local machine                                IDA machine
  ┌──────────────────────────┐              ┌───────────────────────────┐
  │ ida-match / ida-watch     │   HTTP       │ ida_server.py             │
  │  run_match.py / watch.py  │ ───────────► │  GET /func?name=...       │
  │  match_core.py            │ 127.0.0.1    │  GET /funcs?names=a,b,c   │
  │  coff_parser.py   (.obj)  │  :28000      │  GET /health | /refresh   │
  └──────────────────────────┘              │  ida_logic.py  (hot reload)│
                                             └───────────────────────────┘
```

### Module map

| File | Side | Responsibility |
|---|---|---|
| `ida_matcher/matcher/coff_parser.py` | client | Pure-struct COFF `.obj` parser → `{mangled: {bytes, relocs, reloc_widths, offset}}` |
| `ida_matcher/matcher/match_core.py` | client | Compare/diff engine + CLI entry; fetch via HTTP; ANSI/JSON output |
| `ida_matcher/matcher/run_match.py` | client | `ida-match` one-shot wrapper |
| `ida_matcher/matcher/watch.py` | client | `ida-watch` change-triggered loop |
| `ida_matcher/matcher/match.py` | client | Legacy shim → `match_core.main` |
| `ida_matcher/matcher/ida_logic.py` | IDA-side | Extract bytes, fixups, switch/jump tables, thunk flags from live IDB |
| `ida_matcher/matcher/ida_server.py` | IDA-side | HTTP server w/ hot reload (`load_or_reload_logic`) |
| `ida_matcher/matcher/export_baseline.py` | IDA-side | Legacy offline JSON export (not used by live flow) |
| `ida_matcher/matcher/tests/` | — | `pytest` headless suite (client logic, no IDA needed) |

### HTTP contract (current)

| Endpoint | Query | Response |
|---|---|---|
| `GET /func` | `?name=<encoded>` | `200` function record / `404` / `500` |
| `GET /funcs` | `?names=a,b,c` | `200 {"results": {name: record-or-null}}` (batch) |
| `GET /health` | — | `200 {"status":"ok"}` |
| `GET /refresh` | — | `200 {"status":"refreshed"}` (rebuilds name→EA cache) |

Function record: `{ea, size, bytes(hex), is_thunk, switches{off:[offsets]}, fixups{rel_off:symbol}}`.

`.obj` record: `{bytes(bytearray), offset, relocs{rel_off:symbol}, reloc_widths{rel_off:2|4}}`.

## 3. What has been implemented/verified so far

### Bug fixes (correctness)
| # | Area | Status |
|---|---|---|
| F1 | `_normalize_insn` no longer clobbers the whole operand — only `0x…` tokens are replaced; registers/`ds:` preserved; `; <sym>` appended when no hex token. | Done |
| F2 | Reloc/fixup bytes now compare **target symbols** too; `printf→puts` is flagged `[RELOC≠ …!=…]`, anon DB labels (`sub_/unk_/loc_`, bare hex, `j_`-hex tails) never fail. | Done |
| F3 | `compare_functions` denominator is `max(len)`, so added/removed bytes lower the score instead of being hidden. | Done |
| F4 | `FUNC_CACHE` rebuilt on a name miss; client also calls `GET /refresh` before each run. | Done |
| F5 | Jump-table entries with `SWI_ELBASE` resolve as `jtable_ea + entry`; `BADADDR` skipped. | Done |

### Improvements
| # | Area | Status |
|---|---|---|
| I1 | Per-reloc widths (`reloc_widths`) so 2-byte DIR16/REL16 relocs don’t over-mask 4 bytes. | Done |
| I2 | COFF symbol filter (only function-like code-symbols, ext/static, non-`__imp_`); duplicate mangled names → first wins. | Done |
| I3 | Thunks = single leading direct `jmp mem`; returned as an `is_thunk=1` record → client prints `[THNK]`, not `[????]`. | Done |
| I4 | Server logs tracebacks instead of silent `except: pass`; defensive `recv` timeout. | Done |
| I5 | Yellow band (≥80%) in summary. | Done |
| I6 | Watch triggers on `(mtime, size)` — survives same-second rebuilds. | Done |
| I7 | Byte-compare kept strict (one inserted byte is a real signal); resync lives in the insn diff. **Decision, kept.** | Done |
| I8 | `j_`/`__imp_`/`_` prefix normalization + bare-hex anon detection in `_normalize_target_name`/`_looks_anonymous`. | Done (this session) |
| I9 | Client robustness: friendly “IDA server not reachable” message (was a red error per function), `server_alive()` health probe, batch fetch `/funcs` with per-name fallback (old servers keep working). | Done (this session) |
| I10 | `--json` machine-readable summary; `--no-color` / `NO_COLOR` support. | Done (this session) |
| I11 | Watch loop no longer dies when a run fails (`SystemExit` swallowed → keeps watching). | Done (this session) |
| I12 | `load_obj` returns `{}` for a missing/unreadable file instead of raising. | Done (this session) |
| I13 | Automated **pytest** suite added: `tests/test_coff_parser.py` + `tests/test_match_core.py` (28 tests, headless). | Done (this session) |
| I14 | **LCS-based summary resync**: `compare_functions` now aligns via `difflib.SequenceMatcher` before scoring, so an inserted NOP/`int3` drops the score slightly (~95%) instead of decimating it to 0% via offset shift. Reloc semantics (`_reloc_symbols_match`) reapplied per aligned pair. | Done (this session) |
| I15 | **`--strict` CI gate**: exit code 1 when any recognized function is below 100%; summary tracks `match_100`/`match_below` and the JSON output gains a `summary` object. | Done (this session) |
| I16 | **Switch tables excluded from scoring**: `ida_logic` reports each jump table's byte range (`switch_ranges`); the client strips those `.rdata` bytes (and remaps base fixups) so base-only table bytes no longer penalize the match. | Done (this session) |

## 4. Verification performed

- `python -m py_compile` clean across all 9 `.py` files.
- `python -m pytest ida_matcher/matcher/tests -q` → **34 passed**:
  - coff_parser: function extraction, reloc resolution, per-reloc widths, missing file.
  - match_core: identical/different/length-mismatch, reloc-symbol logic (same/diff/anon/compat), LCS resync (leading/mid insertion), switch-range stripping + clamping, instruction normalization (token replace, comment append, jump-relative), name normalization (`__imp_`, `j_`), batch fetch + fallback, JSON summary output + metrics, `--strict` exit codes.
- Headless CLI smoke: `ida-match synth.obj` (server down) prints the friendly connectivity message.

### Not verified in this environment (needs a real IDA/session)
- `ida_server.py` routes (`/func`, `/funcs`, `/health`, `/refresh`) — compile-checked only.
- `ida_logic.py` extraction paths (operands vs fixups, switch tables, thunks) — compile-checked only; the new `switch_ranges` field and F4/F5 behavior need a live IDA session to verify end-to-end.
- End-to-end match against a real binary.

## 5. Known limitations / current design decisions

1. **Summary % is LCS-aligned** (I14): inserted/deleted bytes resync and only drop the score by their own length, so a single leading NOP reads ~95%+, not 0%. True byte-level drift is still a strong signal.
2. **One-side-reloc bytes always `match`** when the other side is concrete (reloc vs. fixed value is treated as “not comparable”, not a diff). Two-sided relocation bytes compare by symbol identity.
3. **Thunks are skipped**, not diffed; real tiny tail-call functions are *not* treated as thunks (guarded by `size ≤ 16` + single `jmp mem`).
4. **Switches are informational + range-stripped** — base jump-table targets are printed but not compared against the `.obj` (COFF relocs don’t carry switch metadata easily); the table’s `.rdata` byte range (`switch_ranges`) is stripped from the base before scoring so it doesn’t penalize the match. Server-side range extraction is compile-checked only (needs live IDA to verify).
5. **Orthogonality**: `compare_functions` masks reloc bytes by width; IDA-side fixups assume width 4 (x86-32 abs addresses) — a corner case for 8-bit/16-bit displaced operands could over-mask, but x86-32 absolute operands are 4 bytes.
6. **Match scope** is exact-mangled-name → rename functions in IDA and they’ll report “not found”.
7. **One connection per 100 ms IDA timer tick** — this was the N-round-trip pain for big `.obj` files; `/funcs` batch removes it for summary runs.

## 6. What can be improved next (prioritized)

### High impact / low risk (can be done headless)
1. ~~**Instruction-level summary resync**~~ — **Done** (I14): summary % is now LCS-aligned via `difflib` while keeping the “insert byte” signal; strict byte-exact behavior can be re-exposed as `--strict-byte` if ever wanted.
2. ~~**CLI exit code for CI**~~ — **Done** (I15): `--strict` exits non-zero when any recognized function is below 100%; lets build pipelines gate on recompilation drift.
3. **Digest caching in `ida-watch`**: store the last `.obj` hash and skip unchanged rebuilds more cheaply (already cheap), and only re-request funcs whose bytes changed (server-side last-write tracking).
4. **More unit tests**: jump-table/tail-call fixtures for `diff_function` using Capstone (installed) — cover `[RELOC≠]` print path and switch block.

### Medium impact / medium effort
5. **Batch diff pipeline** — `ida-watch` fetches all funcs once, recompiles on each change, and re-diffs only changed functions, printing a persistent “full-screen” report.
6. **`.obj`-side thunk detection** so local forwarding stubs also print `[THNK]` rather than a misleading low %.
7. **Per-instruction operand-width fixups from IDA** (`op.specval`/`dt_*` size) so 1/2-byte displaced operands don’t over-mask; makes I1 symmetric between both sides.
8. **Server-side function snapshot export** (JSON) for offline/“no IDA open” diffing and CI; `export_baseline.py` can be rewritten to reuse `ida_logic.get_function_bytes`.

### Harder / architectural
9. **Parallel/threaded server** to drop the 100 ms-per-request scheduling; or move matching server-side to avoid shipping raw bytes.
10. **Support x64 (PE32+) COFF** — current parser is I386-only (`IMAGE_FILE_MACHINE_I386` assumed); ARM64EC/CHPE out of scope.
11. **Multi-token reloc window correctness on the client**: needs the same width source (`reloc_widths`) used in `fetch` paths and diff — already plumbed on the obj side; server-side widths are still fixed-4.

## 7. How to run (quick reference)

```bash
cd <repo>
pip install -e .                    # installs ida-match / ida-watch
# In IDA console: exec ida_matcher/matcher/ida_server.py   (port 28000)

ida-match path/to/file.obj                          # summary
ida-match path/to/file.obj --strict                 # exit 1 if any match < 100% (CI)
ida-match path/to/file.obj --func "?foo@@YAXXZ"      # side-by-side diff
ida-match path/to/file.obj --json | python -m json.tool
ida-watch path/to/file.obj [--func ?foo@@YAXXZ]     # rerun on rebuild
```

### Test suite

```bash
python -m pytest ida_matcher/matcher/tests -q      # 34 tests, offline
```