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
| `ida_matcher/matcher/ida_server.py` | IDA-side | HTTP server w/ hot reload (`load_or_reload_logic`); threaded accept loop + per-connection worker threads (off the 100 ms UI timer) |
| `ida_matcher/matcher/export_baseline.py` | client | Downloads a full `GET /baseline` snapshot from the IDA server to `baseline.json` for offline matching/CI |
| `ida_matcher/matcher/tests/` | — | `pytest` headless suite (client logic, no IDA needed) |

### HTTP contract (current)

| Endpoint | Query | Response |
|---|---|---|
| `GET /func` | `?name=<encoded>` | `200` function record / `404` / `500` |
| `GET /funcs` | `?names=a,b,c` | `200 {"results": {name: record-or-null}}` (batch) |
| `GET /baseline` | — | `200` full baseline snapshot dictionary |
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
| I17 | **objdiff instruction-diff engine (Phase 1)**: `match_core` now ports objdiff-core's `diff/code.rs` + `arch` scan/process logic — Capstone-driven `scan_instructions` (reloc→inline-data, branch-dest resolution with the internal-label rule), Patience alignment over opcodes, `resolve_branches` (branch-target *row* indices), per-arg comparison (`value_loose_eq`, reloc/signed/opaque semantics), and objdiff's penalties (RegDiff=5, ImmDiff=1, Replace=60, Insert/Delete=100). `compare_functions`, `diff_function`, and `match_summary` (`diff_score` per row in `--json`) all run on it. | Done (this session) |
| I18 | **objdiff reloc parity (Phase 2)**: `reloc_eq` now ports objdiff's exact algorithm — flags (class) checked **before** the relaxed shortcut (width never compared), `section_name_eq`, `name_ok` (DataValue / both compiler-generated / `name_addend_ok || address_eq`), and `value_ok` (NameAddress / left symbol not a data symbol / base-side pool `size==0` / `ins_data_literals_eq`). `address_eq` is ported verbatim. COFF Addends are parsed accurately from section bytes (FIX 1) and exact COFF types (e.g. `IMAGE_REL_I386_DIR32`) are matched against legacy markers (FIX 2). | Done (this session) |
| I19 | **objdiff scoring and data/BSS parity (Phase 3 & 4)**: Added data/bss section scoring and symbol diffing (`diff_data_symbol`, `diff_bss_symbol`, `diff_data_section`, `diff_bss_section`). Added `data_accessor` to `_InsnSource` to fetch data cross-symbol for literals (`ins_data_literals_eq`). Modified `match_core` to aggregate data and bss sections accurately. | Done (this session) |
| I20 | **objdiff symbol mapping & classification parity (Phase 5)**: Built the two-pass pairing algorithm (`find_symbol`, `matching_symbols`), flag extraction, size inference, and `find_similar_code_symbols` CLI logic. | Done (this session) |
| I21 | **objdiff config, build & auto-rebuild parity (Phase 6)**: `matcher/config.py` parses `ida_watch.json` (objdiff watch/ignore defaults, per-object `symbol_mappings`, `custom_make`+`custom_args` build via `run_make` parity or a `build_command` template). `ida-watch --config` watches sources, rebuilds affected units, and re-matches only units whose symbol bytes changed (per-symbol hash cache; whole-project build via `build_per_file: false`). Mappings apply in both `match_summary` and `match_focus` (forced pairs win, `selecting_*` blocks auto-pairing); fixed `match_summary` ignoring `mappings_config`. Single-object watch mode unchanged. Post-implementation audit fixes: globset-compatible `**` matching (fnmatch leaked top-level `build/*` files past the default ignore), change-skip cache keyed by obj path instead of `unit.name` (blank-name collision), and case-insensitive path comparison on Windows. | Done (this session) |
| I22 | **Offline Baseline / CI (Phase 7)**: Added `GET /baseline` endpoint in `ida_server.py` that serves a full snapshot of all function/data symbols from memory (`DATA_CACHE` + `FUNC_CACHE`). Rewrote `export_baseline.py` as an HTTP client that saves the snapshot to `baseline.json`. Added `--baseline <file.json>` flag to `ida-match`, which wires into `match_summary` and `match_focus` to bypass network checks and load base records offline. The live Diff engine paths run untouched. Headless CI coverage for offline matching and data `--strict` failures added. | Done (this session) |
| I23 | **Display parity (Phase 8)**: Per-row diff kinds `[OP]`/`[ARG]`/`[REPL]`/`[DEL]`/`[INS]` with **per-argument** mismatch coloring (arg diffs propagated from `diff_instruction` through `diff_code` → `left_args_diffs`/`right_args_diffs`; mismatched operands are red-bg highlighted while equal operands stay plain). Base-side demangling added (`ida_logic.get_demangled_name` via `ida_name.demangle_name`), emitted on `/func`, `/data`, `/baseline` records; demangled names shown in `match_summary` rows (JSON + console) and the `match_focus`/`diff_function` header. `diff_score (score/max)` is shown with `match_percent`. | Done (this session) |
| I24 | **x64 support + threaded server (Phase 9)**: Capstone x64 mode (`CS_MODE_64`, arch selected per side from COFF machine / `inf_is_64bit`), RIP-relative operands, 8-byte ADDR64 reloc-as-inline-data scanning, REL32 branch-dest resolution, `.qword` data mnemonic. Base records now carry `arch`; fixed a latent missing `import ida_ida`. Server moved fully off the 100 ms UI timer: `accept_loop` daemon thread + per-connection worker threads, identical HTTP contract, hot-reload/stop preserved. Headless socket-level test (`test_ida_server.py`) exercises start/accept/stop with mocked IDA modules. | Done (this session) |
| I25 | **Synthetic-object COFF fidelity (Phases F1–F4)**: `ObjectBuilder` configured with `Mangling::Coff` writes COFF symbol names verbatim (no `_` prefix). `synthetic_obj_from_record` (IDA side) and `_compare_functions_objdiff_py` (client side) patch section bytes at relocation sites to MSVC placeholder addends (not runtime image VAs) and compute `writer_addend` (`addend - 4` for REL32, `0` for width-2, else `addend`). Verified 100.00000% match (diff_score `[0, 5600]`) vs real MSVC `process_target.o` via headless golden regression test `test_synthetic_obj_matches_real_msvc_obj`. | Done (this session) |

### Cross-check vs official objdiff-cli (synthetic-object fidelity)

Verified `COnscreenTimerEntry::Process` (167 B, 12 relocs, max_score 5600) against the official
vendored `objdiff-cli`. The scratch units (`target.o`/`current.o`/`code.cpp`/`ctx.cpp`), the
`gta_sa_93.i64` IDA database, `ida_watch.json`, and `match_unit.py` live in the test bed
`E:\repos\gta_sa_test\` (see `OBJDIFF_SYNTH_FIDELITY_PLAN.md` §1.2):

| Comparison | Result |
|---|---|
| `target.o` (decomp.me reference) vs IDA-synth `.o` (fixed) | **100.00000%** — 56 insns, 12 relocs, penalty 0/5600 |
| `current.o` (local recompilation) vs `target.o` | 94.19643% — real codegen drift |
| `current.o` vs IDA-synth `.o` (fixed) | 93.22807% — same real codegen drift |
| `current.o` vs live IDA bytes (own matcher) | 92.00% |

All fidelity fixes (Phases F1–F4) are fully implemented and verified with headless golden regression tests in `test_objdiff_py.py`.

## 4. Verification performed

- `python -m py_compile` clean across all `matcher/` `.py` files (client + engine + tests).
- `python -m pytest ida_matcher/matcher/tests -q` → **158 passed**:
  - coff_parser: function extraction, reloc resolution (9-tuple descriptors with sym metadata), per-reloc widths, missing file.
  - match_core: identical/different/length-mismatch, reloc-symbol logic (same/diff/anon/compat), reloc-vs-concrete (strict 99 / relaxed 100), `reloc_eq` parity (section mismatch, name mismatch, DataValue-name-ignored, compiler-generated, flags-before-relax, width ignored, `address_eq` pool + strict, DataValue pool value_ok, sym-kind `!=data` value_ok, DataValue literal equality via `data_accessor` — equal bytes match, differing bytes ArgMismatch, nonzero offset+addend slice), instruction alignment (leading/mid NOP insertion → 80%), branch-retarget ArgMismatch, switch-range stripping + clamping, instruction normalization (token replace, comment append, jump-relative), name normalization (`__imp_`, `j_`), batch fetch + fallback, JSON summary output + metrics, `--strict` exit codes, data/bss rows scored and aggregated.
  - data: `diff_data_symbol` identical / one-byte change / reloc double-count weighting, `diff_bss_symbol` 100/50, `diff_data_section` gate (data-based replaces generic only when all left relocs match).
  - config (Phase 6): config parse defaults/errors/normalization, `run_make` build-argv parity + `build_command` template, unit resolution (exact + stem), watch-pattern filtering + ignore exclusion + out-of-pattern unit sources, mappings shim, `apply_symbol_mappings` (forced pair wins, section-kind gate, blocks auto-pair), `match_summary` honoring `mappings_config`, watch `_symbol_hashes` rebuild detection.
  - baseline (Phase 7): offline `match_summary`/`match_focus` parity, strict-on-data exit 1, offline right-accessor (no network), `export_baseline` client writes the exact snapshot.
  - display (Phase 8): demangled name in `match_summary` JSON rows.
  - x64 (Phase 9): 32/64-bit mode selection, 8-byte ADDR64 literal scan + identical diff = 100%, REL32 in-range branch resolution, `.qword` mnemonic.
  - ida_server (Phase 9): threaded accept loop + per-connection worker handling over a real loopback socket (IDA modules mocked), start/stop lifecycle.
- Headless CLI smoke: `ida-match synth.obj` (server down) prints the friendly connectivity message.
- `diff_function` display smoke: NOP-insert, reloc-arg, and in-function-branch rows render/score via the engine.
- `ida-watch --config` smoke: config-mode startup prints watch count, runs initial per-unit match, and handles a missing IDA server gracefully (no crash).
- Offline CLI smoke: `ida-match synth.obj --json --baseline synth.json` with no server produces a full JSON summary; `export-baseline` with no server fails gracefully.

### Not verified in this environment (needs a real IDA/session)
- `ida_server.py` routes (`/func`, `/funcs`, `/data`, `/datas`, `/health`, `/refresh`) — compile-checked only.
- `ida_logic.py` extraction paths (operands vs fixups, switch tables, thunks) — compile-checked only; the new `switch_ranges` field and F4/F5 behavior need a live IDA session to verify end-to-end. The `get_demangled_name` (Phase 8) and `"arch"`/64-bit width emission (Phase 9) additions are compile-checked only; server-side threading is covered headless by `test_ida_server.py` over a real loopback socket.
- `ida-watch --config` auto-rebuild loop with a real build system + live IDA (the build/rebuild/skip-unchanged cycle).
- End-to-end match against a real binary.

## 5. Known limitations / current design decisions

1. **Summary % is instruction-based** (I17): `compare_functions` runs the objdiff engine (Patience alignment + per-row penalties). A single leading NOP reads 80%, one reloc-vs-concrete arg mismatch reads 95%; `count` remains the longer byte length for display.
2. **Reloc semantics (I18)**: two-sided relocations compare by flags (class) → section → name/address → value per objdiff's `reloc_eq`. In the default `name_address` mode a reloc vs a concrete immediate is an ArgMismatch (+1, IMM, mirroring objdiff); the `reloc_mode="none"` mode (relaxed) treats left-Value/right-Reloc as equal but flags mismatches still fail (objdiff checks flags before relaxing). Legacy 6-tuple descriptors (no symbol metadata) can't prove `address_eq`, so those fall back to name+addend only.
3. **Thunks are skipped**, not diffed; real tiny tail-call functions are *not* treated as thunks (guarded by `size ≤ 16` + single `jmp mem`).
4. **Switches are informational + range-stripped** — base jump-table targets are printed but not compared against the `.obj` (COFF relocs don’t carry switch metadata easily); the table’s `.rdata` byte range (`switch_ranges`) is stripped from the base before scoring so it doesn’t penalize the match. Server-side range extraction is compile-checked only (needs live IDA to verify).
5. **Orthogonality**: `compare_functions` masks reloc bytes by width; IDA-side fixups assume width 4 (x86-32 abs addresses) — a corner case for 8-bit/16-bit displaced operands could over-mask, but x86-32 absolute operands are 4 bytes.
6. **Match scope** is exact-mangled-name → rename functions in IDA and they’ll report “not found”.
7. **One connection per 100 ms IDA timer tick** — this was the N-round-trip pain for big `.obj` files; `/funcs` batch removes it for summary runs.

## 6. What can be improved next (prioritized)

### High impact / low risk (can be done headless)
1. ~~**Instruction-level summary resync**~~ — **Done** (I17): summary % now uses the objdiff instruction engine (Patience + per-row penalties); strict byte-exact behavior can be re-exposed as `--strict-byte` if ever wanted.
2. ~~**CLI exit code for CI**~~ — **Done** (I15): `--strict` exits non-zero when any recognized function is below 100%; lets build pipelines gate on recompilation drift.
3. ~~**objdiff engine Phase 1**~~ — **Done** (I17): alignment/classification/scoring/branch/arg parity landed in `match_core` (see `OBJDIFF_PARITY_PLAN.md` §6 Phase 1).
4. ~~**objdiff parity (Phases 2-5)**~~ — **Done** (I18/I19): reloc extraction, scoring, data/BSS diffing, and symbol classification/mapping parity achieved.
5. **Digest caching in `ida-watch`**: store the last `.obj` hash and skip unchanged rebuilds more cheaply (already cheap), and only re-request funcs whose bytes changed (server-side last-write tracking).

### Medium impact / medium effort
6. **Batch diff pipeline** — `ida-watch` fetches all funcs once, recompiles on each change, and re-diffs only changed functions, printing a persistent “full-screen” report.
7. **`.obj`-side thunk detection** so local forwarding stubs also print `[THNK]` rather than a misleading low %.
8. **Per-instruction operand-width fixups from IDA** (`op.specval`/`dt_*` size) so 1/2-byte displaced operands don’t over-mask; makes I1 symmetric between both sides.
9. **Server-side function snapshot export** (JSON) for offline/“no IDA open” diffing and CI; `export_baseline.py` can be rewritten to reuse `ida_logic.get_function_bytes`.

### Harder / architectural
10. **Parallel/threaded server** to drop the 100 ms-per-request scheduling; or move matching server-side to avoid shipping raw bytes.
11. **Support x64 (PE32+) COFF** — current parser is I386-only (`IMAGE_FILE_MACHINE_I386` assumed); ARM64EC/CHPE out of scope.
12. **Multi-token reloc window correctness on the client**: needs the same width source (`reloc_widths`) used in `fetch` paths and diff — already plumbed on the obj side; server-side widths are still fixed-4.

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
python -m pytest ida_matcher/matcher/tests -q      # 158 tests, offline
```