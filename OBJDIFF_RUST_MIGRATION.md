# Draft: objdiff-core Rust Migration — What Can Be Done

> Source: `~/.gemini/antigravity/brain/64e335af-.../implementation_plan.md`
> Status: **plan — all open questions answered, decisions locked, no code written yet**

## 1. Context

The repo currently ships a hand-written Python port of the objdiff engine
(`ida_matcher/matcher/engine/*` + `coff_parser.py`/`coff_pure.py`/`coff_lief.py`,
~1,500 lines). It works and is fully tested (pytest suite), but it is a fork with
permanent upstream drift: every objdiff fix has to be re-ported by hand, and only
x86/x64 opcode parsing is implemented (via Capstone).

The external plan proposes replacing the Python port with the official
`objdiff-core` Rust crate, compiled to a native Python extension with PyO3, and
feeding it a **synthetic `.obj`** generated at runtime from the live IDA database
via the `object` crate's writer. This draft evaluates that proposal against the
current code and lists concrete, incremental work items.

## 2. What the plan gets right (verified against this repo)

| Plan claim | Reality in this repo |
|---|---|
| Python port is a maintainability liability | Confirmed — `engine/diff_code.py`, `engine/align.py`, `engine/arch_x86.py`, `engine/data.py` re-implement objdiff's align/diff/reloc logic in Python. |
| `objdiff-core` is arch-independent | True — Rust side already supports x86, x64, PPC, MIPS, ARM; Python port only does x86/x64. |
| IDA already produces bytes+fixups | Confirmed — `ida_logic.get_function_bytes()` already emits `bytes`, `fixups`, `fixup_widths`, `fixup_classes`, `fixup_addends`, `switch_ranges`, `is_thunk`, etc. This maps 1:1 to what `ObjectBuilder` needs. |
| JSON/dict bridge is the right seam | Confirmed — `match_summary()` already builds a dict and the client/server already speak JSON. |
| `object` crate can synthesize a COFF `.obj` | **Validated.** Cross-checked the synthetic object against a real MSVC `target.o` with the official `objdiff-cli`: **100.00000%** after two fidelity fixes (verbatim symbol names; addend-correct reloc sites). Full write-up + phased fix plan: `OBJDIFF_SYNTH_FIDELITY_PLAN.md`. |

## 3. Recommended phased plan

### Phase Status

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 0 | PyO3 bridge spike (`vendor/objdiff-py`) | ✅ Done | Gate: fixtures round-trip through `objdiff-core` |
| 1 | IDA-side `build_synthetic_obj()` + `/synthetic_obj` | ✅ Done | COFF out, `object::read` clean |
| 2 | Client engine swap to `diff_objects()` | ✅ Done | `OBJDIFF_PY` flag; Python engine kept as legacy |
| 3 | Install/build story (maturin, wheels) | ✅ Done | Rust toolchain documented, prebuilt wheels |
| F1–F4 | COFF fidelity of the synthetic object | ⬜ Planned | See `OBJDIFF_SYNTH_FIDELITY_PLAN.md` — verbatim symbol names (F1), addend-correct reloc sites IDA-side (F2) + client-side (F3), golden regression vs real `target.o` (F4) |

> Rule for agents executing a phase: after verification passes, flip this table entry to
> `✅ Done` **and** update `API_MAP.md` with every API added/changed/removed by the phase.

### Phase 0 — Spike the PyO3 bridge (before changing anything)
Build a throwaway `vendor/objdiff-py` crate exposing:
- `ObjectBuilder` (wrap `object::write::Object`) — add section / write bytes / add symbol / add relocation / `.finish() -> bytes`
- `diff_objects(left_obj: bytes, right_obj: bytes) -> dict` — feeds `objdiff_core::diff::diff_objs`

Validate against **the existing pytest fixtures**:
- `tests/conftest.py` already builds synthetic `.obj` byte arrays — reuse them to prove
  `ObjectBuilder` produces COFF output that `objdiff-core` reads back losslessly.
- Gate: `match_percent`/`diff_score` from Rust == Python port on every existing test case.

#### Execution Spec: Phase 0

**Exact Module/File Paths & Signatures:**
* `vendor/objdiff-py/Cargo.toml`: Add dependencies `pyo3`, `object` (with the `write` feature — the `read_core/elf/coff` features on objdiff-core's `object` dep are read-only), `objdiff-core` via `path = "../objdiff/objdiff-core"`.
* `vendor/objdiff-py/src/lib.rs`: Define the PyO3 bridge crate.

> Note: `vendor/objdiff` is a git submodule, NOT part of the root crate. Do **not** add
> `vendor/objdiff-py` to that submodule's workspace; keep it a standalone crate.

**PyO3 API Surface:**
```rust
#[pyclass(module = "objdiff_py", unsendable)]
pub struct ObjectBuilder { /* wraps object::write::Object */ }

#[pymethods]
impl ObjectBuilder {
    #[new]
    pub fn new(arch: &str) -> PyResult<Self>;
    pub fn add_section(&mut self, name: &str, segment: &str, kind: u8) -> PyResult<u64>;
    pub fn write_bytes(&mut self, section_id: u64, offset: u64, data: &[u8]) -> PyResult<()>;
    pub fn add_symbol(&mut self, section_id: u64, name: &str, value: u64, size: u64, kind: u8, flags: u8) -> PyResult<u64>;
    pub fn add_relocation(&mut self, section_id: u64, offset: u64, symbol_id: u64, kind: u8, size: u8, addend: i64) -> PyResult<()>;
    pub fn finish(&mut self, py: Python) -> PyResult<PyObject>; // returns bytes via PyBytes
}

#[pyfunction]
pub fn diff_objects(py: Python, left_obj: &[u8], right_obj: &[u8]) -> PyResult<PyObject>; // returns python dict
```

> The upstream `diff_objs` takes already-parsed `Option<&Object>` (not raw bytes). The bridge
> must first call `obj::read::parse(data, &DiffObjConfig::default(), DiffSide::Target/Base)`
> (verified at `vendor/objdiff/objdiff-core/src/obj/read.rs:1119`) then feed the two
> `Object`s to `diff_objs` with `DiffObjConfig::default()` and `MappingConfig::default()`
> (both derive `Default`). `diff_objects` is a convenience wrapper over that flow.

**Byte/JSON Schema:**
The Python dict returned by `diff_objects` models the exact `DiffObjsResult` struct from `objdiff_core::diff`:
```rust
// vendor/objdiff/objdiff-core/src/diff/mod.rs
pub struct DiffObjsResult {
    pub left: Option<ObjectDiff>,
    pub right: Option<ObjectDiff>,
    pub prev: Option<ObjectDiff>,
}
pub struct ObjectDiff {
    pub symbols: Vec<SymbolDiff>,
    pub sections: Vec<SectionDiff>,
    pub mapping_symbols: Vec<MappingSymbolDiff>,
}
pub struct SymbolDiff {
    pub target_symbol: Option<usize>,
    pub match_percent: Option<f32>,
    pub diff_score: Option<(u64, u64)>, // output as a [u64, u64] list
    pub instruction_rows: Vec<InstructionDiffRow>,
    pub data_rows: Vec<DataDiffRow>,
    pub order: Option<Ordering>,
}
```
The python dict schema must be:
```json
{
  "left": {
    "symbols": [{"target_symbol": 0, "match_percent": 100.0, "diff_score": [123, 123]}],
    "sections": []
  },
  "right": { "symbols": [], "sections": [] }
}
```

**Test Cases to Add (`ida_matcher/matcher/tests/test_objdiff_py.py`):**
* `test_object_builder_roundtrip`: Replicate `build_synthetic_obj` from `tests/conftest.py` using `ObjectBuilder`. Assert the generated bytes equal the raw bytes or at least parse successfully back into an `objdiff_core::obj::Object`.
* `test_diff_objects_match`: Pass the `build_synthetic_obj` byte fixture into both `left_obj` and `right_obj` of `diff_objects`. Assert `match_percent` is 100.0.
* `test_diff_objects_thunk`: Diff `build_synthetic_thunk_obj` vs `build_synthetic_obj`, assert the `diff_score` matches the python baseline logic.

**Definition of Done:**
- [x] `vendor/objdiff-py` crate exists and compiles with `maturin develop` / `pip install .`.
- [x] `ObjectBuilder` class allows defining sections, symbols, relocs, and writing `.obj` bytes.
- [x] `diff_objects` function exposed, accepting raw bytes and outputting a `dict` mirroring `DiffObjsResult`.
- [x] `test_objdiff_py.py` added containing the above tests.
- [x] `python -m pytest ida_matcher/matcher/tests -q` passes without errors.

### Phase 1 — Convert IDA-side extraction to ObjectBuilder
- `ida_logic.py`: add a `build_synthetic_obj(func_name) -> bytes` path using the new
  `ObjectBuilder`; translate existing `fixups`/`fixup_classes`/`fixup_addends` into
  `add_relocation()` calls. The goal is a **real COFF `.obj` that `objdiff-core` parses
  with no issues** — standard `object::write` semantics, MSVC-style relocs
  (DIR32/DIR16/REL32, section-relative), same as what `coff_parser` reads from disk.
- Keep the current JSON dict path for comparison during transition.
- New server endpoint: `GET /synthetic_obj?name=...` returning raw `.obj` bytes
  (Content-Type: application/octet-stream) — or keep JSON with base64 to reuse the existing client.

### Phase 2 — Swap the client diff engine
- `match_core.compare_functions()` and `match_focus()` call `diff_objects()`
  instead of `engine/diff_code.diff_code()`.
- Keep `engine/display.py` (hexdump + inline highlight formatting) — console-only
  rendering stays as-is; no GUI in this phase.
- **No deletions.** The entire Python engine (`engine/diff_code.py`, `engine/align.py`,
  `engine/arch_x86.py`, `engine/data.py`, `engine/types.py`) is retained as an unused
  legacy module set once the Rust path is live — available for rollback and reference.

### Phase 3 — Install/build story
- Build backend: `maturin` + `pyproject.toml` entry
  (`[build-system] requires = ["maturin"]`), wheels per-platform.
- Rust toolchain (cargo/rustc) is **an accepted build requirement** — document
  `rustup` + `maturin build`, but ship prebuilt wheels so end users never touch cargo.

## 4. Decisions (questions answered)

All five open questions are now resolved; the plan above already reflects them.

1. **Synthetic COFF vs. raw representation — ✅ answered.**
   Pass a real COFF `.obj` built with `object::write` such that `objdiff-core`
   (which parses via `object::read`) consumes it from the IDA database with **no
   issues at all** — standard `.obj` semantics, MSVC-compatible relocs. This is the
   recommended option from the original plan; Round-trip is validated in Phase 0.
2. **Which side is "left"? — ✅ answered.**
   Default keeps the current behavior: left = compiled `.obj` (local), right = IDA
   database (base). An optional config setting flips to objdiff-style right-to-left
   diffing for parity with upstream objdiff output.
3. **Rust build step acceptable? — ✅ answered.**
   Yes. Add cargo/rustc to the build; ship prebuilt wheels per platform so only the
   IDA plugin builder needs the toolchain.
4. **Data & BSS symbols — ✅ answered.**
   Keep the Python `engine/data.py` implementation. Do **not** delete it; retain it
   as an unused legacy feature that can be invoked if needed (data/bss are not
   covered by `objdiff-core`'s code-focused diff).
5. **GUI in IDA? — ✅ answered.**
   No GUI needed. Keep the console print rendering exactly as it is today.

## 5. Risks / mitigations

| Risk | Mitigation |
|---|---|
| `object::write` doesn't match MSVC `.obj` exactly | Phase 0 gate: confirm `objdiff-core` (via `object::read`) consumes the synthetic `.obj` with no issues before wiring the client. |
| PyO3 packaging friction (Python 3.9–3.13, abi3) | Ship prebuilt wheels; `pyo3` abi3 feature for wider compat. |
| Behavior drift vs. current tested output | Keep the existing pytest suite (158 tests) as the regression harness; Rust output must match `match_percent`/`diff_score` exactly. |
| MSRV mismatch: objdiff workspace declares `rust-version = "1.88"` | Update the toolchain to ≥ 1.88 (`rustup update stable`) before Phase 0; installed stable is 1.86. |
| `maturin` missing on build machine | `pip install maturin` is a prerequisite for `maturin develop` (Phase 0 DoD). |
| Loss of Python-only conveniences (data/bss, mappings config) | Engine is kept as legacy, not deleted — `engine/data.py` + `config.py` remain available for data/bss and mappings. |
| Two code paths during transition | Feature flag (`OBJDIFF_PY=1`) to switch `compare_functions` between Rust and Python. |

## 6. Suggested work items (smallest first)

- [x] Vendor crate skeleton + `diff_objects` + `ObjectBuilder` (no changes to existing code).
- [x] Unit test: `ObjectBuilder` synthetic `.obj` is consumed by `objdiff-core` with no issues.
- [x] Unit test: `diff_objects` matches Python `diff_code` on all existing fixtures.
- [x] `ida_logic.build_synthetic_obj()` + `/synthetic_obj` endpoint (COFF out, `object::read` clean).
- [x] `match_core` behind `OBJDIFF_PY` flag; CI matrix runs both engines.
- [x] Optional config: right-to-left (objdiff-style) diff direction, default stays left-to-right.
- [x] Gate passes → default engine switches to Rust; Python engine retained as unused legacy.
- [x] `maturin` packaging + prebuilt wheels; document Rust toolchain build requirement.
- [x] F1: `ObjectBuilder` writes COFF symbol names verbatim (`set_mangling(Mangling::Coff)`), wheel rebuilt.
- [x] F2: `synthetic_obj_from_record` patches reloc sites with addends (`addend-4` for REL32, width-2 → 0).
- [x] F3: `_compare_functions_objdiff_py` patches base-side reloc sites; writer rule on both sides.
- [x] F4: golden regression vs real `target.o` (100.00000% / [0, 5600]) + doc sync.

## 7. Recommendation

Feasible and architecturally better long-term. Do it in the phased order above with the
Phase 0 fixture gate as the hard checkpoint — that turns "rewrite the engine" from a risky
big-bang into a measured swap with a regression harness. Decisions are locked: real COFF
via `object::write` (read back cleanly by `objdiff-core`), current left/right default with
an optional objdiff-style flip, Rust build step accepted, no deletions (Python engine stays
as unused legacy), console-only rendering for now.