# Phase 1 Engine Audit Report

> Audited against objdiff-core `main` branch sources:
> `diff/code.rs`, `diff/mod.rs`, `arch/mod.rs`, `arch/x86.rs`,
> `obj/mod.rs`, `obj/read.rs` — fetched 2026-08-18.

---

## 1. Verdict Table

| Subsystem / Function | File:Lines | Verdict | Justification |
|---|---|---|---|
| **Constants** (`PENALTY_*`, `KIND_*`) | match_core.py:103–121 | **PASS** | Values match objdiff exactly |
| **InsnRef / ParsedInsn / InstructionDiffRow** | match_core.py:140–172 | **PASS** | Faithful mirrors of objdiff structs |
| **`_InsnSource` / `reloc_at`** | match_core.py:175–197 | **PASS** | Matches `relocation_at` semantics |
| **`scan_instructions`** (inline data) | match_core.py:231–292 | **PASS** | Reloc-at-pos → OPCODE_DATA + per-byte .byte tail matches x86.rs |
| **`scan_instructions`** (branch cleanup) | match_core.py:275–291 | **DIVERGENT** | See §3.1 — uses heuristic label regex instead of section+address resolution; documented §5.3 |
| **Patience diff** (`_patience_*`) | match_core.py:301–385 | **PASS** | Correct Patience+LCS fallback; merge runs properly |
| **`insn_align`** (Replace padding) | match_core.py:388–412 | **PASS** | Both sides padded to max; matches `diff_instructions` |
| **`resolve_branches`** | match_core.py:415–443 | **PASS** | addr→row map, branch_idx coloring, branch_from list — faithful |
| **`_value_loose_eq`** | match_core.py:448–453 | **PASS** | Opaque string-eq, numeric value-eq; sign handled by Opaque("-") sibling |
| **`_imm_fit_width`** | match_core.py:456–461 | **PASS** | Correct 1/2/4 thresholds |
| **`_reloc_in_imm` / `_reloc_in_mem_disp`** | match_core.py:464–475 | **PASS** | Span check matches iced-x86 constant_offsets logic for x86-32 |
| **`_mem_args`** | match_core.py:478–504 | **DIVERGENT** | See §3.2 — size-name prefix only when no register operands; minor ordering differences vs iced-x86 formatter. Acceptable. |
| **`process_instruction`** (data path) | match_core.py:507–514 | **PASS** | Matches x86.rs data display |
| **`process_instruction`** (branch path) | match_core.py:518–550 | **PASS** | branch_dest → BranchDest, reloc → Reloc, else imm value; matches arch/mod.rs |
| **`process_instruction`** (imm/mem/reloc) | match_core.py:551–577 | **PASS** | reloc_in_imm, reloc_on_disp, fallback reloc append — matches |
| **`reloc_eq`** (Phase 1 proxy) | match_core.py:605–624 | **DIVERGENT** | Width-as-flags (known Phase-2 gap §5.2); documented, acceptable |
| **`arg_eq`** (Value/Value) | match_core.py:629–631 | **PASS** | Delegates to loose_eq correctly |
| **`arg_eq`** (Value/Reloc) | match_core.py:632–633 | **PASS** | Relaxed iff mode==None; matches objdiff |
| **`arg_eq`** (Reloc/Reloc) | match_core.py:636–637 | **PASS** | Delegates to reloc_eq |
| **`arg_eq`** (Reloc/Value) | match_core.py:638–639 | **BUG** | See §2.1 |
| **`arg_eq`** (BranchDest/BranchDest) | match_core.py:642–643 | **PASS** | Compares `branch_to` row index |
| **`arg_eq`** (BranchDest/Reloc) | match_core.py:644 | **BUG** | See §2.2 |
| **`diff_instruction`** (decision tree) | match_core.py:648–690 | **PASS** | Exact ordering: None/None, left-None, right-None, opcode≠, fast-path, arg-count, mnemonic, per-arg, code-length |
| **`diff_code`** (scoring) | match_core.py:693–726 | **PASS** | `min(sum, left_count*100)`, `max_score=left_count*100`, correct formula |
| **`compare_functions`** (argument order) | match_core.py:765–804 | **PASS** | left=obj, right=base; `max_score` from left (obj) count; correct |
| **`diff_function`** (display swap) | match_core.py:976–1044 | **PASS** | Swaps left(obj)↔right(base) for display; scores from same engine call |
| **`match_summary`** (consumer) | match_core.py:1054–1146 | **PASS** | Correctly threads reloc_mode (default), diff_score in JSON |
| **Immediate sign rendering** | match_core.py:542–563 | **PASS** | `-1` via `("opaque","-"),("signed",1)`; `0xffffffff` also wraps to `("-",1)` via `_imm_fit_width`. Cross-compare works. |
| **`--reloc-mode` CLI plumbing** | run_match.py / match_core.py | **BUG** | See §2.3 |

---

## 2. Bugs (ordered by severity)

### 2.1 **`arg_eq`: Reloc/Value allows relaxed match (WRONG)**

**File**: [`match_core.py`](file:///D:/repos/ida_live_matching_diff/ida_matcher/matcher/match_core.py#L635-L640)  
**Lines**: 638–639

**Objdiff behavior** (code.rs L372–375): The `InstructionArg::Reloc` arm only matches
`Reloc/Reloc` (delegating to `reloc_eq`). There is NO `Reloc/Value` case — it falls
through to `false`. The relaxed `Value/Reloc` case is one-directional: only when the
*left* arg is a Value and the *right* arg is a Reloc.

**Current behavior**: `arg_eq` returns `True` when `a[0]=="reloc"` and `b[0] in
("signed","unsigned")` and `reloc_mode==RELOC_MODE_NONE`. This is wrong — a left-side
relocation vs a right-side concrete value should never match, even in relaxed mode.

**Impact**: In relaxed mode, a function with a reloc-bearing instruction on the left
(obj) and a concrete immediate on the right (base) would score as equal when it
shouldn't. In default `name_address` mode this has no effect (the relaxed check fails).

**Concrete failing input**:
```python
# left: mov eax, <reloc>  right: mov eax, 0x12345678
# With reloc_mode=RELOC_MODE_NONE:
# objdiff: arg_eq(Reloc, Value) → false → ArgMismatch +5
# current: arg_eq(Reloc, Value) → true → None (no penalty)
```

**Fix**: Remove lines 638–639. The `Reloc` arm should only match `Reloc/Reloc`:
```python
if a[0] == "reloc":
    if b[0] == "reloc":
        return reloc_eq(ctx, left_ins, right_ins)
    return False
```

---

### 2.2 **`arg_eq`: BranchDest/Reloc missing relaxed case**

**File**: [`match_core.py`](file:///D:/repos/ida_live_matching_diff/ida_matcher/matcher/match_core.py#L641-L645)  
**Lines**: 644

**Objdiff behavior** (code.rs L376–386): `BranchDest/Reloc` matches iff
`diff_config.function_reloc_diffs == FunctionRelocDiffs::None` (relaxed mode).

**Current behavior**: `arg_eq` returns `False` for `BranchDest/Reloc` unconditionally
(line 644 just returns `False` for any non-branch right arg).

**Impact**: In relaxed mode (`RELOC_MODE_NONE`), a branch instruction where one side
has a resolved in-function branch and the other has an unresolved relocation would be
flagged as `ArgMismatch +5` when objdiff would treat them as equal.

**Fix**: Add the relaxed case:
```python
if a[0] == "branch":
    if b[0] == "branch":
        return left_row.branch_to == right_row.branch_to
    if b[0] == "reloc":
        return ctx.reloc_mode == RELOC_MODE_NONE
    return False
```

---

### 2.3 **`--reloc-mode` CLI flag not wired up**

**File**: [`run_match.py`](file:///D:/repos/ida_live_matching_diff/ida_matcher/matcher/run_match.py),
[`match_core.py`](file:///D:/repos/ida_live_matching_diff/ida_matcher/matcher/match_core.py) (main)

**Objdiff behavior**: `FunctionRelocDiffs` is a user-configurable setting with four modes.

**Current behavior**: The `RELOC_MODE_*` constants are defined and `compare_functions`
accepts `reloc_mode=`, but neither `run_match.py` nor `match_core.py main()` expose a
`--reloc-mode` CLI argument. The mode is always the default `name_address`.

**Impact**: Users cannot select `none`/`data_value`/`all` modes from the command line,
which the plan §6 Phase 2 lists and §10.3 settles as a required flag.

**Fix**: Add `--reloc-mode` to `argparse` in both `run_match.py` and
`match_core.py:main()`, threading it to `match_summary`/`match_focus`/
`compare_functions`/`diff_function`.

---

## 3. Acceptable Divergences (documented)

### 3.1 Branch resolution uses label-name heuristic (plan §5.3)

`scan_instructions` resolves reloc'd branches to in-function `BranchDest` by checking
if the relocation target name matches `_INTERNAL_LABEL_RE` (loc_, LAB_, jpt_, $L,
switchD_, etc.). Objdiff instead checks if the relocation's target symbol is in the same
section and its address (+ addend) falls within the function range.

This is documented as an acceptable Phase-1 approximation. It works correctly for IDA
names (which follow the regex) and standard MSVC/GCC labels. Phase 2's richer reloc
data model could improve this.

### 3.2 Memory-operand argument ordering (Capstone vs iced-x86)

`_mem_args` uses Capstone's operand structure which differs subtly from iced-x86's
formatter output:
- Size-name (`dword ptr`) is emitted only when no register operand exists (mimicking
  iced-x86's behavior for `mov dword ptr [addr], imm`), but the exact rules differ.
- Bracket characters (`[`, `]`) are not emitted as separate args (iced-x86 emits them
  as `basic` parts); our code uses `+`/`-` operators between components.

Since both sides (obj and base) are processed by the *same* code path, these
differences cancel out in the diff comparison. The only case where this matters is
cross-tool comparison of rendered output (cosmetic only).

### 3.3 Opcode token space (Capstone `insn.id` vs iced-x86 `Mnemonic as u16`)

Plan §5.1: Capstone x86 instruction IDs may map multiple mnemonics to one ID or
vice versa compared to iced-x86's `Mnemonic` enum. Since both sides use the same
decoder, alignment decisions are consistent. Tiny class-merge differences vs objdiff
are possible but have no practical impact on scoring.

### 3.4 `reloc_eq` uses width-as-flags proxy (plan §5.2)

The Phase-1 `reloc_eq` approximates `RelocationFlags` equality by comparing relocation
widths. This means `DIR32` (absolute, 4 bytes) and `REL32` (relative, 4 bytes) would
compare as equal when they shouldn't. This is a known Phase-2 gap, not a Phase-1 bug.

### 3.5 Switch table handling (plan §5.4)

Objdiff compares object files where tables are section data on both sides. Our tool
compares against a live binary where MSVC jump tables live in `.rdata` outside the
function chunk. The `switch_ranges` strip-and-remap is an intentional divergence.

### 3.6 Thunks skipped (plan §5.5, §10.2)

Current tool skips/scores thunks as `[THNK]`; objdiff diffs them normally. Decision
settled in plan §10.2: keep skip behavior.

---

## 4. Not Verifiable Headless

| Item | Reason |
|---|---|
| Patience diff produces identical alignment as `similar::capture_diff_slices(Patience)` on adversarial real-world inputs | Would need to run objdiff on the same `.obj` pair and compare row-by-row alignment output |
| `scan_instructions` inline-data rule matches on real COFF with embedded jump tables | Needs a real `.obj` with inline reloc data |
| IDA-side fixup extraction correctness (`_get_func_relocs_via_operands/fixups`) | Needs a live IDA session |
| End-to-end score matches objdiff on the same function pair | Needs both tools running on the same binary |
| `_looks_internal_label` regex covers all possible IDA auto-names | IDA's name generation may produce patterns not in the regex |

---

## 5. Plan §4.4 Transcription Error Flagged

**`section_name_eq` does NOT use `$`-prefix matching.**

Plan §4.4 states: *"`section_name_eq`: exact string, but section matching uses the part
before the first `$`"*. Cross-checking against objdiff source:

- `section_name_eq` (diff/mod.rs L975–987) compares `left_section.name == right_section.name`
  — **full** section name, no `$` stripping.
- `get_section_base_name` (obj/read.rs L931–940) does strip at `$`/`.`, but it's used
  for section **combination** and `matching_sections`, NOT by `section_name_eq` in
  `reloc_eq`.

The plan's description conflates these two. For Phase 2 implementation,
`section_name_eq` inside `reloc_eq` should compare **full** section names.

---

## 6. Summary

**Bugs to fix (Part B Step 1):**
1. `arg_eq` Reloc/Value relaxed match — remove (severity: moderate, wrong in relaxed mode)
2. `arg_eq` BranchDest/Reloc missing relaxed case — add (severity: moderate, wrong in relaxed mode)
3. `--reloc-mode` CLI flag not wired — add argparse plumbing (severity: low, no runtime impact until user needs it)

**Phase 1 engine is otherwise faithful to objdiff.** The decision tree, scoring formula,
Patience diff, branch resolution, inline-data scanning, immediate rendering, and
argument processing all match the objdiff source. The documented divergences (§5.1–5.5
in the plan) are all real and justified.
