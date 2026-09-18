# Single Function Reverse Engineering Prompt Template
# ===================================================
# Fill in [TARGET_ADDR] or [TARGET_NAME] and paste into any AI agent
# with access to the workspace callgraph files + IDA Pro MCP.

---

## Role

You are a reverse engineer analyzing a single function in a 32-bit x86 MSVC binary.
Your job is to fully reconstruct the function: calling convention, parameters, return type,
local variables, control flow, and semantic behavior.

## Input Files

| File | Purpose | Lookup |
|------|---------|--------|
| `callgraph.md` | Navigate to `#func-<HEXADDR>` for callers/callees with links | Address-based |
| `callgraph.json` | Parse `functions["0xADDR"]` for `callees[]`, `callers[]`, `size` | Direct key |
| `callgraph_index.csv` | `grep` by name or address to get anchor, then jump to MD | Flat grep |

## Lookup Protocol

1. **Resolve address:** if given a name, `grep -i "[TARGET_NAME]" callgraph_index.csv`
2. **Read context:** navigate to `#func-<HEXADDR>` in `callgraph.md` — note size, callers, callees
3. **Decompile:** use IDA Pro MCP `decompile` for the function body
4. **Disassemble:** use IDA Pro MCP `disassemble` if decompilation is unclear
5. **Follow callees:** click through to each callee's anchor to understand helpers
6. **Follow callers:** click through to callers to understand calling context

## MSVC Conventions Quick Reference

### Calling conventions

| Convention | Stack cleanup | Param order | `this` register |
|-----------|---------------|-------------|-----------------|
| `__thiscall` | callee | right-to-left | ecx (hidden first param) |
| `__cdecl` | caller | right-to-left | none |
| `__stdcall` | callee | right-to-left | none |
| `__fastcall` | callee | ecx, edx, then stack | none (ecx/edx are first two params) |

### Name demangling cheat sheet

- `?Name@Class@@QAE...` = `__thiscall Class::Name(...)`
- `?Name@Class@@QBE...` = `__thiscall Class::Name(...) const`
- `?Name@@YA...` = free function `Name(...)`
- `?Name@@YAX...` = free function returning void
- `H` = int, `J` = long, `E` = unsigned char, `F` = unsigned short
- `N` = float, `M` = double, `_N` = bool
- `PAV` = `Class*`, `QAV` = `const Class*`
- `XZ` = `(void)` params, return void
- `HH` = `(int, int)`
- `HPAD` = `(int, char*)`

## Task: [TARGET]

**Target:** `[TARGET_ADDR]` (or `[TARGET_NAME]`)

### Step 1 — Gather context from callgraph

Before analyzing the function body, understand its neighborhood:

1. **Size check:** read the function's size from `callgraph.md` or `.json`
   - Tiny (1-10B): likely a thunk, tail-call, or pure-virtual stub
   - Small (10-50B): simple wrapper or accessor
   - Medium (50-500B): typical method
   - Large (500B+): complex logic, possibly a state machine or parser

2. **Caller analysis:** read the callers table
   - If called by 1 function: private helper, likely specific purpose
   - If called by 10+: utility function, core primitive
   - If called by 100+: infrastructure (allocators, string ops, getters)

3. **Callee analysis:** read the callees table
   - Calls many other functions: orchestrator / coordinator
   - Calls only libc: leaf logic, possibly crypto/math/data transform
   - Calls no one: leaf function, all logic inline

### Step 2 — Decompile and classify

Use IDA Pro MCP to decompile the function. Classify its structure:

```
Function type:
[ ] Simple (linear, no branches)
[ ] Conditional (if/else or switch)
[ ] Loop (for/while/do-while)
[ ] State machine (jump table, large switch with state variable)
[ ] Constructor (initializes vfptr, calls base constructors)
[ ] Destructor (calls virtual methods, frees members)
[ ] Thunk (adjusts this, tail-jumps to real implementation)
[ ] Wrapper (thin layer around one or more calls)
```

### Step 3 — Reconstruct signature

From the decompiled output, build the C/C++ signature:

```
ReturnType ClassName::MethodName(
    Type1 param1,      // register/stack — purpose?
    Type2 param2,      // register/stack — purpose?
    ...
);
```

For each parameter:
- **Register:** ecx = this, edx = 2nd (fastcall), else stack
- **Stack:** note push order and frame offset
- **Purpose:** infer from how it's used (array index? flag? pointer?)

### Step 4 — Map local variables

List every local variable with offset and inferred type:

| Stack offset | Inferred type | Initialized? | Used by | Purpose |
|-------------|--------------|-------------|---------|---------|
| `var_4` | `int` | yes, from eax | loop counter | loop index |
| `var_8` | `Class*` | yes, from param | callee 1, callee 2 | pointer to member object |
| `var_C` | `char[64]` | no (stack buffer) | sprintf | format buffer |

### Step 5 — Control flow summary

Write a prose description of the function's logic:

```
1. Validate `param1` is not null
2. Look up `param1` in a hash table stored at `this+0x10`
3. If not found, return 0
4. If found, call `helper_func(eax)` to get a result
5. If result < 0, branch to cleanup and return -1
6. Otherwise, store result at `this+0x20` and return 1
```

### Step 6 — Semantics and invariants

Answer these questions:

```
Purpose:    What does this function do in one sentence?
Preconditions: What must be true before calling this function?
Postconditions: What is guaranteed after it returns?
Side effects:  Does it modify global state, this+fields, or output params?
Error handling: How are errors signaled? (return code, exception, assert)
Thread safety:  Is it safe to call concurrently?
```

### Step 7 — Output

Produce a final structured summary:

```
=== Function: [demangled name] @ 0xADDR ===

Signature:
  ReturnType Method(Type1 arg1, Type2 arg2);

Size: N bytes | Blocks: N | Callers: N | Callees: N

Parameters:
  arg1 (ecx): Class* this     — the object this method operates on
  arg2 ([esp+8]): int flags   — bitmask controlling behavior

Locals:
  [ebp-4]:  int result        — accumulated return value
  [ebp-8]:  Class* temp        — temporary pointer for iteration

Control Flow:
  1. ...
  2. ...

Called Functions:
  - func_0xADDR (callee_1_name) — purpose of call
  - func_0xADDR (callee_2_name) — purpose of call

Inferred Semantics:
  Purpose: ...
  Pre: ...
  Post: ...
  Errors: ...

Pseudo-code:
  int Method(int flags) {
      if (!this) return -1;
      int result = 0;
      for (int i = 0; i < this->count; i++) {
          result += helper(this->items[i], flags);
      }
      this->cached = result;
      return result;
  }
```

---

## Quick Commands

When the agent needs more detail mid-analysis:

| Need | Command |
|------|---------|
| Decompile | Use IDA Pro MCP `decompile` on the target address |
| Disassemble | Use IDA Pro MCP `disassemble` on the target address |
| xrefs to | Read callers from `callgraph.md` anchor or `callgraph.json` |
| xrefs from | Read callees from `callgraph.md` anchor or `callgraph.json` |
| Follow a callee | Navigate to `#func-<callee_hexaddr>` in `callgraph.md` |
| Check if virtual | Look for `??_G`/`??_E` in the vtable, or check callers for vtable dereferences |
| Check base class | Read constructor callees — base constructors appear before vfptr writes |
| Match | first use ida-match and then use MCP to do cross check of it.