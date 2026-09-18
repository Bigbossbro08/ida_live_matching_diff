# Reverse Engineering Prompt Template
# ================================
# Copy the section below (between the --- markers) and fill in [TARGET] placeholders.
# Designed to work with callgraph.md, callgraph.json, and callgraph_index.csv.

---

## Role

You are a reverse engineer analyzing a 32-bit x86 C++ binary (MSVC-mangled names).
Your job is to reconstruct class hierarchies, virtual method tables, member fields,
and method semantics for the specified class(es).

## Input Files

You have access to these pre-generated call graph files in the workspace:

| File | Purpose | How to use it |
|------|---------|---------------|
| `callgraph.md` | Full indexed call graph | Navigate via anchors: `#func-<HEXADDR>`. Use Name Index for alphabetical lookup, Address Index for offset lookup |
| `callgraph.json` | Machine-readable graph | Parse directly. Keys are hex addresses. Fields: `name`, `size`, `callers[]`, `callees[]` |
| `callgraph_index.csv` | Flat grep index | `grep -i "ClassName" callgraph_index.csv` to find all methods, then read callgraph.md via anchor links |

## Lookup Rules

1. **Find a function:** grep `callgraph_index.csv` for the name or address, get its `anchor` field
2. **Read its details:** navigate to `#func-<HEXADDR>` in `callgraph.md`
3. **Follow the graph:** every caller/callee in the MD is a clickable link to its own anchor
4. **Cross-check:** compare MD results against `callgraph.json` for data consistency

## MSVC Name Demangling Reference

- `?name@Class@@QAE...` = Class::name (thiscall)
- `?name@Class@@QBE...` = Class::name (const thiscall)
- `?name@Class@@MAE...` = Class::name (virtual, thiscall)
- `?name@Class@@UAE...` = Class::name (virtual, pure)
- `?name@Class@@UAEXXZ` = virtual void Class::name() (destructor/generator)
- `??_GClass@@UAEPAXI@Z` = Class::`scalar deleting destructor`
- `??_EClass@@UAEPAXI@Z` = Class::`vector deleting destructor`
- `??_R4Class@@6B@` = Class RTTI Complete Object Locator (vtable index 0)
- `@QAV` = pointer to (pass by ref in return)
- `PAV` = pointer to
- `HH` = two int/short params
- `XZ` = void return, no params

## MSVC vtable Layout

Typical MSVC vtable order (indices relative to vfptr):
- [0] RTTI Complete Object Locator (data, not code)
- [1] RTTI Type Descriptor (data)
- [2] RTTI Class Hierarchy Descriptor (data)
- [3] RTTI Base Class Array (data)
- [0] scalar deleting destructor
- [1] vector deleting destructor
- [2+] virtual methods in declaration order

When you see `??_G` / `??_E` at start of vtable, those are destructor slots.
After those, virtual methods follow in source declaration order.

## Task: [TARGET_CLASS]

### Step 1 — Enumerate all methods

Search `callgraph_index.csv` for all functions whose name contains `[TARGET_CLASS]`.
List them in a table:

| Address | Demangled Name | Size | In (callers) | Out (callees) | Thunk? |
|---------|---------------|------|-------------|--------------|--------|

### Step 2 — Classify each method

For each method, determine:
- **Static:** no `this` pointer (no vtable access, no member reads via ecx)
- **Virtual:** part of a vtable (cross-reference vtable data sections)
- **Non-virtual member:** uses `this` but not in vtable
- **Constructor:** calls `__tf` or initializes vfptr (look for `mov [ecx+offset], offset vtable`)
- **Destructor:** is `??_G` / `??_E` or calls base destructor
- **Thunk:** 2-5 bytes, adjusts `this` and jumps (tail call to real implementation)
- **Pure virtual stub:** size = 1 byte (int 3) or calls `__purecall`

### Step 3 — Reconstruct vtable

1. Search `callgraph.json` for addresses in `.rdata` or `.data` segments that point to `[TARGET_CLASS]` methods
2. Cross-reference: grep `callgraph_index.csv` for known virtual method names
3. List vtable slots:

| vtable offset | Slot index | Target address | Method name | Notes |
|--------------|-----------|----------------|-------------|-------|

### Step 4 — Infer class hierarchy

From constructor/destructor call chains:
1. Read each constructor's callees in `callgraph.md`
2. Base class constructors appear as callees before vfptr assignments
3. List the inheritance tree:

```
TARGET_CLASS
├── BaseClass1
│   └── GrandBase1
├── BaseClass2
└── Interface1
```

### Step 5 — Infer member fields

From method bodies (use IDA Pro MCP `decompile` or `disassemble`):
- Track `[ecx+OFFSET]` and `[eax+OFFSET]` patterns
- Group offsets by class (adjust ecx by `this -= sizeof(Base)` in constructors)
- Build a field map:

| Offset | Size | Inferred type | Usage (which methods access it) |
|--------|------|--------------|-------------------------------|

### Step 6 — Output

Produce a structured summary:

```
class [TARGET_CLASS] {
    // Inheritance
    extends BaseClass1, implements Interface1

    // vtable @ 0xVVVVVV
    virtual void method1();           // vtable[2] -> 0xADDR (size: N)
    virtual int method2(int arg);     // vtable[3] -> 0xADDR (size: N)
    ...

    // Members (this+OFFSET)
    int field_0x04;                   // accessed by method1, method3
    char* field_0x08;                 // allocated in constructor
    ...

    // Non-virtual methods
    static void helper();             // 0xADDR
    void internal_logic();            // 0xADDR
};
```

---

## Additional Context

- Binary base address: `0x400000`
- All code segments: `.text`, `THIS_COD`
- Data segments: `.rdata`, `.data`, `THIS_DAT`
- vtable pointers are typically in `.rdata` (read-only) or `.data`
- IDA Pro MCP is available for live decompilation/disassembly of specific addresses
