# rogan2 – Matcher & Compiler Tools

Reusable Python modules for **binary matching** and **DLL building**.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.9+ | Ships with the repo's dev environment |
| `capstone` | `pip install capstone` — or just run `pip install -e .` from the repo root |
| MSVC 6.3 | Required **only** for binary matching. Set `VC6_PATH=E:\repos\msvc6.3` |
| MSBuild / VS 2019+ | Required **only** for DLL builds. Run from a Developer Command Prompt |
| IDA Pro 7.x+ | Required for the live matching server. Must have `ida_kernwin`, `ida_bytes`, etc. available |

## Installation (one-time)

```bash
# From the repo root – installs the tools package as editable
pip install -e .
```

This pulls in `capstone` automatically and makes `tools.compiler` / `tools.matcher`
importable from anywhere on your machine.

---

## Workflow A — DLL Build (Debug / Release)

Produces the hook DLL that runs inside the game process. **Not** related to matching.

```bash
build.cmd --mode dll
```

Or from Python:

```python
from tools.compiler import build_dll

build_dll("Debug")    # → build/bin/Debug/rogan2.dll
build_dll("Release")  # → build/bin/Release/rogan2.dll
```

---

## Workflow B — Binary Matching

Binary matching compares the bytes produced by the **original MSVC 6.3 toolchain** against
the bytes in the original game binary that IDA has already analysed.

The overall flow is:

```
IDA Pro (has the original binary open)
    └─ ida_server.py  ←  HTTP server running inside IDA's process
            │
            │  GET /func?name=<mangled_name>  →  { "bytes": "...", "ea": "...", "size": N }
            │
    match_core.py / run_match.py / watch.py
            │
    build.cmd --mode obj  ←  MSVC 6.3 recompiles your source file
            │
    dumpbin /disasm  ←  extracts bytes from the .obj
            │
    side-by-side Capstone diff  ←  printed in the terminal
```

### Step 1 — Start IDA Pro and open the target binary

Open IDA Pro and load the original game binary (or an already-analysed `.idb`/`.i64`).
Let IDA finish its auto-analysis before continuing.

### Step 2 — Load `ida_server.py` inside IDA

In IDA, open the **Python console** (`File → Python console` or `Shift+F2`) and run:

```python
exec(open(r"D:\repos\rogan2\tools\matcher\ida_server.py").read())
start_server()
```

You should see in the IDA output window:

```
IDA Live Matcher: Cached 1234 function symbols.
IDA Live Matcher Server running on port 28000 (Hot-Reload Enabled)...
```

The server listens on `http://127.0.0.1:28000` and stays alive until you call
`stop_server()` or close IDA.

> **Tip:** You can save this as an IDA startup script or put `start_server()` in
> `ida_startup.py` so it launches automatically with IDA.

#### What `ida_server.py` does

- Binds a raw TCP socket on **port 28000** and polls it every 100 ms using IDA's
  `register_timer` API (so it never blocks IDA's UI thread).
- On each incoming request it delegates to `ida_logic.py` (hot-reloaded automatically
  if the file changes on disk — no IDA restart needed).
- Exposes two endpoints:
  - `GET /func?name=<mangled_name>` → returns `{ "ea": "0x...", "size": N, "bytes": "<hex>" }` for the function, or HTTP 404 if not found.
  - `GET /refresh` → forces a full rebuild of the in-memory function cache.

#### What `ida_logic.py` does

- Walks **all functions** in the IDA database with `idautils.Functions()` and builds a
  `dict[mangled_name → effective_address]` cache on first use.
- `get_function_bytes(name)` looks up the mangled name, reads the raw bytes for that
  function's range (`func.start_ea` → `func.end_ea`) with `ida_bytes.get_bytes`, and
  returns them as a hex string.
- Uses **exact mangled names** (e.g. `?setup@RGE_Base_Game@@MAEHXZ`) to avoid C++
  overload collisions — these are the same names that `dumpbin /disasm` and `DUMPBIN /SYMBOLS`
  emit for the `.obj` file.

### Step 3 — Run the matcher

With the server running you can match either:

**A single file (single-shot):**
```bash
python -m tools.matcher.run_match age2_x1/basegame.cpp
```

**A single file (watch mode — re-runs on every save):**
```bash
python -m tools.matcher.watch age2_x1/basegame.cpp
```

**Focus on one function:**
```bash
python -m tools.matcher.watch age2_x1/basegame.cpp "?setup@RGE_Base_Game@@MAEHXZ"
```

Each invocation will:
1. Compile `<file>.cpp` with MSVC 6.3 → `build/BinaryMatching/<file>.obj`
2. Disassemble the `.obj` with `dumpbin /disasm`
3. Query the IDA server for each function's original bytes
4. Print a colour-coded side-by-side diff (green = match, yellow = relocation, red = mismatch)

### Step 4 — Stop the server (optional)

In the IDA Python console:

```python
stop_server()
```

---

## Python API (quick reference)

```python
from tools.compiler import build_dll, build_obj_for_match, get_obj_path
from tools.matcher  import match_summary, match_focus
from pathlib import Path

# --- DLL build ---
build_dll("Debug")    # Premake5 + MSBuild
build_dll("Release")

# --- Binary matching ---
build_obj_for_match("age2_x1/basegame.cpp")     # MSVC 6.3 via build.cmd
obj = get_obj_path("age2_x1/basegame.cpp")       # → build/BinaryMatching/basegame.obj

match_summary(obj)                               # % match for every function
match_focus(obj, "?setup@RGE_Base_Game@@MAEHXZ") # side-by-side diff
```

---

## Using From Another Project

```bash
# Option 1: add rogan2 to PYTHONPATH (no install)
set PYTHONPATH=D:\repos\rogan2

# Option 2: editable install into the other project's venv
pip install -e D:\repos\rogan2
```

Then import and call exactly as shown above. The only requirement is that `build.cmd` is
reachable from the working directory (or you replace `tools.compiler.build._run_cmd` with
your own build invocation).

---

## File Map

```
tools/
├─ README.md                    ← you are here
├─ __init__.py
├─ compiler/
│   ├─ __init__.py              re-exports build_dll, build_obj_for_match, get_obj_path
│   └─ build.py                 wraps build.cmd for both DLL and .obj modes
└─ matcher/
    ├─ __init__.py              re-exports match_summary, match_focus
    ├─ ida_server.py            HTTP server that runs *inside* IDA Pro
    ├─ ida_logic.py             IDA API calls – function cache & byte extraction
    ├─ match_core.py            all matching / diffing logic (pure Python, no IDA)
    ├─ match.py                 compatibility shim → imports match_core
    ├─ watch.py                 file-watch CLI
    └─ run_match.py             single-shot CLI
```

**Dependency rule:** `compiler` never imports `matcher`; `match_core` never triggers builds;
`ida_server` / `ida_logic` are only ever executed **inside IDA** and are never imported by
the other modules.
