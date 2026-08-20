# IDA Live Matching Diff

A live binary matching and diffing tool for reverse-engineering and decompilation projects. It compares **MSVC-compiled `.obj` files** directly against a **live IDA Pro database** with byte-for-byte fidelity powered by the native **`objdiff`** matching engine.

---

## Prerequisites

- **Python 3.9+** on your system.
- **IDA Pro 7.x, 8.x, or 9.x** with Python 3 support enabled.
- *(Source build only)*: [Rust toolchain](https://rustup.rs/) and [MSVC C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

---

## Setup & Installation

### Step 1: Install `ida_matcher` on Your Machine

#### Option A: From Prebuilt Wheel (Recommended)
```bash
pip install dist/ida_matcher-0.1.0-cp39-abi3-win_amd64.whl
```

#### Option B: From Source (Developers)
```bash
# Clone repository and submodules
git clone --recurse-submodules https://github.com/Bigbossbro08/ida_live_matching_diff.git
cd ida_live_matching_diff

# Build and install editable package
pip install -e . --no-build-isolation
```
*(To build `.whl` packages for others, run `build_wheels.bat` or `maturin build --release`)*.

---

### Step 2: Set Up IDA Pro

IDA Pro needs access to the package and the server plugin.

1. **Install into IDA's Python environment**:
   ```cmd
   # Replace with your IDA Pro Python path (e.g. IDA 9.1):
   "C:\Program Files\IDA Professional 9.1\python\3\python.exe" -m pip install dist\ida_matcher-0.1.0-cp39-abi3-win_amd64.whl
   ```
   *(Or if installing from source: `"C:\Program Files\IDA Professional 9.1\python\3\python.exe" -m pip install -e . --no-build-isolation`)*

2. **Install the plugin**:
   Copy [`ida_live_matcher_plugin.py`](ida_live_matcher_plugin.py) into your IDA Pro `plugins/` folder:
   ```cmd
   copy ida_live_matcher_plugin.py "C:\Program Files\IDA Professional 9.1\plugins\"
   ```

   *Alternatively (without copying the plugin), you can manually run `ida_matcher/matcher/ida_server.py` via IDA's **File → Script file…**.*

---

## Everyday Workflow

1. **Open your target database in IDA Pro**.  
   The server will start automatically in the background on port `28000`. You will see in IDA's Output window:
   ```text
   IDA Live Matcher Server running on port 28000 (Threaded, Hot-Reload Enabled)...
   ```

2. **Compile your C++ source code to `.obj`** (e.g., via `cl.exe /c code.cpp -Fo:code.obj` or your project build script).

3. **Run the Matcher**:

   ```bash
   # 1. Summary of all functions in the .obj
   ida-match path/to/compiled.obj

   # 2. Side-by-side instruction diff for a single function
   ida-match path/to/compiled.obj --func "?MyFunction@@YAXXZ"

   # 3. Watch mode (automatically re-runs whenever the .obj is recompiled)
   ida-watch path/to/compiled.obj --func "?MyFunction@@YAXXZ"
   ```

---

## CLI Options

| Flag | Applies to | Description |
|---|---|---|
| `--func <name>` | `ida-match`, `ida-watch` | Focus and diff a single function by mangled symbol name |
| `--json` | `ida-match` | Emit machine-readable JSON summary for CI / tools |
| `--strict` | `ida-match` | Return non-zero exit code if any function is below 100% |
| `--parser <auto\|lief\|pure>` | both | Choose parser backend (`auto` uses LIEF when present) |
| `--reloc-mode <none\|nameaddress\|datavalue\|all>` | both | Configure relocation strictness |
| `--no-color` | both | Disable ANSI color codes |

---

## Project Details & Architecture

For the directory layout, module definitions, and technical workflow, see [**PROJECT_LAYOUT.md**](PROJECT_LAYOUT.md).

---

## Running Tests

Run the full offline test suite (no IDA instance required):

```bash
python -m pytest ida_matcher/matcher/tests -q
```