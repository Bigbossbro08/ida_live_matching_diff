"""ida_matcher.matcher.config
~~~~~~~~~~~~~~~~~~~~
`ida_watch.json` project config: source/obj roots, build command, watch
patterns, and per-object manual symbol mappings.

Mirrors objdiff's ProjectConfig/ProjectObject where they apply to this tool:
- watch/ignore pattern defaults come from objdiff config/mod.rs
  (DEFAULT_WATCH_PATTERNS / DEFAULT_IGNORE_PATTERNS).
- the per-file build command renders as `custom_make + custom_args + obj`
  exactly like objdiff's run_make (build/mod.rs:34), or from a
  `build_command` template ({source}/{obj} placeholders).
"""
import os
import re
import json
import shlex
from pathlib import Path

DEFAULT_WATCH_PATTERNS = [
    "*.c", "*.cc", "*.cp", "*.cpp", "*.cxx", "*.c++",
    "*.h", "*.hh", "*.hp", "*.hpp", "*.hxx", "*.h++",
    "*.pch", "*.pch++", "*.inc", "*.s", "*.S", "*.asm",
    "*.py", "*.yml", "*.txt", "*.json",
]

DEFAULT_IGNORE_PATTERNS = ["build/**/*"]

DEFAULT_MAKE = "make"

RELOC_MODES = ("none", "name_address", "data_value", "all")
PARSERS = ("auto", "lief", "pure")


class ConfigError(Exception):
    pass


class Unit:
    """One compilable object, mirroring objdiff's ProjectObject."""

    __slots__ = ("name", "source", "path", "symbol_mappings", "reloc_mappings")

    def __init__(self, name="", source="", path="", symbol_mappings=None, reloc_mappings=None):
        self.name = name or ""
        self.source = source or ""
        self.path = path or ""
        self.symbol_mappings = dict(symbol_mappings or {})
        self.reloc_mappings = dict(reloc_mappings or {})

    def __repr__(self):
        return f"Unit(name={self.name!r}, source={self.source!r}, path={self.path!r})"


class Config:
    """Parsed ida_watch.json. Unset fields fall back to objdiff defaults."""

    __slots__ = (
        "source_root", "obj_root", "custom_make", "custom_args",
        "build_command", "build_per_file", "watch_patterns",
        "ignore_patterns", "reloc_mode", "parser", "units",
        "diff_direction",
    )

    def __init__(self):
        self.source_root = "."
        self.obj_root = ""
        self.custom_make = None
        self.custom_args = None
        self.build_command = None
        self.build_per_file = True
        self.watch_patterns = list(DEFAULT_WATCH_PATTERNS)
        self.ignore_patterns = list(DEFAULT_IGNORE_PATTERNS)
        self.reloc_mode = "name_address"
        self.parser = "auto"
        self.diff_direction = "left_to_right"
        self.units = []


def _norm(value):
    return str(value).replace("\\", "/") if value else ""


def _glob_to_regex(pattern):
    """Translate a glob to an anchored regex with globset `**` semantics:
    `**` spans zero or more path components, `*`/`?`/`[...]` never cross a `/`."""
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                if i + 2 < n and pattern[i + 2] == "/":
                    out.append("(?:[^/]+/)*")
                    i += 3
                else:
                    out.append(".*")
                    i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j < n:
                cls = pattern[i + 1:j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls + "]")
                i = j + 1
                continue
            out.append(re.escape(c))
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    flags = re.IGNORECASE if os.name == "nt" else 0
    return re.compile("^" + "".join(out) + "$", flags)


_REGEX_CACHE = {}


def _pattern_regex(pattern):
    rx = _REGEX_CACHE.get(pattern)
    if rx is None:
        rx = _REGEX_CACHE[pattern] = _glob_to_regex(pattern)
    return rx


def _matches_any(path, patterns):
    """Globset-like match of the normalized path or its basename against any
    pattern. Case-insensitive on Windows (mirroring fnmatch)."""
    norm = _norm(path)
    base = Path(norm).name
    for pattern in patterns:
        rx = _pattern_regex(pattern)
        if rx.match(norm) or rx.match(base):
            return True
    return False


def _project_dir(config_path):
    if config_path is None:
        return Path(".")
    return Path(config_path).resolve().parent


def _resolve_source(rel, base_dir):
    """Resolve a unit source path relative to the project dir (objdiff's
    ProjectObject.source_path is project-relative)."""
    if not rel:
        return None
    p = Path(rel)
    return p if p.is_absolute() else (base_dir / p).resolve()


def load_config(config_path):
    """Parse `config_path` into a Config. Tolerant: on any error, warn and
    return a Config with defaults (unit/mapping lookups then simply miss)."""
    cfg = Config()
    if config_path is None or not Path(config_path).exists():
        return cfg
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load config {config_path}: {e}")
        return cfg
    if not isinstance(data, dict):
        print(f"Warning: Config {config_path} is not a JSON object.")
        return cfg

    cfg.source_root = data.get("source_root", cfg.source_root)
    cfg.obj_root = data.get("obj_root", cfg.obj_root)
    cfg.custom_make = data.get("custom_make")
    cfg.custom_args = data.get("custom_args")
    cfg.build_command = data.get("build_command")
    cfg.build_per_file = data.get("build_per_file", True)

    if data.get("watch_patterns"):
        cfg.watch_patterns = list(data["watch_patterns"])
    if data.get("ignore_patterns") is not None:
        cfg.ignore_patterns = list(data["ignore_patterns"])

    reloc_mode = _norm(data.get("reloc_mode", "")).lower()
    if reloc_mode:
        reloc_mode = {
            "none": "none",
            "nameaddress": "name_address",
            "name_address": "name_address",
            "datavalue": "data_value",
            "data_value": "data_value",
            "all": "all",
        }.get(reloc_mode, cfg.reloc_mode)
        cfg.reloc_mode = reloc_mode
    if data.get("parser") in PARSERS:
        cfg.parser = data["parser"]

    diff_dir = _norm(data.get("diff_direction", "")).lower()
    if diff_dir in ("right_to_left", "rtl", "objdiff"):
        cfg.diff_direction = "right_to_left"
    elif diff_dir in ("left_to_right", "ltr"):
        cfg.diff_direction = "left_to_right"

    for raw in data.get("units", []) or data.get("objects", []) or []:
        if not isinstance(raw, dict):
            continue
        meta = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
        unit = Unit(
            name=raw.get("name", ""),
            source=raw.get("source", "") or meta.get("source_path", ""),
            path=raw.get("path", "") or raw.get("obj", ""),
            symbol_mappings=raw.get("symbol_mappings", {}),
            reloc_mappings=raw.get("reloc_mappings", {}),
        )
        if unit.path or unit.name or unit.source:
            cfg.units.append(unit)
    return cfg


def _same_path(a, b):
    """Case-insensitive on Windows (filesystem is case-insensitive there)."""
    a, b = str(a), str(b)
    if os.name == "nt":
        return a.casefold() == b.casefold()
    return a == b


def unit_for_source(config, source_path, project_dir=None):
    """Resolve a source file to the unit(s) that compile it. Matches on the
    exact resolved source path, then falls back to a basename/stem match."""
    base = Path(project_dir) if project_dir else Path(".")
    want = Path(source_path).resolve()
    results = []
    for unit in config.units:
        candidate = _resolve_source(unit.source, base)
        if candidate is not None and _same_path(candidate, want):
            results.append(unit)
            continue
        src = Path(unit.source)
        if _same_path(src.name, want.name) or _same_path(src.stem, want.stem):
            results.append(unit)
    return results


def units_for_obj(config, obj_path, project_dir=None):
    """Resolve a compiled object path to the matching unit(s)."""
    base = Path(project_dir) if project_dir else Path(".")
    want = Path(obj_path).resolve()
    exact = []
    for unit in config.units:
        if not unit.path:
            continue
        up = (Path(base) / unit.path).resolve()
        if _same_path(up, want):
            exact.append(unit)
    if exact:
        return exact
    results = []
    for unit in config.units:
        if not unit.path:
            continue
        if _same_path(Path(unit.path).name, want.name):
            results.append(unit)
    return results


def build_command_for(config, unit, project_dir=None):
    """Render the argv used to build `unit`. Prefer a `build_command`
    template; otherwise reproduce objdiff run_make: custom_make + custom_args
    + the obj path relative to the project dir. Returns None when there is
    nothing to run."""
    base = Path(project_dir) if project_dir else Path(".")
    src = _norm((Path(base) / _norm(unit.source)).resolve()) if unit.source else ""
    obj = _norm((Path(base) / _norm(unit.path)).resolve()) if unit.path else ""
    if not obj and not src:
        return None

    if config.build_command:
        rendered = config.build_command
        if unit.source:
            rendered = rendered.replace("{source}", src)
        if unit.path:
            rendered = rendered.replace("{obj}", obj)
        return shlex.split(rendered) if rendered.strip() else None

    argv = [config.custom_make or DEFAULT_MAKE]
    if config.custom_args:
        argv += list(config.custom_args)
    if unit.path:
        argv.append(_norm(Path(unit.path)))
    return argv


def build_command_for_source(config, source_path, project_dir=None):
    """Build command(s) for every unit that compiles `source_path`."""
    return [build_command_for(config, u, project_dir) for u in unit_for_source(config, source_path)]


def watch_files(config, project_dir=None):
    """All watched source files under source_root (watch patterns matched,
    ignore patterns excluded). Every configured unit source is always
    included so out-of-pattern sources still trigger a rebuild."""
    base = Path(project_dir) if project_dir else Path(".")
    src_root = base / config.source_root
    watched = set()
    if src_root.is_dir():
        for p in src_root.rglob("*"):
            if not p.is_file():
                continue
            rel = _norm(p.relative_to(src_root))
            if not _matches_any(rel, config.ignore_patterns) and _matches_any(rel, config.watch_patterns):
                watched.add(p.resolve())
    for unit in config.units:
        if unit.source:
            resolved = _resolve_source(unit.source, base)
            if resolved is not None and resolved.is_file():
                watched.add(resolved)
    return watched


def symbol_mappings_for(config, unit):
    return dict(unit.symbol_mappings)


def reloc_mappings_for(config, unit):
    """Per-unit reloc target-name remap: obj-side reloc symbol name (MSVC
    mangled) -> IDA-side name (e.g. Itanium mangled). Applied before reloc_eq
    so relocation targets on both sides use the same naming scheme."""
    return dict(unit.reloc_mappings)


def load_config_mappings(config_path, obj_path):
    """Back-compat shim used by ida-match: the manual symbol_mappings of the
    unit whose object matches `obj_path` (or {} if none)."""
    cfg = load_config(config_path)
    project_dir = _project_dir(config_path)
    for unit in units_for_obj(cfg, obj_path, project_dir):
        return dict(unit.symbol_mappings)
    return {}


def load_config_reloc_mappings(config_path, obj_path):
    """Per-unit reloc target-name remap for the unit whose object matches
    `obj_path` (or {} if none)."""
    cfg = load_config(config_path)
    project_dir = _project_dir(config_path)
    for unit in units_for_obj(cfg, obj_path, project_dir):
        return dict(unit.reloc_mappings)
    return {}