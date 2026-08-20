"""
ida_matcher.matcher.watch
~~~~~~~~~~~~~~~~~~~
Watch compiled objects for changes and re-run the matcher.

Two modes:

1. Single-object (original): `ida-watch <file.obj> [--func name]` watches one
   .obj and re-matches on every modification.

2. Project config: `ida-watch --config ida_watch.json` watches source files
   (objdiff-style watch/ignore patterns), rebuilds the affected unit(s) via
   the configured build command (custom_make + custom_args + obj, mirroring
   objdiff run_make), and re-matches only the units whose symbol bytes
   actually changed.
"""
import os
import sys
import time
import argparse
import hashlib
import subprocess
from pathlib import Path

from ida_matcher.matcher import match_summary, match_focus, _configure_colors
from ida_matcher.matcher.match_core import load_obj
from ida_matcher.matcher.config import (
    load_config, watch_files, unit_for_source, units_for_obj,
    build_command_for, symbol_mappings_for, reloc_mappings_for,
)

RELOC_MODE_MAP = {
    "none": "none",
    "nameaddress": "name_address",
    "datavalue": "data_value",
    "all": "all",
}


def _get_stat(filepath):
    """(mtime, size) tuple so same-second rebuilds still trigger a re-match."""
    try:
        st = os.stat(filepath)
        return (st.st_mtime, st.st_size)
    except FileNotFoundError:
        return (0, 0)


def _match(obj_path, target_func, parser, reloc_mode, mappings_config=None):
    """Run the matcher. Returns True on success, False on a (recoverable) failure."""
    print(f"\n[{time.strftime('%H:%M:%S')}] Matching {obj_path.name}...")
    try:
        if target_func:
            match_focus(obj_path, target_func, parser=parser, reloc_mode=reloc_mode,
                        mappings_config=mappings_config)
        else:
            match_summary(obj_path, parser=parser, reloc_mode=reloc_mode,
                          mappings_config=mappings_config)
        return True
    except SystemExit:
        # e.g. function not found / server unreachable - keep watching, do not die
        return False


def _symbol_hashes(obj_path, parser):
    """{name: sha1(bytes)} for every symbol in the parsed object. Empty dict
    when the object is missing or unparseable."""
    try:
        obj_funcs = load_obj(obj_path, parser=parser)
    except Exception:
        return {}
    out = {}
    for name, sym in obj_funcs.items():
        b = sym.get("bytes", "")
        if isinstance(b, str):
            b = b.encode()
        out[name] = hashlib.sha1(bytes(b)).hexdigest()
    return out


def _unit_obj_path(unit, project_dir):
    if not unit.path:
        return None
    p = Path(unit.path)
    return p if p.is_absolute() else (Path(project_dir) / p)


def _build_units(config, units, project_dir):
    """Run the per-file build for each unit (objdiff run_make parity). Returns
    True only if every build succeeded."""
    for unit in units:
        argv = build_command_for(config, unit, project_dir)
        if not argv:
            continue
        print(f"    build: {' '.join(argv)}")
        try:
            res = subprocess.run(argv, cwd=project_dir, capture_output=True, text=True, timeout=600)
        except Exception as e:
            print(f"    build failed: {e}")
            return False
        if res.returncode != 0:
            print(f"    build failed ({res.returncode})")
            if res.stderr.strip():
                print(res.stderr.strip()[:2000])
            return False
        if res.stdout.strip():
            print(res.stdout.strip()[:2000])
    return True


def _unit_key(unit):
    """Cache key for the change-skip state. The obj path is unique per unit;
    `name` is NOT (multiple unnamed units default to "")."""
    return unit.path or unit.name


def _match_units(config, units, project_dir, last_hashes, parser, reloc_mode):
    """Re-match only units whose symbol bytes changed since their last run."""
    for unit in units:
        obj_path = _unit_obj_path(unit, project_dir)
        if obj_path is None or not obj_path.exists():
            print(f"\n[{time.strftime('%H:%M:%S')}] {unit.name}: missing {obj_path}")
            continue
        hashes = _symbol_hashes(obj_path, parser)
        key = _unit_key(unit)
        if last_hashes.get(key) == hashes:
            print(f"\n[{time.strftime('%H:%M:%S')}] {unit.name}: no symbol changes, skipping")
            continue
        last_hashes[key] = hashes
        mappings_config = {"mappings": symbol_mappings_for(config, unit),
                           "reloc_mappings": reloc_mappings_for(config, unit)}
        _match(obj_path, None, parser, reloc_mode, mappings_config=mappings_config)


def _run_config(config_path, parser, reloc_mode):
    cfg = load_config(config_path)
    project_dir = Path(config_path).resolve().parent
    if reloc_mode is None:
        reloc_mode = cfg.reloc_mode
    if parser is None:
        parser = cfg.parser

    watched = watch_files(cfg, project_dir)
    obj_paths = [p for u in cfg.units if (p := _unit_obj_path(u, project_dir)) is not None]
    if not watched and not obj_paths:
        print(f"Error: no watch files or units found in {config_path}.")
        sys.exit(1)

    print(f"Watching {len(watched)} source file(s) under '{cfg.source_root}' "
          f"({cfg.reloc_mode} relocs, {cfg.parser} parser)...")

    last_stats = {}
    for p in watched:
        last_stats[p] = _get_stat(p)
    for p in obj_paths:
        last_stats[p] = _get_stat(p)

    last_hashes = {_unit_key(u): None for u in cfg.units}

    # Initial pass: match every unit once.
    _match_units(cfg, cfg.units, project_dir, last_hashes, parser, reloc_mode)

    try:
        while True:
            time.sleep(1.0)
            changed_sources = [p for p in watched if _get_stat(p) != last_stats[p]]
            changed_objs = [p for p in obj_paths if _get_stat(p) != last_stats[p]]
            for p in changed_sources + changed_objs:
                last_stats[p] = _get_stat(p)
            if not changed_sources and not changed_objs:
                continue

            units_to_rematch = set()
            for src in changed_sources:
                units_to_rematch.update(unit_for_source(cfg, src, project_dir))
            for op in changed_objs:
                units_to_rematch.update(units_for_obj(cfg, op, project_dir))

            if not cfg.build_per_file and (changed_sources or changed_objs):
                # Whole-project build: everything may have changed.
                if not _build_units(cfg, [], project_dir):
                    continue
                units_to_rematch = set(cfg.units)
            elif changed_sources:
                if not _build_units(cfg, sorted(units_to_rematch, key=lambda u: u.name), project_dir):
                    continue
            if not units_to_rematch:
                continue
            _match_units(cfg, sorted(units_to_rematch, key=lambda u: u.name),
                         project_dir, last_hashes, parser, reloc_mode)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    parser = argparse.ArgumentParser(
        prog="ida-watch",
        description="Watch compiled .obj files (or a project config) and re-match against IDA.",
    )
    parser.add_argument("obj_file", nargs="?", help="Path to the .obj file to watch (single-object mode)")
    parser.add_argument("--config", help="Path to ida_watch.json project config (project mode)")
    parser.add_argument("--func", help="Focus on a specific function (mangled name)")
    parser.add_argument("--parser", choices=["auto", "lief", "pure"], default=None,
                        help="COFF .obj parser backend (default: config value, or auto)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--reloc-mode", choices=["none", "nameaddress", "datavalue", "all"], default=None,
                        help="Relocation comparison mode (default: config value, or nameaddress)")
    args = parser.parse_args()

    if not args.config and not args.obj_file:
        parser.error("either a .obj file or --config is required")

    _configure_colors(not (args.no_color or os.environ.get("NO_COLOR")))

    if args.config:
        reloc_mode = RELOC_MODE_MAP[args.reloc_mode] if args.reloc_mode else None
        parser_backend = args.parser or None
        _run_config(args.config, parser_backend, reloc_mode)
        return

    if not os.path.exists(args.obj_file):
        print(f"Error: {args.obj_file} not found.")
        sys.exit(1)

    reloc_mode = RELOC_MODE_MAP[args.reloc_mode] if args.reloc_mode else "name_address"
    parser_backend = args.parser or "auto"

    obj_path = Path(args.obj_file)
    target_func = args.func

    if target_func:
        print(f"Watching {args.obj_file} for changes, targeting {target_func} (Press Ctrl+C to stop)...")
    else:
        print(f"Watching {args.obj_file} for changes (Press Ctrl+C to stop)...")

    last_stat = _get_stat(args.obj_file)

    # Initial match
    _match(obj_path, target_func, parser_backend, reloc_mode)

    try:
        while True:
            time.sleep(1.0)
            current_stat = _get_stat(args.obj_file)
            if current_stat != last_stat:
                last_stat = current_stat
                _match(obj_path, target_func, parser_backend, reloc_mode)
    except KeyboardInterrupt:
        print("\nStopped watching.")


if __name__ == "__main__":
    main()