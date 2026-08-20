"""Tests for ida_watch.json config parsing, build rendering, change-set
filtering, and manual symbol mapping application (Phase 6)."""
import json

import pytest

from ida_matcher.matcher import config as cfgmod
from ida_matcher.matcher import match_core as mc
from ida_matcher.matcher.config import (
    DEFAULT_IGNORE_PATTERNS, DEFAULT_MAKE, DEFAULT_WATCH_PATTERNS,
    Config, load_config, load_config_mappings, unit_for_source, units_for_obj,
    build_command_for, watch_files,
)


# ------------------------------------------------------------ config parse

def test_load_config_defaults_when_missing():
    cfg = load_config(None)
    assert cfg.watch_patterns == DEFAULT_WATCH_PATTERNS
    assert cfg.ignore_patterns == DEFAULT_IGNORE_PATTERNS
    assert cfg.reloc_mode == "name_address"
    assert cfg.parser == "auto"
    assert cfg.build_per_file is True
    assert cfg.custom_make is None
    assert cfg.units == []


def test_load_config_bad_json_returns_defaults(tmp_path, capsys):
    bad = tmp_path / "ida_watch.json"
    bad.write_text("{ not json !!!")
    cfg = load_config(bad)
    assert cfg.watch_patterns == DEFAULT_WATCH_PATTERNS
    assert "Failed to load config" in capsys.readouterr().out


def test_load_config_full_parse(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "obj_root": "build",
        "custom_make": "ninja",
        "custom_args": ["-j8", "-k0"],
        "build_per_file": False,
        "watch_patterns": ["*.c", "*.cpp"],
        "ignore_patterns": [],
        "reloc_mode": "nameaddress",
        "parser": "pure",
        "units": [
            {
                "name": "foo",
                "path": "build/foo.obj",
                "metadata": {"source_path": "src/foo.c"},
                "symbol_mappings": {"?foo@@YAXXZ": "Foo"},
            },
            {"name": "bar", "source": "src/bar.cpp", "path": "build/bar.obj"},
        ],
    }))
    cfg = load_config(conf)
    assert cfg.source_root == "src"
    assert cfg.custom_make == "ninja"
    assert cfg.custom_args == ["-j8", "-k0"]
    assert cfg.build_per_file is False
    assert cfg.watch_patterns == ["*.c", "*.cpp"]
    assert cfg.ignore_patterns == []
    assert cfg.reloc_mode == "name_address"
    assert cfg.parser == "pure"
    assert [u.name for u in cfg.units] == ["foo", "bar"]
    foo = cfg.units[0]
    assert foo.path == "build/foo.obj"
    assert foo.source == "src/foo.c"
    assert foo.symbol_mappings == {"?foo@@YAXXZ": "Foo"}


def test_load_config_objects_alias(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({"objects": [{"name": "x", "path": "x.obj"}]}))
    assert load_config(conf).units[0].name == "x"


def test_reloc_mode_normalization(tmp_path):
    conf = tmp_path / "ida_watch.json"
    for key in ("datavalue", "none", "all"):
        conf.write_text(json.dumps({"reloc_mode": key}))
        assert load_config(conf).reloc_mode == {
            "datavalue": "data_value", "none": "none", "all": "all",
        }[key]


# ------------------------------------------------------------ build command

def test_build_command_make_parity():
    cfg = Config()
    cfg.custom_make = "ninja"
    cfg.custom_args = ["-j8"]
    unit = cfgmod.Unit(name="foo", source="src/foo.c", path="build/foo.obj")
    # objdiff run_make parity: make + args + obj path (relative), cwd = project dir.
    assert build_command_for(cfg, unit, project_dir=".") == ["ninja", "-j8", "build/foo.obj"]


def test_build_command_default_make():
    cfg = Config()
    unit = cfgmod.Unit(name="foo", path="build/foo.obj")
    assert build_command_for(cfg, unit, project_dir=".")[0] == DEFAULT_MAKE


def test_build_command_template():
    cfg = Config()
    cfg.build_command = "clang -c {source} -o {obj} -O2"
    unit = cfgmod.Unit(name="foo", source="src/foo.c", path="build/foo.obj")
    argv = build_command_for(cfg, unit, project_dir=".")
    assert argv[0] == "clang"
    assert argv[1] == "-c"
    assert argv[2].endswith("foo.c")
    assert argv[3] == "-o"
    assert argv[4].endswith("foo.obj")


def test_build_command_none_when_nothing_to_build():
    cfg = Config()
    unit = cfgmod.Unit(name="orphan")
    assert build_command_for(cfg, unit, project_dir=".") is None


# ------------------------------------------------------------ unit resolution

def test_unit_for_source_exact_path(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "units": [{"name": "foo", "source": "src/foo.c", "path": "build/foo.obj"}],
    }))
    cfg = load_config(conf)
    (tmp_path / "src").mkdir()
    src = tmp_path / "src" / "foo.c"
    src.touch()
    assert unit_for_source(cfg, src, tmp_path)[0].name == "foo"


def test_unit_for_source_stem_fallback(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "units": [{"name": "foo", "source": "src/foo.c", "path": "build/foo.obj"}],
    }))
    cfg = load_config(conf)
    (tmp_path / "src").mkdir()
    other = tmp_path / "other" / "foo.c"
    other.parent.mkdir()
    other.touch()
    assert unit_for_source(cfg, other, tmp_path)[0].name == "foo"


def test_units_for_obj_by_name(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "units": [{"name": "foo", "path": "build/foo.obj"}],
    }))
    cfg = load_config(conf)
    assert units_for_obj(cfg, tmp_path / "build" / "foo.obj", tmp_path)[0].name == "foo"


# ------------------------------------------------------------ watch filtering

def _mk_tree(base, files):
    for rel in files:
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")


def test_watch_files_patterns_and_ignore(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "ignore_patterns": ["build/**/*"],
    }))
    cfg = load_config(conf)
    _mk_tree(tmp_path, [
        "src/a.c", "src/b.h", "src/c.cpp", "src/note.txt",
        "src/build/sub/out.c",
    ])
    watched = watch_files(cfg, tmp_path)
    rel = sorted(str(p.relative_to(tmp_path)).replace("\\", "/") for p in watched)
    assert "src/a.c" in rel
    assert "src/b.h" in rel
    assert "src/c.cpp" in rel
    assert "src/note.txt" in rel
    assert "src/build/sub/out.c" not in rel


def test_watch_files_includes_unit_source_outside_patterns(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "watch_patterns": ["*.c"],
        "units": [{"name": "gen", "source": "gen/foo.xyz", "path": "build/gen.obj"}],
    }))
    cfg = load_config(conf)
    _mk_tree(tmp_path, ["src/a.c", "gen/foo.xyz"])
    watched = watch_files(cfg, tmp_path)
    gen = tmp_path / "gen" / "foo.xyz"
    assert gen.resolve() in watched


# ------------------------------------------------------------ mappings shim

def test_load_config_mappings_shim(tmp_path):
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "units": [{"name": "foo", "path": "build/foo.obj",
                   "symbol_mappings": {"?foo@@YAXXZ": "Foo"}}],
    }))
    assert load_config_mappings(conf, tmp_path / "build" / "foo.obj") == {"?foo@@YAXXZ": "Foo"}
    assert load_config_mappings(conf, tmp_path / "build" / "other.obj") == {}


def test_units_for_obj_exact_path_wins_over_basename(tmp_path):
    """Two units sharing an obj basename must resolve by full path, not the
    first basename match (regression: current.o existed in two unit dirs)."""
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "units": [
            {"name": "a", "path": "dir_a/current.o",
             "symbol_mappings": {"?a@@YAXXZ": "A"}},
            {"name": "b", "path": "dir_b/current.o",
             "symbol_mappings": {"?b@@YAXXZ": "B"}},
        ],
    }))
    cfg = load_config(conf)
    got_b = units_for_obj(cfg, tmp_path / "dir_b" / "current.o", tmp_path)
    assert [u.name for u in got_b] == ["b"]
    assert load_config_mappings(conf, tmp_path / "dir_b" / "current.o") == {"?b@@YAXXZ": "B"}
    got_a = units_for_obj(cfg, tmp_path / "dir_a" / "current.o", tmp_path)
    assert [u.name for u in got_a] == ["a"]
    assert load_config_mappings(conf, tmp_path / "dir_a" / "current.o") == {"?a@@YAXXZ": "A"}


# ------------------------------------------------------------ watch change detection

def test_symbol_hashes_detect_rebuild(tmp_path):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    from ida_matcher.matcher.watch import _symbol_hashes
    obj = tmp_path / "foo.obj"
    obj.write_bytes(build_synthetic_obj())
    h1 = _symbol_hashes(obj, "auto")
    assert set(h1) >= {"_fa", "_fb"}  # parses real symbol bytes
    assert _symbol_hashes(obj, "auto") == h1  # deterministic

    # Modify a byte in _fa's body (offset 0 raw) -> hash must change.
    raw = bytearray(obj.read_bytes())
    raw[0] ^= 0xFF
    obj.write_bytes(bytes(raw))
    h2 = _symbol_hashes(obj, "auto")
    assert h2 != h1


def test_symbol_hashes_missing_obj():
    from ida_matcher.matcher.watch import _symbol_hashes
    from pathlib import Path
    assert _symbol_hashes(Path("does_not_exist.obj"), "auto") == {}


def test_watch_files_ignore_top_level_build_file(tmp_path):
    # globset `build/**/*` matches build/foo.txt (zero-component `**`);
    # fnmatch does not. Regression test for the default ignore pattern.
    conf = tmp_path / "ida_watch.json"
    conf.write_text(json.dumps({
        "source_root": "src",
        "ignore_patterns": ["build/**/*"],
    }))
    cfg = load_config(conf)
    _mk_tree(tmp_path, ["src/build/foo.txt", "src/a.c"])
    watched = watch_files(cfg, tmp_path)
    rel = sorted(str(p.relative_to(tmp_path)).replace("\\", "/") for p in watched)
    assert "src/build/foo.txt" not in rel
    assert "src/a.c" in rel


def test_glob_regex_star_does_not_cross_slash():
    from ida_matcher.matcher.config import _matches_any
    # `*.c` must not treat src/a.c as matching on the full path, but the
    # basename fallback still catches it.
    assert _matches_any("src/a.c", ["*.c"])
    assert not _matches_any("src/a.c", ["src/a"])


def test_match_units_no_skip_on_blank_names(tmp_path, monkeypatch):
    # Regression: two unnamed units (name defaults to "") must not collide on
    # the change-skip cache key (cache is keyed by obj path, not name).
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    from ida_matcher.matcher import watch
    calls = []
    monkeypatch.setattr(watch, "match_summary", lambda *a, **k: calls.append(a[0]))
    o1 = tmp_path / "a.obj"
    o2 = tmp_path / "b.obj"
    o1.write_bytes(build_synthetic_obj())
    o2.write_bytes(build_synthetic_obj())
    cfg = Config()
    cfg.units = [
        cfgmod.Unit(name="", path="a.obj"),
        cfgmod.Unit(name="", path="b.obj"),
    ]
    last_hashes = {}
    watch._match_units(cfg, cfg.units, tmp_path, last_hashes, "auto", "name_address")
    assert len(calls) == 2  # both units matched, neither skipped as "unchanged"
    assert set(last_hashes) == {"a.obj", "b.obj"}


# ------------------------------------------------------------ mapping application

def _code_sym(name, size=6):
    return {"size": size, "flags": [], "section_kind": "code",
            "section_name": ".text", "bytes": "55" * size, "relocs": {}}


def test_apply_symbol_mappings_forced_pair_wins():
    obj_funcs = {"_a": _code_sym("_a"), "_b": _code_sym("_b")}
    records = {"_a": _code_sym("_a"), "_b": _code_sym("_b")}
    # Force _b -> _a even though auto-pairing would say _b -> _b.
    matches = []
    l_used, r_used = set(), set()
    mc.apply_symbol_mappings(obj_funcs, records, {"mappings": {"_b": "_a"}},
                             l_used, r_used, matches)
    assert matches == [("_b", "_a")]
    assert l_used == {"_b"} and r_used == {"_a"}


def test_apply_symbol_mappings_section_kind_gate():
    obj_funcs = {"_a": _code_sym("_a")}
    data_rec = {"size": 8, "flags": [], "section_kind": "data",
                "section_name": ".data", "bytes": "00" * 8, "relocs": {}}
    matches = []
    l_used, r_used = set(), set()
    mc.apply_symbol_mappings(obj_funcs, {"_d": data_rec}, {"mappings": {"_a": "_d"}},
                             l_used, r_used, matches)
    assert matches == []


def test_matching_symbols_mapping_blocks_auto_pair():
    # Mapped _a -> _b: the auto pass must not re-pair _a or _b.
    obj_funcs = {"_a": _code_sym("_a"), "_c": _code_sym("_c")}
    records = {"_a": _code_sym("_a"), "_b": _code_sym("_b"), "_c": _code_sym("_c")}
    matches = mc.matching_symbols(obj_funcs, records, {"mappings": {"_a": "_b"}})
    assert ("_a", "_b") in matches
    assert not any(r == "_a" for _, r in matches if _ != "_a")
    assert not any(l == "_b" for l, r in matches if r != "_b")


def test_match_summary_honors_mappings_config(tmp_path, monkeypatch, capsys):
    from ida_matcher.matcher.tests.conftest import build_synthetic_obj
    obj = tmp_path / "synthetic.obj"
    obj.write_bytes(build_synthetic_obj())
    monkeypatch.setattr(mc, "server_alive", lambda: True)
    mc.refresh_ida_cache = lambda: None

    def fake_many(names):
        return {
            "_fa": {"is_thunk": False, "bytes": "558be8000000", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
            "_fb": {"is_thunk": True, "bytes": "", "fixups": {}, "switches": {}, "section_name": ".text", "section_kind": "code"},
        }
    monkeypatch.setattr(mc, "fetch_many_from_ida", fake_many)

    # Without mappings _fa auto-pairs to itself (a non-thunk) -> "match".
    mc.match_summary(obj, json_out=True)
    data = json.loads(capsys.readouterr().out)
    assert {r["name"]: r["status"] for r in data["functions"]}["_fa"] == "match"

    # Forcing _fa -> _fb makes the (previously auto) pair hit the thunk path.
    mc.match_summary(obj, json_out=True, mappings_config={"mappings": {"_fa": "_fb"}})
    data = json.loads(capsys.readouterr().out)
    assert {r["name"]: r["status"] for r in data["functions"]}["_fa"] == "thunk"