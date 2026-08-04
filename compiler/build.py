"""
tools.compiler.build
~~~~~~~~~~~~~~~~~~~~
Thin wrapper around build.cmd that exposes two build modes:

  build_dll()           – Premake5 + MSBuild → DLL (Debug/Release)
  build_obj_for_match() – MSVC 6.3 via build.cmd --mode obj → .obj for matching
  get_obj_path()        – returns the expected .obj location without building
"""

import os
import subprocess
import pathlib
from typing import Literal


def _repo_root() -> pathlib.Path:
    """Walk up from this file to find the repository root (contains build.cmd)."""
    here = pathlib.Path(__file__).resolve().parent
    for ancestor in [here] + list(here.parents):
        if (ancestor / "build.cmd").exists():
            return ancestor
    # Fallback: assume we are two levels below the root (tools/compiler/)
    return here.parent.parent


def _run_cmd(cmd: list[str], cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess:
    """
    Centralised runner.
    Prints stdout/stderr and raises RuntimeError on non-zero exit.
    Uses shell=True because build.cmd is a Windows batch file.
    """
    if cwd is None:
        cwd = _repo_root()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=True,
        cwd=cwd,
    )
    if result.stdout:
        print(result.stdout)
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr)
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}"
        )
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_dll(config: Literal["Debug", "Release"] = "Debug") -> bool:
    """
    Build the hook DLL via Premake5 + MSBuild.

    Parameters
    ----------
    config : "Debug" or "Release"

    Returns
    -------
    True on success.

    Raises
    ------
    RuntimeError if the build fails.
    """
    root = _repo_root()
    _run_cmd(["build.cmd", "--mode", "dll", "--config", config], cwd=root)
    return True


def build_obj_for_match(
    cpp_path: str | os.PathLike,
    all_files: bool = False,
) -> bool:
    """
    Compile a source file (or all files) to .obj for binary matching.

    Uses the exact MSVC 6.3 toolchain via ``build.cmd --mode obj``.

    Parameters
    ----------
    cpp_path : str or Path
        Relative (to repo root) or absolute path to the .cpp file.
    all_files : bool
        If True, pass no file argument so build.cmd compiles everything.

    Returns
    -------
    True on success.

    Raises
    ------
    RuntimeError if the build fails.
    """
    root = _repo_root()
    cmd = ["build.cmd", "--mode", "obj"]
    if not all_files:
        cmd.append(str(cpp_path))
    _run_cmd(cmd, cwd=root)
    return True


def get_obj_path(cpp_path: str | os.PathLike) -> pathlib.Path:
    """
    Return the expected .obj file path for a given .cpp source file,
    without actually building anything.

    >>> get_obj_path("age2_x1/basegame.cpp")
    PosixPath('.../build/BinaryMatching/basegame.obj')
    """
    root = _repo_root()
    stem = pathlib.Path(cpp_path).stem
    return root / "build" / "BinaryMatching" / f"{stem}.obj"
