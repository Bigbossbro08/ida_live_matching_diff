"""Resolve the live IDA endpoint for the matcher client.

Priority:
1. ``IDA_MATCHER_URL`` -- explicit base URL (e.g. ``http://127.0.0.1:28100``).
2. A live **ida-cli** connector discovered from
   ``~/.ida-cli/instances/*.json`` (PID liveness + TCP probe).
3. Legacy default ``http://127.0.0.1:28000`` (the standalone ida_server.py).

Centralising this removes the hardcoded port from the client and lets the
matcher use whichever connector is actually running (ida-cli preferred).
"""

import json
import os
import socket
import sys
import time
from pathlib import Path

DEFAULT_BASE_URL = "http://127.0.0.1:28000"
_CACHE_TTL_SEC = 5.0
_cache = {"url": None, "ts": 0.0}


def _instances_dir() -> Path:
    override = os.environ.get("IDA_CLI_INSTANCES_DIR")
    return Path(override) if override else (Path.home() / ".ida-cli" / "instances")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return bool(ok) and exit_code.value == 259
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _probe(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def discover_ida_cli_base_url():
    """Return the base URL of the newest live ida-cli instance, or None."""
    instances_dir = _instances_dir()
    if not instances_dir.is_dir():
        return None
    candidates = []
    for path in instances_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            port = int(data.get("port", 0) or 0)
            pid = int(data.get("pid", 0) or 0)
        except Exception:
            continue
        if port <= 0 or pid <= 0 or not _pid_alive(pid):
            continue
        if not _probe("127.0.0.1", port):
            continue
        candidates.append((data.get("last_heartbeat", 0), port))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return f"http://127.0.0.1:{candidates[0][1]}"


class AmbiguousInstanceError(Exception):
    """Raised when several live ida-cli instances are present and strict mode is on."""


def discover_ida_cli_base_urls():
    """Return base URLs for all live ida-cli instances, newest first."""
    instances_dir = _instances_dir()
    if not instances_dir.is_dir():
        return []
    candidates = []
    for path in instances_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            port = int(data.get("port", 0) or 0)
            pid = int(data.get("pid", 0) or 0)
        except Exception:
            continue
        if port <= 0 or pid <= 0 or not _pid_alive(pid):
            continue
        if not _probe("127.0.0.1", port):
            continue
        candidates.append((data.get("last_heartbeat", 0), port))
    candidates.sort(reverse=True)
    return [f"http://127.0.0.1:{port}" for _, port in candidates]


def _ambiguity_strict() -> bool:
    return os.environ.get("IDA_MATCHER_AMBIGUITY_ERROR", "").strip().lower() in ("1", "true", "yes", "on")


def base_url(force_refresh: bool = False) -> str:
    env = os.environ.get("IDA_MATCHER_URL")
    if env:
        return env.rstrip("/")
    now = time.monotonic()
    if not force_refresh and _cache["url"] and (now - _cache["ts"]) < _CACHE_TTL_SEC:
        return _cache["url"]

    discovered_urls = discover_ida_cli_base_urls()
    if not discovered_urls:
        discovered = DEFAULT_BASE_URL
        # Warn once so a silent fallback to a dead legacy port is visible.
        if not _cache.get("warned_fallback"):
            sys.stderr.write(
                f"[ida-matcher] No live ida-cli instance discovered; falling back to "
                f"{DEFAULT_BASE_URL}. Start ida-cli inside IDA, or set IDA_MATCHER_URL.\n"
            )
            _cache["warned_fallback"] = True
    else:
        if len(discovered_urls) > 1 and _ambiguity_strict():
            raise AmbiguousInstanceError(
                "Multiple live ida-cli instances found (%s). Set IDA_MATCHER_URL to "
                "pin one, or unset IDA_MATCHER_AMBIGUITY_ERROR." % ", ".join(discovered_urls)
            )
        if len(discovered_urls) > 1 and not _cache.get("warned_ambiguous"):
            sys.stderr.write(
                f"[ida-matcher] {len(discovered_urls)} live ida-cli instances found; "
                f"using the newest ({discovered_urls[0]}). Set IDA_MATCHER_URL to pin one, "
                "or IDA_MATCHER_AMBIGUITY_ERROR=1 to fail instead.\n"
            )
            _cache["warned_ambiguous"] = True
        discovered = discovered_urls[0]
        _cache["warned_fallback"] = False
    _cache["url"] = discovered
    _cache["ts"] = now
    return discovered


def url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base_url() + path
