"""
ida_matcher.matcher.export_baseline
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Client-side tool that downloads a full baseline snapshot from the running
IDA server's ``GET /baseline`` endpoint and writes it to a JSON file.

Usage::

    python -m ida_matcher.matcher.export_baseline [--out baseline.json]
                                                   [--host 127.0.0.1]
                                                   [--port 28000]

The resulting ``baseline.json`` can later be fed to ``ida-match --baseline``
so matching runs fully offline (CI, no IDA needed).
"""
import json
import os
import sys
import argparse
import urllib.request

from ida_matcher.matcher import transport


def export_baseline(output_path, host=None, port=None):
    """GET /baseline from the live connector and write the snapshot to *output_path*.

    Endpoint resolution: explicit ``host``/``port`` -> ``transport`` (ida-cli
    discovery, then legacy ``:28000``). Returns the number of records written.
    """
    if host is not None or port is not None:
        base = f"http://{host or '127.0.0.1'}:{port or 28000}"
    else:
        base = transport.base_url()
    url = base + "/baseline"
    with urllib.request.urlopen(url, timeout=120) as response:
        raw = response.read()
    records = json.loads(raw.decode("utf-8"))
    with open(output_path, "w") as f:
        json.dump(records, f, indent=2)
    return len(records)


def main():
    parser = argparse.ArgumentParser(
        prog="export-baseline",
        description="Download a baseline snapshot from the IDA server.",
    )
    parser.add_argument(
        "--out", default="baseline.json", help="Output JSON path (default: baseline.json)"
    )
    parser.add_argument(
        "--host", default=None,
        help="Override host (default: auto-discover ida-cli, else 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Override port (default: auto-discover ida-cli, else 28000)"
    )
    args = parser.parse_args()

    out_path = os.path.abspath(args.out)
    try:
        count = export_baseline(out_path, host=args.host, port=args.port)
        print(f"Baseline exported: {count} records -> {out_path}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
