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


def export_baseline(output_path, host="127.0.0.1", port=28000):
    """GET /baseline from the IDA server and write the snapshot to *output_path*.

    Returns the number of records written, or raises on failure.
    """
    url = f"http://{host}:{port}/baseline"
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
        "--host", default="127.0.0.1", help="IDA server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=28000, help="IDA server port (default: 28000)"
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
