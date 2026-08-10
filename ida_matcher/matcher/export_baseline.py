import ida_funcs
import ida_name
import ida_bytes
import idautils
import json
import os
import argparse

def export_baseline(output_path):
    print(f"Exporting baseline functions to {output_path}...")
    functions = {}
    
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        name = ida_name.get_name(ea)
        
        # Skip compiler-generated or generic subroutines if desired,
        # but for now we export everything that has a name.
        if name and not name.startswith("sub_"):
            # Get function bytes
            size = func.end_ea - func.start_ea
            # Read bytes using ida_bytes
            try:
                raw_bytes = ida_bytes.get_bytes(func.start_ea, size)
                if raw_bytes:
                    hex_bytes = raw_bytes.hex()
                    functions[name] = {
                        "ea": hex(func.start_ea),
                        "size": size,
                        "bytes": hex_bytes
                    }
            except Exception as e:
                print(f"Failed to read {name}: {e}")

    try:
        with open(output_path, "w") as f:
            json.dump(functions, f, indent=2)
        print(f"Successfully exported {len(functions)} functions")
    except Exception as e:
        print(f"Failed to write JSON: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export IDA baseline functions")
    parser.add_argument("--out", default="baseline.json", help="Output JSON path")
    args = parser.parse_args()
    
    out_path = os.path.abspath(args.out)
    export_baseline(out_path)
