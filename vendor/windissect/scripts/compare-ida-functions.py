"""Compare windissect's recovered function starts and extents with an IDA export.

Usage: compare-ida-functions.py WINDISSECT_IR.json IDA_FUNCTIONS.json [--json OUT.json]

The IDA side comes from ida-export-functions.py. Both sides should be produced
without a PDB, so the comparison measures recovery from the binary alone.
"""

import argparse
import collections
import json


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def compare(ir, ida):
    symbols = {}
    for symbol in ir["symbols"]:
        if symbol.get("is_code") and symbol.get("rva") and symbol.get("forwarder") is None:
            symbols.setdefault(symbol["rva"], symbol)
    functions = {function["rva"]: function for function in ida["functions"]}

    matched = symbols.keys() & functions.keys()
    windissect_only = symbols.keys() - functions.keys()
    ida_only = functions.keys() - symbols.keys()

    # An extent is only claimed when the IR marks it as exact (procedure_size).
    claimed = [rva for rva in matched if symbols[rva].get("procedure_size")]
    identical = [rva for rva in claimed if symbols[rva]["size"] == functions[rva]["size"]]

    # Every matched start that carries a size, exact or derived by descent.
    sized = [rva for rva in matched if symbols[rva].get("size")]
    same_size = [rva for rva in sized if symbols[rva]["size"] == functions[rva]["size"]]

    def ratio(part, whole):
        return round(part / whole, 4) if whole else None

    return {
        "machine": ir["binary"].get("machine"),
        "ida_functions": len(functions),
        "windissect_functions": len(symbols),
        "matched_starts": len(matched),
        "recall": ratio(len(matched), len(functions)),
        "precision": ratio(len(matched), len(symbols)),
        "windissect_only": len(windissect_only),
        "ida_only": len(ida_only),
        "claimed_extents": len(claimed),
        "identical_extents": len(identical),
        "extent_agreement": ratio(len(identical), len(claimed)),
        "sized_matches": len(sized),
        "identical_sizes": len(same_size),
        "size_agreement": ratio(len(same_size), len(sized)),
        "matched_by_provenance": dict(
            collections.Counter(symbols[rva]["provenance"] for rva in matched).most_common()
        ),
        "windissect_only_by_provenance": dict(
            collections.Counter(symbols[rva]["provenance"] for rva in windissect_only).most_common()
        ),
        "ida_only_sample": [
            {"rva": rva, "size": functions[rva]["size"], "name": functions[rva]["name"]}
            for rva in sorted(ida_only)[:20]
        ],
        "extent_mismatch_sample": [
            {"rva": rva, "windissect": symbols[rva]["size"], "ida": functions[rva]["size"]}
            for rva in sorted(set(claimed) - set(identical))[:20]
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compare windissect's recovered functions with an IDA export."
    )
    parser.add_argument("ir")
    parser.add_argument("ida")
    parser.add_argument("--json", dest="output")
    args = parser.parse_args()

    result = compare(load(args.ir), load(args.ida))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")

    print(f"IDA functions:        {result['ida_functions']}")
    print(f"windissect functions: {result['windissect_functions']}")
    print(f"matched starts:       {result['matched_starts']}  recall {result['recall']}  precision {result['precision']}")
    print(f"windissect-only:      {result['windissect_only']}  {result['windissect_only_by_provenance']}")
    print(f"IDA-only:             {result['ida_only']}")
    print(f"exact extents:        {result['identical_extents']} of {result['claimed_extents']} identical")
    print(f"all sizes:            {result['identical_sizes']} of {result['sized_matches']} identical")


if __name__ == "__main__":
    main()
