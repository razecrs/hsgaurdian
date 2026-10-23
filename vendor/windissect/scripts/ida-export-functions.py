"""Export IDA's analyzed function boundaries as JSON for mechanical comparison."""

import json

import ida_auto
import ida_funcs
import ida_nalt
import ida_pro
import idautils
import idc


def main() -> None:
    if len(idc.ARGV) != 2:
        raise RuntimeError("usage: ida-export-functions.py OUTPUT.json")

    ida_auto.auto_wait()
    image_base = ida_nalt.get_imagebase()
    functions = []
    for address in idautils.Functions():
        function = ida_funcs.get_func(address)
        if function is None:
            continue
        functions.append(
            {
                "rva": function.start_ea - image_base,
                "start_ea": function.start_ea,
                "end_ea": function.end_ea,
                "size": function.end_ea - function.start_ea,
                "name": ida_funcs.get_func_name(function.start_ea),
                "flags": function.flags,
            }
        )

    document = {
        "analyzer": "IDA Professional 9.4",
        "pdb_disabled": True,
        "image_base": image_base,
        "function_count": len(functions),
        "functions": functions,
    }
    with open(idc.ARGV[1], "w", encoding="utf-8") as output:
        json.dump(document, output, indent=2, sort_keys=True)
        output.write("\n")
    print(f"exported {len(functions)} IDA functions to {idc.ARGV[1]}")


try:
    main()
except Exception as error:
    print(f"IDA export failed: {error!r}")
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
