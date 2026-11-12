#!/usr/bin/env python3
"""BTF2IDA without the IDA window, through idalib (IDA 9.0 or newer).

    python3 tools/btf2ida_headless.py <vmlinux or module.ko or memory export> [--vmlinux <vmlinux>] [--no-analysis]

Opens the file as an IDA database, runs the same import as the menu action (types, __ksymtab names, function
prototypes; for a module, split BTF on top of --vmlinux), prints the same summary and saves the database.
It calls the plugin's own run_import(). Not yet run with a real idalib: we have no IDA licence.

idalib setup (from Hex-Rays): install the idapro wheel shipped in <IDA>/idalib/python and run its
py-activate-idalib.py once, or set IDADIR to your IDA folder.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Apply BTF2IDA to a kernel file with idalib (no IDA window).")
    parser.add_argument("input", help="vmlinux, kernel module (.ko) or memory export to open in IDA")
    parser.add_argument("--vmlinux", help="the matching vmlinux, needed when the input carries split BTF (a module); for a whole kernel without BTF, a BTF file of the same build (raw BTF, vmlinux, or a BTFHub <release>.btf.tar.xz)")
    parser.add_argument("--no-analysis", action="store_true", help="skip IDA's auto-analysis (faster; fewer functions exist to receive prototypes)")
    args = parser.parse_args(argv)
    for path in (args.input, args.vmlinux):
        if path and not os.path.isfile(path):
            parser.error("no such file: %s" % path)

    try:
        import idapro  # must be imported before any ida_* module
    except ImportError as error:
        print("btf2ida_headless: idalib is not available (%s). It needs IDA 9.0 or newer; see the top of this file." % error, file=sys.stderr)
        return 2
    if idapro.open_database(args.input, not args.no_analysis) != 0:
        print("btf2ida_headless: IDA could not open %s" % args.input, file=sys.stderr)
        return 1
    try:
        import btf2ida_entry
        try:
            message = btf2ida_entry.run_import(args.vmlinux, ask=False)  # no dialogs without a window
        except btf2ida_entry.B.BTFError as error:
            print("btf2ida_headless: %s" % error, file=sys.stderr)
            return 3
        print(message)
        return 0
    finally:
        idapro.close_database(True)


if __name__ == "__main__":
    sys.exit(main())
