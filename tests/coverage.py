#!/usr/bin/env python3
"""Prototype coverage of a kernel ELF with symbols, outside IDA (the README's demo figure).

    python3 tests/coverage.py kernel.elf

Counts the FUNC symbols whose name has no compiler suffix ('.isra', '.cold', ...), no __pfx_ padding
prefix and is not one of MemLens' planted memlens_target_* hooks, and how many of those names have a
prototype in the file's own BTF. On the MemLens demo kernel.elf (SHA-256 79a64158...) it prints
50,366 prototypes and 46,900 of 51,092 (91.8%).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import btf as B  # noqa: E402
import btf2c  # noqa: E402
from check_module import elf_symbols  # noqa: E402


def main(argv):
    if len(argv) != 1 or not os.path.isfile(argv[0]):
        print("usage: python3 tests/coverage.py <kernel.elf>", file=sys.stderr)
        return 2
    with open(argv[0], "rb") as handle:
        blob = handle.read()
    names = {name for name, kind, shndx in elf_symbols(blob)
             if kind == 2 and shndx != 0 and "." not in name
             and not name.startswith("__pfx_") and not name.startswith("memlens_target_")}
    generator = btf2c.Generator(B.load(blob))
    generator.declarations()
    prototypes = {name for name, _ in generator.prototypes()}
    covered = len(names & prototypes)
    print("prototypes in the BTF: %d" % len(prototypes))
    print("function symbols with a prototype: %d of %d (%.1f%%)" % (covered, len(names), 100.0 * covered / max(len(names), 1)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
