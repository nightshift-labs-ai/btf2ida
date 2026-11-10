#!/usr/bin/env python3
"""Checks ksymtab.py on a stripped vmlinux against the symbol table of the unstripped one.

    objcopy -S -R .comment vmlinux-dbg vmlinux-stripped
    python3 tests/check_ksymtab.py vmlinux-stripped vmlinux-dbg

Prints how many exported code addresses carry the same name in the debug symbol table, and how
many of those names have a BTF prototype (the prototypes btf2ida could apply with names alone).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import btf as B  # noqa: E402
import ksymtab  # noqa: E402


def symtab_names(blob):
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    shnum = struct.unpack_from("<H", blob, 0x3c)[0]
    secs = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + 64 * i) for i in range(shnum)]
    out = {}
    for s in secs:
        if s[1] != 2:
            continue
        strtab = secs[s[6]]
        for i in range(s[5] // 24):
            nm, info, _, _, value, _ = struct.unpack_from("<IBBHQQ", blob, s[4] + 24 * i)
            end = blob.index(b"\0", strtab[4] + nm)
            out.setdefault(blob[strtab[4] + nm:end].decode("ascii", "replace"), set()).add(value)
    return out


def main(stripped_path, debug_path):
    with open(stripped_path, "rb") as fh:
        stripped = fh.read()
    with open(debug_path, "rb") as fh:
        names = symtab_names(fh.read())
    found = ksymtab.exported(stripped)
    code = {a: n for a, (n, is_code) in found.items() if is_code}
    same = sum(1 for a, n in code.items() if a in names.get(n, ()))
    funcs = {t.name for t in B.load(stripped).own if t.kind == B.FUNC and t.name}
    print("exported symbols %d, in code %d" % (len(found), len(code)))
    print("code exports with the same (address, name) in the debug symtab: %d of %d" % (same, len(code)))
    print("code exports with a BTF prototype: %d" % len(set(code.values()) & funcs))
    return 0 if same >= 0.99 * len(code) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
