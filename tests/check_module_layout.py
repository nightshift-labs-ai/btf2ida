#!/usr/bin/env python3
"""The fake database of tests/check_module.py keeps the module's functions and its extern segment apart, also for a
file with more functions than fit below the old fixed extern address (0x900000, reached after 147,392 functions at
0x40 apart; a stripped kernel whose symbols vmlinux-to-elf restored can have more). Builds small synthetic ELF symbol tables; needs only Python 3.

    python3 tests/check_module_layout.py
"""
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_module  # noqa: E402

SEG_XTRN, SEG_CODE = 1, 2


def synthetic_elf(n_functions, n_imports):
    """A 64-bit little-endian ELF with only a .symtab and a .strtab: n_functions STT_FUNC symbols defined in section 1
    and n_imports undefined symbols."""
    strtab, symbols = bytearray(b"\0"), [bytes(24)]
    for i in range(n_functions + n_imports):
        imported = i >= n_functions
        name = ("imp_%d" if imported else "fn_%d") % i
        symbols.append(struct.pack("<IBBHQQ", len(strtab), 0x12 if not imported else 0x10, 0, 0 if imported else 1,
                                   0, 0))
        strtab += name.encode() + b"\0"
    symtab = b"".join(symbols)
    sym_off = 64
    str_off = sym_off + len(symtab)
    sh_off = str_off + len(strtab)
    sh_off += -sh_off % 8
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 0x28, sh_off)
    struct.pack_into("<HHH", header, 0x3a, 64, 3, 0)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sym_off, len(symtab), 2, 1, 8, 24),  # .symtab, link -> 2
                struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)]   # .strtab
    blob = bytes(header) + symtab + bytes(strtab)
    return blob + bytes(sh_off - len(blob)) + b"".join(sections)


def check(n_functions, n_imports):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "synthetic.ko")
        with open(path, "wb") as handle:
            handle.write(synthetic_elf(n_functions, n_imports))
        functions, externs, _ = check_module.fake_database(path, path)
    segtype = sys.modules["ida_segment"].segtype
    assert len(functions) == n_functions and len(externs) == n_imports, (len(functions), len(externs))
    in_xtrn = [n for n, ea in functions.items() if segtype(ea) != SEG_CODE]
    assert not in_xtrn, "%d of %d functions fall in the extern segment, first %s at 0x%X" % (
        len(in_xtrn), n_functions, in_xtrn[0], functions[in_xtrn[0]])
    assert all(segtype(ea) == SEG_XTRN for ea in externs.values()), "an import outside the extern segment"
    addresses = list(functions.values()) + list(externs.values())
    assert len(set(addresses)) == len(addresses), "two symbols share an address"
    print("OK %d functions, %d imports: functions below the extern segment, imports in it" % (n_functions, n_imports))


if __name__ == "__main__":
    for n_functions, n_imports in ((3, 2), (147_392, 3), (147_393, 3), (200_000, 7)):
        check(n_functions, n_imports)
