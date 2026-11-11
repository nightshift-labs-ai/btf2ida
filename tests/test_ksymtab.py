#!/usr/bin/env python3
"""Synthetic ELFs for ksymtab.py: every __ksymtab entry layout, code vs data, and what must be refused.

    python3 -I tests/test_ksymtab.py

No kernel or IDA needed (tests/check_ksymtab.py compares against real kernels).
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import ksymtab

TEXT, DATA, WTEXT, TAB, STR = 0xffffffff81000000, 0xffffffff82000000, 0xffffffff83000000, 0xffffffff84000000, 0xffffffff85000000
SHF_ALLOC, SHF_WRITE, SHF_EXEC = 2, 1, 4


def elf(sections, kind=2):
    """sections: [(name, flags, address, data)] -> bytes of a 64-bit little-endian ELF."""
    names = b"\0" + b"".join(n + b"\0" for n, _, _, _ in sections) + b".shstrtab\0"
    body, offsets = bytearray(), []
    for _, _, _, data in sections:
        offsets.append(64 + len(body)); body += data
    shstr_off = 64 + len(body); body += names
    shoff = 64 + len(body)
    head = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
    head += struct.pack("<HHIQQQIHHHHHH", kind, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections) + 2, len(sections) + 1)
    table = bytearray(b"\0" * 64)
    pos = 1
    for (name, flags, addr, data), off in zip(sections, offsets):
        table += struct.pack("<IIQQQQIIQQ", pos, 1, flags, addr, off, len(data), 0, 0, 8, 0); pos += len(name) + 1
    table += struct.pack("<IIQQQQIIQQ", pos, 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0)
    return bytes(head + body + table)


strings = b"\0func_a\0data_b\0wfunc_c\0ns\0"
def at(name):
    return STR + strings.index(name.encode() + b"\0")
symbols = [(TEXT + 0x10, "func_a"), (DATA + 0x20, "data_b"), (WTEXT + 0x30, "wfunc_c")]
code = [(b".text", SHF_ALLOC | SHF_EXEC, TEXT, b"\x90" * 0x100), (b".data", SHF_ALLOC | SHF_WRITE, DATA, b"\0" * 0x100),
        (b".wtext", SHF_ALLOC | SHF_EXEC | SHF_WRITE, WTEXT, b"\x90" * 0x100), (b"__ksymtab_strings", SHF_ALLOC, STR, strings)]
want = {TEXT + 0x10: ("func_a", True), DATA + 0x20: ("data_b", False), WTEXT + 0x30: ("wfunc_c", False)}


def prel32(size):
    out = bytearray()
    for index, (value, name) in enumerate(symbols):
        place = TAB + size * index
        out += struct.pack("<ii", value - place, at(name) - (place + 4))
        if size == 12:
            out += struct.pack("<i", at("ns") - (place + 8))
    return bytes(out)


def absolute(size):
    out = bytearray()
    for value, name in symbols:
        out += struct.pack("<QQ", value, at(name)) + (struct.pack("<Q", at("ns")) if size == 24 else b"")
    return bytes(out)


for label, table in (("prel32 5.4+", prel32(12)), ("prel32 4.19-5.3", prel32(8)), ("absolute", absolute(16)), ("absolute+ns", absolute(24))):
    blob = elf(code + [(b"__ksymtab", SHF_ALLOC, TAB, table)])
    got = ksymtab.exported(blob)
    assert got == want, (label, got)
# GPL table read too; a name pointing outside __ksymtab_strings is dropped, not guessed.
gpl = elf(code + [(b"__ksymtab_gpl", SHF_ALLOC, TAB, prel32(12))])
assert ksymtab.exported(gpl) == want
bad = bytearray(prel32(12)); struct.pack_into("<i", bad, 4, 0x7fff0000)
assert ksymtab.exported(elf(code + [(b"__ksymtab", SHF_ALLOC, TAB, bytes(bad))])) == {}  # 2 of 3 names (< 95%): layout refused
# A relocatable object (.o/.ko) has unrelocated entries: nothing is returned.
assert ksymtab.exported(elf(code + [(b"__ksymtab", SHF_ALLOC, TAB, prel32(12))], kind=1)) == {}
# No strings section: nothing. Not an ELF: a clear error.
assert ksymtab.exported(elf(code[:3] + [(b"__ksymtab", SHF_ALLOC, TAB, prel32(12))])) == {}
try:
    ksymtab.exported(b"MZ" + b"\0" * 100)
except ValueError as error:
    assert "64-bit little-endian ELF" in str(error)
else:
    raise AssertionError("non-ELF accepted")
# probe(): address and first bytes of __ksymtab_strings.
assert ksymtab.probe(gpl, 8) == (STR, strings[:8])
print("ksymtab tests OK (4 layouts, GPL table, code vs data vs writable code, refusals, probe)")
