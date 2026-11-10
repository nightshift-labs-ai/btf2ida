"""Names of exported kernel symbols from __ksymtab, for kernels whose symbol table was stripped.

A distribution vmlinux (for example from scripts/extract-vmlinux) has no .symtab, but every
EXPORT_SYMBOL still has an entry in __ksymtab / __ksymtab_gpl that points at the symbol and at
its name in __ksymtab_strings. Since Linux 4.19 on x86-64 and arm64 the entries are 32-bit
place-relative offsets: (value, name) up to 5.3, (value, name, namespace) from 5.4; older kernels
store absolute pointers. Only 64-bit little-endian ELF files are read (x86-64 vmlinux).

    python3 ksymtab.py vmlinux     # prints address, kind, name

No dependencies; no IDA.
"""
import struct
import sys

SHF_WRITE, SHF_EXECINSTR = 1, 4
TABLES = (b"__ksymtab", b"__ksymtab_gpl")


def _sections(blob):
    if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF")
    if struct.unpack_from("<H", blob, 0x10)[0] not in (2, 3):
        return {}, []  # a .o/.ko holds unrelocated entries: no usable addresses
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3a)
    if not shoff or shentsize != 64 or shstrndx >= shnum:
        return {}, []
    raw = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + 64 * i) for i in range(shnum)]
    names_off = raw[shstrndx][4]
    out = {}
    for s in raw:
        end = blob.find(b"\0", names_off + s[0])
        out[blob[names_off + s[0]:end]] = s
    return out, raw


def _reader(strings, blob):
    lo, hi, off = strings[3], strings[3] + strings[5], strings[4]

    def name_at(addr):
        if not lo <= addr < hi:
            return None
        start = off + addr - lo
        end = blob.find(b"\0", start, off + strings[5])
        if end <= start:
            return None
        try:
            text = blob[start:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        return text if text.replace("_", "a").replace(".", "a").isalnum() else None
    return name_at


def _entries(table, blob, name_at):
    """Yield (value, name) for one table, trying the prel32 layout first, then absolute pointers."""
    base, data = table[3], blob[table[4]:table[4] + table[5]]
    for size, decode in (
            (12, lambda i, v, n: (base + i + v, base + i + 4 + n)),   # prel32 5.4+: value, name, namespace
            (8, lambda i, v, n: (base + i + v, base + i + 4 + n)),    # prel32 4.19-5.3: value, name
            (16, None), (24, None)):                                 # absolute: value, name[, namespace]
        if not data or len(data) % size:
            continue
        rows = []
        for i in range(0, len(data), size):
            if size in (8, 12):
                v, n = struct.unpack_from("<ii", data, i)
                value, name_addr = decode(i, v, n)
                value &= 0xFFFFFFFFFFFFFFFF
            else:
                value, name_addr = struct.unpack_from("<QQ", data, i)
            rows.append((value, name_at(name_addr)))
        good = sum(1 for _, n in rows if n)
        if good >= 0.95 * len(rows):
            return [(v, n) for v, n in rows if n]
    return []


def exported(blob):
    """Return {address: (name, is_code)} for every exported symbol found in __ksymtab*."""
    secs, raw = _sections(blob)
    strings = secs.get(b"__ksymtab_strings")
    if strings is None:
        return {}
    name_at = _reader(strings, blob)
    code = [(s[3], s[3] + s[5]) for s in raw if s[2] & SHF_EXECINSTR and not s[2] & SHF_WRITE and s[3]]
    out = {}
    for t in TABLES:
        if t in secs:
            for value, name in _entries(secs[t], blob, name_at):
                out.setdefault(value, (name, any(lo <= value < hi for lo, hi in code)))
    return out


def probe(blob, size=64):
    """(address, bytes) of the start of __ksymtab_strings, to check a database still maps the file the same way."""
    secs, _ = _sections(blob)
    strings = secs.get(b"__ksymtab_strings")
    if strings is None or not strings[5]:
        return None
    n = min(size, strings[5])
    return strings[3], bytes(blob[strings[4]:strings[4] + n])


def main(argv):
    with open(argv[1], "rb") as fh:
        found = exported(fh.read())
    for addr in sorted(found):
        name, is_code = found[addr]
        print("%#x\t%s\t%s" % (addr, "code" if is_code else "data", name))
    print("%d exported symbols, %d in code" % (len(found), sum(1 for n, c in found.values() if c)), file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
