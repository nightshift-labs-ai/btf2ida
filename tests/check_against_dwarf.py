#!/usr/bin/env python3
"""Compare BTF layouts with an independent DWARF-derived Volatility ISF of the same kernel.

    python3 tests/check_against_dwarf.py vmlinux kernel.json.xz
"""
import json
import lzma
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import btf as B  # noqa: E402
import btf2c  # noqa: E402


def main():
    with open(sys.argv[1], "rb") as handle:
        data = B.load(handle.read())
    with lzma.open(sys.argv[2], "rt") as handle:
        isf = json.load(handle)["user_types"]
    gen = btf2c.Generator(data)
    both = size_bad = fields = field_bad = 0
    bad = []
    by_name = {}
    for t in data:
        if t.kind in (B.STRUCT, B.UNION) and t.name:
            by_name.setdefault(t.name, []).append(t)
    for name, types in by_name.items():
        info = isf.get(name)
        if info is None:
            continue
        both += 1
        # Same-named local structs exist: BTF keeps each, an ISF keeps one. Compare with the best match.
        best = None
        for t in types:
            if t.kind != (B.UNION if info.get("kind") == "union" else B.STRUCT):
                continue
            result = [t.size == info.get("size"), 0, 0]
            for m_name, m_type, offset in t.data:
                bit, width = gen.member_bits(t, offset, m_type)
                field = info.get("fields", {}).get(m_name)
                if not m_name or field is None:
                    continue
                result[1] += 1
                if field.get("offset") != bit // 8 and not width:
                    result[2] += 1
            key = (result[0], -result[2], result[1])
            if best is None or key > best[0]:
                best = (key, result)
        if best is None:
            continue
        ok, count, wrong = best[1]
        size_bad += not ok
        fields += count
        field_bad += wrong
        if not ok or wrong:
            bad.append(name)
    print("types in both %d (BTF %d named, ISF %d); size mismatches %d; members compared %d; offset mismatches %d" % (both, len(by_name), len(isf), size_bad, fields, field_bad))
    print("first mismatches:", bad[:12])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python3 tests/check_against_dwarf.py <vmlinux> <kernel ISF .json.xz>")
    main()
