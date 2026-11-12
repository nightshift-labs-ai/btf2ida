#!/usr/bin/env python3
"""Compare BTF layouts with an independent DWARF-derived Volatility ISF of the same kernel.

    python3 tests/check_against_dwarf.py vmlinux kernel.json.xz

Sizes and member byte offsets; for the named bitfield members of named structs also the bit position and
width, and the signedness btf2c.py gives the C bitfield (from the BTF) against the DWARF type's. The ISF
marks _Bool as signed (its own convention; a C _Bool bitfield reads 0 or 1), so _Bool is left out of
the signedness comparison and counted apart.
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
        root = json.load(handle)
    isf, base_types, enums = root["user_types"], root.get("base_types", {}), root.get("enums", {})
    gen = btf2c.Generator(data)
    both = size_bad = fields = field_bad = 0
    bitfields = bit_bad = signs = sign_bad = bools = 0
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
            result = [t.size == info.get("size"), 0, 0, 0, 0, 0, 0, 0]
            for m_name, m_type, offset in t.data:
                bit, width = gen.member_bits(t, offset, m_type)
                field = info.get("fields", {}).get(m_name)
                if not m_name or field is None:
                    continue
                result[1] += 1
                if field.get("offset") != bit // 8 and not width:
                    result[2] += 1
                if width and t.kind == B.STRUCT:  # bitfield: bit position (from the field's byte offset), width, sign
                    kind = field.get("type", {})
                    result[3] += 1
                    if kind.get("kind") != "bitfield" or field.get("offset", 0) * 8 + kind.get("bit_position", 0) != bit \
                            or kind.get("bit_length") != width:
                        result[4] += 1
                        continue
                    inner = kind.get("type", {})
                    base = inner.get("name") if inner.get("kind") == "base" else \
                        enums.get(inner.get("name"), {}).get("base") if inner.get("kind") == "enum" else None
                    if base_types.get(base, {}).get("kind") == "bool":
                        result[7] += 1
                    elif base in base_types:
                        result[5] += 1
                        result[6] += gen.bitfield_signed(m_type) != base_types[base].get("signed")
            key = (result[0], -result[2] - result[4] - result[6], result[1])
            if best is None or key > best[0]:
                best = (key, result)
        if best is None:
            continue
        ok, count, wrong = best[1][:3]
        size_bad += not ok
        fields += count
        field_bad += wrong
        bitfields, bit_bad, signs, sign_bad, bools = [a + b for a, b in zip((bitfields, bit_bad, signs, sign_bad, bools), best[1][3:])]
        if not ok or wrong or best[1][4] or best[1][6]:
            bad.append(name)
    print("types in both %d (BTF %d named, ISF %d); size mismatches %d; members compared %d; offset mismatches %d" % (both, len(by_name), len(isf), size_bad, fields, field_bad))
    print("bitfields compared %d; bit position or width mismatches %d; signedness compared %d, mismatches %d "
          "(_Bool left out: %d)" % (bitfields, bit_bad, signs, sign_bad, bools))
    print("first mismatches:", bad[:12])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python3 tests/check_against_dwarf.py <vmlinux> <kernel ISF .json.xz>")
    main()
