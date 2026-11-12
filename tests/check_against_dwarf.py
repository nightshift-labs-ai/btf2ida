#!/usr/bin/env python3
"""Compare BTF layouts with an independent DWARF-derived Volatility ISF of the same kernel.

    python3 tests/check_against_dwarf.py vmlinux kernel.json.xz

First the kernel release in the input's 'Linux version' banner is compared with the ISF's (its linux_banner, else
the vmlinux-<release> name in its metadata): an ISF of another kernel is a failure, not a comparison. Raw BTF has
no banner, so there the release is not checked (and the output says so). Then sizes and member byte offsets; for the named bitfield members of named structs also the bit position and
width, and the signedness btf2c.py gives the C bitfield (from the BTF) against the DWARF type's. The ISF
marks _Bool as signed (its own convention; a C _Bool bitfield reads 0 or 1), so _Bool is left out of
the signedness comparison and counted apart.
Exit 0 when the releases match (or one is unknown) and every comparison agrees, 1 on any mismatch or when no type
was compared, 2 on bad arguments.
"""
import base64
import json
import lzma
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import btf as B  # noqa: E402
import btf2c  # noqa: E402


def isf_releases(root):
    """Kernel releases the ISF names: from its linux_banner constant, else from the vmlinux-<release> metadata names."""
    banner = root.get("symbols", {}).get("linux_banner", {}).get("constant_data")
    if banner:
        found = B.kernel_releases(base64.b64decode(banner))
        if found:
            return found
    names = [item.get("name", "") for item in root.get("metadata", {}).get("linux", {}).get("symbols", [])]
    return {name[len("vmlinux-"):] for name in names if name.startswith("vmlinux-")}


def main(argv):
    if len(argv) != 2:
        print("usage: python3 tests/check_against_dwarf.py <vmlinux> <kernel ISF .json.xz>", file=sys.stderr)
        return 2
    with open(argv[0], "rb") as handle:
        blob = handle.read()
    data = B.load(blob)
    with lzma.open(argv[1], "rt") as handle:
        root = json.load(handle)
    ours, theirs = B.kernel_releases(blob), isf_releases(root)
    if ours and theirs and not ours & theirs:
        print("kernel release %s, ISF release %s: DIFFERENT kernels, nothing compared"
              % (" / ".join(sorted(ours)), " / ".join(sorted(theirs))))
        return 1
    print("kernel release %s" % ("matches the ISF: " + " / ".join(sorted(ours & theirs)) if ours and theirs else
                                 "not checked (kernel: %s, ISF: %s)" % (" / ".join(sorted(ours)) or "no banner",
                                                                        " / ".join(sorted(theirs)) or "none named")))
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
    failed = both == 0 or size_bad or field_bad or bit_bad or sign_bad
    print("FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
