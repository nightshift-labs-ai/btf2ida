#!/usr/bin/env python3
"""Layout proof, with gcc, for the C bitfields btf2c.py writes, on real BTF.

    python3 tests/check_bitfields.py vmlinux
    python3 tests/check_bitfields.py nf_tables.ko --base vmlinux

btf2c.py cuts each group of adjacent bitfields, at byte boundaries no bitfield crosses, into runs of 1, 2, 4 or
8 bytes written as C bitfields that fill an integer of that size exactly (other runs stay raw bytes). This
script finds every bitfield group in the emitted types itself, from the BTF (outer named types and the
anonymous structs and unions written inline in them), asks the generator how it cuts each group
(Generator.bitfield_runs: which bitfields it writes as C bitfields is its decision, not repeated here), and
checks the header btf2c.py writes for that kernel:

(a) for each group with C bitfields: sizeof the outer type, and offsetof the next named member that
    is not a bitfield, as _Static_asserts with the BTF's numbers. They are compiled against the new header
    and against the raw-byte header (Generator(bitfields=False), the earlier form), so neither moved.
(b) for each of its bitfields: a C program sets the field through the struct and compares the struct's bytes
    with bytes computed here from the BTF bit offset and size (little-endian, as BTF counts them: bit n of
    the struct is bit n % 8 of byte n / 8), with memcmp, and checks that all other bytes are untouched.
    Four cases per field: background 0x00 and 0xFF, each with two complementary values (the first has the
    field's top bit set). It also reads the field back: a signed field (signed BTF int, or an enum BTF marks
    signed) must read back negative with its top bit set, an unsigned one positive.

The program is compiled and run with gcc twice: with GCC's own bitfield rules, and with -mms-bitfields
(GCC's implementation of the Microsoft rules). This checks gcc's layout of the header only: how IDA lays
out the same declarations has not been checked. It also counts what is not converted (groups of other
runs, bitfields directly in a union) and compares every count with the generator's own statistics.
Prints the counts; exit 0 when everything passes (also when nothing is written as C bitfields, for example for
big-endian BTF: it then prints NOTHING TO CHECK), 1 otherwise, 2 on bad arguments or an input without usable BTF.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import btf as B  # noqa: E402
import btf2c  # noqa: E402

def resolved(btf, type_id):
    """The type behind modifiers and typedefs (None for void)."""
    while type_id:
        t = btf[type_id]
        if t.kind not in (B.CONST, B.VOLATILE, B.RESTRICT, B.TYPE_TAG, B.TYPEDEF):
            return t
        type_id = t.ref
    return None


def bits(btf, parent, offset, type_id):
    """(bit offset, width or 0) of a member, decoded here from the BTF rather than through btf2c."""
    if parent.kflag:  # bitfield size in the top 8 bits of the offset
        return offset & 0xFFFFFF, offset >> 24
    t = resolved(btf, type_id)  # older BTF: the width and extra offset are in the int's encoding
    if t is not None and t.kind == B.INT and (t.data & 0xFF) != t.size * 8:
        return offset + ((t.data >> 16) & 0xFF), t.data & 0xFF
    return offset, 0


def signed_of(btf, type_id):
    """Signedness from the BTF: int encoding (bool is unsigned; `signed char`, which old pahole encodes 0, is
    signed), or the enum's signed flag; None otherwise."""
    t = resolved(btf, type_id)
    if t is not None and t.kind == B.INT:
        return bool((t.data >> 24) & B.INT_SIGNED or t.name == "signed char") and not (t.data >> 24) & B.INT_BOOL
    if t is not None and t.kind in (B.ENUM, B.ENUM64):
        return bool(t.kflag)
    return None


class Walk:
    """Every bitfield of every emitted type, with its C access path and absolute bit offset."""

    def __init__(self, gen):
        self.gen, self.btf = gen, gen.btf
        self.groups = []  # ((outer kind, outer tag), C path of the scope, its byte offset, C bitfields, next member or None)
        self.integers = 0  # runs written as C bitfields (one integer each)
        self.raw_runs = 0
        self.raw_fields = 0
        self.union_fields = 0
        self.dropped = 0

    def outer(self, t):
        kind = "union" if t.kind == B.UNION else "struct"
        self.scope(t, (kind, self.gen.tags[t.id]), "", 0)

    def scope(self, t, outer, path, base):
        gen = self.gen
        if t.kind == B.UNION:
            for name, m_type, offset in t.data:
                bit, width = bits(self.btf, t, offset, m_type)
                if width:
                    self.union_fields += 1
                elif gen.size_of(m_type) and not gen.opaque(m_type) and gen.nested(gen.strip(m_type)):
                    self.scope(gen.strip(m_type), outer, path + ("." + btf2c.ident(name) if name else ""), base + bit // 8)
            return
        items = sorted(t.data, key=lambda m: bits(self.btf, t, m[2], m[1])[0])
        cursor, index = 0, 0
        while index < len(items):
            name, m_type, offset = items[index]
            bit, width = bits(self.btf, t, offset, m_type)
            if width:
                start, end, fields = bit // 8, (bit + width + 7) // 8, []
                while index < len(items):
                    o_bit, o_width = bits(self.btf, t, items[index][2], items[index][1])
                    if not o_width or o_bit // 8 > end:
                        break
                    end = max(end, (o_bit + o_width + 7) // 8)
                    fields.append((items[index][0], o_bit, o_width, items[index][1]))
                    index += 1
                if start < cursor:
                    self.dropped += len(fields)
                    continue
                cursor = end
                # Which bitfields become C bitfields is the generator's decision, asked here rather than copied, so a
                # wrong decision (an overlap converted, say) reaches the gcc checks below instead of being repeated.
                converted = []
                for _, _, part, ok in gen.bitfield_runs(fields, start, end):
                    if ok:
                        self.integers += 1
                        converted += part
                    else:
                        self.raw_runs += 1
                        self.raw_fields += len(part)
                if converted:
                    self.groups.append((outer, path, base, converted, self.next_member(t, items[index:], path, base)))
                continue
            index += 1
            size = gen.size_of(m_type)
            if not size:
                continue
            if bit // 8 < cursor:
                self.dropped += 1
                continue
            cursor = bit // 8 + size
            inner = gen.strip(m_type)
            if not gen.opaque(m_type) and gen.nested(inner):
                self.scope(inner, outer, path + ("." + btf2c.ident(name) if name else ""), base + bit // 8)

    def next_member(self, t, rest, path, base):
        """(C path, absolute byte offset) of the first named non-bitfield member after a group, or None."""
        for name, m_type, offset in rest:
            bit, width = bits(self.btf, t, offset, m_type)
            if width or not self.gen.size_of(m_type):
                continue
            inner = self.gen.strip(m_type)
            if name:
                return path + "." + btf2c.ident(name), base + bit // 8
            if self.gen.nested(inner) and inner.kind == B.STRUCT:  # anonymous: its members are the outer's members
                found = self.next_member(inner, sorted(inner.data, key=lambda m: bits(self.btf, inner, m[2], m[1])[0]),
                                         path, base + bit // 8)
                if found:
                    return found
            return None
        return None


def c_value(value, width, signed):
    if signed and value >> (width - 1):
        value -= 1 << width
        return "(-0x%xLL - 1)" % (-value - 1)
    return "0x%xULL" % value


def expected(bit, width, value, background):
    """Bytes lo..hi of the struct after the field at `bit` is set to `value` on a background byte."""
    lo, hi = bit // 8, (bit + width + 7) // 8
    out = bytearray([background] * (hi - lo))
    for i in range(width):
        at = bit + i - lo * 8
        if value >> i & 1:
            out[at // 8] |= 1 << (at % 8)
        else:
            out[at // 8] &= ~(1 << (at % 8)) & 0xFF
    return lo, bytes(out)


CHECK = r"""
/* No #include: the kernel header defines size_t and friends itself. Names start with __cb_ to stay clear of it. */
static long __cb_checks, __cb_failures;
static void __cb_check(const char *what, const void *object, unsigned long size, int background, unsigned long lo,
                       const unsigned char *want, unsigned long n, int read_back)
{
    const unsigned char *p = object;
    unsigned long i;
    int bad = !read_back || __builtin_memcmp(p + lo, want, n) != 0;
    for (i = 0; i < size && !bad; i++)
        if ((i < lo || i >= lo + n) && p[i] != (unsigned char)background)
            bad = 1;
    __cb_checks++;
    if (bad && ++__cb_failures <= 20)
        __builtin_printf("FAIL %s (read back %s)\n", what, read_back ? "ok" : "wrong");
}
"""


def build(gen, walk, header_name):
    """(asserts C text, runtime C text, number of asserts, fields checked, signed fields)."""
    asserts, objects, funcs = [], {}, []
    fields_checked = signed_fields = 0
    sizes = {("union" if t.kind == B.UNION else "struct", gen.tags[t.id]): t.size
             for t in gen.btf if t.kind in (B.STRUCT, B.UNION) and t.id in gen.done}
    for number, (outer, path, base, fields, nxt) in enumerate(walk.groups):
        kind, tag = outer
        what = "%s %s" % (kind, tag)
        asserts.append("_Static_assert(sizeof(%s) == %d, \"%s size\");" % (what, sizes[outer], tag))
        if nxt:
            asserts.append("_Static_assert(__builtin_offsetof(%s, %s) == %d, \"%s%s\");" % (what, nxt[0][1:], nxt[1], tag, nxt[0]))
        obj = objects.setdefault(what, "__cb_o%d" % len(objects))
        lines = []
        for name, bit, width, type_id in fields:
            if not name:
                continue
            signed = signed_of(gen.btf, type_id)
            fields_checked += 1
            signed_fields += signed
            absolute = base * 8 + bit
            mask = (1 << width) - 1
            first = (0x5555555555555555 & mask) | 1 << (width - 1)
            access = "%s%s.%s" % (obj, path, btf2c.ident(name))
            for background, value in ((0, first), (0xFF, first ^ mask), (0, first ^ mask), (0xFF, first)):
                lo, want = expected(absolute, width, value, background)
                read = "(long long)%s == %s" % (access, c_value(value, width, signed)) if signed else \
                       "(unsigned long long)%s == %s" % (access, c_value(value, width, False))
                lines.append("  __builtin_memset(&%s, 0x%02x, sizeof %s); %s = %s;" % (obj, background, obj, access, c_value(value, width, signed)))
                lines.append("  __cb_check(\"%s%s.%s bg %02x value %#x\", &%s, sizeof %s, 0x%02x, %d, (const unsigned char[]){%s}, %d, %s);"
                             % (tag, path, name, background, value, obj, obj, background, lo,
                                ",".join("0x%02x" % b for b in want), len(want), read))
        funcs.append("static void __cb_group%d(void)\n{\n%s\n}\n" % (number, "\n".join(lines)))
    head = '#include "%s"\n' % header_name
    runtime = (head + CHECK + "".join("static %s %s;\n" % (what, obj) for what, obj in objects.items()) + "\n".join(funcs)
               + "int main(void)\n{\n%s  __builtin_printf(\"bitfield checks %%ld, failures %%ld\\n\", __cb_checks, __cb_failures);\n  return __cb_failures != 0;\n}\n"
               % "".join("  __cb_group%d();\n" % n for n in range(len(walk.groups))))
    return head + "\n".join(asserts) + "\n", runtime, len(asserts), fields_checked, signed_fields


def run(cmd, label):
    result = subprocess.run(cmd, capture_output=True, text=True)
    errors = len(re.findall(r"error:", result.stderr))
    print("%s: exit %d, %d errors" % (label, result.returncode, errors))
    if result.returncode:
        print(result.stderr[:2000] + result.stdout[:2000])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="kernel ELF, raw BTF or anything btf2c.py reads")
    parser.add_argument("--base", help="vmlinux, for a kernel module's split BTF")
    parser.add_argument("--keep", help="write the generated files to this folder instead of a temporary one")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.input) or (args.base and not os.path.isfile(args.base)):
        print("usage: python3 tests/check_bitfields.py <kernel or BTF file> [--base vmlinux] [--keep DIR]", file=sys.stderr)
        return 2
    try:
        with open(args.input, "rb") as handle:
            blob = B.unpack_kernel_image(handle.read(), args.input)
        base = None
        if args.base:
            with open(args.base, "rb") as handle:
                base = B.load_base(B.unpack_kernel_image(handle.read(), args.base), args.base)
        data = B.load(blob, base=base)
    except B.BTFError as error:  # NeedsBase and BaseMismatch too: a module without --base, a wrong base
        print("check_bitfields: %s: %s\nusage: python3 tests/check_bitfields.py <kernel or BTF file> [--base vmlinux] [--keep DIR]"
              % (args.input, error), file=sys.stderr)
        return 2
    gen = btf2c.Generator(data)
    new = btf2c.header(gen)
    old = btf2c.header(btf2c.Generator(data, bitfields=False))
    walk = Walk(gen)
    for t in data:
        if t.kind in (B.STRUCT, B.UNION) and t.id in gen.done and t.size and not gen.base_only(t):
            walk.outer(t)
    converted_fields = sum(len(g[3]) for g in walk.groups)
    folder = args.keep or tempfile.mkdtemp(prefix="check_bitfields_")
    os.makedirs(folder, exist_ok=True)
    for name, text in (("new.h", new), ("old.h", old)):
        with open(os.path.join(folder, name), "w", encoding="utf-8") as handle:
            handle.write(text)
    asserts_new, runtime, n_asserts, fields_checked, signed_fields = build(gen, walk, "new.h")
    with open(os.path.join(folder, "asserts_new.c"), "w", encoding="utf-8") as handle:
        handle.write(asserts_new)
    with open(os.path.join(folder, "asserts_old.c"), "w", encoding="utf-8") as handle:
        handle.write(asserts_new.replace('#include "new.h"', '#include "old.h"', 1))
    with open(os.path.join(folder, "runtime.c"), "w", encoding="utf-8") as handle:
        handle.write(runtime)
    stats = gen.stats
    print("%s: bitfields written as C bitfields %d (in %d integers, %d groups), kept as raw bytes %d (in %d runs); "
          "bitfields directly in a union (raw) %d; dropped (overlap) %d"
          % (args.input, converted_fields, walk.integers, len(walk.groups), walk.raw_fields, walk.raw_runs, walk.union_fields, walk.dropped))
    print("generator statistics: %s" % {k: stats[k] for k in ("bitfields", "bitfield_integers", "bitfields_as_storage", "bitfield_raw_runs", "dropped_members")})
    ok = (converted_fields, walk.integers, walk.raw_fields + walk.union_fields, walk.raw_runs) == \
        (stats["bitfields"], stats["bitfield_integers"], stats["bitfields_as_storage"], stats["bitfield_raw_runs"])
    print("counts agree with the generator: %s" % ("yes" if ok else "NO"))
    print("fields checked: %d (%d signed), %d asserts (sizeof + offsetof of the next named member)" % (fields_checked, signed_fields, n_asserts))
    gcc = ["gcc", "-include", "stdbool.h", "-w"]
    results = [run(gcc + ["-fsyntax-only", os.path.join(folder, "asserts_new.c")], "asserts against the new header"),
               run(gcc + ["-fsyntax-only", os.path.join(folder, "asserts_old.c")], "asserts against the raw-byte header"),
               run(gcc + ["-fsyntax-only", "-mms-bitfields", os.path.join(folder, "asserts_new.c")], "asserts against the new header, -mms-bitfields")]
    for flags, label in (([], "gcc"), (["-mms-bitfields"], "gcc -mms-bitfields")):
        exe = os.path.join(folder, "runtime" + ("_ms" if flags else ""))
        built = run(gcc + flags + ["-O1", "-o", exe, os.path.join(folder, "runtime.c")], "build runtime test (%s)" % label)
        results.append(built)
        if built.returncode == 0:
            ran = subprocess.run([exe], capture_output=True, text=True)
            print("run (%s): %s" % (label, ran.stdout.strip().replace("\n", "\n  ")))
            results.append(ran)
    passed = ok and all(r.returncode == 0 for r in results)
    if passed and not fields_checked:  # big-endian BTF, or no group btf2c writes as C bitfields: only the header compiled
        print("NOTHING TO CHECK: no bitfield is written as a C bitfield for this input (the header compiles)")
    else:
        print("PASS" if passed else "FAIL")
    if not args.keep and passed:
        for name in os.listdir(folder):
            os.unlink(os.path.join(folder, name))
        os.rmdir(folder)
    elif not passed:
        print("generated files kept in %s" % folder)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
