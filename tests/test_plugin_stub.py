#!/usr/bin/env python3
"""Runs the plugin against FAKE ida_* modules with a small hand-built BTF.

Checks our logic only: this is not a test in real IDA.
"""
import os
import struct
import subprocess
import sys
import tempfile
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


class Build:
    def __init__(self):
        self.strs = b"\0"
        self.types = b""

    def s(self, text):
        if not text:
            return 0
        offset = len(self.strs)
        self.strs += text.encode() + b"\0"
        return offset

    def t(self, name, kind, vlen, size_or_type, extra=b"", kflag=0):
        self.types += struct.pack("<III", self.s(name), (kflag << 31) | (kind << 24) | vlen, size_or_type) + extra

    def blob(self):
        return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(self.types), len(self.types), len(self.strs)) + self.types + self.strs


def tiny_rel(sections):
    """A minimal ELF64 little-endian relocatable file: the given sections (name or (name, content)) and a .shstrtab."""
    sections = [(item, b"") if isinstance(item, bytes) else item for item in sections]
    names = b"\0" + b"".join(n + b"\0" for n, _ in sections) + b".shstrtab\0"
    payload = names + b"".join(content for _, content in sections)
    shoff = (64 + len(payload) + 7) & ~7
    headers, at, offset = [bytes(64)], 1, 64 + len(names)
    for n, content in sections:
        headers.append(struct.pack("<IIQQQQIIQQ", at, 1, 0, 0, offset, len(content), 0, 0, 1, 0))
        at, offset = at + len(n) + 1, offset + len(content)
    headers.append(struct.pack("<IIQQQQIIQQ", at, 3, 0, 0, 64, len(names), 0, 0, 1, 0))
    ehdr = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), len(headers) - 1)
    return ehdr + payload + bytes(shoff - 64 - len(payload)) + b"".join(headers)


b = Build()
b.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                   # 1
b.t("", 2, 0, 5)                                                                      # 2  struct task *
b.t("", 13, 1, 1, struct.pack("<II", b.s("arg"), 2))                                  # 3  int (struct task *)
b.t("", 2, 0, 3)                                                                      # 4  fn pointer
b.t("task", 4, 4, 32, kflag=1, extra=struct.pack(  # 5  private member, bitfields, fn pointer, padding
    "<" + "III" * 4,
    b.s("private"), 1, 0,
    b.s("a"), 1, (3 << 24) | 32,
    b.s("b"), 1, (5 << 24) | 35,
    b.s("cb"), 4, 64))
b.t("mode_t", 8, 0, 1)                                                                # 6
b.t("colour", 6, 1, 4, struct.pack("<Ii", b.s("RED"), 2))                             # 7
b.t("get_it", 12, 0, 3)                                                               # 8
b.t("data_sym", 12, 0, 3)                                                             # 9
b.t("gone", 12, 0, 3)                                                                 # 10
raw = b.blob()

import btf as B  # noqa: E402
import btf2c  # noqa: E402

data = B.BTF(raw)
assert data.count == 10 and data[5].name == "task"
assert B.carve(b"\x01" * 37 + raw + b"\x02" * 11, min_types=1).count == 10, "carve from arbitrary bytes"
assert B.carve(b"\x01" * 37 + raw + b"\x02" * 11) is None, "a small BPF-sized BTF is not a kernel"
gen = btf2c.Generator(data)
text = btf2c.header(gen)
assert "int private_;" in text and "int (*cb)(struct task *arg);" in text.replace("a1", "arg"), text
assert "  signed char a:3;\n  signed char b:5;\n" in text, "a 1-byte group of signed int bitfields: signed char, full"
assert "RED = 2," in text and "typedef int mode_t;" in text
assert ("get_it", "int get_it(struct task *arg)") in gen.prototypes(), gen.prototypes()
with tempfile.TemporaryDirectory() as folder:
    path = os.path.join(folder, "x.c")
    with open(path, "w") as handle:
        handle.write(text + "_Static_assert(sizeof(struct task) == 32, \"size\");\n_Static_assert(__builtin_offsetof(struct task, cb) == 8, \"cb\");\n")
    subprocess.run(["gcc", "-fsyntax-only", "-w", path], check=True)

# Bitfields: a group of 1, 2, 4 or 8 bytes becomes C bitfields that fill one integer of that size exactly, with
# named fillers for unused bits; signed ints and signed enums stay signed, _Bool is unsigned; other sizes stay raw bytes.
f = Build()
f.t("unsigned int", 1, 0, 4, struct.pack("<I", 32))                                   # 1
f.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                  # 2
f.t("_Bool", 1, 0, 1, struct.pack("<I", 4 << 24 | 8))                                 # 3
f.t("level", 6, 2, 4, struct.pack("<IiIi", f.s("LOW"), -1, f.s("HIGH"), 3), kflag=1)  # 4  enum with a negative value
f.t("long long unsigned int", 1, 0, 8, struct.pack("<I", 64))                         # 5
f.t("long long int", 1, 0, 8, struct.pack("<I", 1 << 24 | 64))                        # 6
f.t("flags", 4, 9, 24, kflag=1, extra=struct.pack(                                    # 7
    "<" + "III" * 9,
    f.s("ready"), 1, 1 << 24 | 0, f.s("mode"), 2, 3 << 24 | 1, f.s("refs"), 1, 8 << 24 | 6,  # bytes 0-1, gaps
    f.s("x"), 2, 32,
    f.s("big"), 1, 20 << 24 | 64,                                                      # bytes 8-10: 3 bytes, raw
    f.s("lvl"), 4, 4 << 24 | 96, f.s("on"), 3, 1 << 24 | 100,                          # byte 12
    f.s("addr"), 5, 52 << 24 | 128, f.s("sign"), 6, 12 << 24 | 180))                   # bytes 16-23
fdata = B.BTF(f.blob())
fgen = btf2c.Generator(fdata)
ftext = btf2c.header(fgen)
assert """struct flags {
  unsigned short ready:1;
  signed short mode:3;
  unsigned short __pad_bits_0_4:2;
  unsigned short refs:8;
  unsigned short __pad_bits_0_14:2;
  unsigned char __pad_2[2];
  int x;
  unsigned char __bits_8[3]; /* big:20@0 */
  unsigned char __pad_b[1];
  signed char lvl:4;
  unsigned char on:1;
  unsigned char __pad_bits_c_5:3;
  unsigned char __pad_d[3];
  unsigned long long addr:52;
  signed long long sign:12;
};""" in ftext, ftext
assert (fgen.stats["bitfield_integers"], fgen.stats["bitfields"], fgen.stats["bitfield_raw_runs"], fgen.stats["bitfields_as_storage"]) == (3, 7, 1, 1), fgen.stats
# Overlapping bitfields (not in real kernels) stay raw bytes, an unnamed bitfield is left to a filler, and a bitfield
# that starts right where the previous group ends joins it (3 bytes + 1 byte = one 4-byte integer).
o = Build()
o.t("unsigned int", 1, 0, 4, struct.pack("<I", 32))                                   # 1
o.t("unsigned char", 1, 0, 1, struct.pack("<I", 8))                                   # 2
o.t("odd", 4, 7, 8, kflag=1, extra=struct.pack(                                       # 3
    "<" + "III" * 7,
    o.s("a"), 1, 4 << 24 | 0, o.s("b"), 1, 4 << 24 | 2,                                # byte 0: b overlaps a
    o.s("c"), 1, 3 << 24 | 16, 0, 1, 2 << 24 | 19, o.s("d"), 1, 3 << 24 | 21,          # byte 2: c, an unnamed :2, d
    o.s("e"), 1, 20 << 24 | 32, o.s("f"), 2, 8 << 24 | 56))                            # bytes 4-6 and byte 7
o.t("cut", 4, 7, 18, kflag=1, extra=struct.pack(                                      # 4  groups cut at byte boundaries
    "<" + "III" * 7,
    o.s("priv"), 1, 32 << 24 | 0, o.s("lltx"), 1, 1 << 24 | 32,                        # 5 bytes: int + char
    o.s("a"), 1, 20 << 24 | 64, o.s("b"), 1, 4 << 24 | 84, o.s("c"), 1, 32 << 24 | 88,   # 7 bytes: 3 raw + int
    o.s("x"), 2, 8 << 24 | 128, o.s("y"), 2, 8 << 24 | 136))                           # 2 bytes of u8: two chars
o.t("short unsigned int", 1, 0, 2, struct.pack("<I", 16))                             # 5
o.t("units", 4, 6, 8, kflag=1, extra=struct.pack(                                     # 6  the declared type's own units
    "<" + "III" * 6,
    o.s("p"), 5, 8 << 24 | 8, o.s("q"), 5, 8 << 24 | 16, o.s("r"), 5, 8 << 24 | 24, o.s("s"), 5, 8 << 24 | 32,  # u16, bytes 1-4
    o.s("m"), 1, 8 << 24 | 48, o.s("n"), 1, 8 << 24 | 56))                             # u32 in bytes 6-7: no own unit
o.t("order", 4, 4, 4, kflag=1, extra=struct.pack(                                     # 7  converting comes first
    "<" + "III" * 4, o.s("f0"), 2, 1 << 24 | 0, o.s("f1"), 2, 1 << 24 | 1, o.s("f2"), 2, 1 << 24 | 2, o.s("g"), 1, 24 << 24 | 8))
odata = B.BTF(o.blob())
ogen = btf2c.Generator(odata)
otext = btf2c.header(ogen)
assert """struct odd {
  unsigned char __bits_0[1]; /* a:4@0, b:4@2 */
  unsigned char __pad_1[1];
  unsigned char c:3;
  unsigned char __pad_bits_2_3:2;
  unsigned char d:3;
  unsigned char __pad_3[1];
  unsigned int e:20;
  unsigned int __pad_bits_4_20:4;
  unsigned int f:8;
};""" in otext, otext
assert """struct cut {
  unsigned int priv:32;
  unsigned char lltx:1;
  unsigned char __pad_bits_4_1:7;
  unsigned char __pad_5[3];
  unsigned char __bits_8[3]; /* a:20@0, b:4@20 */
  unsigned int c:32;
  unsigned char __pad_f[1];
  unsigned char x:8;
  unsigned char y:8;
};""" in otext, otext
# Several cuts convert as many bitfields: an integer of the declared type's size at an offset aligned to it wins (u16
# q and r share the aligned short at byte 2; p and s get chars), else the fewest integers (u32 m, n: one short).
assert """struct units {
  unsigned char __pad_0[1];
  unsigned char p:8;
  unsigned short q:8;
  unsigned short r:8;
  unsigned char s:8;
  unsigned char __pad_5[1];
  unsigned short m:8;
  unsigned short n:8;
};""" in otext, otext
# Converting the most bitfields comes before their own unit: u8 flags + u32 g:24 stay one int (a char for the flags
# would leave g's 3 bytes raw).
assert """struct order {
  unsigned int f0:1;
  unsigned int f1:1;
  unsigned int f2:1;
  unsigned int __pad_bits_0_3:5;
  unsigned int g:24;
};""" in otext, otext
assert (ogen.stats["bitfield_integers"], ogen.stats["bitfields"], ogen.stats["bitfield_raw_runs"], ogen.stats["bitfields_as_storage"]) == (12, 20, 2, 4), ogen.stats
oraw = btf2c.header(btf2c.Generator(odata, bitfields=False))  # the earlier form: one raw run per group
assert "__bits_0[5]; /* priv:32@0, lltx:1@32 */" in oraw and "__bits_8[7]; /* a:20@0, b:4@20, c:32@24 */" in oraw and "__bits_10[2]; /* x:8@0, y:8@8 */" in oraw, oraw
big_endian = B.BTF(f.blob())
big_endian.endian = ">"
for fold in (btf2c.Generator(fdata, bitfields=False), btf2c.Generator(big_endian)):
    otext = btf2c.header(fold)  # the raw-byte form: on request, and for big-endian BTF (not checked there)
    assert "__bits_0[2]; /* ready:1@0, mode:3@1, refs:8@6 */" in otext and "__bits_c[1]" in otext and "__bits_10[8]" in otext, otext
    assert "ready:1;" not in otext and "addr:52;" not in otext and fold.stats["bitfields"] == 0, otext
with tempfile.TemporaryDirectory() as folder:  # the gcc layout proof of tests/check_bitfields.py, GCC and MSVC rules
    path = os.path.join(folder, "flags.btf")
    with open(path, "wb") as handle:
        handle.write(f.blob())
    run = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_bitfields.py"), path],
                         capture_output=True, text=True)
    assert run.returncode == 0 and run.stdout.rstrip().endswith("PASS"), run.stdout + run.stderr
    assert "fields checked: 7 (3 signed)" in run.stdout and "bitfield checks 28, failures 0" in run.stdout, run.stdout
    path = os.path.join(folder, "odd.btf")  # overlap kept raw, unnamed filler, merged groups: gcc agrees with the BTF
    with open(path, "wb") as handle:
        handle.write(o.blob())
    run = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_bitfields.py"), path],
                         capture_output=True, text=True)
    assert run.returncode == 0 and run.stdout.rstrip().endswith("PASS"), run.stdout + run.stderr
    assert "fields checked: 19 (0 signed)" in run.stdout and "counts agree with the generator: yes" in run.stdout, run.stdout
    sc = Build()  # old pahole (Debian 11 5.10, GKI 6.1) encodes `signed char` 0: still signed; plain char as BTF says
    sc.t("signed char", 1, 0, 1, struct.pack("<I", 8))                                    # 1
    sc.t("char", 1, 0, 1, struct.pack("<I", 8))                                           # 2
    sc.t("sc", 4, 2, 1, kflag=1, extra=struct.pack("<IIIIII", sc.s("x"), 1, 5 << 24 | 0, sc.s("y"), 2, 3 << 24 | 5))
    assert "  signed char x:5;\n  unsigned char y:3;\n" in btf2c.header(btf2c.Generator(B.BTF(sc.blob())))
    path = os.path.join(folder, "sc.btf")
    with open(path, "wb") as handle:
        handle.write(sc.blob())
    run = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_bitfields.py"), path],
                         capture_output=True, text=True)  # gcc reads x back negative
    assert run.returncode == 0 and "fields checked: 2 (1 signed)" in run.stdout and run.stdout.rstrip().endswith("PASS"), run.stdout
    plain = Build()  # no bitfield at all: nothing to check is not a failure
    plain.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))
    plain.t("plain", 4, 1, 4, struct.pack("<III", plain.s("x"), 1, 0))
    for name, content, code, words in (("plain.btf", plain.blob(), 0, "NOTHING TO CHECK"), ("nobtf.bin", b"\0" * 4096, 2, "no BTF found")):
        with open(os.path.join(folder, name), "wb") as handle:
            handle.write(content)
        run = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_bitfields.py"),
                              os.path.join(folder, name)], capture_output=True, text=True)
        assert run.returncode == code and words in run.stdout + run.stderr and "Traceback" not in run.stderr, (name, run.stdout, run.stderr)
# The toy demo's expected header is what btf2c.py writes for it now.
toy = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo")
with open(os.path.join(toy, "toy_kernel.elf"), "rb") as handle:
    toy_text = btf2c.header(btf2c.Generator(B.load(handle.read())))
with open(os.path.join(toy, "expected_types.h"), encoding="utf-8") as handle:
    assert handle.read() == toy_text, "demo/expected_types.h is out of date"
assert "  unsigned short ready:1;\n  unsigned short mode:3;\n  unsigned short refs:12;\n  unsigned char __pad_a[2];\n" in toy_text
print("stub test OK: bitfield groups cut into full C bitfield integers of 1/2/4/8 bytes (signed kept), other runs raw; gcc layout check passes")

# tests/check_against_dwarf.py on a tiny BTF and a hand-written ISF: its exit status is the verdict (0 only when the
# kernel releases match or one is unknown and nothing differs), so a mismatch cannot pass unnoticed.
import base64  # noqa: E402
import json  # noqa: E402
import lzma  # noqa: E402
p = Build()
p.t("unsigned int", 1, 0, 4, struct.pack("<I", 32))                                   # 1
p.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                  # 2
p.t("pair", 4, 3, 8, kflag=1, extra=struct.pack("<" + "III" * 3, p.s("a"), 1, 3 << 24 | 0, p.s("b"), 2, 5 << 24 | 3, p.s("c"), 2, 32))


def isf(size=8, b_position=3, b_type="int", release="9.9.9-test"):
    bitfield = lambda position, length, name: {"kind": "bitfield", "bit_position": position, "bit_length": length,  # noqa: E731
                                               "type": {"kind": "base", "name": name}}
    return {"metadata": {"linux": {"symbols": [{"kind": "dwarf", "name": "vmlinux-" + release}]}},
            "symbols": {"linux_banner": {"constant_data": base64.b64encode(b"Linux version %s (builder) #1\n\0" % release.encode()).decode()}},
            "base_types": {"unsigned int": {"kind": "int", "signed": False, "size": 4}, "int": {"kind": "int", "signed": True, "size": 4}},
            "user_types": {"pair": {"kind": "struct", "size": size, "fields": {
                "a": {"offset": 0, "type": bitfield(0, 3, "unsigned int")}, "b": {"offset": 0, "type": bitfield(b_position, 5, b_type)},
                "c": {"offset": 4, "type": {"kind": "base", "name": "int"}}}}}}


dwarf_check = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_against_dwarf.py")
with tempfile.TemporaryDirectory() as folder:
    kernel, bare, isf_path = (os.path.join(folder, name) for name in ("kernel.btf", "bare.btf", "isf.json.xz"))
    with open(kernel, "wb") as handle:
        handle.write(p.blob() + b"Linux version 9.9.9-test (builder) #1\n\0")
    with open(bare, "wb") as handle:
        handle.write(p.blob())
    for kernel_file, kwargs, code, words in ((kernel, {}, 0, "matches the ISF: 9.9.9-test"), (bare, {}, 0, "not checked"),
                                             (kernel, {"size": 12}, 1, "size mismatches 1"),
                                             (kernel, {"b_position": 4}, 1, "bit position or width mismatches 1"),
                                             (kernel, {"b_type": "unsigned int"}, 1, "signedness compared 2, mismatches 1"),
                                             (kernel, {"release": "9.9.8-other"}, 1, "DIFFERENT kernels")):
        with lzma.open(isf_path, "wt") as handle:
            json.dump(isf(**kwargs), handle)
        run = subprocess.run([sys.executable, dwarf_check, kernel_file, isf_path], capture_output=True, text=True)
        assert run.returncode == code and words in run.stdout, (kwargs, run.returncode, run.stdout, run.stderr)
    assert subprocess.run([sys.executable, dwarf_check], capture_output=True).returncode == 2
print("stub test OK: check_against_dwarf exits 1 on a size, bit position, signedness or kernel release mismatch")

# An empty struct (size 0 in BTF) gets a forward declaration only and is counted apart from real bodies.
e = Build()
e.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                   # 1
e.t("lock_class_key", 4, 0, 0)                                                        # 2  empty struct
e.t("", 2, 0, 2)                                                                      # 3  pointer to it
e.t("holder", 4, 2, 16, extra=struct.pack("<" + "III" * 2, e.s("key"), 3, 0, e.s("n"), 1, 64))  # 4
egen = btf2c.Generator(B.BTF(e.blob()))
etext = btf2c.header(egen)
assert "struct lock_class_key;" in etext and "struct lock_class_key {" not in etext, etext
assert egen.stats["empty"] == 1 and egen.stats["structs"] == 1, egen.stats

# An external module with a distilled .BTF.base (Linux 6.11+): its split BTF sits on that small base, which
# names kernel structs by size only. They must stay forward declarations (a padding body would replace the real one).
dbase = Build()
dbase.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                               # 1
dbase.t("sk_buff", 4, 0, 232)                                                         # 2  name + size only
dbase_raw = dbase.blob()
dsplit_strs = b"skb\0mod_xmit\0holder\0"
skb_off, fn_off, holder_off = len(dbase.strs), len(dbase.strs) + 4, len(dbase.strs) + 13
dsplit_types = (struct.pack("<III", 0, 2 << 24, 2)                                      # 3  struct sk_buff *
                + struct.pack("<III", 0, 13 << 24 | 1, 1) + struct.pack("<II", skb_off, 3)  # 4  int (struct sk_buff *)
                + struct.pack("<III", fn_off, 12 << 24, 4)                              # 5  mod_xmit
                + struct.pack("<III", holder_off, 4 << 24 | 2, 240)                     # 6  struct holder: sk_buff by value
                + struct.pack("<III", skb_off, 2, 0) + struct.pack("<III", fn_off, 1, 232 * 8))
dsplit_raw = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(dsplit_types), len(dsplit_types), len(dsplit_strs)) + dsplit_types + dsplit_strs
distilled_ko = tiny_rel([b".gnu.linkonce.this_module", (b".BTF.base", dbase_raw), (b".BTF", dsplit_raw)])
ddata = B.load(distilled_ko)
assert ddata.distilled and ddata.count == 6 and B.load(distilled_ko, base=B.BTF(raw)).distilled, "own .BTF.base wins over a given base"
dgen = btf2c.Generator(ddata)
dtext = btf2c.header(dgen)
assert "struct sk_buff;" in dtext and "struct sk_buff {" not in dtext and dgen.stats["base_only"] == 1, (dtext, dgen.stats)
assert dgen.prototypes(ddata.own) == [("mod_xmit", "int mod_xmit(struct sk_buff *skb)")], dgen.prototypes(ddata.own)
assert "unsigned char skb[232]; /* struct sk_buff, known only" in dtext and dgen.stats["opaque_members"] == 1, dtext
with tempfile.TemporaryDirectory() as folder:  # the header must compile: no member of an incomplete type
    path = os.path.join(folder, "d.c")
    with open(path, "w") as handle:
        handle.write(dtext + "_Static_assert(sizeof(struct holder) == 240, \"size\");\n")
    subprocess.run(["gcc", "-fsyntax-only", "-w", path], check=True)

try:  # split BTF: strings that do not start with NUL
    B.BTF(struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, 0, 0, 2) + b"a\0")
    raise SystemExit("split BTF was accepted without a base")
except B.NeedsBase:
    pass

# Split BTF checked against its base: a name offset in the middle of a base string means the wrong vmlinux.
base_b = Build()
base_b.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))
base_btf = B.BTF(base_b.blob())
def split_blob(name_off):
    own_types = struct.pack("<III", name_off, 2 << 24, 1)  # pointer to type 1, named from the base strings
    own_strs = b"x\0"
    return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(own_types), len(own_types), len(own_strs)) + own_types + own_strs
assert B.BTF(split_blob(1), base=base_btf).own[0].name == "int"
try:
    B.BTF(split_blob(2), base=base_btf)
    raise SystemExit("a mismatched base was accepted")
except B.NeedsBase:
    raise
except B.BTFError as error:
    assert "does not match the chosen vmlinux" in str(error), error

calls = []
kw = types.ModuleType("ida_kernwin")
kw.action_handler_t = object
kw.action_desc_t = lambda *a: a
kw.SETMENU_APP = 1
kw.AST_ENABLE_ALWAYS = 1
kw.register_action = lambda d: calls.append(("reg", d[0])) or True
kw.attach_action_to_menu = lambda m, a, f: calls.append(("menu", m, a)) or True
kw.unregister_action = lambda a: calls.append(("unreg", a)) or True
kw.msg = lambda s: calls.append(("msg", s))
kw.info = lambda s: calls.append(("info", s))
kw.warning = lambda s: calls.append(("warn", s))
kw.show_wait_box = kw.replace_wait_box = lambda s: None
kw.hide_wait_box = lambda: None
kw.user_cancelled = lambda: False
api = types.ModuleType("ida_idaapi")
api.plugin_t = object
api.PLUGIN_KEEP = 2
api.PLUGIN_HIDE = 0x10
ida = types.ModuleType("ida_ida")
ida.inf_is_64bit = lambda: True
ida.inf_is_be = lambda: False
idc = types.ModuleType("idc")
idc.PT_SIL, idc.PT_PAK1, idc.BADADDR = 1, 0x10, -1
idc.parse_decls = lambda text, flags: calls.append(("parse", text, flags)) or text.count("struct broken")
idc.get_name_ea_simple = lambda n: {"get_it": 0x1000, "data_sym": 0x2000}.get(n, idc.BADADDR)
idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
idc.get_segm_end = lambda s: s + len(raw)
idc.get_func_name = lambda ea: "get_it.isra.0"
funcs = types.ModuleType("ida_funcs")
funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea) if ea == 0x1000 else None
autos = types.ModuleType("idautils")
autos.Segments = lambda: [0x4000]
autos.Functions = lambda: [0x3000]
dbytes = types.ModuleType("ida_bytes")
dbytes.get_bytes = lambda ea, size: raw
nalt = types.ModuleType("ida_nalt")
nalt.get_input_file_path = lambda: ""
user_typed = set()
nalt.is_userti = lambda ea: ea in user_typed
dbytes.get_flags = lambda ea: 1 if ea == 0x5000 else 0          # 0x5000 carries a user name
dbytes.has_user_name = lambda flags: flags == 1
funcs.add_func = lambda ea: calls.append(("add_func", ea)) or True
iname = types.ModuleType("ida_name")
iname.SN_NOCHECK, iname.SN_NOWARN = 1, 256
iname.set_name = lambda ea, n, f: calls.append(("set_name", ea, n, f)) or True
seg = types.ModuleType("ida_segment")
seg.SEG_XTRN, seg.SEG_CODE = 1, 2                                      # values from the SDK's segment.hpp
seg.segtype = lambda ea: calls.append(("segtype", ea)) or (seg.SEG_XTRN if 0x8000 <= ea < 0x9000 else seg.SEG_CODE)
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_ida=ida, idc=idc, ida_funcs=funcs, idautils=autos, ida_bytes=dbytes, ida_nalt=nalt, ida_name=iname, ida_segment=seg)

import btf2ida_entry as m  # noqa: E402

plugin = m.PLUGIN_ENTRY()
assert plugin.init() == api.PLUGIN_KEEP
assert m.ApplyBTF().activate(None) == 1
assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "int __btf2ida_fn(struct task *arg);")], calls
assert all(c[2] == idc.PT_SIL | idc.PT_PAK1 for c in calls if c[0] == "parse")
parsed = "\n".join(c[1] for c in calls if c[0] == "parse")
assert "struct task {" in parsed and "#pragma" not in parsed and "signed char b:5;" in parsed
message = [c[1] for c in calls if c[0] == "info"][0]
assert "applied to 1 functions" in message and "not in this database 1" in message and "not a function start 1" in message and "1 compiler clones" in message, message
assert m.import_in_batches(["a;", "BAD;", "b;"], lambda t: t.count("BAD"), batch=2) == ["BAD;"]
assert "Named 0 exported functions" in message, message
assert "imported kernel functions" not in message and not [c for c in calls if c[0] == "segtype"], "a whole kernel never looks for externs"
assert "Bitfields kept as raw bytes" not in message, message
# C bitfields need IDA to allocate bitfields from the least significant bit, as BTF counts them: in a big-endian
# database (or where IDA 9.5's inf_get_bf_order says otherwise, or cannot tell) they stay raw bytes, and the summary says why.
for setup, words in ((lambda: setattr(ida, "inf_is_be", lambda: True), "this database is big-endian"),
                     (lambda: setattr(ida, "inf_get_bf_order", lambda: 2), "from the most significant bit in this database"),
                     (lambda: setattr(ida, "inf_is_be", lambda: 1 // 0), "could not read the database's bitfield order")):
    setup()
    del calls[:]
    assert m.ApplyBTF().activate(None) == 1
    parsed = "\n".join(c[1] for c in calls if c[0] == "parse")
    message = [c[1] for c in calls if c[0] == "info"][0]
    assert "__bits_4[1]; /* a:3@0, b:5@3 */" in parsed and "b:5;" not in parsed, parsed
    assert "Bitfields kept as raw bytes (names in a comment): " in message and words in message, message
    ida.inf_is_be = lambda: False
    if hasattr(ida, "inf_get_bf_order"):
        del ida.inf_get_bf_order
ida.inf_get_bf_order, ida.BFO_LSB_TO_MSB = (lambda: 1), 1                  # IDA 9.5, little-endian: C bitfields
del calls[:]
assert m.ApplyBTF().activate(None) == 1
assert "signed char b:5;" in "\n".join(c[1] for c in calls if c[0] == "parse")
del ida.inf_get_bf_order, ida.BFO_LSB_TO_MSB
real_load_btf = m.find_btf
def big_endian_btf(*args):
    found, source = real_load_btf(*args)
    found.endian = ">"  # as if read from a big-endian kernel (btf2c keeps its bitfields raw: not checked there)
    return found, source
m.find_btf = big_endian_btf
del calls[:]
assert m.ApplyBTF().activate(None) == 1
m.find_btf = real_load_btf
message = [c[1] for c in calls if c[0] == "info"][0]
assert "Bitfields kept as raw bytes (names in a comment): the BTF is big-endian" in message, message

# A kernel module (split BTF): its own functions are typed and counted as before. vmlinux's functions are
# typed only where IDA lists them in an extern segment; the others are not counted as missing.
vb = Build()
vb.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                   # 1
vb.t("", 13, 1, 1, struct.pack("<II", vb.s("x"), 1))                    # 2  int (int x)
vb.t("imp_fn", 12, 0, 2)                                                 # 3  called by the module: in the extern segment
vb.t("base_local", 12, 0, 2)                                             # 4  a module function of the same name, in code
vb.t("unused_base", 12, 0, 2)                                            # 5  not used by the module


class Split(Build):
    """Module BTF: type ids and string offsets continue those of the base."""
    def __init__(self, base):
        Build.__init__(self)
        self.strs, self.offset = b"", len(base.strs)

    def s(self, text):
        return Build.s(self, text) + self.offset if text else 0


mb = Split(vb)
mb.t("mod_fn", 12, 0, 2)                                                 # 6
mb.t("mod_gone", 12, 0, 2)                                               # 7  not in the database
with tempfile.TemporaryDirectory() as folder:
    paths = {}
    for label, blob in (("vmlinux.btf", vb.blob()), ("mod.ko", mb.blob())):
        paths[label] = os.path.join(folder, label)
        with open(paths[label], "wb") as handle:
            handle.write(blob)
    nalt.get_input_file_path = lambda: paths["mod.ko"]
    kw.ask_file = lambda save, default, prompt: paths["vmlinux.btf"]
    idc.get_name_ea_simple = lambda n: {"mod_fn": 0x1000, "imp_fn": 0x8000, "base_local": 0x1100}.get(n, idc.BADADDR)
    whole_get_func = funcs.get_func
    funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea) if ea in (0x1000, 0x1100) else None
    del calls[:]
    assert m.ApplyBTF().activate(None) == 1
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "int __btf2ida_fn(int x);"),
                                                        ("settype", 0x8000, "int __btf2ida_fn(int x);")], calls
    message = [c[1] for c in calls if c[0] == "info"][0]
    assert "applied to 1 functions" in message and "not in this database 1;" in message, message
    assert "Typed 1 imported kernel functions in the extern segment" in message, message
    # The headless path passes vmlinux directly: no file dialog.
    def no_dialog(*a):
        raise AssertionError("asked for a file although vmlinux was given")
    kw.ask_file = no_dialog
    seen_bool, real_generator = [], m.btf2c.Generator
    m.btf2c.Generator = lambda *args, **kwargs: seen_bool.append(kwargs.get("bool_name")) or real_generator(*args, **kwargs)
    ida.inf_get_cc_size_b = lambda: 4                     # IDA's bool is 4 bytes in this database: _BOOL1 reaches btf2c
    message64 = m.run_import(paths["vmlinux.btf"])
    m.btf2c.Generator = real_generator
    del ida.inf_get_cc_size_b
    assert seen_bool == ["_BOOL1"], seen_bool
    assert "BTF from the input file" in message64 and "32-bit database" not in message64, message64
    ida.inf_is_64bit = lambda: False  # 32-bit: types only, and the summary says why no prototype was applied
    message32 = m.run_import(paths["vmlinux.btf"])
    assert "Prototypes not applied: this is a 32-bit x86 database" in message32 and "applied to 0 functions" in message32, message32
    ida.inf_get_procname = lambda: "ARM"  # 32-bit ARM: no regparm, so prototypes are applied
    message_arm = m.run_import(paths["vmlinux.btf"])
    assert "Prototypes not applied" not in message_arm and "applied to 0 functions" not in message_arm, message_arm
    ida.inf_get_procname = lambda: "metapc"
    assert "Prototypes not applied: this is a 32-bit x86 database" in m.run_import(paths["vmlinux.btf"])
    del ida.inf_get_procname
    ida.inf_is_64bit = lambda: True
    try:  # headless without --vmlinux: a clear error, never a dialog
        m.run_import(None, ask=False)
        raise AssertionError("split BTF without vmlinux must fail")
    except B.BTFError as error:
        assert "--vmlinux" in str(error), error
    kw.ask_file = lambda save, default, prompt: paths["vmlinux.btf"]
    # The extern check can never stop the run: an error, or no ida_segment at all, only skips the imports.
    own, imports = [("mod_fn", "int mod_fn(int x)")], [("imp_fn", "int imp_fn(int x)")]
    def broken(ea):
        raise RuntimeError("synthetic")
    seg.segtype = broken
    result = m.apply_prototypes(own, None, imports)
    assert (result["applied"], result["imports"], result["absent"]) == (1, 0, 0), result
    m.ida_segment = None
    result = m.apply_prototypes(own, None, imports)
    assert (result["applied"], result["imports"], result["absent"]) == (1, 0, 0), result
    m.ida_segment = seg
    seg.segtype = lambda ea: seg.SEG_XTRN
    user_typed.add(0x8000)                                               # an import typed by hand is kept
    result = m.apply_prototypes(own, None, imports)
    assert (result["imports"], result["kept"]) == (0, 1), result
    user_typed.discard(0x8000)
    seg.segtype = lambda ea: seg.SEG_XTRN if ea == 0x8000 else seg.SEG_CODE
    # A kernel module with no BTF of its own: only its imports are typed, from the chosen vmlinux.
    nobtf = os.path.join(folder, "nobtf.ko")
    with open(nobtf, "wb") as handle:
        handle.write(tiny_rel([b".gnu.linkonce.this_module", (b".symtab", bytes(24) + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0)),
                               (b".strtab", b"\0imp_fn\0")]))
    assert not B.is_kernel_module(tiny_rel([b".text"]) + b".gnu.linkonce.this_module\x00"), "the string alone is not a module"
    assert not B.is_kernel_module(tiny_rel([b".gnu.linkonce.this_module"])[:70]), "truncated"
    nalt.get_input_file_path = lambda: nobtf
    whole_segments = autos.Segments
    autos.Segments = lambda: []
    del calls[:]
    message = m.run_import()
    assert "no BTF of its own" in message and "Typed 1 imported kernel functions" in message, message
    assert "The module's 1 undefined symbols: 1 found in this database, 0 of them outside" in message, message
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x8000, "int __btf2ida_fn(int x);")], calls
    ida.inf_is_64bit = lambda: False  # 32-bit: the summary must not claim the imports were typed
    message32 = m.run_import()
    assert "no prototype was applied (32-bit" in message32 and "Typed " not in message32, message32
    ida.inf_is_64bit = lambda: True
    # Its vermagic release is compared with the chosen vmlinux's "Linux version" banner.
    with open(nobtf, "wb") as handle:
        handle.write(tiny_rel([b".gnu.linkonce.this_module", (b".modinfo", b"license=GPL\0vermagic=6.1.0-x SMP mod_unload \0")]))
    assert B.module_release(tiny_rel([(b".modinfo", b"vermagic=6.1.0-x SMP \0")])) == "6.1.0-x"
    message = m.run_import()  # raw BTF has no banner: imported, with a "Not checked" line
    assert "Typed 1 imported" in message and "Not checked: the module was built for 6.1.0-x" in message, message
    with open(paths["vmlinux.btf"], "rb") as handle:
        raw_vmlinux = handle.read()
    for release, refused in (("6.1.0-x", False), ("6.17.0-41-generic", True)):
        bannered = os.path.join(folder, "vmlinux-" + release)
        with open(bannered, "wb") as handle:
            handle.write(raw_vmlinux + b"Linux version %s (builder@host) #1 SMP\0" % release.encode())
        try:
            message = m.run_import(bannered, ask=False)
            assert not refused and "Typed 1 imported" in message and "Not checked" not in message, message
        except B.BTFError as error:
            assert refused and "built for 6.1.0-x, but the chosen vmlinux is 6.17.0-41-generic" in str(error), error
    # A memory image can also hold older banners in logs (journald, dmesg), in any order: one that matches is enough.
    with open(bannered, "wb") as handle:
        handle.write(raw_vmlinux + b"MESSAGE=Linux version 6.0.9-old (b@h) #1\0Linux version 6.1.0-x (builder@host) #1\0")
    message = m.run_import(bannered, ask=False)
    assert "Typed 1 imported" in message and "Not checked" not in message, message
    nalt.get_input_file_path = lambda: os.path.join(folder, "moved-away.ko")  # the input file is gone
    try:
        m.run_import(bannered, ask=False)
        raise AssertionError("a missing input file must be named")
    except B.BTFError as error:
        assert "is not on disk" in str(error), error
    nalt.get_input_file_path = lambda: nobtf
    try:
        m.run_import(None, ask=False)
        raise AssertionError("a module without BTF and without vmlinux must fail")
    except B.BTFError as error:
        assert "--vmlinux" in str(error) and "no BTF of its own" in str(error), error
    plain = os.path.join(folder, "plain_kernel")                       # a whole kernel built without BTF
    with open(plain, "wb") as handle:
        handle.write(tiny_rel([b".text"]))
    nalt.get_input_file_path = lambda: plain
    try:
        m.run_import(None, ask=False)
        raise AssertionError("a whole kernel without BTF and without a BTF file must fail")
    except B.BTFError as error:
        assert "BTFHub" in str(error) and "--vmlinux" in str(error), error
    message = m.run_import(paths["vmlinux.btf"], ask=False)            # headless: --vmlinux <BTF file>
    assert "a separate file: btf2ida cannot check" in message and "Prototypes applied" in message, message
    with open(plain, "wb") as handle:                                   # the kernel names its release in a banner
        handle.write(tiny_rel([b".text"]) + b"Linux version 5.8.0-63-generic (b@h) #1\0")
    hub = os.path.join(folder, "5.4.0-1-generic.btf")                  # BTFHub naming, another release
    with open(paths["vmlinux.btf"], "rb") as source_handle, open(hub, "wb") as handle:
        handle.write(source_handle.read())
    message = m.run_import(hub, ask=False)
    assert "WARNING: this kernel is 5.8.0-63-generic, the chosen file is for 5.4.0-1-generic" in message, message
    same = os.path.join(folder, "5.8.0-63-generic.btf")
    os.rename(hub, same)
    assert "same kernel release as this kernel: 5.8.0-63-generic" in m.run_import(same, ask=False)
    with open(plain, "ab") as handle:                                   # an older banner in a log of the image
        handle.write(b"MESSAGE=Linux version 5.4.0-1-generic (b@h) #1\0")
    assert "matches one of the releases named in the input file" in m.run_import(same, ask=False)
    assert m.named_release("/x/5.8.0-63-generic.btf.tar.xz") == {"5.8.0-63-generic"} and m.named_release("/x/vmlinux") == set()
    assert m.named_release("/x/vmlinux.btf") == set(), "not a release"
    kw.ask_file = lambda save, default, prompt: paths["vmlinux.btf"] if "built without BTF" in prompt else None
    assert "a separate file" in m.run_import(None, ask=True)             # interactive: btf2ida asks for the file
    try:
        m.run_import(nobtf, ask=False)
        raise AssertionError("a chosen file without BTF must fail")
    except B.BTFError as error:
        assert "has no usable BTF" in str(error), error
    distilled_file = os.path.join(folder, "distilled.ko")              # a module's BTF is not a whole kernel's
    with open(distilled_file, "wb") as handle:
        handle.write(distilled_ko)
    try:
        m.run_import(distilled_file, ask=False)
        raise AssertionError("a module's distilled BTF must not be used for a whole kernel")
    except B.BTFError as error:
        assert "split BTF, not the BTF of a whole kernel" in str(error), error
    try:
        m.run_import(os.path.join(folder, "no-such-file.btf"), ask=False)
        raise AssertionError("a missing BTF file must fail with a clear message")
    except B.BTFError as error:
        assert "cannot read the chosen file" in str(error), error
    kw.ask_file = no_dialog
    autos.Segments = whole_segments
    nalt.get_input_file_path = lambda: paths["mod.ko"]
    idc.SetType = lambda ea, d: ea != 0x8000                             # IDA refuses the import's prototype
    result = m.apply_prototypes(own, None, imports)
    assert (result["applied"], result["rejected"], result["imports"], result["imports_rejected"]) == (1, [], 0, ["imp_fn"]), result
    idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
    nalt.get_input_file_path = lambda: ""
    funcs.get_func = whole_get_func
# __ksymtab naming: skip data, user names and names already in use; create a missing function first.
with tempfile.NamedTemporaryFile() as fake_input:
    fake_input.write(b"placeholder")
    fake_input.flush()
    nalt.get_input_file_path = lambda: fake_input.name
    m.ksymtab.exported = lambda blob: {0x1000: ("taken_elsewhere", True), 0x3000: ("tcp_sendmsg", True),
                                       0x4000: ("some_data", False), 0x5000: ("user_named", True),
                                       0x6000: ("get_it", True)}
    idc.get_name_ea_simple = lambda n: 0x1000 if n in ("taken_elsewhere", "get_it") else idc.BADADDR
    m.ksymtab.probe = lambda blob: (0x9000, b"zz")      # database does not map the file the same way
    del calls[:]
    assert m.name_exports() == 0 and not [c for c in calls if c[0] == "set_name"], calls
    m.ksymtab.probe = lambda blob: (0x9000, raw)         # matches what the fake get_bytes returns
    del calls[:]
    assert m.name_exports() == 1
    assert ("set_name", 0x3000, "tcp_sendmsg", 257) in calls and ("add_func", 0x3000) in calls, calls
    assert [c for c in calls if c[0] == "set_name"] == [("set_name", 0x3000, "tcp_sendmsg", 257)], calls
# Headless runner (tools/btf2ida_headless.py) with a FAKE idapro: open, run_import(vmlinux), close + save, exit codes.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
idapro = types.ModuleType("idapro")
opened = []
idapro.open_database = lambda path, analysis: opened.append(("open", analysis)) or 0
idapro.close_database = lambda save: opened.append(("close", save))
sys.modules["idapro"] = idapro
import btf2ida_headless as headless  # noqa: E402
real_run_import = m.run_import
m.run_import = lambda vmlinux=None, ask=True: opened.append(("run", vmlinux, ask)) or "summary"
with tempfile.NamedTemporaryFile() as handle:
    assert headless.main([handle.name, "--vmlinux", handle.name, "--no-analysis"]) == 0
    assert opened == [("open", False), ("run", handle.name, False), ("close", True)], opened
    def no_btf(vmlinux=None, ask=True):
        raise B.BTFError("no BTF found in the input file or the loaded segments.")
    m.run_import = no_btf
    del opened[:]
    assert headless.main([handle.name]) == 3 and opened == [("open", True), ("close", True)], opened
    idapro.open_database = lambda path, analysis: 1
    del opened[:]
    assert headless.main([handle.name]) == 1 and opened == [], opened
    run = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "btf2ida_headless.py"), handle.name],
                         capture_output=True, text=True)
    assert run.returncode == 2 and "idalib is not available" in run.stderr, (run.returncode, run.stderr)
m.run_import = real_run_import
del sys.modules["idapro"]
# An unexpected error inside the action becomes one warning, not a traceback dialog.
def boom():
    raise IndexError("synthetic")
m.run_import = boom
del calls[:]
assert m.ApplyBTF().activate(None) == 0
warns = [c[1] for c in calls if c[0] == "warn"]
assert len(warns) == 1 and "unexpected error" in warns[0] and "/btf2ida/issues" in warns[0], calls
assert any(c[0] == "msg" and "IndexError: synthetic" in c[1] for c in calls), calls
plugin.term()
assert ("unreg", "btf2ida:apply") in calls
# "void f(void)" from BTF: skipped for assembly entry points (memcpy) and where IDA's type already has parameters;
# a genuine void f(void) with no better type is still applied
addrs = {"memcpy": 0x7100, "irq_enter_rcu": 0x7200, "has_args": 0x7300, "with_args": 0x7400}
idc.get_name_ea_simple = lambda n: addrs.get(n, idc.BADADDR)
sys.modules["ida_funcs"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea) if ea in addrs.values() else None
idc.get_type = lambda ea: {0x7300: "void __fastcall(void *a1, int a2)", 0x7200: "void __fastcall()"}.get(ea)
nalt.is_userti = lambda ea: False
del calls[:]
idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
til = types.ModuleType("ida_typeinf")  # IDA's type libraries know the SYMBOL til_func(void *p) (one argument)
til.NTF_SYMM, til.NTF_SYMU, til.NTF_TYPE, til.TINFO_GUESSED = 0, 8, 1, 0
library = {"til_func"}
til.get_named_type = lambda t, name, flags: (1, b"T:" + name.encode(), b"", "", "", 0, 0) if t == "idati" and flags == til.NTF_SYMU and name in library else None


class FakeTinfo:
    def deserialize(self, til_, typ, fields):
        self.name = typ[2:].decode()
        return True

    def is_func(self):
        return True

    def get_nargs(self):
        return 1


til.tinfo_t = FakeTinfo
til.get_idati = lambda: "idati"
til.apply_tinfo = lambda ea, tif, flags: calls.append(("apply_tinfo", ea, tif.name, flags)) or True
sys.modules["ida_typeinf"] = til
addrs.update(til_func=0x7500, int_void=0x7900, imp_memcpy=0x8100)
idc.get_type = lambda ea: {0x7300: "void __fastcall(void *a1, int a2)", 0x7200: "void __fastcall()",
                           0x7900: "int __fastcall(int a1)"}.get(ea)  # int f(void) from BTF is a real C prototype
userti_set = set()
nalt.is_userti = lambda ea: ea in userti_set
res = m.apply_prototypes([("memcpy", "void memcpy(void)"), ("irq_enter_rcu", "void irq_enter_rcu(void)"),
                          ("has_args", "void has_args(void)"), ("with_args", "int with_args(int x)"),
                          ("til_func", "void til_func(void)"), ("int_void", "int int_void(void)")])
typed = sorted(c[1] for c in calls if c[0] == "settype")
assert typed == [0x7200, 0x7400, 0x7900] and (res["void_asm"], res["void_ida"], res["applied"]) == (1, 2, 3), (typed, res)
text = m.report("x", btf2c.Generator(B.BTF(raw)), [], res)
assert "Not applied: 1 'void f(void)' prototypes of known assembly functions such as memcpy (BTF records them without " \
       "parameters) and 2 where IDA's type lists parameters; left as IDA has them" in text, text
# the J1 case itself: an IMPORT (extern segment) named like an assembly function is not typed void(void)
seg.segtype = lambda ea: seg.SEG_XTRN if ea == 0x8100 else seg.SEG_CODE
addrs["__arch_copy_to_user"] = 0x8100
del calls[:]
res = m.apply_prototypes([], None, [("__arch_copy_to_user", "void __arch_copy_to_user(void)")])
assert res["void_asm"] == 1 and res["imports"] == 0 and not [c for c in calls if c[0] == "settype"], (res, calls)
# a user-set type is checked first: kept, even for an assembly name with a non-void(void) type
userti_set.add(0x7100)
idc.get_type = lambda ea: {0x7100: "void *__fastcall(void *, const void *, size_t)"}.get(ea)
res = m.apply_prototypes([("memcpy", "void memcpy(void)")])
assert (res["kept"], res["void_asm"]) == (1, 0), res
userti_set.clear()
# IDA's tinfo API, when present, decides "IDA's type lists parameters" (no text parsing)
nalt.get_tinfo = lambda tif, ea: ea == 0x7200
del calls[:]
res = m.apply_prototypes([("irq_enter_rcu", "void irq_enter_rcu(void)")])
assert res["void_ida"] == 1 and not [c for c in calls if c[0] == "settype"], (res, calls)
del nalt.get_tinfo
idc.get_type = lambda ea: {0x7300: "void __fastcall(void *a1, int a2)", 0x7200: "void __fastcall()"}.get(ea)
del sys.modules["ida_typeinf"]
print("stub test OK: void(void) skipped for assembly names (also imports) and where IDA's type or type-library symbol has parameters; int f(void) and real void(void) applied")
# A re-run replaces btf2ida's own earlier prototypes (recorded in a netnode with a CRC of the type text) but keeps a
# type changed by hand since, and removes a 0.1.20-style 'void f(void)' on memcpy (no record) for IDA's library type.
class FakeNode:
    def __init__(self, name, namlen, create):
        self.alt = store

    def altval_ea(self, ea):
        return self.alt.get(ea, 0)

    def altset_ea(self, ea, value):
        self.alt[ea] = value
        return True

    def altdel_ea(self, ea):
        return self.alt.pop(ea, None) is not None


store, shown, userti = {}, {}, set()
netnode_mod = types.ModuleType("ida_netnode")
netnode_mod.netnode = FakeNode
sys.modules["ida_netnode"] = netnode_mod
addrs = {"fn_a": 0x7600, "fn_b": 0x7700, "memcpy": 0x7800}
idc.get_name_ea_simple = lambda n: addrs.get(n, idc.BADADDR)
sys.modules["ida_funcs"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea) if ea in addrs.values() else None
idc.get_type = lambda ea: shown.get(ea)
nalt.is_userti = lambda ea: ea in userti


def settype(ea, decl):
    calls.append(("settype", ea, decl))
    shown[ea] = "IDA:" + decl
    userti.add(ea)
    return True


idc.SetType = settype


def del_tinfo(ea):
    calls.append(("del_tinfo", ea))
    shown.pop(ea, None)
    userti.discard(ea)


nalt.del_tinfo = del_tinfo
til = types.ModuleType("ida_typeinf")
til.NTF_SYMM, til.NTF_SYMU, til.TINFO_GUESSED = 0, 8, 0
library.add("memcpy")
til.get_named_type = lambda t, name, flags: (1, b"T:" + name.encode(), b"", "", "", 0, 0) if t == "idati" and flags == til.NTF_SYMU and name in library else None
til.apply_tinfo = lambda ea, tif, flags: calls.append(("apply_tinfo", ea, tif.name, flags)) or True
til.tinfo_t = FakeTinfo
til.get_idati = lambda: "idati"
sys.modules["ida_typeinf"] = til
del calls[:]
res = m.apply_prototypes([("fn_a", "int fn_a(int x)"), ("fn_b", "int fn_b(int x)")])
assert res["applied"] == 2 and res["retyped"] == 0 and sorted(store) == [0x7600, 0x7700], (res, store)
shown[0x7700] = "IDA:long fn_b(long y);"                                # the user edits fn_b by hand
shown[0x7800], userti = "void __fastcall()", userti | {0x7800}           # memcpy typed void(void) by btf2ida 0.1.20
del calls[:]
res = m.apply_prototypes([("fn_a", "int fn_a(long x)"), ("fn_b", "int fn_b(long x)"), ("memcpy", "void memcpy(void)")])
assert [c[1] for c in calls if c[0] == "settype"] == [0x7600], calls
assert (res["retyped"], res["applied"], res["kept"], res["void_removed"], res["void_asm"]) == (1, 1, 1, 1, 0), res
assert ("del_tinfo", 0x7800) in calls and ("apply_tinfo", 0x7800, "memcpy", til.TINFO_GUESSED) in calls, calls
addrs["late_asm"] = 0x7B00               # btf2ida's own void(void) on a name that a later list marks as assembly
res = m.apply_prototypes([("late_asm", "void late_asm(void)")])
assert res["applied"] == 1 and 0x7B00 in store, res
saved_asm, m.ASM_VOID = m.ASM_VOID, m.ASM_VOID | {"late_asm"}
res = m.apply_prototypes([("late_asm", "void late_asm(void)")])
assert res["void_removed"] == 1 and 0x7B00 not in store and 0x7B00 not in shown, (res, store)  # record deleted too
m.ASM_VOID = saved_asm
assert shown[0x7700] == "IDA:long fn_b(long y);", "a type edited by hand must stay"
addrs["fn_c"] = 0x7A00                                                   # run 1: btf2ida sets int fn_c(int x)
res = m.apply_prototypes([("fn_c", "int fn_c(int x)")])
assert res["applied"] == 1 and 0x7A00 in store, res
library.add("fn_c")                         # run 2 (another kernel's BTF): void fn_c(void), IDA's library has fn_c(int)
del calls[:]
res = m.apply_prototypes([("fn_c", "void fn_c(void)")])
assert (res["void_removed"], res["void_ida"]) == (0, 1) and shown[0x7A00] == "IDA:int __btf2ida_fn(int x);", (res, calls)
userti = set()                                                            # without netnode support: as before
del sys.modules["ida_netnode"]
del calls[:]
res = m.apply_prototypes([("fn_a", "int fn_a(int x)")])
assert res["applied"] == 1 and res["retyped"] == 0, res
del sys.modules["ida_typeinf"]
print("stub test OK: a re-run re-types btf2ida's own unchanged prototypes, keeps hand edits, removes an old void(void) on memcpy")
# Names that clash with types: SetType gets a fixed declarator (IDA ignores the name), and btf2c renames a parameter
# named like a typedef or tag; rejected prototypes are named in the summary.
assert m.unnamed("void bpf_spin_lock(struct bpf_spin_lock *lock)", "bpf_spin_lock") == "void __btf2ida_fn(struct bpf_spin_lock *lock)"
assert m.unnamed("int (*get_op(int x))(void *get_op_arg)", "get_op") == "int (*__btf2ida_fn(int x))(void *get_op_arg)"
assert m.unnamed("void f(int x)", "f") == "void __btf2ida_fn(int x)"
assert m.unnamed("void x.f(int a)", "f") == "void x.f(int a)", "a name inside another identifier is left alone"
gen = btf2c.Generator(B.BTF(raw))
res = dict(m.apply_prototypes([]), rejected=["a", "b", "c", "d"], imports_rejected=["e"])
text = m.report("x", gen, [], res)
assert "Prototypes rejected by IDA (first 3 of 5): a, b, c" in text, text
c = Build()
c.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                   # 1
c.t("code", 8, 0, 1)                                                                  # 2  typedef int code
c.t("_Bool", 1, 0, 1, struct.pack("<I", 4 << 24 | 8))                                 # 3  _Bool
c.t("", 13, 3, 1, struct.pack("<IIIIII", c.s("code"), 2, c.s("task"), 1, c.s("on"), 3))  # 4  int (code, int, _Bool)
c.t("task", 4, 1, 4, struct.pack("<III", c.s("x"), 1, 0))                             # 5  struct task
c.t("code_user", 12, 0, 4)                                                            # 6
c.t("task", 12, 0, 4)                                                                 # 7  function named like a tag
cgen = btf2c.Generator(B.BTF(c.blob()))
protos = dict(cgen.prototypes())
assert protos == {"code_user": "int code_user(code code_, int task, bool on)", "task": "int task(code code_, int task, bool on)"}, protos
assert m.unnamed(protos["task"], "task") == "int __btf2ida_fn(code code_, int task, bool on)"
d = Build()
d.t("int", 1, 0, 4, struct.pack("<I", 1 << 24 | 32))                                   # 1
d.t("code", 8, 0, 1)                                                                  # 2  typedef int code
d.t("", 13, 2, 1, struct.pack("<IIII", d.s("code"), 2, d.s("code_"), 1))              # 3  int (code code, int code_)
d.t("clash", 12, 0, 3)                                                                # 4
assert dict(btf2c.Generator(B.BTF(d.blob())).prototypes())["clash"] == "int clash(code code__, int code_)"
assert "#include" not in btf2c.header(cgen), "the header must stay parseable by IDA (no includes)"
ida.inf_get_cc_size_b = lambda: 1
assert m.bool_name() == "bool"
ida.inf_get_cc_size_b = lambda: 4                                      # a database whose compiler bool is 4 bytes
assert m.bool_name() == "_BOOL1"
del ida.inf_get_cc_size_b
assert m.bool_name() == "_BOOL1"
assert dict(btf2c.Generator(B.BTF(c.blob()), bool_name="_BOOL1").prototypes())["task"] == "int task(code code_, int task, _BOOL1 on)"
print("stub test OK: fixed declarator name for SetType, rejected prototypes named, typedef-named parameters renamed, _Bool as bool")
# Undefined symbols of the input module vs the database: explains an import count of 0.
def tiny_elf32_be(sections):
    """ELF32 big-endian relocatable file with the given (name, content) sections and a .shstrtab."""
    names = b"\0" + b"".join(n + b"\0" for n, _ in sections) + b".shstrtab\0"
    payload = names + b"".join(content for _, content in sections)
    shoff = (52 + len(payload) + 3) & ~3
    headers, at, offset = [bytes(40)], 1, 52 + len(names)
    for n, content in sections:
        headers.append(struct.pack(">IIIIIIIIII", at, 1, 0, 0, offset, len(content), 0, 0, 1, 0))
        at, offset = at + len(n) + 1, offset + len(content)
    headers.append(struct.pack(">IIIIIIIIII", at, 3, 0, 0, 52, len(names), 0, 0, 1, 0))
    ehdr = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 8, 1, 0, 0, shoff, 0, 52, 0, 0, 40, len(headers), len(headers) - 1)
    return ehdr + payload + bytes(shoff - 52 - len(payload)) + b"".join(headers)


strtab = b"\0imp_a\0imp_b\0own\0"
sym64 = bytes(24) + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0) + struct.pack("<IBBHQQ", 7, 0x10, 0, 0, 0, 0) + struct.pack("<IBBHQQ", 13, 0x12, 0, 1, 0, 8)
sym32 = bytes(16) + struct.pack(">IIIBBH", 1, 0, 0, 0x10, 0, 0) + struct.pack(">IIIBBH", 7, 0, 0, 0x10, 0, 0) + struct.pack(">IIIBBH", 13, 0, 8, 0x12, 0, 1)
assert B.undefined_symbols(tiny_rel([(b".symtab", sym64), (b".strtab", strtab)])) == {"imp_a", "imp_b"}
assert B.undefined_symbols(tiny_elf32_be([(b".symtab", sym32), (b".strtab", strtab)])) == {"imp_a", "imp_b"}
assert B.undefined_symbols(tiny_rel([b".text"])) == set() and B.undefined_symbols(b"junk") == set()
modfile = os.path.join(tempfile.mkdtemp(), "m.ko")
with open(modfile, "wb") as handle:
    handle.write(tiny_rel([(b".symtab", sym64), (b".strtab", strtab)]))
nalt.get_input_file_path = lambda: modfile
idc.get_name_ea_simple = lambda n: {"imp_a": 0x8000, "imp_b": 0x3000, "own": 0x3100}.get(n, idc.BADADDR)
m.ida_segment = seg
seg.segtype = lambda ea: seg.SEG_XTRN if ea == 0x8000 else seg.SEG_CODE
assert m.undefined_in_database() == (2, 2, 1), m.undefined_in_database()
seg.segtype = lambda ea: seg.SEG_CODE                                  # IDA put no import in an extern segment
assert m.undefined_in_database() == (2, 2, 2)
modgen = types.SimpleNamespace(stats=gen.stats, btf=types.SimpleNamespace(count=1, base=object(), distilled=False, unchecked_release=None))
text = m.report("x", modgen, [], dict(m.apply_prototypes([]), undefined=(2, 2, 2)))
assert "The module's 2 undefined symbols: 2 found in this database, 2 of them outside an extern segment" in text, text
assert "IDA put none of the module's imports in an extern segment" in text, text
text = m.report("x", modgen, [], dict(m.apply_prototypes([]), undefined=(2, 2, 1)))
assert "1 of them outside" in text and "IDA put none" not in text, text
assert "undefined symbols" not in m.report("x", modgen, [], dict(m.apply_prototypes([]), undefined=(0, 0, 0)))  # no symtab
nalt.get_input_file_path = lambda: os.path.join(tempfile.mkdtemp(), "gone.ko")
assert m.undefined_in_database() is None
print("stub test OK: undefined symbols of the module counted (ELF64 LE, ELF32 BE), 'outside an extern segment' explained")
print("stub test OK (fake IDA modules)")
