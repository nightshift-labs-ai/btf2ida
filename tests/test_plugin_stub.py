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
assert "int private_;" in text and "__bits_4[1]" in text and "int (*cb)(struct task *arg);" in text.replace("a1", "arg"), text
assert "RED = 2," in text and "typedef int mode_t;" in text
assert ("get_it", "int get_it(struct task *arg)") in gen.prototypes(), gen.prototypes()
with tempfile.TemporaryDirectory() as folder:
    path = os.path.join(folder, "x.c")
    with open(path, "w") as handle:
        handle.write(text + "_Static_assert(sizeof(struct task) == 32, \"size\");\n_Static_assert(__builtin_offsetof(struct task, cb) == 8, \"cb\");\n")
    subprocess.run(["gcc", "-fsyntax-only", "-w", path], check=True)

try:  # split BTF: strings that do not start with NUL
    B.BTF(struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, 0, 0, 2) + b"a\0")
    raise SystemExit("split BTF was accepted without a base")
except B.NeedsBase:
    pass

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
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_ida=ida, idc=idc, ida_funcs=funcs, idautils=autos, ida_bytes=dbytes, ida_nalt=nalt)

import btf2ida_entry as m  # noqa: E402

plugin = m.PLUGIN_ENTRY()
assert plugin.init() == api.PLUGIN_KEEP
assert m.ApplyBTF().activate(None) == 1
assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "int get_it(struct task *arg);")], calls
assert all(c[2] == idc.PT_SIL | idc.PT_PAK1 for c in calls if c[0] == "parse")
parsed = "\n".join(c[1] for c in calls if c[0] == "parse")
assert "struct task {" in parsed and "#pragma" not in parsed
message = [c[1] for c in calls if c[0] == "info"][0]
assert "applied to 1 functions" in message and "not in this database 1" in message and "not a function start 1" in message and "1 compiler clones" in message, message
assert m.import_in_batches(["a;", "BAD;", "b;"], lambda t: t.count("BAD"), batch=2) == ["BAD;"]
plugin.term()
assert ("unreg", "btf2ida:apply") in calls
print("stub test OK (fake IDA modules)")
