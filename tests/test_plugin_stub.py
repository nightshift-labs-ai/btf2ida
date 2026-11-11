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
assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "int get_it(struct task *arg);")], calls
assert all(c[2] == idc.PT_SIL | idc.PT_PAK1 for c in calls if c[0] == "parse")
parsed = "\n".join(c[1] for c in calls if c[0] == "parse")
assert "struct task {" in parsed and "#pragma" not in parsed
message = [c[1] for c in calls if c[0] == "info"][0]
assert "applied to 1 functions" in message and "not in this database 1" in message and "not a function start 1" in message and "1 compiler clones" in message, message
assert m.import_in_batches(["a;", "BAD;", "b;"], lambda t: t.count("BAD"), batch=2) == ["BAD;"]
assert "Named 0 exported functions" in message, message
assert "imported kernel functions" not in message and not [c for c in calls if c[0] == "segtype"], "a whole kernel never looks for externs"

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
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "int mod_fn(int x);"),
                                                        ("settype", 0x8000, "int imp_fn(int x);")], calls
    message = [c[1] for c in calls if c[0] == "info"][0]
    assert "applied to 1 functions" in message and "not in this database 1;" in message, message
    assert "Typed 1 imported kernel functions in the extern segment" in message, message
    # The headless path passes vmlinux directly: no file dialog.
    def no_dialog(*a):
        raise AssertionError("asked for a file although vmlinux was given")
    kw.ask_file = no_dialog
    message64 = m.run_import(paths["vmlinux.btf"])
    assert "BTF from the input file" in message64 and "32-bit database" not in message64, message64
    ida.inf_is_64bit = lambda: False  # 32-bit: types only, and the summary says why no prototype was applied
    message32 = m.run_import(paths["vmlinux.btf"])
    assert "Prototypes not applied: this is a 32-bit database" in message32 and "applied to 0 functions" in message32, message32
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
        handle.write(b"\x7fELF" + bytes(12) + b"\x01\x00" + bytes(46) + b".gnu.linkonce.this_module\x00")
    nalt.get_input_file_path = lambda: nobtf
    whole_segments = autos.Segments
    autos.Segments = lambda: []
    del calls[:]
    message = m.run_import()
    assert "no BTF of its own" in message and "Typed 1 imported kernel functions" in message, message
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x8000, "int imp_fn(int x);")], calls
    try:
        m.run_import(None, ask=False)
        raise AssertionError("a module without BTF and without vmlinux must fail")
    except B.BTFError as error:
        assert "--vmlinux" in str(error) and "no BTF of its own" in str(error), error
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
print("stub test OK (fake IDA modules)")
