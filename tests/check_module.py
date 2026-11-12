#!/usr/bin/env python3
"""Runs the plugin's own import on a kernel module (.ko) against a fake IDA database, outside IDA.

    python3 tests/check_module.py nf_tables.ko vmlinux
    python3 tests/check_module.py nf_tables.ko vmlinux --no-names

The fake database is built from the module's ELF symbol table, the way IDA lays out a module:
every defined FUNC symbol is a function, every undefined symbol sits in an extern segment
(SEG_XTRN). With --no-names every name lookup fails. The IDA modules are stand-ins written here,
not IDA: this checks what btf2ida decides and counts, not how IDA itself parses the declarations
(parse_decls always succeeds here). It prints the same summary the menu action shows, the number
of SetType calls, and up to three of the prototypes applied to imports.

Needs only Python 3 (no readelf, no IDA). The module must be a 64-bit little-endian ELF.
"""
import os
import struct
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
USAGE = "usage: python3 tests/check_module.py <module.ko> <vmlinux> [--no-names]"

FUNC_BASE = 0x1000      # fake addresses of the module's own functions
EXTERN_BASE = 0x900000  # fake extern segment; everything at or above it is SEG_XTRN


def elf_symbols(blob):
    """[(name, type, shndx)] from every SHT_SYMTAB section of a 64-bit little-endian ELF."""
    if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise SystemExit("check_module: not a 64-bit little-endian ELF file")
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", blob, 0x3a)
    sections = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + shentsize * i) for i in range(shnum)]
    out = []
    for sec in sections:
        if sec[1] != 2:  # SHT_SYMTAB
            continue
        strtab = sections[sec[6]]
        for i in range(sec[5] // 24):
            st_name, st_info, _, st_shndx, _, _ = struct.unpack_from("<IBBHQQ", blob, sec[4] + 24 * i)
            if not st_name:
                continue
            start = strtab[4] + st_name
            name = blob[start:blob.index(b"\0", start)].decode("utf-8", "replace")
            out.append((name, st_info & 0xF, st_shndx))
    return out


def fake_database(module_path, vmlinux_path, with_names=True):
    """Install stand-in IDA modules in sys.modules; returns (functions, externs, SetType log)."""
    with open(module_path, "rb") as handle:
        symbols = elf_symbols(handle.read())
    functions, externs = {}, {}
    for name, kind, shndx in symbols:
        if shndx == 0:  # SHN_UNDEF: an import
            externs.setdefault(name, EXTERN_BASE + 16 * len(externs))
        elif kind == 2 and name not in functions:  # STT_FUNC
            functions[name] = FUNC_BASE + 0x40 * len(functions)
    names = {**functions, **externs} if with_names else {}
    by_address = {address: name for name, address in names.items()}
    settype = []

    def module(name, **attrs):
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        sys.modules[name] = mod
        return mod

    badaddr = (1 << 64) - 1
    module("ida_kernwin", action_handler_t=object, show_wait_box=lambda *a: None,
           replace_wait_box=lambda *a: None, hide_wait_box=lambda: None, msg=lambda *a: None,
           info=lambda *a: None, warning=lambda *a: None, user_cancelled=lambda: False,
           ask_file=lambda *a: vmlinux_path)
    module("ida_idaapi", plugin_t=object, PLUGIN_KEEP=2, PLUGIN_HIDE=16)
    module("ida_ida", inf_is_64bit=lambda: True)
    module("idc", PT_SIL=1, PT_PAK1=16, BADADDR=badaddr, parse_decls=lambda text, flags: 0,
           get_name_ea_simple=lambda n: names.get(n, badaddr),
           SetType=lambda ea, decl: settype.append((ea, decl)) or True,
           get_segm_end=lambda ea: ea, get_func_name=lambda ea: by_address.get(ea, ""))
    own = set(functions.values()) if with_names else set()
    module("ida_funcs", get_func=lambda ea: types.SimpleNamespace(start_ea=ea) if ea in own else None,
           add_func=lambda ea: True)
    module("idautils", Segments=lambda: [], Functions=lambda: sorted(own))
    module("ida_bytes", get_bytes=lambda ea, n: b"", get_flags=lambda ea: 0, has_user_name=lambda f: False)
    module("ida_nalt", get_input_file_path=lambda: module_path, is_userti=lambda ea: False)
    module("ida_name", SN_NOCHECK=1, SN_NOWARN=256, set_name=lambda *a: True)
    module("ida_segment", SEG_XTRN=1, SEG_CODE=2,
           segtype=lambda ea: 1 if EXTERN_BASE <= ea < badaddr else 2)
    return functions, externs, settype


def main(argv):
    args = [a for a in argv if a != "--no-names"]
    if len(args) != 2 or not all(os.path.isfile(a) for a in args):
        print(USAGE, file=sys.stderr)
        return 2
    module_path, vmlinux_path = (os.path.abspath(a) for a in args)
    functions, externs, settype = fake_database(module_path, vmlinux_path, "--no-names" not in argv)
    sys.path.insert(0, os.path.dirname(HERE))
    import btf as B  # noqa: E402
    import btf2ida_entry  # noqa: E402

    print("Fake database: %d module functions, %d undefined symbols in an extern segment%s"
          % (len(functions), len(externs), " (names hidden: --no-names)" if "--no-names" in argv else ""))
    start = time.time()
    try:
        summary = btf2ida_entry.run_import(vmlinux_path, ask=False)
    except B.BTFError as error:
        print("BTF2IDA: %s" % error)
        return 1
    print(summary)
    print("SetType calls: %d (%.1f s)" % (len(settype), time.time() - start))
    by_address = {ea: name for name, ea in externs.items()}
    shown = [(ea, decl) for ea, decl in settype if ea >= EXTERN_BASE][:3]
    for ea, decl in shown:  # btf2ida passes IDA a fixed declarator name; show the import's own name here
        print("  import typed: %s" % decl.strip().replace("__btf2ida_fn(", by_address.get(ea, "?") + "(", 1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
