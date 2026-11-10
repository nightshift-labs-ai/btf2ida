#!/usr/bin/env python3
"""Check every ida_*/idc name used by the plugin against the official IDAPython sources.

The stub test uses fake modules, so a misspelled or removed API would pass there. This one needs a
checkout of https://github.com/HexRaysSA/ida-sdk (only src/plugins/idapython is read):

    python3 tests/check_ida_api.py <ida-sdk>/src/plugins/idapython

It proves the names exist, not that the calls behave as intended in IDA.
"""
import ast
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MODULES = ("ida_kernwin", "ida_idaapi", "ida_nalt", "ida_name", "ida_bytes", "ida_funcs", "ida_ida", "idautils", "idc")


def dotted(node):
    """'a.b.c' for an attribute chain rooted at a plain name, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def used_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            name = dotted(node)
            if name and name.split(".")[0] in MODULES:
                names.add(name)
    # A name is covered by its longest form only, so ida_kernwin.Choose.CHCOL_EA checks the member.
    return {n for n in names if not any(o.startswith(n + ".") for o in names)}


def known_api(idapython):
    with open(os.path.join(idapython, "api_contents.brief")) as handle:
        known = {line.strip() for line in handle if line.strip()}
    with open(os.path.join(idapython, "python", "idc.py")) as handle:
        source = handle.read()
    known |= {"idc." + name for name in re.findall(r"^(?:def )?([A-Za-z_]\w*)\s*[=(]", source, re.M)}
    with open(os.path.join(idapython, "python", "idautils.py")) as handle:
        known |= {"idautils." + name for name in re.findall(r"^def ([A-Za-z_]\w*)", handle.read(), re.M)}
    # Plain Python constants live in the wrappers, not in the generated API list.
    for path, prefix in (("py_idaapi.py", "ida_idaapi."), ("py_kernwin_choose.py", "ida_kernwin.Choose.")):
        with open(os.path.join(idapython, "pywraps", path)) as handle:
            known |= {prefix + name for name in re.findall(r"^\s*([A-Z][A-Z_]+)\s*=", handle.read(), re.M)}
    return known


def main():
    with open(os.path.join(ROOT, "btf2ida_entry.py")) as handle:
        tree = ast.parse(handle.read())
    known = known_api(sys.argv[1])
    used = used_names(tree)
    # Methods called on instances of IDA classes, which the module walk above cannot see.
    used |= {"ida_idaapi.plugin_t.run", "ida_idaapi.plugin_t.term"}
    used |= {"ida_kernwin.action_handler_t.activate", "ida_kernwin.action_handler_t.update"}
    missing = sorted(used - known)
    for name in missing:
        print("NOT IN OFFICIAL API:", name)
    print("%d names checked, %d missing" % (len(used), len(missing)))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
