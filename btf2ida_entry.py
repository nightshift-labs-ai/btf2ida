"""btf2ida: apply a Linux kernel's own BTF type information in IDA, with no debug package.

One action under Edit > Plugins: BTF2IDA: Apply kernel types and prototypes. It finds BTF in the input
file or the loaded segments (vmlinux, a kernel module, a raw kernel, a memory image), imports every
struct, union, enum and typedef, then applies a prototype to each function whose name matches.
"""
import traceback
import mmap
import struct
import os
import sys

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import idautils
import idc

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import btf as B  # noqa: E402  (needs the plugin folder on sys.path)
import btf2c  # noqa: E402
import ksymtab  # noqa: E402

FILE_PROMPT = "FILTER vmlinux or raw BTF|*\nThis is a kernel module: choose vmlinux (or a copy of /sys/kernel/btf/vmlinux)"
SUFFIXES = (".isra.", ".constprop.", ".part.", ".cold", ".lto_priv")  # the compiler may have changed the ABI


def parse_batch(text):
    """IDA's own parser. PT_PAK1: the layouts are explicit, pack(1) must apply."""
    return idc.parse_decls(text, idc.PT_SIL | idc.PT_PAK1)


def import_in_batches(declarations, parse, batch=1000, progress=None):
    """Feed declarations to parse(text) -> error count; returns those failing on their own.

    One rejected declaration must not cost the rest, so a failing batch is split in half until the
    bad ones are isolated. parse_decls ignores redeclarations, which makes re-parsing a batch safe.
    """
    failed = []

    def run(items):
        if not parse("\n".join(items)):
            return
        if len(items) == 1:
            failed.append(items[0])
            return
        middle = len(items) // 2
        run(items[:middle])
        run(items[middle:])

    for start in range(0, len(declarations), batch):
        if progress and progress(start, len(declarations)):
            break
        run(declarations[start:start + batch])
    return failed


def from_input(base):
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        try:  # mmap: the input may be a many-gigabyte memory image
            blob = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            return None
        try:
            return B.load(blob, base=base)
        except B.NeedsBase:
            raise
        except B.BTFError:
            return None
        finally:
            blob.close()


def from_segments(base):
    best = None
    for start in idautils.Segments():
        end = idc.get_segm_end(start)
        blob = ida_bytes.get_bytes(start, end - start)
        if not blob:
            continue
        try:
            found = B.BTF(blob, base=base) if blob[:2] in (b"\x9f\xeb", b"\xeb\x9f") else B.carve(blob, base=base, little=None)
        except B.BTFError:
            continue
        if found is not None and (best is None or len(found.own) > len(best.own)):
            best = found
    return best


def find_btf():
    """(BTF, where it came from). Asks for vmlinux only when the data is split BTF."""
    base = None
    for attempt in range(2):
        try:
            found = from_input(base)
            if found is not None:
                return found, "the input file"
            found = from_segments(base)
            return found, "the loaded segments"
        except B.NeedsBase:
            if attempt:
                raise
            ida_kernwin.hide_wait_box()  # no modal dialog over a wait box
            path = ida_kernwin.ask_file(False, None, FILE_PROMPT)
            ida_kernwin.show_wait_box("BTF2IDA: reading BTF")
            if not path:
                return None, ""
            with open(path, "rb") as handle:
                base = B.load(handle.read())
    return None, ""


def name_exports():
    """Name exported functions from __ksymtab where the database has no name (a stripped vmlinux).

    Only addresses inside code, never over a name the user gave, never a name already used.
    Returns how many functions were named.
    """
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        return 0
    with open(path, "rb") as handle:
        try:
            blob = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            return 0
        try:
            found = ksymtab.exported(blob)
            check = ksymtab.probe(blob)
        except (ValueError, IndexError, struct.error):
            return 0
        finally:
            blob.close()
    # The addresses come from the file on disk: use them only if the database maps it unchanged.
    if check is None or ida_bytes.get_bytes(check[0], len(check[1])) != check[1]:
        return 0
    named = 0
    for index, (address, (name, is_code)) in enumerate(sorted(found.items())):
        if index % 500 == 0:
            ida_kernwin.replace_wait_box("BTF2IDA: naming exported functions (%d of %d)" % (index, len(found)))
            if ida_kernwin.user_cancelled():
                break
        if not is_code or ida_bytes.has_user_name(ida_bytes.get_flags(address)):
            continue
        if idc.get_name_ea_simple(name) != idc.BADADDR:
            continue
        if ida_funcs.get_func(address) is None:
            ida_funcs.add_func(address)
        if ida_name.set_name(address, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN):
            named += 1
    return named


def apply_prototypes(prototypes, progress=None):
    """Type every function found by exact name; compiler-rewritten clones are left alone."""
    result = {"applied": 0, "rejected": [], "absent": 0, "not_function": 0, "clones": 0, "kept": 0}
    wanted = dict(prototypes)
    for index, (name, declaration) in enumerate(prototypes):
        if progress and index % 500 == 0 and progress(index, len(prototypes)):
            break
        address = idc.get_name_ea_simple(name)
        if address == idc.BADADDR:
            result["absent"] += 1
            continue
        function = ida_funcs.get_func(address)
        if function is None or function.start_ea != address:
            result["not_function"] += 1
            continue
        if ida_nalt.is_userti(address):  # typed by hand or by an earlier run: never overwrite it
            result["kept"] += 1
            continue
        if idc.SetType(address, declaration + ";"):
            result["applied"] += 1
        else:
            result["rejected"].append(name)
    for address in idautils.Functions():
        name = idc.get_func_name(address)
        if any(mark in name for mark in SUFFIXES) and name.split(".")[0] in wanted:
            result["clones"] += 1
    return result


def report(source, generator, failed, result, named=0):
    stats = generator.stats
    lines = [
        "BTF from %s: %d types" % (source, generator.btf.count),
        "Imported %d structs, %d unions, %d enums, %d typedefs (%d declarations rejected by IDA)" % (stats["structs"], stats["unions"], stats["enums"], stats["typedefs"], len(failed)),
        "Named %d exported functions from __ksymtab (the database had no name there)" % named,
        "Prototypes applied to %d functions; rejected by IDA %d; not in this database %d; name is not a function start %d" % (result["applied"], len(result["rejected"]), result["absent"], result["not_function"]),
        "Left untyped on purpose: %d compiler clones (.isra, .constprop, .part, .cold), their ABI may differ" % result["clones"],
        "Kept as they were: %d functions that already had a user-set type" % result["kept"],
    ]
    if failed:
        lines.append("First rejected declaration: %s" % failed[0][:200])
    return "\n".join(lines)


def run_import():
    data, source = find_btf()
    if data is None:
        raise B.BTFError("no BTF found in the input file or the loaded segments.")
    pointer_size = 8 if ida_ida.inf_is_64bit() else 4
    generator = btf2c.Generator(data, pointer_size)
    declarations = generator.declarations()
    # 32-bit x86 kernels pass arguments in registers (regparm), which a plain C prototype would misstate.
    prototypes = generator.prototypes() if pointer_size == 8 else []

    def types_progress(done, total):
        ida_kernwin.replace_wait_box("BTF2IDA: importing types (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    def proto_progress(done, total):
        ida_kernwin.replace_wait_box("BTF2IDA: applying prototypes (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    failed = import_in_batches(declarations, parse_batch, progress=types_progress)
    named = name_exports() if prototypes and not ida_kernwin.user_cancelled() else 0
    return report(source, generator, failed, apply_prototypes(prototypes, proto_progress), named)



ISSUES_URL = "https://github.com/nightshift-labs-ai/btf2ida/issues"


def guarded(activate):
    """Any unexpected error becomes one warning plus the traceback in the Output window."""
    def wrapper(self, ctx):
        try:
            return activate(self, ctx)
        except Exception:  # noqa: BLE001  (last line of defence inside IDA)
            ida_kernwin.msg("[BTF2IDA] unexpected error:\n%s\n" % traceback.format_exc())
            ida_kernwin.warning("BTF2IDA: unexpected error, details are in the Output window.\nPlease report it: %s" % ISSUES_URL)
            return 0
    return wrapper

class ApplyBTF(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        problem = None
        ida_kernwin.show_wait_box("BTF2IDA: reading BTF")
        try:
            message = run_import()
        except B.BTFError as error:
            message = None
            problem = str(error)
        finally:
            ida_kernwin.hide_wait_box()
        if problem:
            ida_kernwin.warning("BTF2IDA: %s" % problem)
        if message:
            ida_kernwin.msg("[BTF2IDA] %s\n" % message)
            ida_kernwin.info(message.replace("%", "%%"))  # info() is printf-style in IDAPython (not wrapped like msg/warning)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTION = "btf2ida:apply"
LABEL = "BTF2IDA: Apply kernel types and prototypes"


class BTF2IDA(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Apply Linux BTF types and function prototypes"
    help = "Finds BTF in a Linux kernel or module and applies its types and prototypes"
    wanted_name = "BTF2IDA"
    wanted_hotkey = ""

    def init(self):
        ida_kernwin.register_action(ida_kernwin.action_desc_t(ACTION, LABEL, ApplyBTF()))
        if not ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION, ida_kernwin.SETMENU_APP):
            ida_kernwin.msg("[BTF2IDA] could not add the menu item\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info("BTF2IDA is under Edit > Plugins.")

    def term(self):
        ida_kernwin.unregister_action(ACTION)


def PLUGIN_ENTRY():
    return BTF2IDA()
