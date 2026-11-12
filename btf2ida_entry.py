"""btf2ida: apply a Linux kernel's own BTF type information in IDA, with no debug package.

One action under Edit > Plugins: BTF2IDA: Apply kernel types and prototypes. It finds BTF in the input
file or the loaded segments (vmlinux, a kernel module, a raw kernel, a memory image), imports every
struct, union, enum and typedef, then applies a prototype to each function whose name matches
(for a kernel module: its own functions, plus the kernel functions it imports, in the extern segment).
"""
import re
import traceback
import zlib
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

try:  # part of IDAPython; only used to type a kernel module's imports, which is skipped without it
    import ida_segment
except ImportError:
    ida_segment = None

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
    bad ones are isolated. parse_decls ignores redeclarations, which makes re-parsing a batch safe
    (SDK typeinf.hpp: parse_decls "always uses the #HTI_DCL bit" = "don't complain about redeclarations").
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
        except (B.NeedsBase, B.BaseMismatch):
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


SOURCE_NO_OWN_BTF = "the chosen vmlinux (this kernel module has no BTF of its own)"


def input_is_module():
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as handle:
            blob = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                return B.is_kernel_module(blob)
            finally:
                blob.close()
    except (OSError, ValueError):
        return False


def vmlinux_for_module(vmlinux, ask):
    """vmlinux BTF for a kernel module that has no BTF of its own (its imports can still be typed)."""
    why = "this kernel module has no BTF of its own"
    path = vmlinux
    if not path and not ask:
        raise B.BTFError(why + ": give the matching vmlinux with --vmlinux to type the kernel functions it calls.")
    if not path:
        ida_kernwin.hide_wait_box()  # no modal dialog over a wait box
        path = ida_kernwin.ask_file(False, None, FILE_PROMPT)
        ida_kernwin.show_wait_box("BTF2IDA: reading BTF")
    if not path:
        raise B.BTFError(why + ": choose the matching vmlinux to type the kernel functions it calls.")
    with open(path, "rb") as handle:
        blob = B.unpack_kernel_image(handle.read(), path)
    data = B.load_base(blob, path)
    # Nothing in the BTF ties it to the module (no split BTF to check), so compare the kernel releases.
    built_for, found = input_module_release(), B.kernel_releases(blob)
    if built_for and found and built_for not in found:
        raise B.BTFError("this kernel module was built for %s, but the chosen vmlinux is %s: choose the vmlinux "
                         "of the same build (its prototypes may differ)." % (built_for, " / ".join(sorted(found))))
    data.unchecked_release = built_for if built_for and not found else None
    return data


def input_module_release():
    """vermagic release of the input file, or None if it is gone or has none."""
    path = ida_nalt.get_input_file_path()
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            return B.module_release(handle.read())
    except (OSError, ValueError):
        return None


def find_btf(vmlinux=None, ask=True):
    """(BTF, where it came from). For split BTF it uses the vmlinux path given, or asks for one (if ask)."""
    base = None
    for attempt in range(2):
        try:
            found = from_input(base)
            if found is not None:
                return found, "the input file"
            found = from_segments(base)
            if found is None and base is None and input_is_module():
                return vmlinux_for_module(vmlinux, ask), SOURCE_NO_OWN_BTF
            return found, "the loaded segments"
        except B.NeedsBase:
            if attempt:
                raise
            path = vmlinux
            if not path and not ask:
                raise B.BTFError("this is split BTF (a kernel module): give the matching vmlinux with --vmlinux.")
            if not path:
                ida_kernwin.hide_wait_box()  # no modal dialog over a wait box
                path = ida_kernwin.ask_file(False, None, FILE_PROMPT)
                ida_kernwin.show_wait_box("BTF2IDA: reading BTF")
            if not path:
                raise B.BTFError("this is split BTF (a kernel module): it needs the matching vmlinux, and none was chosen.")
            with open(path, "rb") as handle:
                base = B.load_base(B.unpack_kernel_image(handle.read(), path), path)
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


def in_extern_segment(address):
    """True if IDA put this address in an extern segment (SEG_XTRN), where a module's imports are.

    segtype() rather than getseg().type: getseg is marked deprecated in the IDA 9.5 SDK (segment.hpp).
    Any failure counts as "no", which only leaves that import untyped.
    """
    if ida_segment is None:
        return False
    try:
        return ida_segment.segtype(address) == ida_segment.SEG_XTRN
    except Exception:  # noqa: BLE001  (an optional step must never stop the import)
        return False


# BTF records an assembly function as "void f(void)" (pahole has no C prototype for it), the same record as a real
# void f(void). Applied to memcpy, __arch_copy_from_user & co., it would wipe the arguments at every call, so btf2ida
# leaves such a prototype out for the names below and wherever IDA's own type (at the address, or in its type
# libraries for that name) lists parameters. The list: entry points defined in arch/x86 and arch/arm64 .S files
# (mostly SYM_FUNC_START / SYM_CODE_START), and on 7.0 the lib/crypto ones, that BTF records as void f(void) on Debian 13
# 6.12 (amd64, arm64), Ubuntu 24.04 6.8 (amd64, arm64) and Ubuntu 26.04 7.0 (amd64). Skipping a name here costs
# nothing: BTF has no real prototype for any of them.
ASM_VOID = frozenset("""
    __WARN_trap __arch_clear_user __arch_copy_from_user __arch_copy_to_user __arm_smccc_hvc __arm_smccc_smc
    __ashlti3 __ashrti3 __clear_pages_unrolled __copy_user_nocache __cpu_secondary_check52bitva __cpu_setup
    __cpu_suspend_enter __efi64_thunk __efi_call __efi_rt_asm_wrapper __enable_mmu __enc_copy __fentry__
    __fpsimd_restore_state __fpsimd_save_state __get_user_1 __get_user_2 __get_user_4 __get_user_8
    __get_user_nocheck_1 __get_user_nocheck_2 __get_user_nocheck_4 __get_user_nocheck_8 __guest_enter
    __hyp_reset_vectors __hyp_set_vectors __lshrti3 __memcpy __memmove __memset __no_granule_support
    __pi_caches_clean_inval_pou __pi_clear_page __pi_copy_page __pi_dcache_clean_inval_poc __pi_dcache_clean_poc
    __pi_dcache_clean_pop __pi_dcache_inval_poc __pi_idmap_cpu_replace_ttbr1 __pi_memchr __pi_memcmp __pi_memcpy
    __pi_memmove __pi_memset __pi_sme_encrypt_execute __pi_strchr __pi_strcmp __pi_strlen __pi_strncmp __pi_strnlen
    __pi_strrchr __primary_switch __primary_switched __put_user_1 __put_user_2 __put_user_4 __put_user_8
    __put_user_nocheck_1 __put_user_nocheck_2 __put_user_nocheck_4 __put_user_nocheck_8 __relocate_kernel __seamcall
    __seamcall_ret __seamcall_saved_ret __secondary_switched __secondary_too_slow __sve_restore_state
    __sve_save_state __sw_hweight32 __sw_hweight64 __switch_to_asm __tdcall __tdcall_ret __tdcall_saved_ret
    _cpu_resume aes128_expandkey_aesni aes256_expandkey_aesni aes_decrypt_aesni aes_encrypt_aesni arm_smccc_1_2_hvc
    arm_smccc_1_2_smc asm_acpi_mp_play_dead asm_fred_entry_from_kvm asm_load_gs_index blake2s_compress_avx512
    blake2s_compress_ssse3 caches_clean_inval_pou caches_clean_inval_user_pou call_depth_return_thunk
    call_on_irq_stack chacha_2block_xor_avx2 chacha_2block_xor_avx512vl chacha_4block_xor_avx2
    chacha_4block_xor_avx512vl chacha_4block_xor_ssse3 chacha_8block_xor_avx2 chacha_8block_xor_avx512vl
    chacha_block_xor_ssse3 check_events clear_bhb_loop clear_page clear_page_erms clear_page_orig clear_page_rep
    clear_page_tables copy_mc_enhanced_fast_string copy_mc_fragile copy_page copy_page_regs copy_to_nontemporal
    core_restore_code cpu_do_resume cpu_do_suspend cpu_switch_to crc16_msb_pclmul_sse crc16_msb_vpclmul_avx2
    crc16_msb_vpclmul_avx512 crc32_lsb_pclmul_sse crc32_lsb_vpclmul_avx2 crc32_lsb_vpclmul_avx512 crc32c_x86_3way
    crc64_lsb_pclmul_sse crc64_lsb_vpclmul_avx2 crc64_lsb_vpclmul_avx512 crc64_msb_pclmul_sse crc64_msb_vpclmul_avx2
    crc64_msb_vpclmul_avx512 crc_pcl create_idmap create_kernel_mapping csum_partial_copy_generic
    dcache_clean_inval_poc dcache_clean_poc dcache_clean_pop dcache_clean_pou dcache_inval_poc do_suspend_lowlevel
    entry_ibpb entry_untrain_ret finalise_el2 fpsimd_load_state fpsimd_save_state ftrace_caller ftrace_regs_caller
    ftrace_stub ftrace_stub_direct_tramp ftrace_stub_graph hchacha_block_ssse3 ibt_selftest icache_inval_pou
    idmap_cpu_replace_ttbr1 idmap_kpti_install_ng_mappings init_kernel_el memcpy memcpy_orig memmove memset
    memset_orig mte_clear_page_tags mte_copy_page_tags mte_copy_tags_from_user mte_copy_tags_to_user
    mte_restore_page_tags mte_save_page_tags mte_zero_clear_page_tags native_save_fl poly1305_blocks_avx
    poly1305_blocks_avx2 poly1305_blocks_avx512 poly1305_blocks_x86_64 poly1305_emit_avx poly1305_emit_x86_64
    poly1305_init_x86_64 privcmd_call remap_region rep_movs_alternative rep_stos_alternative restore_image
    restore_registers retbleed_untrain_ret secondary_entry secondary_holding_pen secondary_startup
    set_cpu_boot_mode_flag sev_verify_cbit sha1_ni_transform sha1_transform_avx sha1_transform_avx2
    sha1_transform_ssse3 sha256_ni_finup2x sha256_ni_transform sha256_transform_avx sha256_transform_rorx
    sha256_transform_ssse3 sha512_transform_avx sha512_transform_rorx sha512_transform_ssse3 sme_encrypt_execute
    srso_alias_safe_ret srso_alias_untrain_ret srso_untrain_ret strchr sve_flush_live sve_get_vl sve_load_state
    sve_save_state sve_set_vq swsusp_arch_suspend this_cpu_cmpxchg16b_emu verify_cpu wakeup_long64 write_ibpb
    xen_hypercall_amd xen_hypercall_hvm xen_hypercall_intel xen_hypercall_pv xen_irq_disable_direct
    xen_irq_enable_direct xen_read_cr2 xen_read_cr2_direct xen_save_fl_direct""".split())
VOID_VOID = re.compile(r"^void\s+[A-Za-z_][A-Za-z_0-9]*\(void\)$")


def library_prototype(name):
    """The prototype IDA's loaded type libraries hold for the function symbol `name` (memcpy in gnulnx_x64), or None.
    Prototypes are symbols in a type library (NTF_SYMM), not type names."""
    try:
        import ida_typeinf
        found = ida_typeinf.get_named_type(None, name, ida_typeinf.NTF_SYMM)
        tif = ida_typeinf.tinfo_t()
        if found and tif.deserialize(None, found[1], found[2]) and tif.is_func():
            return tif
    except Exception:  # noqa: BLE001  (no type library answer)
        pass
    return None


def current_has_parameters(address):
    """True when IDA's current type at address is a function type with at least one parameter."""
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        return bool(ida_nalt.get_tinfo(tif, address) and tif.is_func() and tif.get_nargs() > 0)
    except Exception:  # noqa: BLE001  (no tinfo API: read the type text instead)
        pass
    try:
        current = idc.get_type(address) or ""
    except Exception:  # noqa: BLE001  (no type information)
        return False
    inside = current[current.find("(") + 1:current.rfind(")")] if "(" in current else ""
    return bool(inside.strip()) and inside.strip() != "void"


def void_void_unsafe(address, name, declaration, check_current=True):
    """Why "void name(void)" must not be applied: "asm" for a known assembly function, "ida" when IDA's type at the
    address or its type library prototype for the name lists parameters; None to apply it."""
    if not VOID_VOID.match(declaration.strip()):
        return None
    if name in ASM_VOID:
        return "asm"
    library = library_prototype(name)
    if library is not None and library.get_nargs() > 0:
        return "ida"
    return "ida" if check_current and current_has_parameters(address) else None


# Every prototype btf2ida sets is "definite" (IDA's user-type flag), the same flag as a type set by hand. To tell its
# own earlier work from the user's, btf2ida records, per address, a CRC of the type text IDA shows right after it set
# it. A later run may replace a prototype only while that record still matches (nobody changed it since).
OWN_NODE = "$ btf2ida typed"


def own_types():
    """The netnode holding btf2ida's own earlier prototypes, or None (no record: user-set types are kept, except an old
    void f(void) on a known assembly name)."""
    try:
        import ida_netnode
        return ida_netnode.netnode(OWN_NODE, 0, True)
    except Exception:  # noqa: BLE001  (no netnode support: no record)
        return None


def type_mark(address):
    """CRC of the type text IDA shows at address, plus 1 (0 = no type)."""
    try:
        text = idc.get_type(address) or ""
    except Exception:  # noqa: BLE001
        return 0
    return (zlib.crc32(text.encode("utf-8", "replace")) & 0xFFFFFFFF) + 1 if text else 0


def earlier_void_void(address, name):
    """True when the user-set type at address looks like the 'void f(void)' that btf2ida 0.1.20 and earlier put on an
    assembly function (memcpy & co.), before the record of its own types existed: a known assembly name whose current
    type has no parameters. Nobody types memcpy as taking no arguments by hand."""
    if name not in ASM_VOID:
        return False
    try:
        current = idc.get_type(address) or ""
    except Exception:  # noqa: BLE001
        return False
    inside = current[current.find("(") + 1:current.rfind(")")].strip() if "(" in current else None
    return inside in ("", "void")


def remove_void_void(address, name, own, result):
    """Undo an earlier btf2ida 'void f(void)' on an assembly function: drop it, and give the address the prototype of
    IDA's type libraries for that name when they have one."""
    try:
        ida_nalt.del_tinfo(address)
        library = library_prototype(name)
        if library is not None:
            import ida_typeinf
            ida_typeinf.apply_tinfo(address, library, ida_typeinf.TINFO_GUESSED)
    except Exception:  # noqa: BLE001  (no type library prototype: the address stays untyped)
        pass
    if own is not None:
        own.altdel_ea(address)
    result["void_removed"] += 1


def unnamed(declaration, name):
    """The declaration with the function's own name replaced by a fixed one. IDA ignores that name when it applies a
    type (idc.SetType), and a kernel function named like a struct, union or enum tag (bpf_spin_lock, 87 on Debian 13)
    could otherwise clash with the type of that name in IDA's parser."""
    return re.sub(r"(?<![A-Za-z0-9_$.])%s(?=\()" % re.escape(name), "__btf2ida_fn", declaration, count=1)


def set_prototype(address, name, declaration, result, is_import=False, own=None):
    ours = own is not None and own.altval_ea(address) != 0 and own.altval_ea(address) == type_mark(address)
    if ida_nalt.is_userti(address) and not ours:  # typed by hand (or changed by hand since btf2ida typed it)
        if VOID_VOID.match(declaration.strip()) and earlier_void_void(address, name):
            remove_void_void(address, name, own, result)
        else:
            result["kept"] += 1
        return
    why = void_void_unsafe(address, name, declaration, check_current=not ours)  # btf2ida's own type is not IDA's
    if why and ours and not current_has_parameters(address):  # btf2ida's own earlier void f(void) goes; IDA's type
        remove_void_void(address, name, own, result)                # library prototype for the symbol comes back
    elif why:
        result["void_" + why] += 1
    elif idc.SetType(address, unnamed(declaration, name) + ";"):
        result["imports" if is_import else "applied"] += 1
        if ours:
            result["retyped"] += 1
        if own is not None:
            own.altset_ea(address, type_mark(address))
    else:
        result["imports_rejected" if is_import else "rejected"].append(name)


def undefined_in_database():
    """(undefined symbols of the input module, how many of these names IDA has, how many of those sit outside an
    extern segment), or None when the input file cannot be read. Explains an import count of 0."""
    path = ida_nalt.get_input_file_path()
    try:
        with open(path, "rb") as handle:
            names = B.undefined_symbols(handle.read())
    except (OSError, TypeError):
        return None
    found = outside = 0
    for name in names:
        address = idc.get_name_ea_simple(name)
        if address != idc.BADADDR:
            found += 1
            outside += not in_extern_segment(address)
    return len(names), found, outside


def apply_prototypes(prototypes, progress=None, imported=()):
    """Type every function found by exact name; compiler-rewritten clones are left alone.

    For a kernel module, `prototypes` are its own functions and `imported` are vmlinux's: those are
    applied only to names in an extern segment (the kernel functions the module calls). vmlinux
    functions the module does not use are not "missing", so they are not counted.
    """
    result = {"applied": 0, "rejected": [], "absent": 0, "not_function": 0, "clones": 0, "kept": 0, "imports": 0, "imports_rejected": [], "void_asm": 0, "void_ida": 0,
              "retyped": 0, "void_removed": 0}
    own = own_types()
    wanted = dict(imported)
    wanted.update(prototypes)
    jobs = [(name, declaration, False) for name, declaration in prototypes]
    jobs += [(name, declaration, True) for name, declaration in imported]
    for index, (name, declaration, is_import) in enumerate(jobs):
        if progress and index % 500 == 0 and progress(index, len(jobs)):
            break
        address = idc.get_name_ea_simple(name)
        if is_import:
            if address != idc.BADADDR and in_extern_segment(address):
                set_prototype(address, name, declaration, result, is_import=True, own=own)
            continue
        if address == idc.BADADDR:
            result["absent"] += 1
            continue
        function = ida_funcs.get_func(address)
        if function is None or function.start_ea != address:
            result["not_function"] += 1
            continue
        set_prototype(address, name, declaration, result, own=own)
    for address in idautils.Functions():
        name = idc.get_func_name(address)
        if any(mark in name for mark in SUFFIXES) and name.split(".")[0] in wanted:
            result["clones"] += 1
    return result


def report(source, generator, failed, result, named=0, cancelled=False, no_prototypes_32=False, no_own_btf=False):
    stats = generator.stats
    lines = ["CANCELLED: the import stopped early, so only part of what is listed below reached the database."] if cancelled else []
    lines += [
        "BTF from %s: %d types" % (source, generator.btf.count),
        "Declarations sent to IDA: %d structs, %d unions, %d enums, %d typedefs (%d rejected by IDA); "
        "%d empty structs/unions as forward declarations only" % (stats["structs"], stats["unions"], stats["enums"], stats["typedefs"], len(failed), stats["empty"]),
        "Named %d exported functions from __ksymtab (the database had no name there)" % named,
        "Prototypes applied to %d functions; rejected by IDA %d; not in this database %d; name is not a function start %d" % (result["applied"], len(result["rejected"]), result["absent"], result["not_function"]),
    ]
    if no_prototypes_32:
        lines.append("Prototypes not applied: this is a 32-bit x86 database (or the processor is unknown). 32-bit x86 kernels "
                     "pass arguments in registers (regparm), which a plain C prototype would misstate, so btf2ida only imports types there.")
    if no_own_btf and no_prototypes_32:
        lines.append("This kernel module has no BTF of its own (distribution out-of-tree modules are often built without it): "
                     "the types come from the vmlinux BTF; no prototype was applied (32-bit, see above).")
    elif no_own_btf:
        lines.append("This kernel module has no BTF of its own (distribution out-of-tree modules are often built without it): "
                     "its own functions get no prototype; the kernel functions it calls are typed from the vmlinux BTF.")
    distilled = generator.btf.distilled
    if distilled:
        lines.append("This module carries a distilled base BTF (.BTF.base; external modules built on Linux 6.11 or newer): "
                     "its own functions %s; %d kernel structs/unions it uses are known only by name and size, so only "
                     "a forward declaration is sent for them; the kernel functions it calls are not typed (their prototypes "
                     "are only in vmlinux's BTF)." % ("get no prototype (32-bit, see above)" if no_prototypes_32 else "are typed",
                                                 stats["base_only"]))
    if no_own_btf and getattr(generator.btf, "unchecked_release", None):
        lines.append("Not checked: the module was built for %s, and the chosen file has no 'Linux version' banner "
                     "(raw BTF?), so make sure it comes from that same build." % generator.btf.unchecked_release)
    if (generator.btf.base is not None or no_own_btf) and not no_prototypes_32 and not distilled:  # a module: the counts above are its own functions
        lines.append("Typed %d imported kernel functions in the extern segment (prototypes from the vmlinux BTF); rejected by IDA %d" % (result["imports"], len(result["imports_rejected"])))
        if result.get("undefined") and result["undefined"][0]:
            total, found, outside = result["undefined"]
            lines.append("The module's %d undefined symbols: %d found in this database, %d of them outside an extern segment "
                         "(left alone: only imports in an extern segment are typed)" % (total, found, outside))
            if total and found and found == outside:
                lines.append("IDA put none of the module's imports in an extern segment, so none could be typed. Please "
                             "report your IDA version at %s." % ISSUES_URL)
    lines += [
        "Left untyped on purpose: %d compiler clones (.isra, .constprop, .part, .cold), their ABI may differ" % result["clones"],
        "Kept as they were: %d functions that already had a user-set type" % result["kept"],
    ]
    if result.get("retyped"):
        lines.append("Re-typed: %d functions whose prototype an earlier btf2ida run had set (unchanged since)"
                     % result["retyped"])
    if result.get("void_removed"):
        lines.append("Removed: %d 'void f(void)' prototypes an earlier btf2ida run had put on assembly functions such as "
                     "memcpy (replaced by the prototype from IDA's type libraries where they have one)"
                     % result["void_removed"])
    if result.get("void_asm") or result.get("void_ida"):
        lines.append("Not applied: %d 'void f(void)' prototypes of known assembly functions such as memcpy (BTF records "
                     "them without parameters) and %d where IDA's type lists parameters; left as IDA has them"
                     % (result.get("void_asm", 0), result.get("void_ida", 0)))
    if failed:
        lines.append("First rejected declaration: %s" % failed[0][:200])
    rejected = result["rejected"] + result["imports_rejected"]
    if rejected:
        lines.append("Prototypes rejected by IDA (first %d of %d): %s" % (min(3, len(rejected)), len(rejected), ", ".join(rejected[:3])))
    return "\n".join(lines)


def run_import(vmlinux=None, ask=True):
    data, source = find_btf(vmlinux, ask)
    if data is None:
        path = ida_nalt.get_input_file_path()
        if path and not os.path.isfile(path):
            raise B.BTFError("no BTF found in the loaded segments, and the input file %s is not on disk, so btf2ida "
                             "cannot read it or tell whether it is a kernel module. Put the file back at that path." % path)
        raise B.BTFError("no BTF found in the input file or the loaded segments.")
    pointer_size = 8 if ida_ida.inf_is_64bit() else 4
    generator = btf2c.Generator(data, pointer_size)
    # 32-bit x86 kernels pass arguments in registers (regparm), which a plain C prototype would misstate; other
    # 32-bit kernels (ARM, MIPS, RISC-V) use their standard C calling convention. Unknown processor: treat as x86.
    procname = (getattr(ida_ida, "inf_get_procname", lambda: None)() or "").lower()
    regparm = pointer_size == 4 and procname in ("", "metapc")
    declarations = generator.declarations()
    prototypes, imported = [], []
    if not regparm and data.base is not None:  # a kernel module: split BTF on top of vmlinux's
        prototypes, imported = generator.prototypes(data.own), generator.prototypes(data.base)
    elif not regparm and source == SOURCE_NO_OWN_BTF:  # only the module's imports can be typed
        imported = generator.prototypes()
    elif not regparm:
        prototypes = generator.prototypes()

    def types_progress(done, total):
        ida_kernwin.replace_wait_box("BTF2IDA: importing types (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    def proto_progress(done, total):
        ida_kernwin.replace_wait_box("BTF2IDA: applying prototypes (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    failed = import_in_batches(declarations, parse_batch, progress=types_progress)
    named = name_exports() if prototypes and not ida_kernwin.user_cancelled() else 0
    result = apply_prototypes(prototypes, proto_progress, imported)
    if data.base is not None or source == SOURCE_NO_OWN_BTF:
        result["undefined"] = undefined_in_database()
    return report(source, generator, failed, result, named, cancelled=bool(ida_kernwin.user_cancelled()),
                  no_prototypes_32=regparm, no_own_btf=source == SOURCE_NO_OWN_BTF)



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
