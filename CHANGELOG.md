# Changelog

Taken from the GitHub release notes. Newest first.

## v0.1.22 (2026-11-15)

- Bitfields: bitfields are now written as C bitfields. Each group of adjacent bitfields is cut, at byte boundaries that no bitfield crosses, into runs; each run of 1, 2, 4 or 8 bytes becomes C bitfields that fill an integer of that size exactly, for example the toy's `unsigned short ready:1; unsigned short mode:3; unsigned short refs:12;` (it was `unsigned char __bits_8[2]` with the names in a comment), or `net_device`'s `priv_flags:32` + `lltx:1` (5 bytes) as an `unsigned int` and an `unsigned char`. Where several cuts convert as many bitfields, integers of the bitfields' own declared size at an offset aligned to it come first (the kernel's storage units: `sk_buff`'s 28 `__u8` flags from `tstamp_type` on become four `unsigned char`, not one `unsigned int` at an odd offset), then the fewest integers. The integer is `unsigned char`/`short`/`int`/`long long` by the run's size; a signed BTF int, or an enum that BTF marks signed (its kflag, Linux 6.0+), becomes `signed` of that size; `_Bool` and the other enums are unsigned. So the declared type is not kept: an enum bitfield loses its constants, `_Bool` and typedef names (`u8`, `u32`) are gone (of the 2,222 C bitfields in the MemLens demo kernel.elf: 18 enums, 105 `_Bool`, 1,400 others declared with a typedef). Unused bits get named fillers (`__pad_bits_<run's first byte, hex>_<bit within the run>`, plus `_n<scope>` inside an inline struct or union, for example `__pad_bits_c_5`), so the integer is full and, under `#pragma pack(1)`, the next member starts right after it with the GCC and the MSVC bitfield rules alike. A run of another size that a bitfield crosses (3 or 7 bytes in the kernels below), bitfields directly in a union (none in the kernels below) and big-endian BTF keep the raw bytes; so does a database where IDA allocates bitfields from the most significant bit (`ida_ida.inf_is_be()`, or IDA 9.5's `inf_get_bf_order()`), for example little-endian BTF carved into a big-endian database, and the summary says why (stub test with fake IDA modules). MemLens demo kernel.elf: 2,222 of 2,239 bitfields (17 raw, in 3 runs of 3 bytes); Debian 13 vmlinux `f741142f`: 1,973 of 1,973; WSL2 6.18.33.1: 3,115 of 3,131; Debian 13 `nf_tables.ko --base vmlinux`: 2,015 of 2,018. Checked with gcc only: the new `tests/check_bitfields.py` builds a program with gcc that sets every converted bitfield through the struct and compares the bytes with the BTF bit offset (4 cases per field, and a read-back, so a signed field must read back negative), and asserts sizeof and the next member's offset against the new and the old raw-byte header; built once with gcc's rules and once with `-mms-bitfields` (gcc's implementation of the MSVC rules; MSVC itself was not run): 0 failures on those four and on arm64 GKI 6.1, Ubuntu 6.8 amd64 and arm64, Ubuntu mainline 7.0, Debian 11 5.10, BTFHub Ubuntu 5.8 and Debian 13 `bridge.ko`. `tests/check_against_dwarf.py` now also compares bitfields with the DWARF-derived ISF, exits 1 on any mismatch, and refuses an ISF of another kernel release (compared through the `Linux version` banners): the MemLens demo kernel.elf (79a64158…) with `debian-6.12.115+deb13.1-amd64.json.xz` from the same demo zip gives 1,364 bit positions and widths, 0 mismatches; signedness of 1,260 (all but `_Bool`), 0 mismatches. Header, prototypes and `--asserts` still compile with gcc (0 errors); outside the bitfield lines the header is unchanged. Not yet seen in real IDA: how IDA lays out these bitfields under PT_PAK1 is not checked. So after the import the plugin reads back from IDA the layout of every struct/union with bitfields (`get_udt_details`: its size, each C bitfield's bit offset and width, no other named bitfield, the offsets of its direct members) and compares it with the BTF; one that differs is declared again with raw bytes (`parse_decl` + `set_named_type` with `NTF_REPLACE`) and checked again, and the summary says how many matched ('Bitfield layout checked in IDA: ...') or gives the counts and the first difference ('Bitfield layout in IDA does not match the BTF in ...'). `tests/check_bitfields.py` checks that the layout the plugin compares matches its own gcc-checked walk of the BTF (MemLens demo kernel.elf: 365 structs/unions with bitfields, 363 of them with C bitfields). Stub test with fake IDA modules only. To get the earlier raw bytes: the new menu item **BTF2IDA: Apply kernel types and prototypes (bitfields as raw bytes)**, `tools/btf2ida_headless.py --no-bitfields` (both run the plugin's `run_import(bitfields=False)`; stub test with fake IDA modules), `btf2c.py --no-bitfields` (on the MemLens demo kernel.elf the same header, byte for byte, as before this change). IDA 9.3's `__at()` is not used, since the plugin supports IDA 9.0 and later.
- A kernel module without BTF of its own and a vmlinux of another kernel release: btf2ida used to refuse outright (while a raw BTF file of any kernel passed with a note). It now asks whether to use that vmlinux anyway (default No; headless `--force`, also in `tests/check_module.py`), and the summary then says "Used anyway (your choice)" with both releases. Measured: Ubuntu 6.17 `intel_cvs.ko` with the Debian 13 6.12 vmlinux, refused without `--force`, 40 of 56 imports typed with it. Split BTF is never used anyway, and a chosen vmlinux that its string or type references overrun is now reported as a mismatch ("this module's BTF does not match the chosen vmlinux (string offset out of range)"; Ubuntu 26.04 7.0 `nf_tables.ko` with the Debian 13 6.12 vmlinux) instead of falling through to the whole-kernel file dialog. The question text is escaped for `ask_yn`'s printf-style format. Stub tests for Yes / No / Cancel, `--force`, the wait box around the question, a `%` in a release and the overrun base; 64 `ida_*` / `idc` names in the IDA 9.1 to 9.5 stubs, 87 API names against ida-sdk (counts with the `ida_auto` change below and the bitfield layout check above). Fake IDA modules only.
- Running the menu action while IDA is still analysing the file: functions IDA had not created yet got no prototype and the summary only counted them as "not a function start". btf2ida now asks first whether to wait for the analysis (default Yes: it waits in a wait box with Cancel; Cancel in the question stops before anything is imported). If you choose No, the summary starts with "IDA's analysis had not finished ... Run BTF2IDA again when it has". With auto-analysis turned off (Options > General > Analysis), its queues may never empty, so it neither asks nor adds that line. Headless is unchanged (idalib waits for the analysis, or `--no-analysis` skips it). Stub test; fake IDA modules only.
- A memory image without BTF: once the input file has been searched (through mmap), loaded segments over 256 MiB are no longer copied into memory a second time, which could freeze IDA or run out of memory before the "choose BTF" dialog. When the input file is not on disk, they are still read. Segments over 256 MiB that are not in the input file (for example loaded as an additional binary file) are no longer searched either. Stub test with a 4 GiB fake segment.
- A vmlinux chosen for a kernel module that cannot be read (for example Ubuntu's root-only `/boot/vmlinuz-*`) now gives "cannot read the chosen file ..." with a hint, instead of the "unexpected error, details are in the Output window" box (headless: exit code 3 instead of a traceback). Stub test with a mode-0 file; fake IDA modules only.
- A kernel module's split BTF on the chosen vmlinux, besides the Ubuntu 26.04 `nf_tables.ko` case above: raw split BTF (not inside an ELF) that overruns the vmlinux is refused the same way ("this module's BTF does not match the chosen vmlinux (string offset out of range)"), and damage in the module's own BTF (for example an unknown BTF kind) reads "this module's BTF could not be read on the chosen vmlinux (...)". In v0.1.21 both fell through to the whole-kernel file dialog (headless: the module was taken for a whole kernel without BTF, and the chosen vmlinux's BTF was imported for it with no error). Stub tests through the real parser.
- Bitfields: if IDA rejects the declaration of a struct or union with C bitfields (not observed so far), each rejected declaration is offered again with its bitfields as raw bytes, in the same order (so a struct that holds a rejected one by value comes after it), and the summary says how many kept raw bytes that way ("Bitfields kept as raw bytes (names in a comment) in N structs/unions: IDA rejected their declaration with C bitfields"); the layout check then expects raw bytes there. When none of the structs/unions with bitfields is in IDA's local types, the layout line says "Bitfield layout not checked in IDA". Stub test with fake IDA modules only.
- Bitfields: the layout check declares every struct/union that differs again with raw bytes before it checks any of them again, so a struct that holds another differing one by value is checked with the other one's new size (not reported as "could not be: please report it" because IDA still had the other one's old size). Stub test with fake IDA modules only.

## v0.1.21 (2026-11-14)

- Prototypes: BTF records assembly functions as `void f(void)`, the same record as a real `void f(void)`; applying it wiped the arguments at every call (in a Debian 13 `nf_tables.ko`, the imports memcpy, memmove and memset; on arm64 also `strchr`, and `__arch_copy_from_user` / `__arch_copy_to_user` behind every `copy_from_user` / `copy_to_user`). btf2ida now leaves such a prototype out for 228 assembly names (entry points defined in the x86 and arm64 `.S` files, mostly by `SYM_FUNC_START`/`SYM_CODE_START`, plus the 7.0 `lib/crypto` routines, that BTF records as `void f(void)` on Debian 13 6.12 amd64 and arm64, Ubuntu 24.04 6.8 amd64 and arm64, and Ubuntu 26.04 7.0), and for any name whose type in IDA lists parameters: the type at the address (read with `get_tinfo`), or the prototype IDA's type libraries hold for that symbol (`get_named_type` with `NTF_SYMU`). A new summary line counts the two cases. An `int f(void)` or other non-void record is a real C prototype and is still applied, and so is every other `void f(void)` (the Debian 13 demo `kernel.elf` has 1,942 such records, mostly real C functions such as `synchronize_rcu`). `nf_tables.ko`: 150 imports typed (was 154) + "Not applied: 4" (those three and the ftrace hook `__fentry__`); arm64 `nf_tables.ko`: 137 + 2. Stub test; tested only on fake IDA modules.
- BTFHub archives: a `<release>.btf.tar.xz` from BTFHub (aquasecurity/btfhub-archive, BTF for distribution kernels built without it) is read wherever btf2ida or `btf2c.py` takes a BTF or vmlinux file (the BTF file inside the archive is used; also `.tar.gz` and plain `.tar`). Ubuntu 20.04 `5.8.0-63-generic.btf.tar.xz`: `btf2c.py` writes 49,744 prototypes (+1 as a comment, a name clash), header and prototypes compile with gcc. When a whole kernel has no BTF, btf2ida now asks for a BTF file of the same build (headless: `--vmlinux <file>`; raw BTF, a vmlinux with BTF, or a BTFHub archive) and applies its types and prototypes. It compares the kernel release in the input's `Linux version` banner with the chosen file's banner or BTFHub file name and warns in the summary when they differ (it does not refuse); when either side names no release, the summary says the match was not checked. A kernel module's BTF (split or distilled) chosen for a whole kernel is refused, and an unreadable file gives a clear error. Without such a file the error points to BTFHub. Stub test; tested only on fake IDA modules.
- For a kernel module, a new summary line compares the module's undefined symbols (read from its own symbol table, ELF32 or ELF64, either byte order) with the database: how many IDA has, and how many of those are outside an extern segment, where btf2ida leaves them alone. If IDA put none of them in an extern segment (a loader that works differently), the summary says so instead of a bare "Typed 0 imported kernel functions". Debian 13 `nf_tables.ko` on the fake database: 193 undefined symbols, 193 found, 0 outside (arm64: 165; Debian 11: 176). Stub test; tested only on fake IDA modules.
- Names that clash with types: a kernel function can have the name of a struct, union or enum tag (`bpf_spin_lock`, `btf_header`; 83 of the 47,900 prototypes of the Debian 13 vmlinux), and in IDA tags and typedefs share one namespace. IDA ignores the name in a declaration it applies, so btf2ida now passes a fixed name (`__btf2ida_fn`) instead of the function's own. A parameter named like a typedef (`size_t code`, where `code` is also a typedef) is renamed with a trailing `_` (92 of 47,900 prototypes on that vmlinux; tag names such as `struct page *page` stay as they are). The summary now names the first three prototypes IDA rejects. Header and prototypes still compile with gcc (0 errors). Not checked in IDA whether it rejected any of these before.
- BTF's `_Bool` is now IDA's own `bool` (it was `unsigned char`); if the database's compiler setting gives `bool` another size than 1 byte, the plugin uses IDA's fixed 1-byte `_BOOL1` instead, so no layout moves, for example `void __pm_runtime_disable(struct device *dev, bool check_resume)`. The C header that `btf2c.py` writes stays free of `#include` lines (IDA's own parser reads it too); for gcc, the `--asserts` file includes `<stdbool.h>` and the header is compiled with `-include stdbool.h`: checked with `gcc -fsyntax-only` on the WSL2 6.18 kernel (header and 65,664 prototypes), the MemLens demo `kernel.elf` (59,761 asserts) and the Debian 13 vmlinux `f741142f` (56,214 asserts and 47,900 prototypes), 0 errors. Not checked in IDA.
- A compressed kernel chosen as the vmlinux: btf2ida (and `btf2c.py`, for its input and `--base`) unpacks an x86 bzImage packed with gzip, xz, lzma or bzip2, or an EFI zboot image packed with gzip, xz or lzma (Python's standard library) and an arm64 `Image.gz` (zboot: synthetic files only). For zstd, lz4 or lzo it says what to install and that extract-vmlinux without the tool exits 0, says "Extracted vmlinux using 'cat'", and writes the bzImage unchanged (before, the message only said "extract it first with scripts/extract-vmlinux", which the user may just have done). Checked on Debian 11 5.10 (xz: same output as with the extracted vmlinux), Debian 13 6.12 (zstd: refused with "install zstd") and Ubuntu 24.04 arm64 6.8 (gzip Image); `tests/test_unpack.py`.
- Running btf2ida again on the same database: every prototype it sets carries IDA's user-type flag, the same as a type set by hand, so a second run used to keep all of them ("Kept as they were"). btf2ida now records the prototypes it set (in a netnode, with a checksum of the type text IDA shows) and replaces them on a later run, unless someone changed them since (a type set by hand to exactly the same text counts as btf2ida's); other hand-set types are still kept. Prototypes set by 0.1.20 or earlier carry no record and are kept, except the assembly `void f(void)` below. A `void f(void)` that btf2ida 0.1.20 or earlier put on a known assembly function such as memcpy is removed, and the prototype IDA's type libraries hold for that symbol is applied (as a guessed type) where they have one. New summary lines say how many. Stub test; tested only on fake IDA modules.
- `tests/check_ida_names.py <stub dir>...`: checks that every `ida_*` / `idc` name btf2ida uses exists in a folder of IDAPython stubs; all 50 are in the stubs of IDA 9.1 to 9.5 (PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11, 0.0.12). It does not check methods; the methods btf2ida calls on `netnode` and `tinfo_t` were checked by hand in the same five. `tests/check_ida_api.py` now also covers `ida_typeinf` and `ida_netnode`, methods included: 62 names against the HexRaysSA/ida-sdk IDAPython sources, 0 missing.

## v0.1.20 (2026-11-13)

- `tests/check_ida_api.py` prints a usage line and exits 2 when run without the IDAPython source folder; the other check scripts already printed one.
- Prototypes are skipped only on 32-bit x86 databases (regparm), or when IDA's processor name is unknown; 32-bit ARM, MIPS and RISC-V databases get them, since those kernels use their standard C calling convention. Stub-test case (ARM applies, metapc skips); not tried on a real 32-bit kernel.
- `tests/coverage.py <kernel.elf>` re-counts the README's demo coverage figure outside IDA (50,366 prototypes; 46,900 of 51,092 function symbols, 91.8%, on the MemLens demo kernel.elf).
- External modules with a distilled `.BTF.base` (builds outside the kernel tree on Linux 6.11+ with a recent pahole): the split `.BTF` is read on top of the module's own `.BTF.base`, so no vmlinux is needed and the module's own types and prototypes are imported. The kernel structs that base names by size only get a forward declaration only, and a module struct that holds one by value gets a byte array of the same size there, with the type named in a comment (so the header stays complete and the layout right) (before this, a vmlinux was demanded and then refused as a mismatch; a padding body like `unsigned char __pad_0[232]` for `sk_buff` would also have replaced a real definition). The summary says so; the kernel functions such a module calls are not typed. Non-distilled inputs give byte-identical output (WSL 6.18 header and prototypes, Debian 13 nf_tables.ko, toy). `--asserts` skips the forward-only structs. Checked only on synthetic modules: a stub-test case, a hand-made `.ko`, and Debian 13 nf_tables.ko re-distilled by a script that follows libbpf's rules (56 base-only structs, 102 by-value members as byte arrays; header, header plus prototypes and all `--asserts` checks compile with gcc). Not yet run in real IDA.

## v0.1.19 (2026-11-12)

- The summary counts empty structs and unions (size 0 in BTF, forward declaration only) apart: "Declarations sent to IDA: ... ; N empty structs/unions as forward declarations only". Before, they were counted as structs although no body was sent (Debian 13 nf_tables.ko: 470 of the 8,619 counted). Stub test case. README: a "Known limitations" list in the Status section (32-bit, no names, layout details, empty structs, clones, modules without BTF, distilled `.BTF.base` not supported yet).
- `tests/check_module.py <module.ko> <vmlinux> [--no-names]` runs the plugin's own import on a kernel module against a fake IDA database built from the module's ELF symbol table (its functions as functions, its undefined symbols in an extern segment; no readelf, no IDA needed) and prints the summary. The README's new "Try a real module" block gives the download and extraction commands for Debian 13 `nf_tables.ko` and its vmlinux, their SHA-256, and the expected lines (488 own functions, 7 not in the database, 154 imports; 154 imports also with `.BTF` removed). `tests/check_ksymtab.py` and `tests/check_against_dwarf.py` print a usage line instead of a traceback when arguments are missing. The README names the toy's folder after `hcli plugin install`.
- A kernel module with no BTF of its own (distribution out-of-tree modules are often built without it, because their build has no vmlinux) no longer stops with "no BTF found": btf2ida asks for the matching vmlinux (or takes `--vmlinux`) and types the kernel functions the module calls, in its extern segment, from the vmlinux BTF. The summary says the module's own functions get no prototype. Modules are recognised as ELF relocatable files with a `.gnu.linkonce.this_module` section (checked on Ubuntu usbio.ko and intel_cvs.ko, Debian nf_tables.ko; not on vmlinux). Measured with a fake database on Debian 13 nf_tables.ko with `.BTF` removed: 154 imports typed, the same as with its BTF; the module with BTF is unchanged (488 own + 154 imports). Stub test case added. The module's `vermagic` release is compared with the chosen vmlinux's `Linux version` banners (a memory image can also hold older ones in logs, so one match is enough): a different kernel is refused with the releases named (a wrong vmlinux would give wrong prototypes, e.g. an extra parameter in `__kvmalloc_node_noprof` with a 6.18 BTF on a 6.12 module); a raw BTF file has no banner, so the summary says the match was not checked. If the input file is no longer on disk, the error says so instead of only "no BTF found". The module check looks up the section in the ELF section table (a plain string search also matched the kernel's own module loader code). On a 32-bit database the summary says the types came from the vmlinux BTF and that no prototype was applied, instead of claiming the imports were typed. Not yet run in real IDA.
- Headless runner: a module without `--vmlinux` now stops with "give the matching vmlinux with --vmlinux" instead of reaching IDA's file dialog, which idalib has no window for (`run_import(..., ask=False)`). Stub test case added.
- A vmlinux chosen as a module's base (file dialog, `--vmlinux`, or `btf2c.py --base`) that has no BTF now gets a message that names the file and says what to do: a compressed bzImage (recognised by its `HdrS` header) must be extracted first with scripts/extract-vmlinux, otherwise use the uncompressed vmlinux of the same build or a copy of its /sys/kernel/btf/vmlinux. Before, it said only "no BTF found", which read as if the module had none. Checked on Debian 13 nf_tables.ko with its own /boot/vmlinuz (bzImage) and with a file of zeros; the right vmlinux still gives the same output.
- On a 32-bit database the summary now says why no prototype was applied (types only; 32-bit x86 kernels pass arguments in registers). Before, it showed only "Prototypes applied to 0 functions". README Status notes the limit; stub test case added.
- README: demo coverage re-counted on the current demo kernel.elf (re-exported with MemLens 0.3.23): 46,900 of 51,092 function symbols (was 46,904 of 51,116 on the older export; still 91.8%).
- README: the wrong-base row now says 2,451 of 2,601 references on WSL 6.18.33.1 (2,419 was measured on an earlier WSL 6.18 build).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.18 (2026-11-11)

- **Headless runner for idalib** (IDA 9.0+): `python3 tools/btf2ida_headless.py <file> [--vmlinux <vmlinux>] [--no-analysis]` runs the same import as the menu action and saves the database. Exit codes: 0 done, 1 IDA could not open the file, 2 no idalib, 3 no usable BTF (the message says why). `run_import()` and `find_btf()` take an optional vmlinux path, so split BTF needs no file dialog there; the menu action is unchanged.
- The stub test covers the runner with a fake `idapro` (open, import, close and save, every exit code) and the dialog-free split-BTF path. Not yet run with a real idalib.
- Also in this release: `tests/test_ksymtab.py` (synthetic ELFs for all four `__ksymtab` layouts, the GPL table, code/data/writable-code checks, refusals and the probe).

## v0.1.17 (2026-11-11)

Command line only: the header and the `--prototypes` file now compile together.

A C function may not share its name with a typedef or an enum constant. On the Debian 13 kernel the function `dmi_callback` and the typedef `dmi_callback` both exist, so `gcc` stopped with "redeclared as different kind of symbol" when both files were compiled as one. `btf2c.py --prototypes` now writes such a prototype as a comment and says how many on stderr.

Checked: Debian 13 demo kernel, header + prototypes compile with 0 errors (1 prototype commented, every other line unchanged); WSL2 kernel 0 clashes, all 65,664 prototypes kept, 0 errors; toy demo outputs byte-identical; stub test passes. The IDA path is unchanged.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.16 (2026-11-11)

An anonymous struct or union that the kernel only reaches through a pointer is now defined, so its members are no longer lost (judge-review item).

Example: `struct parsed_partitions` has `struct { ... } *parts;`. Before, the header said `struct __anon_63787 *parts;` and never defined `__anon_63787`, so `parts[i].from` could not be shown. Now it is defined with its real members (`from`, `size`, `flags`, `has_info`, `info`). Anonymous types written inline as members are still not repeated at top level.

Checked: WSL2 kernel header 12,274 → 12,275 structs (exactly this one; top-level `__anon` bodies 260 → 261) and it compiles with `gcc -fsyntax-only`; Debian 13 demo 8,928 → 8,929 structs, compiles; the toy demo output is byte-identical; the BTF-vs-ISF layout check is unchanged (8,884 types, 54,303 members, 0 size or offset mismatches); stub test passes.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.15 (2026-11-11)

Kernel modules: imported kernel functions get prototypes, and the summary counts only the module's own functions.

- A module's split BTF holds its own functions; the kernel functions it calls are in the vmlinux BTF. btf2ida now applies vmlinux prototypes only to names in an extern segment (`ida_segment.segtype(ea) == SEG_XTRN`), where IDA should list the module's imports. A vmlinux name elsewhere in the module is left alone. Before, imports were never typed, because they are not function starts.
- "Not in this database" now counts only the module's own functions. Before, it counted every vmlinux function. A new summary line gives the number of imports typed. Whole kernels behave as before.
- If the segment lookup fails, or `ida_segment` is missing, only the imports stay untyped; the run continues.
- Measured with fake IDA modules on Debian 13 `nf_tables.ko` (6.12.115) with its vmlinux:
  - With no names in the database, "not in this database" drops from 48,395 to 495.
  - With names from the module's symbol table, 488 module functions and 154 of its 193 imports are typed. "Not in this database" is 7.
  - The module's `jhash` is no longer typed; its BTF is only in vmlinux's part.
  - Whole-kernel output is byte-identical to v0.1.14 on the Debian 13 demo kernel and the toy kernel.
- `tests/check_ida_api.py` now covers `ida_segment`: 45 names, 0 missing. `segtype` is used because `getseg` is marked deprecated in the IDA 9.5 SDK. The stub test adds a module case: an extern is typed, while a vmlinux name in code and an unused vmlinux function are not.
- README: new section "A real kernel module".

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.14 (2026-11-11)

README only (no code change apart from a docstring), answering two questions a reviewer asked:

- **Compared with bpftool and Parse C header file**: measured with bpftool 7.8.1 on the same inputs. On the Debian 13 memory export bpftool stops (`failed to find '.BTF' ELF section`), while btf2ida carves 50,366 prototypes from it. On the WSL2 kernel bpftool's header (172,354 lines) declares none of the 65,664 functions in the BTF; btf2ida applies them by name. bpftool's header is written for clang (`#pragma clang attribute push (...preserve_access_index...)`, 305 `__attribute__` lines); we have not checked how IDA's parser treats it.
- **Does my kernel have BTF?**: how to check on a running system, in a kernel file, and without IDA (`python3 btf2c.py <file> /dev/null`).
- The redeclaration assumption behind batch re-parsing now cites the SDK: `parse_decls` "always uses the HTI_DCL bit" ("don't complain about redeclarations", typeinf.hpp).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.13 (2026-11-11)

The command-line tool (btf2c.py) prints one clear line instead of a Python traceback. A kernel module without `--base` now gets "this is split BTF (a kernel module) ... (add --base /path/to/vmlinux or /sys/kernel/btf/vmlinux)". A module with the wrong `--base` gets "this module's BTF does not match the chosen vmlinux ...". A missing file and corrupt BTF give one-line errors too. All of these exit with code 1. Checked on a Debian 13 nf_tables.ko; the toy demo output is unchanged.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.12 (2026-11-11)

Cleaner Local Types: nested anonymous structs and unions are no longer emitted twice.

Before, every anonymous struct or union inside another type was declared inline in its parent and also again as a separate top-level `__anon_N` type that nothing referenced. Now only the inline copy is emitted. Top-level `__anon` types drop from 2,222 to 260 on the WSL 6.18 kernel and from 1,748 to 182 on the Debian 13 demo kernel. The unions count in the summary drops from 1,192 to 229 on WSL.

Unchanged where it matters: the headers still compile; the generated `_Static_assert` layout checks all pass (81,753 on WSL 6.18, 59,761 on Debian 13); the DWARF comparison still gives 8,884 types, 0 size mismatches, 54,303 members, 0 offset mismatches; the prototype files are byte-identical (65,664 and 50,366). demo/expected_types.h was regenerated and loses its two redundant `__anon` copies.

The fix was suggested and prototyped by a judge-style review. Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.11 (2026-11-11)

Error paths and robustness, from a fresh judge-style review that re-ran every README number (all matched):

- A kernel module whose BTF does not fit the chosen vmlinux now shows "this module's BTF does not match the chosen vmlinux: N of M ..." in IDA too. Before, only the command-line tool said so, and the plugin said "no BTF found".
- Cancelling the "choose vmlinux" dialog for a module now says that split BTF was found and needs its vmlinux, not "no BTF found".
- After Cancel, the summary starts with "CANCELLED: the import stopped early", and the type line now reads "Declarations sent to IDA" instead of "Imported".
- Corrupt BTF is refused up front: every type reference must exist, and modifier, pointer and typedef chains must end. Before, a self-referencing type, for example from a damaged memory image, could make the import loop forever. Checked with crafted blobs: self-cycle, two-type cycle, dangling reference.
- README: 1-byte and 64-bit enums become plain integers without constants (a few dozen per kernel).

Regression checks: WSL 6.18 65,664 prototypes; MemLens demo kernel.elf 50,366 prototypes; toy demo output byte-identical to demo/expected_*; stub test OK; Debian 13 nf_tables.ko with the wrong base gives BaseMismatch. Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.10 (2026-11-10)

- Functions that already have a user-set type keep it, and the summary says how many were kept. This also means a second run will not change functions typed by the first.
- The demo coverage figure is now stated against real functions: 46,904 of 51,119 kernel function symbols with no module prefix, compiler suffix or __pfx_ padding prefix (91.8%).
- Install notes that the plugin index can lag behind releases.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.9 (2026-11-10)

Fixes to the __ksymtab naming from an independent review: sections that are writable as well as executable no longer count as code (on Ubuntu 26.04 7.0 that kept 406 exported data objects from being turned into functions: 14,717 exported functions named, all matching the debug symbol table; 13,865 prototypes, unchanged; Debian 13 unchanged at 10,497 / 10,333); names are applied only when the database still maps the input file unchanged; Cancel is honoured, with progress; the 4.19-5.3 ksymtab layout is read; the README now says this applies to an x86-64 ELF vmlinux (a raw arm64 Image gets types only). The 0.1.7 notes gave 15,123 for Ubuntu 7.0; the correct count is 14,717.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.1.8 (2026-11-10)

A kernel module's split BTF is now checked against the vmlinux chosen as its base: with the wrong vmlinux, its name references land in the middle of unrelated strings, and btf2ida refuses with a clear message instead of importing garbage names. Checked on Debian 13 nf_tables.ko: wrong base (WSL 6.18) refused, 2,419 of 2,601 references mid-string; its own base, 0 of 1,090. Output for normal kernels is byte-identical.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.1.7 (2026-11-10)

A stripped vmlinux (for example from extract-vmlinux) now gets prototypes for its exported functions: btf2ida names them from the kernel's own __ksymtab, only where the database has no name, then applies the BTF prototypes. Checked outside IDA on objcopy -S copies of two distribution kernels against their debug symbol tables: Debian 13 6.12, 10,497 of 10,497 names at the right address, 10,333 prototypes; Ubuntu 26.04 7.0, 15,123 of 15,123, 13,865. An unexpected error now shows one warning (traceback in the Output window) instead of a traceback dialog, and importing the plugin no longer changes Python's recursion limit for all of IDA (same output at the default limit on three kernels).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.1.6 (2026-11-10)

README accuracy pass after an independent review. The first try now uses MemLens's 22 MB demo kernel.elf, which has both symbols and BTF (outside IDA: 50,366 prototypes, matching 46,880 of 98,063 plain kernel function symbols; tcp_sendmsg and vfs_getattr shown). It also says plainly that a stripped vmlinuz gives types but no prototypes, that BTF needs CONFIG_DEBUG_INFO_BTF, how bitfields and zero-length arrays reach IDA, and that the GKI coverage numbers use System.map names. No code changes.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.1.5 (2026-11-10)

The success dialog after an import now escapes % in its text. ida_kernwin.info is a printf-style function in IDAPython (only msg, warning and error are wrapped), so a message containing % could print garbage. Found by a review of every IDAPython call against the IDA 9.5 SDK sources (no load or API problems found otherwise). Not yet run inside real IDA; see the README. Built by an AI agent (Nightshift Labs).

## v0.1.4 (2026-11-09)

Pointers to zero-length arrays are emitted as plain pointers (same layout). Not yet run inside real IDA; see the README. Built by an AI agent.

## v0.1.3 (2026-11-09)

README: prototype coverage on a real x86-64 GKI kernel. Not yet run inside real IDA; see the README. Built by an AI agent.

## v0.1.2 (2026-11-09)

Fixes from a review against the official IDAPython sources. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.

## v0.1.1 (2026-11-09)

README: why it matters, a walkthrough and credits. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.

## v0.1.0 (2026-11-09)

First release. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.
