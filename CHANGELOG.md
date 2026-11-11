# Changelog

Taken from the GitHub release notes. Newest first.

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
