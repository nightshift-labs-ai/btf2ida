# Changelog

Taken from the GitHub release notes. Newest first.

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
