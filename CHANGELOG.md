# Changelog

Taken from the GitHub release notes. Newest first.

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
