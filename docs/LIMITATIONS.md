# Known limitations

[README](../README.md) · [Kernels](KERNELS.md) · [Usage](USAGE.md) · [Verification](VERIFICATION.md) · [How it works](HOW_IT_WORKS.md)

btf2ida has not yet been run inside real IDA (see [What is not verified](#what-is-not-verified)). The summary says so when one of the 32-bit x86, empty-struct, compiler-clone, assembly `void f(void)`, no-BTF-module or distilled-base cases below applies.

## 32-bit x86 databases

32-bit x86 databases get types only, no prototypes: 32-bit x86 kernels pass arguments in registers (regparm), which a plain C prototype would misstate. Other 32-bit databases (ARM, MIPS, RISC-V: IDA's processor is not `metapc`) get prototypes too; not tried on a real 32-bit kernel.

## No function names, no prototypes

Prototypes are applied by name, so a database without function names gets types only: a raw arm64 `Image`, raw BTF or a raw memory image. For a raw `Image` or a stripped `vmlinux`, rebuild the symbols with vmlinux-to-elf first ([Kernels](KERNELS.md#android-gki-and-other-raw-images)).

## Layout details IDA does not get as types

How btf2ida writes bitfields: each group of adjacent bitfields is cut, at byte boundaries that no bitfield crosses, into integers of 1, 2, 4 or 8 bytes (`unsigned short ready:1; unsigned short mode:3; unsigned short refs:12;`, unused bits as named fillers). That covers 2,222 of the 2,239 bitfields in the MemLens demo kernel.elf.

- Bitfields in a run of other than 1, 2, 4 or 8 bytes that a bitfield crosses (17 of 2,239 in the MemLens demo kernel.elf, in 3 runs of 3 bytes; 7 bytes in some kernels) are raw storage bytes with their names in a comment, so those members are not separately visible in IDA.
- Zero-length trailing arrays (flexible arrays such as the toy's `payload[]`) are comments only, so code that indexes them stays a raw offset in the decompiler.
- Enums that are 1 byte wide or 64-bit (ENUM64; a few dozen per kernel) become plain unsigned integers of that size, without their constants.
- A bitfield written as a C bitfield gets a plain signed or unsigned integer of its run's size, not its declared type (the toy's `unsigned int ready:1` becomes `unsigned short ready:1`; not yet observed in IDA, which may show it as `unsigned __int16`). So an enum bitfield loses its constants, and `_Bool` and typedef names such as `u8` or `u32` are not kept. Of the 2,222 in the MemLens demo kernel.elf: 18 enums, 105 `_Bool`, 1,400 others declared with a typedef, 482 with a plain integer type of another size.

## Bitfields checked with gcc only

The layout of the C bitfields was checked by compiling and running the header with gcc, under its own rules and under `-mms-bitfields` (gcc's implementation of the Microsoft rules; MSVC itself was not run), see [Verification](VERIFICATION.md). Each integer is filled exactly, so both rules give the same layout; how IDA lays them out has not been observed.

- After the import, the plugin reads back from IDA the layout of every struct and union with bitfields (its size, each C bitfield's bit offset and width, the offsets of its direct members) and compares it with the BTF. One that differs is declared again with raw bytes and checked again, and the summary says how many (checked with fake IDA modules only).
- A struct or union whose declaration with C bitfields IDA rejects is offered again with raw bytes, and the summary says how many (also checked with fake IDA modules only).
- Big-endian BTF keeps all bitfields as raw bytes, and so does a big-endian database, where IDA allocates bitfields from the most significant bit (the summary says so; checked with fake IDA modules only).
- The menu item **BTF2IDA: Apply kernel types and prototypes (bitfields as raw bytes)** keeps every bitfield as raw bytes ([Usage](USAGE.md#the-menu-actions)).

## Empty structs and unions

Empty structs and unions (size 0 in BTF) get a forward declaration only; the summary counts them apart.

## Compiler clones

Compiler clones (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped on purpose, because their calling convention may differ from the source signature.

## Assembly functions

Assembly functions (`memcpy`, `__arch_copy_to_user`, `__get_user_N`, ...): BTF records them as `void f(void)`, which would hide their arguments. btf2ida leaves that prototype out for 228 known x86-64 and arm64 assembly names, and for any name whose type in IDA (at the address, or in IDA's type libraries) lists parameters, and counts both in the summary. An assembly function not on the list still gets `void f(void)`.

## A kernel module without BTF of its own

Only the kernel functions it calls are typed (see [Kernels: a module with no BTF of its own](KERNELS.md#a-module-with-no-btf-of-its-own)).

## Out-of-tree modules with a distilled `.BTF.base`

Pahole's `distilled_base`, which `scripts/Makefile.btf` requests for external modules since Linux 6.11: the module's own types and prototypes are imported from its own BTF, without a vmlinux. The kernel structs it uses are known there only by name and size, so they get a forward declaration only (a module struct that holds one by value gets a byte array of that size, the type named in a comment); the kernel functions it calls are not typed. Checked only on a synthetic module (a stub-test case and a hand-made `.ko`).

## Kernel modules in IDA

Not checked in IDA:

- whether IDA puts a module's imports in a `SEG_XTRN` segment under their plain names;
- whether IDA accepts a prototype there.

## What is not verified

Behaviour inside real IDA, including how fast IDA ingests a full kernel's types (a whole kernel takes a while; not timed in IDA), how it lays out the bitfields, and whether it rejects specific declarations. The plugin is written to split rejected batches and report them instead of failing; that relies on IDA ignoring a redeclaration when a batch is parsed again. The SDK documents it, since `parse_decls` "always uses the HTI_DCL bit", which means "don't complain about redeclarations" (`typeinf.hpp` in HexRaysSA/ida-sdk), but it has not been observed in IDA.

The headless runner calls the plugin's own code; like the rest of the IDA layer it has only been run against fake modules (`tests/test_plugin_stub.py`), not a real idalib.

The offline checks used x86-64 kernels, plus the arm64 kernels where a row of [Verification](VERIFICATION.md) says so.
