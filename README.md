# btf2ida

Open a Linux kernel in IDA and get its **real types and function prototypes** with one click, with no debug package and no matching source tree.

*Status: not yet run in real IDA; what was checked offline is under [Verification](#verification).*

Most current distribution and Android GKI kernels carry [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format, built in with `CONFIG_DEBUG_INFO_BTF`), a compact description of every kernel struct, union, enum and function signature. Many embedded and older vendor kernels do not. Where it exists, it is there in a stripped `vmlinux`, in Android GKI kernels, and in RAM. btf2ida finds it and applies it:

- **Every kernel type**: all structs, unions, enums and typedefs imported as IDA local types, every member at its exact byte offset (packed and anonymous members included). Bitfields are kept as raw storage bytes with their names in a comment, and zero-length trailing arrays appear only as comments, so those members are not separately visible in IDA. Enums that are 1 byte wide or 64-bit (ENUM64; a few dozen per kernel) become plain unsigned integers of that size, without their constants.
- **Function prototypes by name**: each function in the database whose name has a BTF signature gets that signature, so the decompiler shows `struct sock *sk` instead of `__int64 a1`. On a stripped kernel, exported functions are first named from `__ksymtab`. In a kernel module, the plugin also applies prototypes to the kernel functions the module imports ([A real kernel module](#a-real-kernel-module)).
- **Finds BTF on its own**: from the input file (`vmlinux`, a kernel module `.ko`, raw BTF, a memory image, by carving) or from the loaded segments. For a kernel module it asks for the matching `vmlinux` to resolve split BTF. Raw BTF or a raw memory image gives types only: prototypes need function names in the database.

It adds nothing to your binary and needs nothing installed besides the plugin.

## Why it matters

A Linux kernel without its debug package is mostly `__int64 a1`, and matching headers or a debug package are often impossible to get: vendor kernels, Android devices, a kernel seen only in a memory image. The BTF is already inside the image. Using it replaces retyping structures by hand.

## Try it

Smallest try, nothing to download: `demo/toy_kernel.elf` (17 KB) is a small program with kernel-style types, built with `gcc -gbtf`, so it carries BTF and no DWARF and IDA has no other source for these types (`demo/build.sh` rebuilds it).

1. Open `demo/toy_kernel.elf` in IDA (after `hcli plugin install`, it is in the plugin's folder: `$IDAUSR/plugins/btf2ida/demo/`).
2. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**.
3. `demo_open` should become `int demo_open(struct demo_device *dev, unsigned int flags)` (all five prototypes are in `demo/expected_prototypes.txt`), and Local Types should hold `struct demo_device` as in `demo/expected_types.h`: bitfields as raw bytes with their names in a comment, `private` renamed `private_`, the flexible array as a comment.

A real kernel, ready with symbols and BTF: Download `memlens-demo-debian13.zip` (22 MB) from the [MemLens demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data), our companion plugin that exports a running kernel from a memory image.

1. Unzip it and open `kernel.elf` in IDA; let auto-analysis finish (a whole kernel takes a while; not timed in IDA).
2. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**.
3. Open `tcp_sendmsg` or `vfs_getattr`. Their prototypes in this kernel's BTF, as btf2ida generates them (`python3 btf2c.py kernel.elf types.h --prototypes protos.txt`, run outside IDA):

```c
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags);
```

Outside IDA on this file: BTF found by carving in 0.3 s, 50,366 prototypes, matching 46,900 of the 51,092 kernel function symbols that have no module prefix, compiler suffix or `__pfx_` padding prefix (91.8%; demo kernel.elf SHA-256 79a64158…, the MemLens 0.3.23 export; leaving out its 3 planted `memlens_target_*` hooks; `python3 tests/coverage.py kernel.elf` re-counts it).

Your own kernel: on x86-64, the `vmlinux` inside a distribution's `vmlinuz` (for example from `scripts/extract-vmlinux`) is an ELF with its symbol table stripped. btf2ida then names the **exported** functions from the kernel's own `__ksymtab` (only where the database has no name, never over yours) and applies their prototypes; the other functions get no prototype. Measured outside IDA on `objcopy -S` copies of two distribution kernels: Debian 13 6.12, 10,497 exported functions named, all at the same address as in the debug symbol table, 10,333 with a prototype (`tcp_sendmsg` and `vfs_getattr` among them); Ubuntu 26.04 7.0, 14,717 named, 13,865 with a prototype. An arm64 or Android kernel usually comes as a raw `Image`, which gets types only. For every function, give IDA a kernel ELF with all its symbols, for example one rebuilt from kallsyms by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (not tried here on a distribution `vmlinuz`).

## Status: read this first

**btf2ida has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is listed under [Verification](#verification): the parsing and the generated types are checked against independent ground truth, while the IDA calls are only checked to exist in the official SDK and run against stubs. If you try it in IDA and something is off, please open an issue.

Known limitations (the summary says so when one of the 32-bit x86, empty-struct, compiler-clone, no-BTF-module or distilled-base cases applies):

- **32-bit x86 databases** get types only, no prototypes: 32-bit x86 kernels pass arguments in registers (regparm), which a plain C prototype would misstate. Other 32-bit databases (ARM, MIPS, RISC-V: IDA's processor is not `metapc`) get prototypes too; not tried on a real 32-bit kernel.
- **No function names, no prototypes**: a raw arm64 `Image`, raw BTF or a raw memory image gets types only.
- **Layout details IDA does not get as types**: bitfields are raw storage bytes with their names in a comment, zero-length trailing arrays are comments, and 1-byte or 64-bit enums are plain unsigned integers without their constants.
- **Empty structs and unions** (size 0 in BTF) get a forward declaration only; the summary counts them apart.
- **Compiler clones** (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped, because their calling convention may differ.
- **A kernel module without BTF of its own**: only the kernel functions it calls are typed (see [A real kernel module](#a-real-kernel-module)).
- **Out-of-tree modules with a distilled `.BTF.base`** (pahole's `distilled_base`, which `scripts/Makefile.btf` requests for external modules since Linux 6.11): the module's own types and prototypes are imported from its own BTF, without a vmlinux; the kernel structs it uses are known there only by name and size, so they get a forward declaration only (a module struct that holds one by value gets a byte array of that size, the type named in a comment); the kernel functions it calls are not typed. Checked only on a synthetic module (a stub-test case and a hand-made `.ko`).

btf2ida was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install btf2ida
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later. The plugin index can lag behind the [GitHub releases](https://github.com/nightshift-labs-ai/btf2ida/releases); if `hcli plugin status` shows an older version, copy the folder from the latest release. The offline checks below used x86-64 kernels, plus two arm64 kernels where a row says so.

## Usage

Open a kernel or kernel module in IDA, then **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**. A summary says how many types IDA accepted and how many prototypes were applied.

Functions the compiler rewrote (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped on purpose: their calling convention may differ from the source signature.

**Does my kernel have BTF?** On a running system: `ls /sys/kernel/btf/vmlinux`. For a kernel file: `readelf -S vmlinux | grep BTF`. A memory export has no `.BTF` section, but the data is still in it; the plugin finds it by its header and checks it. Without IDA, `python3 btf2c.py <file> /dev/null` prints the type counts, or `btf2c: no BTF found`. Every kernel we tried has it (Debian 13, Ubuntu 26.04, WSL2, Android GKI 6.1).

Without IDA, as a generator of a C header for the same types:

```
python3 btf2c.py /sys/kernel/btf/vmlinux vmlinux_types.h
```

Headless, with idalib (IDA 9.0 or newer; set up the `idapro` module as Hex-Rays describes):

```
python3 tools/btf2ida_headless.py vmlinux
python3 tools/btf2ida_headless.py nf_tables.ko --vmlinux vmlinux
```

It opens the file as a database, runs the same import as the menu action, prints the same summary and saves the database. A module's split BTF needs `--vmlinux` (the menu action asks for it instead). It calls the plugin's own code; like the rest of the IDA layer it has only been run against fake modules (`tests/test_plugin_stub.py`), not a real idalib.

## A real kernel module

*Measured outside IDA, with fake IDA modules standing in for IDA. Not yet run in IDA.*

A module's BTF is split: its own functions are in the module, while the kernel functions it calls are in vmlinux's BTF. btf2ida applies the module's own prototypes by name, as for a whole kernel. It applies vmlinux prototypes only to names in an extern segment (`SEG_XTRN`), where the module's imports should be. "Not in this database" counts only the module's own functions.

Debian 13 `nf_tables.ko` (6.12.115+deb13.1-cloud-amd64), with that kernel's vmlinux as the base. To re-run it, see [Try a real module](#try-a-real-module) below (`tests/check_module.py`; `--no-names` for the first row):

| Fake database | v0.1.14 | v0.1.15 |
|---|---|---|
| No names (every lookup fails) | not in this database: 48,395 | not in this database: 495 (the module's own functions) |
| Names from the module's symbol table: its 193 undefined symbols in an extern segment, its 1,042 text symbols as functions | 489 functions typed, 0 imports; not in this database: 47,752 | 488 module functions and 151 imports typed (for example `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`); not in this database: 7 |

- The 7 have BTF but no symbol in the module.
- The other 39 imports have no function BTF in vmlinux. Examples: data (`jiffies`), thunks (`__x86_indirect_thunk_rax`), functions of another module (`nfnetlink_*`), and `memcmp`.
- One function typed before is now left alone: the module's own `jhash`, whose BTF is only in vmlinux's part. A vmlinux name outside the extern segment is not trusted to be the same function.

**A module with no BTF of its own.** Distribution out-of-tree modules are often built without BTF, because their build has no vmlinux (for example Ubuntu's `usbio.ko` and `intel_cvs.ko` have no `.BTF` section). For such a module (an ELF relocatable file with a `.gnu.linkonce.this_module` section and no BTF), btf2ida asks for the matching vmlinux (headless: `--vmlinux`) and types only the kernel functions the module calls, in its extern segment, from the vmlinux BTF. The module's own functions get no prototype, and the summary says so. With no split BTF to check against, it compares the module's `vermagic` release with the vmlinux's `Linux version` banner (in a memory image, any of its banners) and refuses a different kernel (for example Ubuntu's 6.17 `intel_cvs.ko` with the Debian 6.12 vmlinux: "this kernel module was built for 6.17.0-41-generic, but the chosen vmlinux is 6.12.115+deb13.1-cloud-amd64"); a raw BTF file has no banner, and then the summary says the match was not checked. Measured with the same fake database as above on Debian 13 `nf_tables.ko` with its `.BTF` section removed (`objcopy --remove-section .BTF`): 151 imports typed, the same 151 as with its BTF (`nla_put` identical), 0 own functions typed. This path has only been run against fake IDA modules.

Not checked in IDA:

- whether IDA puts a module's imports in a `SEG_XTRN` segment under their plain names;
- whether IDA accepts a prototype there.

### Try a real module

A module opens in IDA in seconds, so it is the quickest try on real kernel code. Debian 13's cloud kernel package (35 MB) holds both the module and its kernel:

```
curl -LO https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.12.115+deb13.1-cloud-amd64_6.12.115-2_amd64.deb
dpkg-deb -x linux-image-6.12.115+deb13.1-cloud-amd64_6.12.115-2_amd64.deb deb    # or: mkdir deb; ar x the .deb; tar -xf data.tar.xz -C deb
xz -dc deb/usr/lib/modules/6.12.115+deb13.1-cloud-amd64/kernel/net/netfilter/nf_tables.ko.xz > nf_tables.ko
curl -LO https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
sh extract-vmlinux deb/boot/vmlinuz-6.12.115+deb13.1-cloud-amd64 > vmlinux    # first install zstd: Debian 13 packs its kernel with zstd
file vmlinux                                                                   # must say ELF
```

Without `unzstd`, extract-vmlinux still exits 0 and writes the bzImage unchanged; btf2ida then says "install zstd". A kernel packed with gzip, xz, lzma or bzip2 (Debian 11, for example) needs no extract-vmlinux: choose the `vmlinuz` itself and btf2ida unpacks it. An arm64 `Image.gz` (Ubuntu's arm64 `vmlinuz`) is unpacked too.

SHA-256 of the results: `nf_tables.ko` 670cb309625f77c0…, `vmlinux` f741142f44058b03…. If the Debian pool no longer has this version, the same package is kept on snapshot.debian.org; another Debian 13 cloud kernel works the same way, with other numbers.

In IDA: open `nf_tables.ko`, run **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes** and choose `vmlinux` when it asks; `nla_put` in the extern segment should get `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`. Outside IDA, the same import on a fake database (stand-in IDA modules, see the script's docstring):

```
python3 tests/check_module.py nf_tables.ko vmlinux
```

prints, among the summary lines:

```
Prototypes applied to 488 functions; rejected by IDA 0; not in this database 7; name is not a function start 0
Typed 151 imported kernel functions in the extern segment (prototypes from the vmlinux BTF); rejected by IDA 0
The module's 193 undefined symbols: 193 found in this database, 0 of them outside an extern segment (left alone: only imports in an extern segment are typed)
Not applied: 3 'void f(void)' prototypes of assembly functions such as memcpy (BTF has no real prototype for them; IDA's own type is kept)
```

For the no-BTF case: `objcopy --remove-section .BTF nf_tables.ko nf_tables_nobtf.ko`, then the same command on `nf_tables_nobtf.ko` gives "Prototypes applied to 0 functions", the line "This kernel module has no BTF of its own ..." and the same 151 imports.

## Verification

All numbers from runs on real kernels; the scripts are in `tests/`.

| Check | Result |
|---|---|
| BTF layouts vs an independent DWARF-derived symbol file (`dwarf2json` ISF), Debian 13 kernel 6.12.115, `tests/check_against_dwarf.py` | 8,884 structs/unions compared, 0 size mismatches; 54,303 members compared, 0 offset mismatches (bitfield positions are not compared) |
| Generated C header compiled with `gcc -fsyntax-only`, WSL2 6.18 kernel (`/sys/kernel/btf/vmlinux`) and the carved Debian 13 data | compiles; 65,664 and 50,366 function prototypes, which also compile together with the header (on Debian 13 one, `dmi_callback`, has the same name as a typedef; `--prototypes` writes it as a comment) |
| BTF carved from raw memory dumps of a running Debian 13 VM (1 GB, ELF core) | 113,902 types found in a few seconds (1 to 3 s measured) |
| `--asserts`: 59,761 generated `_Static_assert` size and offset checks compiled with gcc against the generated header, the MemLens demo `kernel.elf` (a Debian 13 vmlinux `f741142f` gives 56,214) | all pass |
| Split BTF of a kernel module (`nf_tables.ko`, Debian 13) with `--base vmlinux` | header generated and compiles |
| The same module with the wrong base (the WSL 6.18 kernel's BTF) | refused with a clear error: 2,451 of 2,601 base string references land mid-string on WSL 6.18.33.1 (2,419 on an earlier WSL 6.18 build: the count depends on the exact kernel); with its own Debian 13 base, 0 of 1,090 |
| Public x86-64 Android GKI kernel 6.1.84 (`kernel-6.1` + its `System.map`) | 134,947 BTF types; 58,909 of 61,982 named kernel functions (95.0%) have a BTF prototype to apply (names from `System.map`, which the plugin does not read: in IDA the kernel needs its symbols, for example via vmlinux-to-elf) |
| `tests/check_ksymtab.py`: names from `__ksymtab` of a stripped (`objcopy -S`) vmlinux vs the debug vmlinux's symbol table | Debian 13 6.12: 10,497 of 10,497 exported code addresses match, 10,333 have a BTF prototype; Ubuntu 26.04 7.0: 14,717 of 14,717 (writable code-flagged sections excluded), 13,865 |
| `tests/test_ksymtab.py`: synthetic ELFs, no kernel needed | all four `__ksymtab` entry layouts (place-relative 12 and 8 bytes, absolute 16 and 24) give the right names; GPL table read; code, data and writable code told apart; relocatable files, missing strings and non-ELF input refused |
| `tests/check_ida_api.py` against HexRaysSA/ida-sdk IDAPython sources | 47 IDA API names used, 0 missing |
| `tests/check_ida_names.py` against the IDAPython stubs of IDA 9.1, 9.2, 9.3, 9.4 (PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11) and 9.5 | 44 `ida_*` / `idc` names used, 0 missing in each |
| A compressed kernel chosen as the vmlinux (`tests/check_module.py`) | Debian 11 `nf_tables.ko` (5.10.0-32, no BTF of its own) with its xz `vmlinuz`: 95 imports typed, the same output as with the extracted vmlinux. Debian 13 zstd `vmlinuz`: refused with "install zstd". Ubuntu 24.04 arm64 6.8 `vmlinuz` (gzip `Image`): unpacked, BTF and release banner found |
| arm64: Debian 13 `nf_tables.ko` (6.12.115+deb13.1-cloud-arm64) with that package's `vmlinuz` (an uncompressed `Image`) as the vmlinux, `tests/check_module.py` | 487 module functions and 138 imports typed; "Not applied: 1" (an assembly `void f(void)`) |
| `tests/test_unpack.py`: synthetic bzImages | gzip, xz, lzma and bzip2 payloads unpacked; zstd, lz4 and lzo refused with what to install; broken payloads refused |
| `tests/test_plugin_stub.py` with fake `ida_*` modules | full flow passes |

Not verified: behaviour inside real IDA, including how fast IDA ingests a full kernel's types and whether it rejects specific declarations (the plugin is written to split rejected batches and report them instead of failing; that relies on IDA ignoring a redeclaration when a batch is parsed again; the SDK documents it, since `parse_decls` "always uses the HTI_DCL bit", which means "don't complain about redeclarations" (`typeinf.hpp` in HexRaysSA/ida-sdk), but it has not been observed in IDA). The offline checks used x86-64 kernels, apart from the two arm64 rows.

## Compared with bpftool and Parse C header file

`bpftool btf dump file <vmlinux> format c` (bpftool 7.8.1) also writes kernel types as C, and IDA can parse a C header. What that route does not do, measured on the same inputs as the table above:

- **No `.BTF` section, no BTF.** On the Debian 13 memory export it stops with `libbpf: failed to find '.BTF' ELF section ... No data available`. btf2ida carves the BTF out of the image instead (50,366 prototypes from the same file).
- **Types only, no function prototypes.** On the WSL2 kernel bpftool's header has 172,354 lines but declares none of the 65,664 functions in the BTF (`vfs_read` and `tcp_sendmsg` do not appear; functions only show up as function-pointer typedefs). btf2ida applies the prototypes to the functions by name.
- **Written for clang, not IDA.** The header opens with `#pragma clang attribute push (__attribute__((preserve_access_index)), ...)` and has 305 lines with `__attribute__`. btf2c writes plain declarations with explicit padding under `#pragma pack(1)`. We have not checked how IDA's parser treats bpftool's header.

bpftool remains the right tool for CO-RE BPF programs; btf2ida is for getting the same data into an IDA database.

## How it works

`btf.py` reads the BTF container (own or split base + module) with no dependencies. `btf2c.py` turns it into ordered C declarations IDA's parser accepts: dependency-sorted, with forward declarations, renamed reserved words, and explicit padding so offsets match exactly under `#pragma pack(1)`. `btf2ida_entry.py` is the thin IDA layer.

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs". Thanks to the Linux BTF authors and to the Volatility project (dwarf2json), used for the ground-truth check.

## Licence

MIT.
