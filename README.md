# btf2ida

Open a Linux kernel in IDA and get its **real types and function prototypes** with one click, with no debug package and no matching source tree.

*Status: not yet run in real IDA; what was checked offline is under [Verification](#verification).*

Most current distribution and Android GKI kernels carry [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format, built in with `CONFIG_DEBUG_INFO_BTF`), a compact description of every kernel struct, union, enum and function signature. Many embedded and older vendor kernels do not. Where it exists, it is there in a stripped `vmlinux`, in Android GKI kernels, and in RAM. btf2ida finds it and applies it:

- **Every kernel type**: all structs, unions, enums and typedefs imported as IDA local types, every member at its exact byte offset (packed and anonymous members included). Bitfields are kept as raw storage bytes with their names in a comment, and zero-length trailing arrays appear only as comments, so those members are not separately visible in IDA.
- **Function prototypes by name**: each function in the database whose name has a BTF signature gets that signature, so the decompiler shows `struct sock *sk` instead of `__int64 a1`. On a stripped kernel, exported functions are first named from `__ksymtab`.
- **Finds BTF on its own**: from the input file (`vmlinux`, a kernel module `.ko`, raw BTF, a memory image, by carving) or from the loaded segments. For a kernel module it asks for the matching `vmlinux` to resolve split BTF. Raw BTF or a raw memory image gives types only: prototypes need function names in the database.

It adds nothing to your binary and needs nothing installed besides the plugin.

## Why it matters

A Linux kernel without its debug package is mostly `__int64 a1`, and matching headers or a debug package are often impossible to get: vendor kernels, Android devices, a kernel seen only in a memory image. The BTF is already inside the image. Using it replaces retyping structures by hand.

## Try it

Smallest try, nothing to download: `demo/toy_kernel.elf` (17 KB) is a small program with kernel-style types, built with `gcc -gbtf`, so it carries BTF and no DWARF and IDA has no other source for these types (`demo/build.sh` rebuilds it).

1. Open `demo/toy_kernel.elf` in IDA.
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

Outside IDA on this file: BTF found by carving in 0.3 s, 50,366 prototypes, matching 46,904 of the 51,119 kernel function symbols that have no module prefix, compiler suffix or `__pfx_` padding prefix (91.8%).

Your own kernel: on x86-64, the `vmlinux` inside a distribution's `vmlinuz` (for example from `scripts/extract-vmlinux`) is an ELF with its symbol table stripped. btf2ida then names the **exported** functions from the kernel's own `__ksymtab` (only where the database has no name, never over yours) and applies their prototypes; the other functions get no prototype. Measured outside IDA on `objcopy -S` copies of two distribution kernels: Debian 13 6.12, 10,497 exported functions named, all at the same address as in the debug symbol table, 10,333 with a prototype (`tcp_sendmsg` and `vfs_getattr` among them); Ubuntu 26.04 7.0, 14,717 named, 13,865 with a prototype. An arm64 or Android kernel usually comes as a raw `Image`, which gets types only. For every function, give IDA a kernel ELF with all its symbols, for example one rebuilt from kallsyms by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (not tried here on a distribution `vmlinuz`).

## Status: read this first

**btf2ida has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is listed under [Verification](#verification): the parsing and the generated types are checked against independent ground truth, while the IDA calls are only checked to exist in the official SDK and run against stubs. If you try it in IDA and something is off, please open an issue.

btf2ida was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install btf2ida
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later. The plugin index can lag behind the [GitHub releases](https://github.com/nightshift-labs-ai/btf2ida/releases); if `hcli plugin status` shows an older version, copy the folder from the latest release. The offline checks below used x86-64 kernels.

## Usage

Open a kernel or kernel module in IDA, then **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**. A summary says how many types IDA accepted and how many prototypes were applied.

Functions the compiler rewrote (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped on purpose: their calling convention may differ from the source signature.

Without IDA, as a generator of a C header for the same types:

```
python3 btf2c.py /sys/kernel/btf/vmlinux vmlinux_types.h
```

## Verification

All numbers from runs on real kernels; the scripts are in `tests/`.

| Check | Result |
|---|---|
| BTF layouts vs an independent DWARF-derived symbol file (`dwarf2json` ISF), Debian 13 kernel 6.12.115, `tests/check_against_dwarf.py` | 8,884 structs/unions compared, 0 size mismatches; 54,303 members compared, 0 offset mismatches (bitfield positions are not compared) |
| Generated C header compiled with `gcc -fsyntax-only`, WSL2 6.18 kernel (`/sys/kernel/btf/vmlinux`) and the carved Debian 13 data | compiles; 65,664 and 50,366 function prototypes |
| BTF carved from raw memory dumps of a running Debian 13 VM (1 GB, ELF core) | 113,902 types found in a few seconds (1 to 3 s measured) |
| `--asserts`: 59,761 generated `_Static_assert` size and offset checks compiled with gcc against the generated header, Debian 13 vmlinux | all pass |
| Split BTF of a kernel module (`nf_tables.ko`, Debian 13) with `--base vmlinux` | header generated and compiles |
| The same module with the wrong base (the WSL 6.18 kernel's BTF) | refused with a clear error: 2,419 of 2,601 base string references land mid-string; with its own Debian 13 base, 0 of 1,090 |
| Public x86-64 Android GKI kernel 6.1.84 (`kernel-6.1` + its `System.map`) | 134,947 BTF types; 58,909 of 61,982 named kernel functions (95.0%) have a BTF prototype to apply (names from `System.map`, which the plugin does not read: in IDA the kernel needs its symbols, for example via vmlinux-to-elf) |
| `tests/check_ksymtab.py`: names from `__ksymtab` of a stripped (`objcopy -S`) vmlinux vs the debug vmlinux's symbol table | Debian 13 6.12: 10,497 of 10,497 exported code addresses match, 10,333 have a BTF prototype; Ubuntu 26.04 7.0: 14,717 of 14,717 (writable code-flagged sections excluded), 13,865 |
| `tests/check_ida_api.py` against HexRaysSA/ida-sdk IDAPython sources | 43 IDA API names used, 0 missing |
| `tests/test_plugin_stub.py` with fake `ida_*` modules | full flow passes |

Not verified: behaviour inside real IDA, including how fast IDA ingests a full kernel's types and whether it rejects specific declarations (the plugin is written to split rejected batches and report them instead of failing; that relies on IDA ignoring a redeclaration when a batch is parsed again, which has not been observed in IDA). Only x86-64 kernels were used in the offline checks.

## How it works

`btf.py` reads the BTF container (own or split base + module) with no dependencies. `btf2c.py` turns it into ordered C declarations IDA's parser accepts: dependency-sorted, with forward declarations, renamed reserved words, and explicit padding so offsets match exactly under `#pragma pack(1)`. `btf2ida_entry.py` is the thin IDA layer.

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs". Thanks to the Linux BTF authors and to the Volatility project (dwarf2json), used for the ground-truth check.

## Licence

MIT.
