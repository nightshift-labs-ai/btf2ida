# btf2ida

Open a Linux kernel in IDA and get its **real types and function prototypes** with one click, with no debug package and no matching source tree.

Most modern kernels carry [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format), a compact description of every kernel struct, union, enum and function signature. It is there in a stripped `vmlinux`, in Android GKI kernels, and in RAM. btf2ida finds it and applies it:

- **Every kernel type**: all structs, unions, enums and typedefs imported as IDA local types with exact layouts (bitfields, packed members, anonymous members).
- **Function prototypes by name**: each function in the database whose name has a BTF signature gets that signature, so the decompiler shows `struct sock *sk` instead of `__int64 a1`.
- **Finds BTF on its own**: from the input file (`vmlinux`, a kernel module `.ko`, raw BTF, a memory image, by carving) or from the loaded segments. For a kernel module it asks for the matching `vmlinux` to resolve split BTF.

It adds nothing to your binary and needs nothing installed besides the plugin.

## Why it matters

A Linux kernel without its debug package is mostly `__int64 a1`, and matching headers or a debug package are often impossible to get: vendor kernels, Android devices, a kernel seen only in a memory image. The BTF is already inside the image. Using it replaces retyping structures by hand.

## Try it

Any recent distribution kernel works, because they ship BTF:

1. Decompress your kernel, for example with the kernel's own `scripts/extract-vmlinux /boot/vmlinuz-$(uname -r) > vmlinux`, or use Android's `boot.img` kernel through [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) so it has symbols.
2. Open it in IDA and let auto-analysis finish.
3. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**, then open a function such as `tcp_sendmsg`: its arguments should now be typed (`struct sock *sk`, `struct msghdr *msg`).

Prototypes need a symbol name to match by, so a kernel with no symbols gets types but no prototypes.

## Status: read this first

**btf2ida has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is listed under [Verification](#verification): the parsing and the generated types are checked against independent ground truth, while the IDA calls are only checked to exist in the official SDK and run against stubs. If you try it in IDA and something is off, please open an issue.

btf2ida was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install btf2ida
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later, x86-64 kernels are the tested target.

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
| BTF carved from raw memory dumps of a running Debian 13 VM (1 GB, ELF core) | 113,902 types found in about 1 s |
| `--asserts`: 59,761 generated `_Static_assert` size and offset checks compiled with gcc against the generated header, Debian 13 vmlinux | all pass |
| Split BTF of a kernel module (`nf_tables.ko`, Debian 13) with `--base vmlinux` | header generated and compiles |
| Public x86-64 Android GKI kernel 6.1.84 (`kernel-6.1` + its `System.map`) | 134,947 BTF types; 58,909 of 61,982 named kernel functions (95.0%) have a BTF prototype to apply |
| `tests/check_ida_api.py` against HexRaysSA/ida-sdk IDAPython sources | 36 IDA API names used, 0 missing |
| `tests/test_plugin_stub.py` with fake `ida_*` modules | full flow passes |

Not verified: behaviour inside real IDA, including how fast IDA ingests a full kernel's types and whether it rejects specific declarations (the plugin splits rejected batches and reports them instead of failing). Only x86-64 has been tested end to end.

## How it works

`btf.py` reads the BTF container (own or split base + module) with no dependencies. `btf2c.py` turns it into ordered C declarations IDA's parser accepts: dependency-sorted, with forward declarations, renamed reserved words, and explicit padding so offsets match exactly under `#pragma pack(1)`. `btf2ida_entry.py` is the thin IDA layer.

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs". Thanks to the Linux BTF authors and to the Volatility project (dwarf2json), used for the ground-truth check.

## Licence

MIT.
