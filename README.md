# btf2ida

<img src="assets/logo.png" alt="btf2ida logo" width="140" align="right">

Open a Linux kernel in IDA and get its **real types and function prototypes** with one click, from the kernel's own BTF: no debug package, no matching source tree.

*Status: not yet run in real IDA; checked offline against real kernels ([Verification](docs/VERIFICATION.md)).*

- **Every kernel type**: structs, unions, enums and typedefs as IDA local types, each member at its exact offset.
- **Prototypes by name**, including the kernel functions a module imports.
- **Finds the BTF itself** in a `vmlinux`, a `.ko`, a memory image or a BTFHub file.

**Expected**, on the bundled toy: `demo_open` should get `int demo_open(struct demo_device *dev, unsigned int flags)` and its store to `[rdi+0xc]` should become `dev->state`; `demo_checksum` should read `dev->id`, `dev->x`, `dev->y` and `dev->private_` ([every access](demo/expected_members.txt)). In a real module, the import `nla_put` should get `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`.

## Try it

Install the current release:

```
hcli plugin install https://github.com/nightshift-labs-ai/btf2ida/archive/refs/tags/v0.1.24.zip
```

### The toy: nothing to download

`demo/toy_kernel.elf` (17 KB) is a small program with kernel-style types, built with `gcc -gbtf`, so it carries BTF and no DWARF and IDA has no other source for these types (`demo/build.sh` rebuilds it). After `hcli plugin install` it is in `plugins/btf2ida/demo/` under your IDA user folder: `$IDAUSR` if set, otherwise `~/.idapro` (Linux, macOS) or `%APPDATA%\Hex-Rays\IDA Pro` (Windows); both are hidden folders. Or download it directly: [toy_kernel.elf](https://github.com/nightshift-labs-ai/btf2ida/raw/main/demo/toy_kernel.elf).

1. Open `toy_kernel.elf` in IDA and press **F5** in `demo_open` and `demo_checksum`. With no types, the decompiler can only show their accesses to `dev` as offsets.
2. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**.
3. Press **F5** in `demo_open` again. It should be `int demo_open(struct demo_device *dev, unsigned int flags)` (all five prototypes are in `demo/expected_prototypes.txt`), and its store to `[rdi+0xc]` should read `dev->state = DEMO_RUNNING;`. Its source, `demo/toy_kernel.c:33-35`:
   ```c
   dev->state = DEMO_RUNNING;
   dev->mode = flags & 7;
   return dev->refs++;
   ```
   `mode` and `refs` are bitfields: the code sets `mode` with a byte read-modify-write at `[rdi+0x8]` and `refs` with a word read-modify-write at the same address. Whether Hex-Rays folds these masks into `dev->mode` and `dev->refs` has not been seen in real IDA; it may show the masks instead.
4. In `demo_checksum`, the sum should read `dev->id`, `dev->x`, `dev->y` and `dev->private_` (`private` is renamed: it is a C++ keyword, which IDA's parser may refuse), as in `demo/toy_kernel.c:47-49`:
   ```c
   long sum = (long)dev->id + dev->x + dev->y + dev->private;
   for (size_t i = 0; i < len; i++)
   	sum += dev->payload[i];
   ```
   The `payload[i]` loop stays a raw offset: `payload` is a flexible array, which btf2ida declares only as a comment ([Known limitations](#known-limitations)).
5. Local Types should hold `struct demo_device` as in `demo/expected_types.h`: `ready`, `mode` and `refs` as `unsigned short` bitfields (IDA may show them as `unsigned __int16`).

[`demo/expected_members.txt`](demo/expected_members.txt) lists every memory access of the toy's `demo_*` functions with the member it touches, derived offline from `objdump -d` and btf2ida's layout (`tests/check_toy_members.py`).

### A real module in two minutes

Download [`btf2ida-try-module.zip`](https://github.com/nightshift-labs-ai/btf2ida/releases/download/try-module/btf2ida-try-module.zip) (1.7 MB): Debian 13's `nf_tables.ko` and its kernel's BTF as `vmlinux.btf` (sources and SHA-256 in its `README.txt`). No Linux tools needed.

1. Unzip it and open `nf_tables.ko` in IDA (it takes seconds).
2. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**, and choose `vmlinux.btf` when it asks for the module's kernel.
3. The summary's "Look at:" line names `nft_data_init`; press F5 there. btf2ida gives it (fake database; Hex-Rays prints it its own way) `int nft_data_init(const struct nft_ctx *ctx, struct nft_data *data, struct nft_data_desc *desc, const struct nlattr *nla)`.
   The import `nla_put` in the extern segment should be `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`. Expected in total: 488 of the module's own functions and 150 imported kernel functions typed (`python3 tests/check_module.py nf_tables.ko vmlinux.btf`, on a fake IDA database).

### A real kernel, ready with symbols and BTF

Download `memlens-demo-debian13.zip` (22 MB) from the [MemLens demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (MemLens is our companion plugin that exports a running kernel from a memory image).

1. Unzip it and open `kernel.elf` in IDA; let auto-analysis finish (a whole kernel takes a while).
2. **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**.
3. Open `tcp_sendmsg` or `vfs_getattr`. Their prototypes in this kernel's BTF, as btf2ida generates them (`python3 btf2c.py kernel.elf types.h --prototypes protos.txt`, run outside IDA):

```c
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags);
```

46,900 of its 51,092 function symbols (91.8%; compiler clones and padding symbols not counted) have a prototype to apply (`python3 tests/coverage.py kernel.elf`; [details](docs/KERNELS.md#a-kernel-with-its-symbols)).

### Your own kernel

| What you have | Do this first | Functions with a prototype (measured outside IDA) |
|---|---|---|
| A kernel with symbols | nothing | MemLens demo: 91.8% |
| A distribution `vmlinuz` (x86-64) | `extract-vmlinux`, then `vmlinux-to-elf vmlinux kernel.elf` | Ubuntu mainline 7.0: 72.0% (68,830 of 95,537) |
| Android GKI `boot.img` or raw `Image` | `vmlinux-to-elf Image kernel.elf` ([recipe](docs/KERNELS.md#android-gki-and-other-raw-images)) | GKI 6.1 / 6.6 / 6.12: 98.6% / 97.9% / 93.7% |
| A kernel module `.ko` | choose its kernel's `vmlinux` (or its raw BTF) when asked | `nf_tables.ko`: 488 own, 150 imports ([kit](#a-real-module-in-two-minutes)) |
| A kernel without BTF | choose a [BTFHub](https://github.com/aquasecurity/btfhub-archive) file when asked | as for its kind above |

[vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (`pipx install vmlinux-to-elf`) restores the function names a stripped or raw kernel keeps for kallsyms. Without it, a stripped `vmlinux` gets prototypes only for its exported functions, which btf2ida names from `__ksymtab` (13,840 on that Ubuntu kernel), and a raw `Image` gets types only. Recipes, downloads and all measurements: [docs/KERNELS.md](docs/KERNELS.md).

## Why it matters

A Linux kernel without its debug package is mostly `__int64 a1`, and matching headers or a debug package are often impossible to get: vendor kernels, Android devices, a kernel seen only in a memory image. The BTF is already inside the image. Using it replaces retyping structures by hand. It adds nothing to your binary and needs nothing installed besides the plugin.

## Install

```
hcli plugin install btf2ida
```

Or copy this folder into your IDA `plugins` directory. IDA 9.1 or later (the IDA API names it uses are checked against the IDAPython stubs of 9.1 to 9.5; 9.0 is not checked). The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/btf2ida/releases); if `hcli plugin status` shows an older version, install the release zip by URL as in [Try it](#try-it).

## Usage

Open a kernel or kernel module, then **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**. If IDA is still analysing, btf2ida first offers to wait. A summary says how many types IDA accepted and how many prototypes were applied; it starts with a one-line headline (after a CANCELLED or analysis warning, if any), and a "Look at:" line names one typed function to open with F5 (`tcp_sendmsg` on a kernel where it got its prototype).

- **BTF2IDA: Apply kernel types and prototypes (bitfields as raw bytes)** does the same with every bitfield as raw bytes.
- Headless with idalib: `python3 tools/btf2ida_headless.py vmlinux` (a module: `nf_tables.ko --vmlinux vmlinux`).
- Without IDA, as a C header generator: `python3 btf2c.py /sys/kernel/btf/vmlinux vmlinux_types.h`.

All options: [docs/USAGE.md](docs/USAGE.md).

## Known limitations

- **32-bit x86 databases** get types only, no prototypes (regparm calling convention).
- **No function names, no prototypes**: raw BTF, a raw memory image or a raw `Image` gets types only.
- **Some layout details are not types**: flexible arrays are comments; a few bitfields (17 of 2,239 in the MemLens demo) stay raw bytes; bitfields lose their declared type (enum, `_Bool`, typedef); 1-byte and 64-bit enums lose their constants.
- **Bitfield layout checked with gcc only**; the plugin reads IDA's layout back and falls back to raw bytes where it differs.
- **Compiler clones** (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped; empty structs get a forward declaration only.
- **Assembly functions** recorded in BTF as `void f(void)` are skipped for 228 known names; others still get it.
- **Modules without BTF** get their imports typed, not their own functions; modules with a distilled `.BTF.base` get their own, not their imports.

Each in full, with numbers: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Verification

The parsing and the generated types are checked against independent ground truth on real kernels, for example the MemLens demo kernel against its DWARF: 8,884 structs and unions, 54,303 member offsets and 1,364 bitfields, 0 mismatches. The IDA calls are only checked to exist in the official SDK and IDAPython stubs, and run against fake `ida_*` modules. If you try it in IDA and something is off, please open an issue. Every check, command and number: [docs/VERIFICATION.md](docs/VERIFICATION.md).

## How it works

`btf.py` reads the BTF (also carved from memory images, BTFHub archives and compressed kernels), `btf2c.py` turns it into C declarations IDA's parser accepts with every offset exact, and `btf2ida_entry.py` is the thin IDA layer. Unlike `bpftool btf dump`, it also finds BTF without a `.BTF` section and applies function prototypes. More: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs". Thanks to the Linux BTF authors and to the Volatility project (dwarf2json), used for the ground-truth check.

## Licence

MIT.
