# Kernels: what to open, and what you get

[README](../README.md) · [Usage](USAGE.md) · [Limitations](LIMITATIONS.md) · [Verification](VERIFICATION.md) · [How it works](HOW_IT_WORKS.md)

Most current distribution and Android GKI kernels carry [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format, built in with `CONFIG_DEBUG_INFO_BTF`), a compact description of every kernel struct, union, enum and function signature. Many embedded and older vendor kernels do not. Where it exists, it is there in a stripped `vmlinux`, in Android GKI kernels, and in RAM.

btf2ida imports the types from the BTF alone. Prototypes are applied **by name**, so how many functions get one depends on how many functions in the database have their kernel name. All counts on this page were measured outside IDA (`tests/coverage.py`, `tests/check_ksymtab.py`, `tests/check_module.py` with its fake IDA database); the commands and outputs are in [Verification](VERIFICATION.md#getting-function-names-vmlinux-to-elf-and-__ksymtab).

| What you have | What to open in IDA | Functions with a prototype (measured) |
|---|---|---|
| A kernel ELF with its symbols (debug `vmlinux`, a MemLens export) | the file itself | MemLens demo kernel.elf: 46,900 of 51,092 (91.8%) |
| A distribution `vmlinuz` (x86-64) | `vmlinux-to-elf` output ([below](#a-distribution-vmlinuz)) | Ubuntu mainline 7.0: 68,830 of 95,537 named functions (72.0%), 68,698 applied |
| The same, without vmlinux-to-elf | the extracted `vmlinux`; btf2ida names exports from `__ksymtab` | Ubuntu mainline 7.0: 13,840 (exported functions only) |
| An Android GKI `boot.img` or raw arm64 `Image` | `vmlinux-to-elf` output ([below](#android-gki-and-other-raw-images)) | GKI 6.1 / 6.6 / 6.12: 98.6% / 97.9% / 93.7% |
| A raw `Image`, raw BTF or a raw memory image as it is | the file itself | types only (no function names) |
| A kernel module `.ko` | the `.ko`, then choose its kernel's `vmlinux` when asked ([below](#kernel-modules)) | Debian 13 `nf_tables.ko`: 488 own functions and 150 imports |
| A kernel built without BTF | the kernel, then a [BTFHub](https://github.com/aquasecurity/btfhub-archive) file when asked ([below](#a-kernel-built-without-btf)) | as for its kind above |

## Where btf2ida looks for BTF

From the input file (`vmlinux`, a kernel module `.ko`, raw BTF, a memory image, by carving) or from the loaded segments. For a kernel module it asks for the matching `vmlinux` to resolve split BTF. Raw BTF or a raw memory image gives types only: prototypes need function names in the database.

**Does my kernel have BTF?** On a running system: `ls /sys/kernel/btf/vmlinux`. For a kernel file: `readelf -S vmlinux | grep BTF`. A memory export has no `.BTF` section, but the data is still in it; the plugin finds it by its header and checks it. Without IDA, `python3 btf2c.py <file> /dev/null` prints the type counts, or `btf2c: no BTF found`. Every kernel we tried has it (Debian 13, Ubuntu 26.04, WSL2, Android GKI 6.1).

## A kernel with its symbols

The MemLens demo `kernel.elf` (in `memlens-demo-debian13.zip`, 22 MB, from the [MemLens demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data)) is a Debian 13 6.12 kernel exported from a memory image with its symbols. Outside IDA on this file: BTF found by carving in 0.3 s, 50,366 prototypes, matching 46,900 of the 51,092 kernel function symbols that have no module prefix, compiler suffix or `__pfx_` padding prefix (91.8%; demo kernel.elf SHA-256 79a64158…, the MemLens 0.3.23 export; leaving out the 3 `memlens_target_*` labels the MemLens exporter adds for copied hook pages; `python3 tests/coverage.py kernel.elf` re-counts it).

## A distribution vmlinuz

On x86-64, the `vmlinux` inside a distribution's `vmlinuz` is an ELF with its symbol table stripped, but the kernel keeps its function names in its own compressed symbol table (kallsyms, the table behind `/proc/kallsyms`). [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) rebuilds an ELF with those names:

```
pipx install vmlinux-to-elf          # from PyPI; 1.4.0 was used here
vmlinux-to-elf vmlinux kernel.elf    # vmlinux: extracted from the vmlinuz, as below
```

Then open `kernel.elf` in IDA and run btf2ida. Measured on the Ubuntu mainline 7.0 stripped vmlinux (7.0.0-070000-generic, SHA-256 dd678585…; vmlinux-to-elf 1.4.0 took 105 s and 1.5 GB of memory here, and a second run gave a byte-identical file):

- 95,537 named function symbols, 68,830 of them with a BTF prototype (72.0%), out of 70,032 prototypes in the BTF;
- the plugin's import on a fake IDA database: prototypes applied to 68,698 functions (the other 132 are assembly `void f(void)` records, [left out](LIMITATIONS.md#assembly-functions)), 15,299 compiler clones left untyped;
- the names agree with the kernel's `__ksymtab` on all 14,690 exported code addresses (`tests/check_ksymtab.py`).

The `vmlinux` comes out of the `vmlinuz` with the kernel's `scripts/extract-vmlinux` (see [Try a real module](#try-a-real-module) for the commands). vmlinux-to-elf also unpacks compressed kernels itself, according to its documentation; that was not measured here.

**Without vmlinux-to-elf**, btf2ida names only the **exported** functions, from the kernel's own `__ksymtab` (only where the database has no name, never over yours), and applies their prototypes; the other functions get no prototype. On the same Ubuntu mainline 7.0 vmlinux that is 13,840 functions with a prototype (of 14,690 exported code addresses), against 68,698 with vmlinux-to-elf. Measured outside IDA on `objcopy -S` copies of two distribution kernels: Debian 13 6.12, 10,497 exported functions named, all at the same address as in the debug symbol table, 10,333 with a prototype (`tcp_sendmsg` and `vfs_getattr` among them); Ubuntu 26.04 7.0, 14,717 named, 13,865 with a prototype.

## Android GKI and other raw images

An arm64 or Android kernel usually comes as a raw `Image`. Opened as it is, it gets types only, because IDA has no function names for it. With vmlinux-to-elf it gets its names back, and with them the prototypes. A public GKI kernel, for example: [gki-certified-boot-android14-6.1-2024-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip) from Android's [GKI release builds](https://source.android.com/docs/core/architecture/kernel/gki-release-builds) page holds `boot-6.1.img`:

```
python3 -c "import struct; b = open('boot-6.1.img', 'rb').read(); open('Image', 'wb').write(b[4096:4096 + struct.unpack_from('<I', b, 8)[0]])"
vmlinux-to-elf Image kernel.elf
```

The first line copies the kernel out of the boot image (a version 4 header: the kernel starts at byte 4096, its size at byte 8); on the three boot images below it writes, byte for byte, the `Image` measured here. Then open `kernel.elf` in IDA. Measured outside IDA (`tests/coverage.py`; vmlinux-to-elf took 21 s on 6.1 and gave a byte-identical file on a second run):

| GKI kernel (arm64) | Download | Function symbols with a prototype |
|---|---|---|
| 6.1.57-android14-11 | [android14-6.1-2024-01_r1](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip) | 55,349 of 56,129 (98.6%) |
| 6.6.58-android15-8 | [android15-6.6-2025-01_r1](https://dl.google.com/android/gki/gki-certified-boot-android15-6.6-2025-01_r1.zip) | 59,762 of 61,065 (97.9%) |
| 6.12.23-android16-5 | [android16-6.12-2025-06_r1](https://dl.google.com/android/gki/gki-certified-boot-android16-6.12-2025-06_r1.zip) | 61,658 of 65,817 (93.7%) |

On 6.1, the plugin's import on a fake IDA database applies 55,348 prototypes; the one left is an assembly `void f(void)`. A public x86-64 GKI kernel 6.1.84 (`kernel-6.1` with its `System.map`) has 134,947 BTF types and a BTF prototype for 58,909 of its 61,982 named kernel functions (95.0%); btf2ida does not read `System.map`, so there too the names have to come from vmlinux-to-elf.

## A kernel built without BTF

Older distribution kernels such as Ubuntu 20.04's 5.8 have no BTF. btf2ida then asks for a BTF file of the same build, for example `<release>.btf.tar.xz` from [BTFHub](https://github.com/aquasecurity/btfhub-archive) (headless: `--vmlinux <file>`). The summary warns when the release in the kernel's banner differs from the file's banner or BTFHub name, so pick the exact release. When none is chosen, the error ends with the path of the toy demo (`demo/toy_kernel.elf` in the plugin folder), to see btf2ida work.

## Compressed kernels

A kernel packed with gzip, xz, lzma or bzip2 (Debian 11, for example) needs no extract-vmlinux when btf2ida asks for a vmlinux: choose the `vmlinuz` itself and btf2ida unpacks it. An arm64 `Image.gz` (Ubuntu's arm64 `vmlinuz`) is unpacked too, and so is an EFI zboot `vmlinuz` packed with gzip, xz or lzma (`MZ` ... `zimg`; a zstd one needs extract-vmlinux with zstd installed; checked on synthetic files only). Without `unzstd`, extract-vmlinux still exits 0 and writes the bzImage unchanged; btf2ida then says "install zstd".

## Kernel modules

*Measured outside IDA, with fake IDA modules standing in for IDA.*

A module's BTF is split: its own functions are in the module, while the kernel functions it calls are in vmlinux's BTF. btf2ida applies the module's own prototypes by name, as for a whole kernel. It applies vmlinux prototypes only to names in an extern segment (`SEG_XTRN`), where the module's imports should be. "Not in this database" counts only the module's own functions.

Debian 13 `nf_tables.ko` (6.12.115+deb13.1-cloud-amd64), with that kernel's vmlinux as the base. To re-run it, see [Try a real module](#try-a-real-module) below (`tests/check_module.py`; `--no-names` for the first row):

| Fake database | v0.1.14 | v0.1.15 to v0.1.20 |
|---|---|---|
| No names (every lookup fails) | not in this database: 48,395 | not in this database: 495 (the module's own functions) |
| Names from the module's symbol table: its 193 undefined symbols in an extern segment, its 1,042 text symbols as functions | 489 functions typed, 0 imports; not in this database: 47,752 | 488 module functions and 154 imports typed (for example `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`); not in this database: 7 |

- The 7 have BTF but no symbol in the module.
- Since v0.1.21, 150 of the 154: four (`__fentry__`, `memcpy`, `memmove`, `memset`) are assembly functions, which BTF records as `void f(void)`; they are left as IDA has them (the "Not applied: 4" line below).
- The other 39 imports have no function BTF in vmlinux. Examples: data (`jiffies`), thunks (`__x86_indirect_thunk_rax`), functions of another module (`nfnetlink_*`), and `memcmp`.
- One function typed before is now left alone: the module's own `jhash`, whose BTF is only in vmlinux's part. A vmlinux name outside the extern segment is not trusted to be the same function.

### A module with no BTF of its own

Distribution out-of-tree modules are often built without BTF, because their build has no vmlinux (for example Ubuntu's `usbio.ko` and `intel_cvs.ko` have no `.BTF` section). For such a module (an ELF relocatable file with a `.gnu.linkonce.this_module` section and no BTF), btf2ida asks for the matching vmlinux (headless: `--vmlinux`); the file dialog names the release from the module's `vermagic` and the BTFHub file of that release, for example "This kernel module was built for 6.17.0-41-generic and has no BTF of its own: choose that kernel's vmlinux or a copy of its /sys/kernel/btf/vmlinux (an old distribution kernel without BTF: BTFHub 6.17.0-41-generic.btf.tar.xz)" (checked with fake `ida_*` modules). It types only the kernel functions the module calls, in its extern segment, from the vmlinux BTF. The module's own functions get no prototype, and the summary says so.

With no split BTF to check against, it compares the module's `vermagic` release with the vmlinux's `Linux version` banner (in a memory image, any of its banners) and refuses a different kernel, for example Ubuntu's 6.17 `intel_cvs.ko` with the Debian 6.12 vmlinux: "this kernel module was built for 6.17.0-41-generic, but the chosen vmlinux is 6.12.115+deb13.1-cloud-amd64". You can choose to use it anyway: the menu action asks (default No), headless takes `--force`, and the summary then has a line "Used anyway (your choice)" that names both releases (that same pair with `tests/check_module.py ... --force`: 40 of the 56 imports typed). A raw BTF file has no banner, and then the summary says the match was not checked.

A module that has its own split BTF is never "used anyway": it is refused when the chosen vmlinux does not fit its string and type references, for example Ubuntu 26.04's 7.0 `nf_tables.ko` with the Debian 13 6.12 vmlinux: "this module's BTF does not match the chosen vmlinux (string offset out of range)" (before, that pair fell through to the whole-kernel file dialog).

Measured with the same fake database as above on Debian 13 `nf_tables.ko` with its `.BTF` section removed (`objcopy --remove-section .BTF`): 150 imports typed, the same 150 as with its BTF (`nla_put` identical), 0 own functions typed. This path has only been run against fake IDA modules.

### Try a real module

A module opens in IDA in seconds, so it is the quickest try on real kernel code. The ready-made [`btf2ida-try-module.zip`](https://github.com/nightshift-labs-ai/btf2ida/releases/download/try-module/btf2ida-try-module.zip) (1.7 MB) holds the two files below, with `vmlinux.btf` (the vmlinux's `.BTF` section, `objcopy -O binary --only-section=.BTF vmlinux vmlinux.btf`) in place of the 58 MB vmlinux; the counts are the same with either. To build them yourself: Debian 13's cloud kernel package (35 MB) holds both the module and its kernel (Linux tools; `extract-vmlinux` needs `zstd` here):

```
curl -LO https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.12.115+deb13.1-cloud-amd64_6.12.115-2_amd64.deb
dpkg-deb -x linux-image-6.12.115+deb13.1-cloud-amd64_6.12.115-2_amd64.deb deb    # or: mkdir deb; ar x the .deb; tar -xf data.tar.xz -C deb
xz -dc deb/usr/lib/modules/6.12.115+deb13.1-cloud-amd64/kernel/net/netfilter/nf_tables.ko.xz > nf_tables.ko
curl -LO https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
sh extract-vmlinux deb/boot/vmlinuz-6.12.115+deb13.1-cloud-amd64 > vmlinux    # first install zstd: Debian 13 packs its kernel with zstd
file vmlinux                                                                   # must say ELF
```

SHA-256 of the results: `nf_tables.ko` 670cb309625f77c0…, `vmlinux` f741142f44058b03…. If the Debian pool no longer has this version, the same package is kept on snapshot.debian.org; another Debian 13 cloud kernel works the same way, with other numbers.

In IDA: open `nf_tables.ko`, run **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes** and choose `vmlinux` when it asks; `nla_put` in the extern segment should get `int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)`. Outside IDA, the same import on a fake database (stand-in IDA modules, see the script's docstring):

```
python3 tests/check_module.py nf_tables.ko vmlinux
```

prints, among the summary lines:

```
Prototypes applied to 488 functions; rejected by IDA 0; not in this database 7; name is not a function start 0
Typed 150 imported kernel functions in the extern segment (prototypes from the vmlinux BTF); rejected by IDA 0
The module's 193 undefined symbols: 193 found in this database, 0 of them outside an extern segment (left alone: only imports in an extern segment are typed)
Not applied: 4 'void f(void)' prototypes of known assembly functions such as memcpy (BTF records them without parameters) and 0 where IDA's type lists parameters; left as IDA has them
```

For the no-BTF case: `objcopy --remove-section .BTF nf_tables.ko nf_tables_nobtf.ko`, then the same command on `nf_tables_nobtf.ko` gives "Prototypes applied to 0 functions", the line "This kernel module has no BTF of its own ..." and the same 150 imports.

### Out-of-tree modules with a distilled `.BTF.base`

See [Limitations](LIMITATIONS.md#out-of-tree-modules-with-a-distilled-btfbase): the module's own types and prototypes are imported without a vmlinux; the kernel functions it calls are not typed.
