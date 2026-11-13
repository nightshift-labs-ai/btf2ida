# Verification

[README](../README.md) · [Kernels](KERNELS.md) · [Usage](USAGE.md) · [Limitations](LIMITATIONS.md) · [How it works](HOW_IT_WORKS.md)

**btf2ida has not yet been run inside real IDA.** It was built without an IDA installation. The parsing and the generated types are checked against independent ground truth, while the IDA calls are only checked to exist in the official SDK and run against stubs (fake `ida_*` modules). If you try it in IDA and something is off, please open an issue.

All numbers below are from runs on real kernels; the scripts are in `tests/`. The offline checks used x86-64 kernels, apart from the arm64 rows. What is not verified: [Limitations](LIMITATIONS.md#what-is-not-verified).

## Checks

| Check | Result |
|---|---|
| BTF layouts vs an independent DWARF-derived symbol file (`dwarf2json` ISF): the MemLens demo `kernel.elf` (79a64158…, Debian 13 6.12.115) with `debian-6.12.115+deb13.1-amd64.json.xz` from the same demo zip, `python3 tests/check_against_dwarf.py kernel.elf debian-6.12.115+deb13.1-amd64.json.xz` (exit 1 on any mismatch, or for an ISF of another kernel release) | 8,884 structs/unions compared, 0 size mismatches; 54,303 members compared, 0 offset mismatches; 1,364 bitfields (named members of named structs): 0 bit position or width mismatches, and the signedness btf2c gives 1,260 of them (all but `_Bool`) matches DWARF |
| `tests/check_bitfields.py` (`python3 tests/check_bitfields.py kernel.elf`; a module: `python3 tests/check_bitfields.py nf_tables.ko --base vmlinux`; needs gcc): the header's C bitfields, compiled and run with gcc under its own rules and under `-mms-bitfields`; each bitfield is set through the struct and the bytes are compared with the BTF bit offset (4 cases, read back too, so signed fields must read negative), and sizeof and the next member's offset are asserted against the new and the old raw-byte header | MemLens demo `kernel.elf`: 2,222 of 2,239 bitfields as C bitfields (17 raw, in 3 runs); Debian 13 vmlinux `f741142f`: 1,973 of 1,973; WSL2 6.18.33.1: 3,115 of 3,131; Debian 13 `nf_tables.ko --base vmlinux`: 2,015 of 2,018. 0 failures under either rule set, also on arm64 GKI 6.1, Ubuntu 6.8 amd64 and arm64, Ubuntu mainline 7.0, Debian 11 5.10, BTFHub Ubuntu 5.8 and Debian 13 `bridge.ko`. gcc only, not IDA |
| Generated C header compiled with `gcc -fsyntax-only -include stdbool.h`, WSL2 6.18 kernel (`/sys/kernel/btf/vmlinux`) and the carved Debian 13 data | compiles; 65,664 and 50,366 function prototypes, which also compile together with the header (on Debian 13 one, `dmi_callback`, has the same name as a typedef; `--prototypes` writes it as a comment) |
| `tests/check_clang.sh kernel.elf...` (`CLANG=...`, `CLANG_INCLUDE=...`): btf2c's header + prototypes and its `--asserts` file parsed by standalone clang 22.1.4, the front end of IDA 9.5's default type parser, `-fsyntax-only -x c`, targets x86_64 and aarch64 | MemLens demo `kernel.elf` (Debian 13 6.12): 59,761 layout asserts pass, 0 errors; arm64 GKI 6.12 `gki.elf`: 78,637 asserts pass, 0 errors; the toy: 0 errors. C mode only; clang only, not IDA |
| BTF carved from raw memory dumps of a running Debian 13 VM (1 GB, ELF core) | 113,902 types found in a few seconds (1 to 3 s measured) |
| `--asserts`: 59,761 generated `_Static_assert` size and offset checks compiled with gcc against the generated header, the MemLens demo `kernel.elf` (the Debian 13 cloud-amd64 vmlinux `f741142f` gives 56,214) | all pass |
| Split BTF of a kernel module (`nf_tables.ko`, Debian 13) with `--base vmlinux` | header generated and compiles |
| The same module with the wrong base (the WSL 6.18 kernel's BTF) | refused with a clear error: 2,451 of 2,601 base string references land mid-string on WSL 6.18.33.1 (2,419 on an earlier WSL 6.18 build: the count depends on the exact kernel); with its own Debian 13 base, 0 of 1,090 |
| Public x86-64 Android GKI kernel 6.1.84 (`kernel-6.1` + its `System.map`) | 134,947 BTF types; 58,909 of 61,982 named kernel functions (95.0%) have a BTF prototype to apply (names from `System.map`, which the plugin does not read: in IDA the kernel needs its symbols, for example via vmlinux-to-elf) |
| Public arm64 Android GKI kernels 6.1, 6.6 and 6.12 (raw `Image`, symbols restored by vmlinux-to-elf 1.4.0), `python3 tests/coverage.py gki.elf` | 55,349 of 56,129 function symbols with a BTF prototype (98.6%), 59,762 of 61,065 (97.9%), 61,658 of 65,817 (93.7%); 6.1 on the fake IDA database: 55,348 applied ([below](#getting-function-names-vmlinux-to-elf-and-__ksymtab)) |
| Ubuntu mainline 7.0 stripped vmlinux, symbols restored by vmlinux-to-elf 1.4.0: `tests/coverage.py`, `tests/check_module.py` (fake IDA database) and `tests/check_ksymtab.py` | 68,830 of 95,537 function symbols with a prototype (72.0%); 68,698 applied on the fake database; vmlinux-to-elf names agree with `__ksymtab` on 14,690 of 14,690 exported code addresses, of which 13,840 have a prototype (the most the `__ksymtab` path alone can give) |
| `tests/check_ksymtab.py`: names from `__ksymtab` of a stripped (`objcopy -S`) vmlinux vs the debug vmlinux's symbol table | Debian 13 6.12: 10,497 of 10,497 exported code addresses match, 10,333 have a BTF prototype; Ubuntu 26.04 7.0: 14,717 of 14,717 (writable code-flagged sections excluded), 13,865 |
| `tests/test_ksymtab.py`: synthetic ELFs, no kernel needed | all four `__ksymtab` entry layouts (place-relative 12 and 8 bytes, absolute 16 and 24) give the right names; GPL table read; code, data and writable code told apart; relocatable files, missing strings and non-ELF input refused |
| `tests/check_ida_api.py` against HexRaysSA/ida-sdk IDAPython sources | 87 IDA API names used (module functions, constants and the methods btf2ida calls), 0 missing |
| `tests/check_ida_names.py` against the IDAPython stubs of IDA 9.1, 9.2, 9.3, 9.4 (PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11) and 9.5 (`idapro` 0.0.12) | 64 `ida_*` / `idc` module-level names used, 0 missing in each |
| A compressed kernel chosen as the vmlinux (`tests/check_module.py`) | Debian 11 `nf_tables.ko` (5.10.0-32, no BTF of its own) with its xz `vmlinuz`: 95 imports typed, the same output as with the extracted vmlinux. Debian 13 zstd `vmlinuz`: refused with "install zstd". Ubuntu 24.04 arm64 6.8 `vmlinuz` (gzip `Image`): unpacked, BTF and release banner found |
| arm64: Debian 13 `nf_tables.ko` (6.12.115+deb13.1-cloud-arm64) with that package's `vmlinuz` (an uncompressed `Image`) as the vmlinux, `tests/check_module.py` | 487 module functions and 137 imports typed; "Not applied: 2" (`memmove` and `strchr`, assembly on arm64) |
| A BTFHub archive as input (for a kernel built without BTF, btf2ida asks for one; headless `--vmlinux`): Ubuntu 20.04 `5.8.0-63-generic.btf.tar.xz` (`btf2c.py`) | 49,744 prototypes (+1 written as a comment); header and prototypes compile with gcc |
| `tests/test_unpack.py`: synthetic bzImages, EFI zboot images and BTF tar archives | gzip, xz, lzma and bzip2 payloads unpacked; zstd, lz4 and lzo refused with what to install; corrupt, truncated and unknown payloads refused |
| `tests/check_toy_members.py`: the toy's `demo/expected_members.txt` regenerated from `objdump -d` and btf2c's layout, and the README's quotes of `demo/toy_kernel.c` | file and quotes match (exit 1 on drift) |
| `tests/test_plugin_stub.py` with fake `ida_*` modules | full flow passes |

## Getting function names: vmlinux-to-elf and `__ksymtab`

How the numbers in [Kernels](KERNELS.md) were measured (2026-11-13; vmlinux-to-elf 1.4.0 from PyPI, Python 3.12, each command alone on an 8 GB machine).

Kernels:

- GKI arm64 kernels from the three zips linked in [Kernels](KERNELS.md#android-gki-and-other-raw-images), `Image` cut out of each `boot.img` with the one-liner given there. Banners: `6.1.57-android14-11-gfc4b04d84027-ab11318753`, `6.6.58-android15-8-g217cec2d0381-ab12874290-4k`, `6.12.23-android16-5-g2d954fcf3d1b-ab13586339-4k`. SHA-256 of the `Image` files: 421d6d03…, 8520bd55…, 62c2f0a6….
- Ubuntu mainline 7.0 (`7.0.0-070000-generic`, the mainline-PPA build): its stripped `vmlinux` (an ELF without a symbol table), SHA-256 dd678585….

vmlinux-to-elf:

```
$ vmlinux-to-elf Image gki.elf                  # GKI 6.1: 21 s, 0.65 GB peak memory
$ vmlinux-to-elf vmlinux ubuntu70.elf           # Ubuntu mainline 7.0: 105 s, 1.5 GB peak memory
```

A second run gave byte-identical output for both (`cmp`). Output SHA-256: GKI 6.1 c4e833c0…, 6.6 89ef8689…, 6.12 9d80f8d6…, Ubuntu 7.0 4f2d7a75….

Coverage (`python3 tests/coverage.py <elf>`; about 1.5 s each on GKI, 6 s on Ubuntu 7.0):

```
GKI 6.1    prototypes in the BTF: 55349   function symbols with a prototype: 55349 of 56129 (98.6%)
GKI 6.6    prototypes in the BTF: 59762   function symbols with a prototype: 59762 of 61065 (97.9%)
GKI 6.12   prototypes in the BTF: 61658   function symbols with a prototype: 61658 of 65817 (93.7%)
Ubuntu 7.0 prototypes in the BTF: 70032   function symbols with a prototype: 68830 of 95537 (72.0%)
```

The plugin's own import on a fake IDA database built from the ELF's symbol table (`python3 tests/check_module.py <elf> <elf>`), summary lines:

```
GKI 6.1:
Prototypes applied to 55348 functions; rejected by IDA 0; not in this database 0; name is not a function start 0
Not applied: 1 'void f(void)' prototypes of known assembly functions such as memcpy (BTF records them without parameters) ...

Ubuntu 7.0:
Prototypes applied to 68698 functions; rejected by IDA 0; not in this database 1202; name is not a function start 0
Left untyped on purpose: 15299 compiler clones (.isra, .constprop, .part, .cold), their ABI may differ
Not applied: 132 'void f(void)' prototypes of known assembly functions such as memcpy (BTF records them without parameters) ...
```

The Ubuntu 7.0 file has 188,129 functions; the script's fake extern segment starts above the last of them (earlier copies of the script overlapped them past 147,392 functions and printed a few stray `import typed: ... ?(...)` lines; the counts above are the same either way, `tests/check_module_layout.py` checks the layout).

vmlinux-to-elf's names against the kernel's own `__ksymtab` (`python3 tests/check_ksymtab.py vmlinux ubuntu70.elf`; the stripped vmlinux first, the vmlinux-to-elf output in place of a debug vmlinux):

```
exported symbols 15551, in code 14690
code exports with the same (address, name) in the debug symtab: 14690 of 14690
code exports with a BTF prototype: 13840
```
