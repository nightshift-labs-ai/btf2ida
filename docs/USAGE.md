# Usage

[README](../README.md) · [Kernels](KERNELS.md) · [Limitations](LIMITATIONS.md) · [Verification](VERIFICATION.md) · [How it works](HOW_IT_WORKS.md)

## The menu actions

Open a kernel or kernel module in IDA, then **Edit > Plugins > BTF2IDA: Apply kernel types and prototypes**.

- If IDA is still analysing the file (and auto-analysis is not turned off), btf2ida first asks whether to wait for the analysis to finish (functions IDA has not created yet would get no prototype).
- For a kernel module it asks for the matching `vmlinux` (see [Kernels](KERNELS.md#kernel-modules)); for a whole kernel without BTF, for a BTF file of the same build ([Kernels](KERNELS.md#a-kernel-built-without-btf)).
- A summary says how many types IDA accepted and how many prototypes were applied. It starts with a headline, after a CANCELLED or analysis warning if any (`BTF2IDA: 13016 types sent to IDA; 46817 functions typed with their kernel prototype` on the MemLens demo kernel, measured with `tests/check_summary.py` on a fake database; for a module the count includes the kernel functions it calls, typed in its extern segment, and says how many; a 32-bit x86 database says "no prototypes") and a "Look at:" line: the module's or kernel's own functions only, the first of `demo_open`, `tcp_sendmsg`, `do_sys_openat2`, `vfs_read`, `vfs_write`, `commit_creds` that got a prototype, else, among the typed functions whose prototype is at most 160 characters (so the line shows it uncut; a longer one only if none is that short), the one with the most struct pointer parameters (its own parameters only, not those of a callback type; on a tie the shorter declaration, then the lower address), with its address and new prototype. On Debian 13 `nf_tables.ko` that is `nft_data_init`.

**Edit > Plugins > BTF2IDA: Apply kernel types and prototypes (bitfields as raw bytes)** runs the same import but keeps every bitfield as raw storage bytes with its name in a comment, the form before C bitfields, for a database where IDA lays out the C bitfields differently from the BTF. A struct that still has C bitfields from an earlier import is then declared again with raw bytes (see [Bitfields checked with gcc only](LIMITATIONS.md#bitfields-checked-with-gcc-only)).

Functions the compiler rewrote (`.isra`, `.constprop`, `.part`, `.cold`) are left untyped on purpose: their calling convention may differ from the source signature.

Running btf2ida again on the same database replaces the prototypes it set itself and keeps the ones set by hand (see the [CHANGELOG](../CHANGELOG.md), v0.1.21).

## Headless, with idalib

IDA 9.1 or newer; set up the `idapro` module as Hex-Rays describes:

```
python3 tools/btf2ida_headless.py vmlinux
python3 tools/btf2ida_headless.py nf_tables.ko --vmlinux vmlinux
```

It opens the file as a database, runs the same import as the menu action, prints the same summary and saves the database. A module's split BTF needs `--vmlinux` (the menu action asks for it instead). `--no-bitfields` keeps every bitfield as raw storage bytes with its name in a comment instead of C bitfields. `--no-analysis` skips IDA's auto-analysis (faster; fewer functions exist to receive prototypes). `--force` uses a vmlinux of another release for a module without BTF of its own ([Kernels](KERNELS.md#a-module-with-no-btf-of-its-own)). It calls the plugin's own code; like the rest of the IDA layer it has only been run against fake modules (`tests/test_plugin_stub.py`), not a real idalib.

## Without IDA: a C header

As a generator of a C header for the same types:

```
python3 btf2c.py /sys/kernel/btf/vmlinux vmlinux_types.h
python3 btf2c.py kernel.elf types.h --prototypes protos.txt
python3 btf2c.py nf_tables.ko types.h --base vmlinux
```

`--prototypes` writes the function prototypes, `--base` gives a module's vmlinux, `--asserts` writes `_Static_assert` size and offset checks, and `--no-bitfields` writes every bitfield as raw storage bytes with its name in a comment, the form before C bitfields. `python3 btf2c.py <file> /dev/null` only prints the type counts, or `btf2c: no BTF found`.
