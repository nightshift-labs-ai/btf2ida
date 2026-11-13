# How it works

[README](../README.md) · [Kernels](KERNELS.md) · [Usage](USAGE.md) · [Limitations](LIMITATIONS.md) · [Verification](VERIFICATION.md)

## The pieces

- `btf.py` reads the BTF container (own or split base + module) with no dependencies. It also finds BTF where there is no `.BTF` section: carved out of a memory image by its header, inside a BTFHub archive, or in a compressed kernel it unpacks.
- `btf2c.py` turns it into ordered C declarations IDA's parser accepts: dependency-sorted, with forward declarations, renamed reserved words, explicit padding so offsets match exactly under `#pragma pack(1)`, and bitfields as C bitfields that fill integers of 1, 2, 4 or 8 bytes (or raw bytes).
- `ksymtab.py` names a stripped kernel's exported functions from its own `__ksymtab`.
- `btf2ida_entry.py` is the thin IDA layer: it sends the declarations to IDA, applies the prototypes by name, reads the bitfield layout back from IDA and writes the summary. `tools/btf2ida_headless.py` runs the same code with idalib.

It adds nothing to your binary and needs nothing installed besides the plugin.

## Compared with bpftool and Parse C header file

`bpftool btf dump file <vmlinux> format c` (bpftool 7.8.1) also writes kernel types as C, and IDA can parse a C header. What that route does not do, measured on the same inputs as the [Verification](VERIFICATION.md) table:

- **No `.BTF` section, no BTF.** On the Debian 13 memory export it stops with `libbpf: failed to find '.BTF' ELF section ... No data available`. btf2ida carves the BTF out of the image instead (50,366 prototypes from the same file).
- **Types only, no function prototypes.** On the WSL2 kernel bpftool's header has 172,354 lines but declares none of the 65,664 functions in the BTF (`vfs_read` and `tcp_sendmsg` do not appear; functions only show up as function-pointer typedefs). btf2ida applies the prototypes to the functions by name.
- **Written for clang, not IDA.** The header opens with `#pragma clang attribute push (__attribute__((preserve_access_index)), ...)` and has 305 lines with `__attribute__`. btf2c writes plain declarations with explicit padding under `#pragma pack(1)`. We have not checked how IDA's parser treats bpftool's header.

bpftool remains the right tool for CO-RE BPF programs; btf2ida is for getting the same data into an IDA database.
