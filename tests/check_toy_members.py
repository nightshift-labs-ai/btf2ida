#!/usr/bin/env python3
"""Which struct member each memory access in the toy's code touches, from objdump and btf2c's layout.

    python3 tests/check_toy_members.py            # compare with demo/expected_members.txt (exit 1 on drift)
    python3 tests/check_toy_members.py --write    # write it again (demo/build.sh does this after a rebuild)

Disassembles demo/toy_kernel.elf with `objdump -d -M intel` (binutils), gives each demo_* function's pointer
arguments the types of the prototype btf2ida applies (System V order: rdi, rsi, ...), and names the member at every
[reg+offset] operand from the toy's BTF, walked the way btf2c writes demo/expected_types.h (renamed members such as
`private_`, which bitfields are C bitfields, which members are only a comment). This is where the decompiler should
show member names instead of raw offsets after the import. It is derived offline; it is not IDA output.

It also checks that the C lines the README quotes after a `demo/toy_kernel.c:A-B` reference are lines A to B of
demo/toy_kernel.c. Exit 0: all match; 1: drift (the differences are printed); 2: objdump or a file is missing.
"""
import difflib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import btf as B  # noqa: E402
import btf2c  # noqa: E402

DEMO = os.path.join(ROOT, "demo")
ELF = os.path.join(DEMO, "toy_kernel.elf")
SOURCE = os.path.join(DEMO, "toy_kernel.c")
EXPECTED = os.path.join(DEMO, "expected_members.txt")
README = os.path.join(ROOT, "README.md")

ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
CLOBBERED = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
WIDTHS = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8}
NO_DEST = ("cmp", "test", "call", "jmp", "ret", "push", "endbr64", "nop")


def family(reg):
    """'esi' -> 'rsi', 'sil' -> 'rsi', 'r8d' -> 'r8'; None for anything that is not a general register."""
    reg = reg.strip()
    match = re.fullmatch(r"(r\d+)[dwb]?", reg)
    if match:
        return match.group(1)
    for full, names in (("rax", "eax ax al ah"), ("rbx", "ebx bx bl bh"), ("rcx", "ecx cx cl ch"),
                        ("rdx", "edx dx dl dh"), ("rsi", "esi si sil"), ("rdi", "edi di dil"),
                        ("rbp", "ebp bp bpl"), ("rsp", "esp sp spl")):
        if reg == full or reg in names.split():
            return full
    return None


class Layout:
    """Members of the toy's structs as btf2c writes them: flattened inline members, bit offsets, renamed names."""

    def __init__(self, blob, base=None):
        self.gen = btf2c.Generator(B.load(blob, base=base))  # base: the vmlinux BTF of a module (check_kit_members)
        self.gen.declarations()  # fills tags and bitfield_layout, as for the header
        self.structs = {t.id: t for t in self.gen.btf if t.kind in (B.STRUCT, B.UNION) and t.name}

    def members(self, t, base_bit=0, prefix=""):
        """[(path, bit offset, width in bits, is a bitfield, size in bytes, BTF type id)]."""
        out = []
        for name, m_type, offset in t.data:
            bit, width = self.gen.member_bits(t, offset, m_type)
            bit += base_bit
            inner = self.gen.strip(m_type)
            if not width and inner is not None and inner.kind in (B.STRUCT, B.UNION) and not inner.name:
                label = btf2c.ident(name) if name else ""
                out.extend(self.members(inner, bit, prefix + (label + "." if label else "")))
                continue
            size = self.gen.size_of(m_type)
            out.append((prefix + btf2c.ident(name), bit, width or 8 * size, bool(width), size, m_type))
        return out

    def c_bitfields(self, t):
        """Names written as C bitfields in the header (the others in a bitfield run are raw bytes)."""
        entry = self.gen.bitfield_layout.get(self.gen.tags[t.id])
        return {path for path, _, _ in entry[1]} if entry else set()

    def pointee(self, type_id):
        """The named struct a pointer type points to, or None."""
        t = self.gen.resolve(type_id)
        if t is None or t.kind != B.PTR:
            return None
        target = self.gen.resolve(t.ref)
        return target if target is not None and target.id in self.structs else None

    def prototype(self, name):
        for t in self.gen.btf:
            if t.kind == B.FUNC and t.name == name:
                return self.gen.btf[t.ref]
        return None


def disassemble(path):
    """{function: [(address, mnemonic, operands)]} for the demo_* functions."""
    text = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path], check=True,
                          stdout=subprocess.PIPE, universal_newlines=True).stdout
    out, current = {}, None
    for line in text.splitlines():
        head = re.match(r"^[0-9a-f]+ <(\w+)>:$", line)
        if head:
            current = head.group(1) if head.group(1).startswith("demo_") else None
            if current:
                out[current] = []
            continue
        body = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if current and body:
            out[current].append((int(body.group(1), 16), body.group(2), body.group(3).split("#")[0].strip()))
    return out


def split_operands(text):
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        depth += ch == "["
        depth -= ch == "]"
        if ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    if text.strip():
        parts.append(text[start:].strip())
    return parts


MEMORY = re.compile(r"^(?:(BYTE|WORD|DWORD|QWORD) PTR )?\[(\w+)(?:\+(\w+)\*(\d))?(?:([+-])0x([0-9a-f]+))?\]$")


def member_text(members, bitfields, lo, size):
    """The members overlapping bytes lo..lo+size (size 0: the member at lo)."""
    hit = []
    for path, bit, width, is_bf, msize, _ in members:
        start, end = bit // 8, (bit + width + 7) // 8
        if (size and start < lo + size and end > lo) or (not size and start <= lo < max(end, start + 1)):
            if is_bf:
                first = bit - 8 * lo
                bits = "bit %d" % first if width == 1 else "bits %d-%d" % (first, first + width - 1)
                hit.append("%s (%s%s)" % (path, bits, "" if path in bitfields else ", raw bytes"))
            elif msize == 0:
                hit.append("%s (no size: a comment in the header)" % path)
            else:
                hit.append(path)
    return hit


def annotate(layout, function, code):
    """[(address, instruction, what it touches)] for one function."""
    proto = layout.prototype(function)
    regs = {}  # register family -> ("struct", BTF struct, C expression) or ("into", C expression of an array)
    for reg, (pname, ptype) in zip(ARG_REGS, proto.data if proto is not None else []):
        target = layout.pointee(ptype)
        if target is not None:
            regs[reg] = ("struct", target, pname)
    loaded = {}  # register family -> index into `out` of the load of a bitfield unit, its byte offset, width, members
    out = []
    for address, mnemonic, operands in code:
        ops = split_operands(operands)
        text = "%s %s" % (mnemonic, operands) if operands else mnemonic
        notes = []
        new_state = None
        for op in ops:
            mem = MEMORY.match(op)
            if not mem or family(mem.group(2)) not in regs:
                continue
            kind = regs[family(mem.group(2))]
            disp = int(mem.group(6), 16) * (-1 if mem.group(5) == "-" else 1) if mem.group(6) else 0
            width = WIDTHS.get(mem.group(1), 0)
            if kind[0] == "into":
                notes.append("%s[...] (through a pointer into it, raw bytes)" % kind[1])
                continue
            struct, expr = kind[1], kind[2]
            members = layout.members(struct)
            names = member_text(members, layout.c_bitfields(struct), disp, 0 if mnemonic == "lea" else width)
            arrow = "%s->" % expr
            if mnemonic == "lea":
                target = [m for m in members if m[1] // 8 == disp and m[4] == 0]
                if target:
                    new_state = ("into", arrow + target[0][0])
                notes.append("&" + ", &".join(arrow + n for n in names) + (" + index" if mem.group(3) else ""))
                continue
            notes.append(", ".join(arrow + n for n in names))
            whole = [m for m in members if m[1] == 8 * disp and m[2] == 8 * width and not m[3]]
            if mnemonic == "mov" and whole and op == ops[-1]:
                target = layout.pointee(whole[0][5])
                if target is not None:
                    new_state = ("struct", target, arrow + whole[0][0])
            bits = [m for m in members if m[3] and m[1] // 8 < disp + width and (m[1] + m[2] + 7) // 8 > disp]
            if bits and op == ops[-1] and mnemonic.startswith(("mov", "movzx")):
                loaded[family(ops[0])] = (len(out), disp, width, bits)
            if bits and op == ops[0] and len(ops) == 2 and family(ops[1]) in loaded:
                written = loaded[family(ops[1])][3]
                if len(written) == 1:  # a single bitfield cleared by an `and` mask before this store
                    notes[-1] = "%s%s (the field the mask cleared)" % (arrow, written[0][0])
        dest = family(ops[0]) if ops and mnemonic not in NO_DEST and not MEMORY.match(ops[0]) and not mnemonic.startswith("j") else None
        if mnemonic == "call":
            for reg in CLOBBERED:
                regs.pop(reg, None)
                loaded.pop(reg, None)
        elif dest is not None:
            src = family(ops[1]) if len(ops) == 2 else None
            immediate = re.fullmatch(r"0x([0-9a-f]+)", ops[1]) if len(ops) == 2 else None
            if mnemonic in ("and", "shr") and immediate and dest in loaded:
                at, disp, width, bits = loaded[dest]
                value = int(immediate.group(1), 16)
                if mnemonic == "and":
                    cleared = ~value & ((1 << 8 * width) - 1)
                    hit = [m for m in bits if all(cleared >> (b - 8 * disp) & 1 for b in range(m[1], m[1] + m[2]) if b - 8 * disp < 8 * width)
                           and m[1] - 8 * disp < 8 * width]
                    out[at][2].append("then `and %s` clears %s" % (ops[1], ", ".join(m[0] for m in hit) or "no whole bitfield"))
                    loaded[dest] = (at, disp, width, hit)
                else:
                    hit = [m for m in bits if m[1] - 8 * disp == value]
                    out[at][2].append("then `shr %s` reads %s" % (ops[1], ", ".join(m[0] for m in hit) or "no bitfield start"))
                    loaded.pop(dest, None)
            elif mnemonic == "or" and dest in loaded:
                pass  # merging the new value into the cleared bits keeps the unit
            elif mnemonic == "mov" and src is not None and src in loaded and dest not in loaded:
                loaded[dest] = loaded[src]
                if src in regs:
                    regs[dest] = regs[src]
            elif new_state is None and (dest not in loaded or loaded[dest][0] != len(out)):
                loaded.pop(dest, None)
            if mnemonic in ("add", "sub") and immediate and dest in regs and regs[dest][0] == "into":
                pass  # stepping through the array
            elif new_state is not None:
                regs[dest] = new_state
            elif mnemonic == "mov" and src is not None and src in regs:
                regs[dest] = regs[src]
            else:
                regs.pop(dest, None)
        if notes:
            out.append((address, text, notes))
    return out


def render(elf_path):
    with open(elf_path, "rb") as handle:
        layout = Layout(handle.read())
    lines = [
        "# Which struct member each memory access of the toy's demo_* functions touches, in btf2ida's layout.",
        "# Written by tests/check_toy_members.py from `objdump -d -M intel` of demo/toy_kernel.elf and the toy's BTF;",
        "# derived offline, not IDA output. After the import the decompiler should show these names instead of offsets.",
        "# Bit numbers count from the accessed address. The flexible array `payload` is only a comment in the header,",
        "# so its loop in demo_checksum stays a raw offset.",
        "#",
        "# function  address  instruction  ->  member",
    ]
    for function, code in disassemble(elf_path).items():
        for address, text, notes in annotate(layout, function, code):
            lines.append("%-14s %#x  %-36s ->  %s" % (function, address, text, "; ".join(notes)))
    return "\n".join(lines) + "\n"


def readme_quotes():
    """Differences between the README's quoted toy source lines and demo/toy_kernel.c."""
    with open(SOURCE) as handle:
        source = handle.read().splitlines()
    problems, found = [], 0
    docs = os.path.join(ROOT, "docs")
    paths = [README] + (sorted(os.path.join(docs, n) for n in os.listdir(docs) if n.endswith(".md"))
                        if os.path.isdir(docs) else [])
    for path in paths:
        with open(path) as handle:
            lines = handle.read().splitlines()
        for i, line in enumerate(lines):
            for first, last in re.findall(r"demo/toy_kernel\.c:(\d+)-(\d+)", line):
                fence = next((j for j in range(i + 1, min(i + 4, len(lines))) if lines[j].lstrip().startswith("```")), None)
                if fence is None:
                    continue
                end = next(j for j in range(fence + 1, len(lines)) if lines[j].lstrip().startswith("```"))
                quoted = [q.strip() for q in lines[fence + 1:end]]
                wanted = [s.strip() for s in source[int(first) - 1:int(last)]]
                found += 1
                if quoted != wanted:
                    problems.append("%s:%d quotes toy_kernel.c:%s-%s as %r, the file has %r"
                                    % (os.path.relpath(path, ROOT), i + 1, first, last, quoted, wanted))
    return problems, found


def main(argv):
    if shutil.which("objdump") is None:
        print("check_toy_members: objdump (binutils) is needed", file=sys.stderr)
        return 2
    if not os.path.isfile(ELF):
        print("check_toy_members: %s is missing" % ELF, file=sys.stderr)
        return 2
    text = render(ELF)
    if "--write" in argv:
        with open(EXPECTED, "w") as handle:
            handle.write(text)
        print("wrote %s" % os.path.relpath(EXPECTED, ROOT))
        return 0
    status = 0
    if not os.path.isfile(EXPECTED):
        print("check_toy_members: %s is missing (run with --write)" % EXPECTED, file=sys.stderr)
        return 2
    with open(EXPECTED) as handle:
        old = handle.read()
    if old != text:
        sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                                   "demo/expected_members.txt", "regenerated"))
        status = 1
    problems, found = readme_quotes()
    for problem in problems:
        print(problem)
    if problems or not found:
        print("README quotes of demo/toy_kernel.c: %d checked, %d differ" % (found, len(problems)))
        status = 1
    if status == 0:
        print("demo/expected_members.txt matches the toy; %d README quote(s) of demo/toy_kernel.c match" % found)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
