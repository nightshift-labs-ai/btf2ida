#!/usr/bin/env python3
"""Which struct member each access of nft_data_init in the try-module kit touches, from objdump and the module's BTF.

    python3 tests/check_kit_members.py nf_tables.ko vmlinux.btf           # compare with docs/kit_members.txt
    python3 tests/check_kit_members.py nf_tables.ko vmlinux.btf --write   # write it again
    python3 tests/check_kit_members.py                                    # only the self-test and the README's quotes

The two files are those of the try-module kit (btf2ida-try-module.zip, README "A real module in two minutes"). This is
tests/check_toy_members.py on real kernel code: nft_data_init, the function the summary's "Look at:" line names on the
kit (README step 3). Its pointer arguments get the types of the prototype btf2ida applies, from the module's split BTF
on top of vmlinux.btf (System V order: rdi, rsi, rdx, rcx), and each [reg+offset] operand whose base register holds
one of them is named with the member at that offset, in the layout btf2c writes for IDA (btf2c's member names, the
members of named and anonymous inner structs and unions, array elements, bitfields; an access that overlaps several
members, as in a union, names them all).

A register holds an argument at the function's entry, after a full 64-bit `mov` from a register that holds it, and
after a QWORD load of a member that is a pointer to a struct (then it holds that, for example `ctx->net`). It stops
being tracked once it is overwritten: by an instruction that writes it (any part of it, or implicitly for the
instructions in IMPLICIT, such as rdx by `div`) or by a call, which clobbers rax, rcx, rdx, rsi, rdi and r8 to r11.
Stack slots are not tracked. The scan follows the function's jumps (and `loop`): a register counts at an instruction
only if every path from the entry leaves it holding the same value, so a block reached from several places is not
judged by the code just above it.

Relocations matter in a .ko: it is not linked, so `objdump -d` alone shows the call to `__fentry__` at the start and
the return through `__x86_return_thunk` as a call and a jump to the next instruction. The scan reads `objdump -d -r`
(the relocations), keeps the argument registers across the `__fentry__` call (ftrace's entry hook, a NOP until
tracing is on, preserves them; without the relocations that call would end the tracking of every argument before the
first access, and no access would be named) and treats a relocated jump as leaving the function (a return or a tail
call), not as a jump to the next instruction. An access in an instruction that has a relocation is not named (its
displacement may be the relocated part); string instructions (rep movs, rep stos) are not named either. `ud2` falls
through to the next instruction (the kernel's WARN_ON is a `ud2` that returns).

A self-test runs these rules on hand-built code with the toy's demo_open (SELF_TEST), with or without the kit: on
nft_data_init some of them (the joins, the calls, ud2, negative displacements) cannot change the output.

The result is where the decompiler should show member names instead of offsets from the arguments after the import.
It is derived offline; it is not IDA output. It also checks that each line the README quotes in the code block after
a link to docs/kit_members.txt is a line of that file (whitespace aside), and the counts of the README's linking line
("3 of the 19 lines") and of docs/VERIFICATION.md ("19 lines named"). Exit 0: all match; 1: drift (the
differences are printed); 2: objdump or a file is missing, or a file is not the kit's (no BTF, another kernel's BTF,
no nft_data_init). With --write the file is written, then the README's quotes and the counts are checked against it.
"""
import difflib
import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import btf as B  # noqa: E402
import btf2c  # noqa: E402
import check_toy_members as toy  # noqa: E402  (its Layout: btf2c's members, as for the toy)

FUNCTION = "nft_data_init"
EXPECTED = os.path.join(ROOT, "docs", "kit_members.txt")
README = os.path.join(ROOT, "README.md")
VERIFICATION = os.path.join(ROOT, "docs", "VERIFICATION.md")
USAGE = "usage: python3 tests/check_kit_members.py [nf_tables.ko vmlinux.btf [--write]]"

REG64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"} | {"r%d" % n for n in range(8, 16)}
PREFIXES = ("lock", "rep", "repz", "repe", "repnz", "repne", "notrack", "bnd", "data16", "cs", "ds")
NO_DEST = ("cmp", "test", "bt", "call", "jmp", "ret", "push", "endbr64", "nop", "ud2", "int3", "hlt")
STRING_OPS = ("movs", "stos", "lods", "scas", "cmps")  # objdump writes their operands as es:[rdi] and ds:[rsi]
IMPLICIT = {"mul": ("rax", "rdx"), "div": ("rax", "rdx"), "idiv": ("rax", "rdx"), "cqo": ("rdx",), "cdq": ("rdx",),
            "cwd": ("rdx",), "cdqe": ("rax",), "cwde": ("rax",), "cbw": ("rax",), "cmpxchg": ("rax",),
            "cpuid": ("rax", "rbx", "rcx", "rdx"), "rdtsc": ("rax", "rdx"), "rdmsr": ("rax", "rdx"),
            "syscall": ("rax", "rcx", "r11"), "leave": ("rbp",), "rdtscp": ("rax", "rdx", "rcx"),
            "rdpmc": ("rax", "rdx"), "xgetbv": ("rax", "rdx"), "cmpxchg8b": ("rax", "rdx"),
            "cmpxchg16b": ("rax", "rdx"), "lahf": ("rax",), "xlat": ("rax",), "xlatb": ("rax",), "loop": ("rcx",),
            "loope": ("rcx",), "loopne": ("rcx",)}
WIDTHS = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8, "TBYTE": 10, "XMMWORD": 16, "YMMWORD": 32, "ZMMWORD": 64}
MEMORY = re.compile(r"^(?:(\w+) PTR )?(?:[a-z]s:)?\[(\w+)(?:\+(\w+)\*(\d+))?(?:([+-])0x([0-9a-f]+))?\]$")


def disassemble(path, function):
    """(section, start, [(address, mnemonic, [operands], [(relocation type, symbol)])]) of one function, from
    `objdump -d -r`; addresses as objdump gives them in a .ko: from the start of the section."""
    text = subprocess.run(["objdump", "-d", "-r", "-M", "intel", "--no-show-raw-insn", path], check=True,
                          stdout=subprocess.PIPE, universal_newlines=True).stdout
    code, inside, section, found = [], False, None, (None, None)
    for line in text.splitlines():
        part = re.match(r"^Disassembly of section (\S+):$", line)
        head = re.match(r"^([0-9a-f]+) <([\w.]+)>:$", line)
        if part or head:
            section = part.group(1) if part else section
            inside = bool(head) and head.group(2) == function
            found = (section, int(head.group(1), 16)) if inside else found
            continue
        if not inside:
            continue
        reloc = re.match(r"^\s+[0-9a-f]+: (R_\w+)\s+(\S+)$", line)
        if reloc and code:
            code[-1][3].append((reloc.group(1), reloc.group(2)))
            continue
        body = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if body:
            mnemonic, operands = body.group(2), body.group(3).split("#")[0].strip()
            while mnemonic in PREFIXES and operands:  # `rep stos ...`, `lock cmpxchg ...`: the instruction itself
                mnemonic, _, operands = operands.partition(" ")
                operands = operands.strip()
            code.append((int(body.group(1), 16), mnemonic, toy.split_operands(operands), []))
    return found + (code,)


def successors(code, where, index):
    """Indexes of the instructions that can run after code[index] inside the function (where: address -> index).
    `ud2` falls through: the kernel's WARN_ON is a `ud2` that returns."""
    address, mnemonic, ops, relocs = code[index]
    if mnemonic.startswith("ret") or mnemonic in ("int3", "hlt"):
        return []
    branch = mnemonic.startswith(("j", "loop"))
    target = re.fullmatch(r"([0-9a-f]+) <[^>]*>", ops[0]) if branch and ops else None
    jump = []
    if target is not None and not relocs and int(target.group(1), 16) in where:
        jump = [where[int(target.group(1), 16)]]
    if mnemonic == "jmp":  # relocated (a return thunk, a tail call), indirect or out of the function: it leaves
        return jump
    following = [index + 1] if index + 1 < len(code) else []
    return jump + following if branch else following


class Kit:
    """btf2c's layout (a check_toy_members.Layout) and the member text of an access."""

    def __init__(self, layout):
        self.layout = layout
        self.gen = layout.gen

    @classmethod
    def load(cls, module_path, vmlinux_path):
        """The module's split BTF on vmlinux.btf."""
        with open(vmlinux_path, "rb") as handle:
            base = B.load_base(B.unpack_kernel_image(handle.read(), vmlinux_path), vmlinux_path)
        with open(module_path, "rb") as handle:
            return cls(toy.Layout(handle.read(), base=base))

    def members(self, struct, lo, size, prefix=""):
        """Paths of the members of `struct` that bytes lo..lo+size touch (size 0, a `lea`: the member at lo)."""
        hit = []
        bitfields = self.layout.c_bitfields(struct)
        for path, bit, width, is_bf, msize, m_type in self.layout.members(struct):
            start, end = bit // 8, (bit + width + 7) // 8
            overlaps = start < lo + size and end > lo if size else start <= lo < max(end, start + 1)
            if not overlaps:
                continue
            name = prefix + path
            if is_bf:
                first = bit - 8 * lo
                bits = "bit %d" % first if width == 1 else "bits %d-%d" % (first, first + width - 1)
                hit.append("%s (%s%s)" % (name, bits, "" if path in bitfields else ", raw bytes"))
                continue
            if msize == 0:
                hit.append("%s (no size: a comment in the header)" % name)
                continue
            inner = self.gen.resolve(m_type)
            if inner is not None and inner.kind in (B.STRUCT, B.UNION):
                hit.extend(self.members(inner, max(lo - start, 0), min(lo + size, end) - max(lo, start) if size else 0,
                                        name + "."))
            elif inner is not None and inner.kind == B.ARRAY and self.gen.size_of(inner.data[0]):
                step = self.gen.size_of(inner.data[0])
                first = (max(lo, start) - start) // step
                last = (min(lo + size, end) - 1 - start) // step if size else first
                element = self.gen.resolve(inner.data[0])
                if first == last and element is not None and element.kind in (B.STRUCT, B.UNION):
                    at = max(lo, start) - start - first * step
                    clipped = min(lo + size, end) - max(lo, start) if size else 0
                    hit.extend(self.members(element, at, clipped, "%s[%d]." % (name, first)))
                else:
                    hit.append("%s[%s]" % (name, first if first == last else "%d..%d" % (first, last)))
            elif size and (lo > start or lo + size < end):
                part = max(lo, start) - start, min(lo + size, end) - 1 - start
                hit.append("%s (byte%s of %d)" % (name, " %d" % part[0] if part[0] == part[1] else "s %d-%d" % part, msize))
            else:
                hit.append(name)
        if not hit and not prefix:
            if size == 0 and lo == struct.size:
                return ["+ 1 (right after the %d-byte struct %s)" % (struct.size, struct.name)]
            if lo < 0 or lo >= struct.size:
                return ["(outside the %d-byte struct %s)" % (struct.size, struct.name)]
            return ["(padding of struct %s)" % struct.name]
        return hit

    def pointer_member(self, struct, disp):
        """(path, struct pointed to) when a whole 8-byte member at disp is a pointer to a named struct."""
        for path, bit, width, is_bf, msize, m_type in self.layout.members(struct):
            if bit == 8 * disp and msize == 8 and not is_bf:
                target = self.layout.pointee(m_type)
                if target is not None:
                    return path, target
        return None


def track(kit, code, arguments):
    """{instruction index: {register: (BTF struct, C expression, offset text)}} that holds on every path."""
    entry = {}
    for reg, (name, type_id) in zip(toy.ARG_REGS, arguments):
        target = kit.layout.pointee(type_id)
        if target is not None:
            entry[reg] = (target, btf2c.ident(name), "arg%d" % (toy.ARG_REGS.index(reg) + 1))
    where = {insn[0]: i for i, insn in enumerate(code)}
    state, work = {0: entry}, [0]
    while work:
        index = work.pop()
        out = step(kit, code[index], state[index])
        for nxt in successors(code, where, index):
            old = state.get(nxt)
            new = dict(out) if old is None else {r: v for r, v in old.items() if out.get(r) == v}
            if old is None or new != old:
                state[nxt] = new
                work.append(nxt)
    return state


def step(kit, insn, before):
    """The registers that hold a tracked value after one instruction."""
    _, mnemonic, ops, relocs = insn
    after = dict(before)
    if mnemonic == "call":
        if not any(symbol.startswith("__fentry__") for _, symbol in relocs):
            for reg in toy.CLOBBERED:
                after.pop(reg, None)
        return after
    written = set(IMPLICIT.get(mnemonic, ()))
    if string_op(mnemonic, ops):
        written |= {"rax", "rcx", "rsi", "rdi"}
    if mnemonic == "imul" and len(ops) == 1:
        written |= {"rax", "rdx"}
    dest = toy.family(ops[0]) if ops and mnemonic not in NO_DEST and not mnemonic.startswith("j") else None
    if dest:
        written.add(dest)
    if mnemonic in ("xchg", "xadd", "mulx") and len(ops) >= 2 and toy.family(ops[1]):  # mulx: two destinations
        written.add(toy.family(ops[1]))
    value = None
    if mnemonic == "mov" and len(ops) == 2 and ops[0] in REG64:
        mem = MEMORY.match(ops[1])
        if ops[1] in REG64:
            value = before.get(ops[1])
        elif mem and mem.group(1) == "QWORD" and not mem.group(3) and not relocs and mem.group(2) in before:
            struct, expr, where = before[mem.group(2)]
            disp = displacement(mem)
            found = kit.pointer_member(struct, disp)
            if found:
                value = (found[1], "%s->%s" % (expr, found[0]), "*(%s%s)" % (where, offset_text(disp)))
    for reg in written:
        after.pop(reg, None)
    if value is not None:
        after[dest] = value
    return after


def string_op(mnemonic, ops):
    return mnemonic in STRING_OPS or any(":[rdi]" in op or ":[rsi]" in op for op in ops)


def displacement(mem):
    return int(mem.group(6), 16) * (-1 if mem.group(5) == "-" else 1) if mem.group(6) else 0


def offset_text(disp):
    return "%s%#x" % ("-" if disp < 0 else "+", abs(disp))


def annotate(kit, code, state):
    """[(address, instruction, offset text, member text)] for the accesses through tracked registers."""
    out = []
    for index, (address, mnemonic, ops, relocs) in enumerate(code):
        regs = state.get(index, {})  # an instruction no known path reaches holds nothing
        for op in ops if mnemonic != "nop" and not string_op(mnemonic, ops) else ():
            mem = MEMORY.match(op)
            if not mem or mem.group(2) not in regs:
                continue
            struct, expr, where = regs[mem.group(2)]
            disp = displacement(mem)
            index_text = " + index" if mem.group(3) else ""
            text = "%s %s" % (mnemonic, ",".join(ops))
            if relocs:
                out.append((address, text, where + "+?", "(the instruction has a relocation: not named)"))
                continue
            size = 0 if mnemonic == "lea" else WIDTHS.get(mem.group(1), 0)
            names = kit.members(struct, disp, size)
            if names[0].startswith(("+", "(")):
                member = "%s %s" % (expr, names[0])
            else:
                member = ", ".join(("&" if mnemonic == "lea" else "") + "%s->%s" % (expr, n) for n in names)
            out.append((address, text, where + offset_text(disp) + index_text, member + index_text))
    return out


# Hand-built code on the toy's demo_open(struct demo_device *dev, unsigned int flags), dev in rdi: what each case
# pins, the code, and the member text expected at its last instruction (None: not named). On nft_data_init some of
# these rules cannot change the output, and without the kit only this runs.
SELF_TEST = [
    ("a join counts a register only if every path leaves it holding the argument",
     [(0x0, "je", ["4 <L>"], []), (0x2, "mov", ["rdi", "0x0"], []), (0x4, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])],
     None),
    ("a call clobbers rdi", [(0x0, "call", ["5 <f>"], []), (0x5, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], None),
    ("the __fentry__ call keeps the arguments",
     [(0x0, "call", ["5 <f>"], [("R_X86_64_PLT32", "__fentry__-0x4")]),
      (0x5, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], "dev->state"),
    ("a relocated jmp leaves the function (it does not join the next instruction)",
     [(0x0, "je", ["9 <L>"], []), (0x2, "mov", ["rdi", "0x0"], []),
      (0x4, "jmp", ["9 <L>"], [("R_X86_64_PLT32", "__x86_return_thunk-0x4")]),
      (0x9, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], "dev->state"),
    ("ud2 falls through", [(0x0, "ud2", [], []), (0x2, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], "dev->state"),
    ("a 32-bit write ends the tracking",
     [(0x0, "mov", ["edi", "0x0"], []), (0x5, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], None),
    ("a negative displacement is outside the struct",
     [(0x0, "mov", ["eax", "DWORD PTR [rdi-0x4]"], [])], "dev (outside the 48-byte struct demo_device)"),
    ("a struct pointer loaded from a member is followed",
     [(0x0, "mov", ["rax", "QWORD PTR [rdi+0x20]"], []), (0x4, "mov", ["rdx", "QWORD PTR [rax+0x8]"], [])],
     "dev->ops->close"),
    ("loop is a branch", [(0x0, "loop", ["3 <L>"], []), (0x2, "ret", [], []),
                          (0x3, "mov", ["eax", "DWORD PTR [rdi+0xc]"], [])], "dev->state"),
]
SELF_TEST += [("%s writes %s" % (mnemonic, reg), [(0x0, "mov", [reg, "rdi"], []), (0x3, mnemonic, ops, []),
                                                  (0x5, "mov", ["eax", "DWORD PTR [%s+0xc]" % reg], [])], None)
              for mnemonic, ops, reg in (("div", ["r9"], "rdx"), ("rdtscp", [], "rcx"), ("lahf", [], "rax"),
                                         ("cmpxchg16b", ["XMMWORD PTR [r9]"], "rdx"), ("loop", ["5 <L>"], "rcx"),
                                         ("xlat", ["BYTE PTR ds:[rbx]"], "rax"), ("mulx", ["r8", "rsi", "r9"], "rsi"))]


def self_test():
    """The SELF_TEST cases that fail, as text."""
    if not os.path.isfile(toy.ELF):
        return ["%s is missing" % toy.ELF]
    with open(toy.ELF, "rb") as handle:
        kit = Kit(toy.Layout(handle.read()))
    arguments = kit.layout.prototype("demo_open").data
    failed = []
    for what, code, expected in SELF_TEST:
        hits = [r for r in annotate(kit, code, track(kit, code, arguments)) if r[0] == code[-1][0]]
        got = hits[0][3] if hits else None
        if got != expected:
            failed.append("self-test, %s: %r, expected %r" % (what, got, expected))
    return failed


class WrongFile(Exception):
    """A file that is not the kit's (main exits 2)."""


def render(module_path, vmlinux_path):
    kit = Kit.load(module_path, vmlinux_path)
    func = next((t for t in kit.gen.btf if t.kind == B.FUNC and t.name == FUNCTION), None)
    if func is None:
        raise WrongFile("no BTF prototype for %s in %s" % (FUNCTION, module_path))
    proto = kit.gen.btf[func.ref]
    section, start, code = disassemble(module_path, FUNCTION)
    if not code:
        raise WrongFile("%s is not in objdump's output for %s" % (FUNCTION, module_path))
    rows = annotate(kit, code, track(kit, code, proto.data))
    with open(module_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    args = ", ".join("%s = %s" % (reg, btf2c.ident(name)) for reg, (name, _) in zip(toy.ARG_REGS, proto.data))
    lines = [
        "# Which struct member each access of %s through its pointer arguments touches, in btf2ida's layout." % FUNCTION,
        "# Written by tests/check_kit_members.py from `objdump -d -r -M intel` of the try-module kit's nf_tables.ko",
        "# and its split BTF on vmlinux.btf; derived offline, not IDA output. nf_tables.ko SHA-256:",
        "# %s" % digest,
        "# Prototype btf2ida applies:",
        "# %s" % kit.gen.decl(func.ref, FUNCTION),
        "# Arguments at the entry (System V order): %s." % args,
        "# A register counts while it holds one of them (also after a copy to another register) or a struct pointer",
        "# loaded from one (ctx->net), on every path to the access; stack slots are not tracked.",
        "# Offsets into %s, which objdump puts at %#x of %s (IDA may load the section at another address)."
        % (FUNCTION, start, section),
        "# After the import the decompiler should show these members instead of offsets from the arguments.",
        "# Several members on one line: the access overlaps all of them (the members of a union overlap).",
        "#",
        "# offset  instruction  offset from the arguments  ->  member",
    ]
    for address, text, where, member in rows:
        lines.append("+%-5s  %-36s %-18s ->  %s" % ("%#x" % (address - start), text, where, member))
    return "\n".join(lines) + "\n"


def normal(line):
    return " ".join(line.split())


def rows(expected):
    """The lines of docs/kit_members.txt that name an access (not its # header)."""
    return [line for line in expected.splitlines() if line.strip() and not line.startswith("#")]


def readme_quotes(expected):
    """Problems with the README's quotes of docs/kit_members.txt (the code block after a link to it): a quoted line
    that is not a line of the file, or a count on the linking line ("3 of the 19 lines") that is not the block's and
    the file's. Also the count in docs/VERIFICATION.md ("19 lines named"). Returns (problems, lines quoted)."""
    total = len(rows(expected))
    wanted = {normal(line) for line in rows(expected)}
    with open(README) as handle:
        lines = handle.read().splitlines()
    problems, found = [], 0
    for i, line in enumerate(lines):
        if "docs/kit_members.txt" not in line:
            continue
        fence = next((j for j in range(i + 1, min(i + 4, len(lines))) if lines[j].lstrip().startswith("```")), None)
        if fence is None:
            continue
        end = next(j for j in range(fence + 1, len(lines)) if lines[j].lstrip().startswith("```"))
        for number in range(fence + 1, end):
            found += 1
            if normal(lines[number]) not in wanted:
                problems.append("README.md:%d quotes %r, which is not a line of docs/kit_members.txt"
                                % (number + 1, lines[number].strip()))
        count = re.search(r"(\d+) of the (\d+) lines", line)
        if count is None or int(count.group(1)) != end - fence - 1 or int(count.group(2)) != total:
            problems.append("README.md:%d says %r; the block quotes %d of the file's %d lines"
                            % (i + 1, count.group(0) if count else "no 'N of the M lines'", end - fence - 1, total))
    with open(VERIFICATION) as handle:
        lines = handle.read().splitlines()
    row = next((i for i, line in enumerate(lines) if "tests/check_kit_members.py" in line), None)
    count = re.search(r"(\d+) lines named", lines[row]) if row is not None else None
    if count is None or int(count.group(1)) != total:
        problems.append("docs/VERIFICATION.md:%s says %r; docs/kit_members.txt has %d lines" % (
            row + 1 if row is not None else "?", count.group(0) if count else "no 'N lines named'", total))
    return problems, found


def main(argv):
    paths = [a for a in argv if a != "--write"]
    if len(paths) not in (0, 2) or ("--write" in argv and not paths):
        print(USAGE, file=sys.stderr)
        return 2
    if paths:
        if shutil.which("objdump") is None:
            print("check_kit_members: objdump (binutils) is needed", file=sys.stderr)
            return 2
        missing = [p for p in paths if not os.path.isfile(p)]
        if missing:
            print("check_kit_members: %s is missing\n%s" % (", ".join(missing), USAGE), file=sys.stderr)
            return 2
        try:
            text = render(*paths)
        except (B.BTFError, WrongFile, subprocess.CalledProcessError) as error:
            print("check_kit_members: %s\n%s" % (error, USAGE), file=sys.stderr)
            return 2
        if "--write" in argv:  # then the README's quotes are checked against what was written
            with open(EXPECTED, "w") as handle:
                handle.write(text)
            print("wrote %s" % os.path.relpath(EXPECTED, ROOT))
    if not os.path.isfile(EXPECTED):
        print("check_kit_members: %s is missing (run with the kit and --write)" % EXPECTED, file=sys.stderr)
        return 2
    with open(EXPECTED) as handle:
        old = handle.read()
    status = 0
    failed = self_test()
    for problem in failed:
        print(problem)
    if failed:
        status = 1
    if paths and old != text:
        sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                                   "docs/kit_members.txt", "regenerated"))
        status = 1
    problems, found = readme_quotes(old)
    for problem in problems:
        print(problem)
    if problems or not found:
        print("docs/kit_members.txt in README.md and docs/VERIFICATION.md: %d quote(s) checked, %d problem(s)"
              % (found, len(problems)))
        status = 1
    if status == 0:
        print("%s%d README quote(s) of it and its count (%d lines) in README.md and docs/VERIFICATION.md match; "
              "self-test: %d cases pass%s" % ("docs/kit_members.txt matches the kit; " if paths else "", found,
                                             len(rows(old)), len(SELF_TEST),
                                             "" if paths else " (give the kit's two files to regenerate it)"))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
