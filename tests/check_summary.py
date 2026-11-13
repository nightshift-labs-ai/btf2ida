#!/usr/bin/env python3
"""The summary btf2ida shows after an import starts with a one-line headline and a "Look at:" line that names one
typed function to open in the decompiler (judge s178 item 5). Runs the plugin's own import on tests/check_module.py's
fake database (not IDA):

    python3 tests/check_summary.py                 # the toy demo: demo_open
    python3 tests/check_summary.py vmlinux         # also a kernel with BTF and symbols: tcp_sendmsg
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOY = os.path.join(HERE, "..", "demo", "toy_kernel.elf")


def summary(path):
    run = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_module.py"), path, path],
                         capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr
    lines = run.stdout.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("BTF2IDA: "))  # after check_module's own line
    return lines[start:]


def check(path, name):
    lines = summary(path)
    head = re.fullmatch(r"BTF2IDA: (\d+) types sent to IDA; (\d+) functions? typed with (?:their|its) kernel prototype",
                        lines[0])
    assert head, "headline: %r" % lines[0]
    applied = next(line for line in lines if line.startswith("Prototypes applied to "))
    imports = next((int(line.split()[1]) for line in lines if line.startswith("Typed ") and " imported " in line), 0)
    assert int(head.group(2)) == int(applied.split()[3]) + imports, (lines[0], applied, imports)
    look = re.fullmatch(r"Look at: (\S+) at 0x([0-9A-F]+): (.+) \(press F5 there\)", lines[1])
    assert look and look.group(1) == name and name + "(" in look.group(3), "look-at line: %r" % lines[1]
    print("OK %s: %s / %s" % (os.path.basename(path), lines[0], lines[1]))


def choice():
    """consider_example / set_prototype directly, on check_module's fake database (review s179 MINOR 1, 2)."""
    sys.path.insert(0, HERE)
    import check_module
    check_module.fake_database(TOY, TOY)
    sys.path.insert(0, os.path.dirname(HERE))
    import btf2ida_entry as m

    def pick(*candidates):
        result = {}
        for address, name, declaration in candidates:
            m.consider_example(result, address, name, declaration)
        return result["example"][2]
    # only top-level parameters count: struct pointers inside a callback type do not
    assert pick((0x10, "a", "int a(void (*cb)(struct x *p, struct y *q), int n)"), (0x20, "b", "int b(struct x *p)")) == "b"
    assert pick((0x10, "a", "int a(void (*cb)(int n, struct y *q, struct z *r), int n)"), (0x20, "b", "int b(struct x *p)")) == "b"
    assert pick((0x10, "a", "int a(void (*cb)(struct x *p))"), (0x20, "b", "int b(struct x *p, int a_long_name)")) == "b"
    # a struct passed by value is not a struct pointer
    assert pick((0x10, "i", "int i(struct x a, struct y b, struct z c)"), (0x20, "j", "int j(struct x *p)")) == "j"
    # the same count: the shorter declaration, then the lower address
    assert pick((0x30, "c", "int c(struct x *p, int a_long_name)"), (0x40, "d", "int d(struct x *p)")) == "d"
    assert pick((0x60, "f", "int f(struct x *p)"), (0x50, "e", "int e(struct y *p)")) == "e"
    assert pick((0x70, "g", "int g(const struct x *p, struct y **q, struct z *r)"), (0x80, "h", "int h(struct x *p)")) == "g"
    # a name of LOOK_AT wins over any count
    assert pick((0x90, "many", "int many(struct a *a, struct b *b, struct c *c)"),
                (0xA0, "tcp_sendmsg", "int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)")) == "tcp_sendmsg"
    # set_prototype: an import, or a prototype IDA rejects, is never the example
    result = {"applied": 0, "imports": 0, "rejected": [], "imports_rejected": [], "kept": 0, "retyped": 0,
              "void_asm": 0, "void_ida": 0, "void_removed": 0}
    m.set_prototype(0x900000, "tcp_sendmsg", "int tcp_sendmsg(struct sock *sk)", result, is_import=True)
    assert result["imports"] == 1 and "example" not in result, result
    set_type, m.idc.SetType = m.idc.SetType, lambda ea, decl: False
    try:
        m.set_prototype(0x1000, "vfs_read", "long vfs_read(struct file *f)", result)
    finally:
        m.idc.SetType = set_type
    assert result["rejected"] == ["vfs_read"] and "example" not in result, result
    m.set_prototype(0x1040, "vfs_read", "long vfs_read(struct file *f)", result)
    assert result["applied"] == 1 and result["example"][2] == "vfs_read", result
    print("OK Look-at choice: top-level struct pointers, shorter, lower address; LOOK_AT first; no import, no rejected")


if __name__ == "__main__":
    choice()
    check(TOY, "demo_open")
    for kernel in sys.argv[1:]:
        check(kernel, "tcp_sendmsg")
