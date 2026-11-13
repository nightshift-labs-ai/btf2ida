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


if __name__ == "__main__":
    check(TOY, "demo_open")
    for kernel in sys.argv[1:]:
        check(kernel, "tcp_sendmsg")
