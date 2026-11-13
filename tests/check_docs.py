#!/usr/bin/env python3
"""Checks README.md and docs/*.md: every relative link points to a file that exists, every #anchor to a heading.

    python3 tests/check_docs.py

Anchors follow GitHub's rule (lower case, punctuation dropped, spaces as hyphens, -1, -2 for repeats). Links to
http(s) and mailto are not fetched. Also checks the README's shape: at most 150 words before "## Try it", no line over
80 words, and "not yet run in real IDA" said once. Exit 0: all fine; 1: the problems are printed.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)|<img [^>]*src=\"([^\"]+)\"")


def slugs(path):
    out, seen, fenced = set(), {}, False
    with open(path) as handle:
        for line in handle:
            if line.lstrip().startswith("```"):
                fenced = not fenced
            match = None if fenced else re.match(r"^#{1,6} (.+?)\s*$", line)
            if match:
                slug = re.sub(r"[^\w\- ]", "", match.group(1).lower()).replace(" ", "-")
                count = seen.get(slug, 0)
                seen[slug] = count + 1
                out.add(slug if count == 0 else "%s-%d" % (slug, count))
    return out


def links(path):
    out, fenced = [], False
    with open(path) as handle:
        for number, line in enumerate(handle, 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if not fenced:
                out.extend((number, a or b) for a, b in LINK.findall(line))
    return out


def main():
    docs = os.path.join(ROOT, "docs")
    files = [os.path.join(ROOT, "README.md")] + sorted(
        os.path.join(docs, n) for n in os.listdir(docs) if n.endswith(".md"))
    problems, checked = [], 0
    for path in files:
        for number, target in links(path):
            if re.match(r"^(https?:|mailto:)", target):
                continue
            checked += 1
            file_part, _, anchor = target.partition("#")
            dest = os.path.normpath(os.path.join(os.path.dirname(path), file_part)) if file_part else path
            where = "%s:%d" % (os.path.relpath(path, ROOT), number)
            if not os.path.exists(dest):
                problems.append("%s: %s does not exist" % (where, target))
            elif anchor and (not dest.endswith(".md") or anchor not in slugs(dest)):
                problems.append("%s: no heading for #%s in %s" % (where, anchor, os.path.relpath(dest, ROOT)))
    with open(files[0]) as handle:
        readme = handle.read()
    lines = readme.splitlines()
    cut = next((i for i, line in enumerate(lines) if line.strip() == "## Try it"), None)
    before = len("\n".join(lines[:cut]).split()) if cut is not None else None
    if before is None or before > 150:
        problems.append("README: %s words before '## Try it' (at most 150)" % before)
    for number, line in enumerate(lines, 1):
        if len(line.split()) > 80:
            problems.append("README:%d: %d words on one line (at most 80)" % (number, len(line.split())))
    said = readme.lower().count("not yet run in real ida")
    if said != 1:
        problems.append("README: 'not yet run in real IDA' %d times (once, in the Status line)" % said)
    for problem in problems:
        print(problem)
    print("%d relative links and anchors in %d files; README: %d words, %s before '## Try it'; %d problem(s)"
          % (checked, len(files), len(readme.split()), before, len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
