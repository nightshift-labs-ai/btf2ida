#!/bin/sh
# Rebuild the demo and its expected outputs (gcc 13+ for -gbtf; checked with gcc 13.3).
set -e
cd "$(dirname "$0")"
gcc -O1 -gbtf -fno-inline -o toy_kernel.elf toy_kernel.c
python3 ../btf2c.py toy_kernel.elf expected_types.h --prototypes expected_prototypes.txt
gcc -fsyntax-only -x c expected_types.h
echo "demo rebuilt; header compiles"
