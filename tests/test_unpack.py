#!/usr/bin/env python3
"""Compressed kernel files chosen as the vmlinux (btf.unpack_kernel_image), on synthetic bzImages.

Real files checked by hand (README): Debian 11 5.10 (xz bzImage), Debian 13 6.12 (zstd bzImage), Ubuntu 24.04 arm64
6.8 (gzip Image).
"""
import bz2
import gzip
import lzma
import os
import struct
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import btf as B  # noqa: E402

KERNEL = b"\x7fELF" + b"Linux version 9.9.9-test (builder) #1\x00" + bytes(range(256)) * 64


def bzimage(payload, setup_sects=3, version=0x20F, trailer=b"\x00\x10\x00\x00"):
    """A minimal bzImage: setup header fields that the kernel's boot protocol defines, payload after 300 bytes of
    decompressor stub, then the 4-byte size the kernel build appends (inside payload_length)."""
    head = bytearray(((setup_sects or 4) + 1) * 512)
    head[0x1F1] = setup_sects
    head[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", head, 0x206, version)
    struct.pack_into("<II", head, 0x248, 300, len(payload) + len(trailer))
    return bytes(head) + b"\x90" * 300 + payload + trailer + b"\x00" * 64


lzma_xz = lzma.compress(b"\x7fELF" + b"x" * 1000, lzma.FORMAT_XZ)
packers = {"gzip": lambda d: gzip.compress(d), "xz": lambda d: lzma.compress(d, lzma.FORMAT_XZ, check=lzma.CHECK_CRC32),
           "lzma": lambda d: lzma.compress(d, lzma.FORMAT_ALONE), "bzip2": lambda d: bz2.compress(d)}
for kind, pack in packers.items():
    image = bzimage(pack(KERNEL))
    assert B.bzimage_payload(image)[0] == kind, kind
    assert B.unpack_kernel_image(image, "img") == KERNEL, kind
    assert B.kernel_releases(B.unpack_kernel_image(image, "img")) == {"9.9.9-test"}, kind
assert B.unpack_kernel_image(bzimage(gzip.compress(KERNEL), setup_sects=0), "img") == KERNEL   # setup_sects 0 means 4
for kind, magic, tool in (("zstd", b"\x28\xb5\x2f\xfd", "install zstd (unzstd)"), ("lz4", b"\x02\x21\x4c\x18", "install lz4"),
                          ("lzo", b"\x89LZO", "install lzop")):
    try:
        B.unpack_kernel_image(bzimage(magic + b"\x00" * 100), "vmlinuz-x")
        raise SystemExit("%s was not refused" % kind)
    except B.BTFError as error:
        assert tool in str(error) and "vmlinuz-x" in str(error) and "file vmlinux" in str(error), error
for bad, words in ((bzimage(b"\xfd7zXZ\x00" + b"\x01" * 50), "could not be unpacked"),
                   (bzimage(b"QQQQ" * 30), "format btf2ida does not know"),
                   (bzimage(b"\x1f\x8b" + b"\x00" * 40, version=0x206), "format btf2ida does not know")):
    try:
        B.unpack_kernel_image(bad, "img")
        raise SystemExit("a broken bzImage was accepted")
    except B.BTFError as error:
        assert words in str(error), error
assert B.unpack_kernel_image(gzip.compress(KERNEL), "Image.gz") == KERNEL      # whole-file gzip (arm64 Image.gz)
assert B.unpack_kernel_image(KERNEL, "vmlinux") is KERNEL                       # anything else: unchanged
assert B.unpack_kernel_image(b"\x1f\x8b" + b"junk" * 10, "x") == b"\x1f\x8b" + b"junk" * 10  # not really gzip
for kind, pack in packers.items():                                             # a truncated payload is refused
    packed = pack(KERNEL)
    try:
        B.unpack_kernel_image(bzimage(packed[:len(packed) // 2], trailer=b""), "img")
        raise SystemExit("a truncated %s payload was accepted" % kind)
    except B.BTFError as error:
        assert "could not be unpacked" in str(error), error
half = gzip.compress(KERNEL)[:len(gzip.compress(KERNEL)) // 2]
assert B.unpack_kernel_image(half, "x") == half                                    # incomplete whole-file gzip: unchanged
saved = {name: sys.modules.get(name) for name in ("lzma", "_lzma", "bz2", "_bz2")}
sys.modules.update(lzma=None, _lzma=None, bz2=None, _bz2=None)                    # a Python built without liblzma/bzip2
try:
    probe = subprocess.run([sys.executable, "-c", "import sys; sys.modules.update(lzma=None, _lzma=None, bz2=None, _bz2=None); "
                            "sys.path.insert(0, %r); import btf; print('loaded')" % ROOT], capture_output=True, text=True)
    assert probe.stdout.strip() == "loaded", probe.stderr                          # the plugin still loads
    assert B.unpack_kernel_image(bzimage(gzip.compress(KERNEL)), "img") == KERNEL   # gzip needs only zlib
    try:
        B.unpack_kernel_image(bzimage(lzma_xz), "img")
        raise SystemExit("xz without lzma was accepted")
    except B.BTFError as error:
        assert "this Python has no xz module" in str(error), error
finally:
    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module
print("unpack test OK: gzip/xz/lzma/bzip2 bzImages unpacked; zstd/lz4/lzo refused with what to install; Image.gz unpacked")
