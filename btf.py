#!/usr/bin/env python3
"""Read Linux BTF from a raw blob, an ELF file or any memory image. Standard library only."""
import bz2
import lzma
import re
import struct
import zlib

MAGIC = 0xEB9F
VOID, INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG, ENUM64 = range(20)
INT_SIGNED, INT_CHAR, INT_BOOL = 1, 2, 4


class BTFError(ValueError):
    pass


class BaseMismatch(BTFError):
    """Split BTF whose string offsets do not fit the chosen vmlinux."""


class NeedsBase(BTFError):
    """Split BTF (a kernel module): its ids and strings continue those of vmlinux."""


class Type:
    __slots__ = ("id", "kind", "name", "vlen", "kflag", "size", "ref", "data")

    def __repr__(self):
        return "<Type %d kind=%d %r>" % (self.id, self.kind, self.name)


class Header:
    def __init__(self, blob, offset=0):
        if len(blob) < offset + 24:
            raise BTFError("too short for a BTF header")
        magic = struct.unpack_from("<H", blob, offset)[0]
        self.endian = "<" if magic == MAGIC else ">" if magic == 0x9FEB else None
        if self.endian is None:
            raise BTFError("no BTF magic at 0x%x" % offset)
        _, self.version, self.flags, self.hdr_len, self.type_off, self.type_len, self.str_off, self.str_len = struct.unpack_from(self.endian + "HBBIIIII", blob, offset)
        if self.version != 1 or not 24 <= self.hdr_len <= 256:
            raise BTFError("unsupported BTF version or header")
        self.total = self.hdr_len + max(self.type_off + self.type_len, self.str_off + self.str_len)
        if self.type_len % 4 or self.str_len == 0 or offset + self.total > len(blob):
            raise BTFError("BTF sections do not fit")
        if self.type_off + self.type_len > self.str_off:
            raise BTFError("BTF type section overlaps strings")


class BTF:
    def __init__(self, blob, base=None, offset=0):
        head = Header(blob, offset)
        self.distilled = False  # True when the base is a module's own distilled .BTF.base, not vmlinux
        self.unchecked_release: "str | None" = None  # set by the plugin when a module's vmlinux could not be matched by release
        self.endian = head.endian
        self.size_on_disk = head.total
        start = offset + head.hdr_len
        self.strings = bytes(blob[start + head.str_off:start + head.str_off + head.str_len])
        if self.strings[-1:] != b"\0":
            raise BTFError("BTF string section is not terminated")
        if base is None and self.strings[:1] != b"\0":
            raise NeedsBase("this is split BTF (a kernel module): load the vmlinux BTF as its base")
        self.base = base
        self.str_start = base.str_end if base else 0
        self.str_end = self.str_start + len(self.strings)
        self.first_id = base.next_id if base else 1
        self.own = []
        self._base_refs = self._base_misses = 0
        self._parse(bytes(blob[start + head.type_off:start + head.type_off + head.type_len]))
        self.next_id = self.first_id + len(self.own)
        # A module's split BTF names many strings of its base. With the wrong vmlinux those offsets land
        # in the middle of unrelated strings: refuse instead of producing garbage names.
        if base is not None and self._base_refs and self._base_misses > 0.02 * self._base_refs:
            raise BaseMismatch("this module's BTF does not match the chosen vmlinux: %d of %d base string references "
                               "point into the middle of a string" % (self._base_misses, self._base_refs))
        self._validate()

    def _validate(self):
        """Every type reference must name an existing type, and chains of modifiers, pointers, typedefs and
        function returns must end; corrupt BTF (for example carved from a damaged image) is refused here
        instead of hanging later."""
        n = self.next_id
        chain = (PTR, TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG, FUNC, FUNC_PROTO, VAR, DECL_TAG)
        for t in self.own:
            refs = [t.ref] if t.kind in chain else []
            if t.kind == ARRAY:
                refs = list(t.data[:2])
            elif t.kind in (STRUCT, UNION):
                refs = [m[1] for m in t.data]
            elif t.kind == FUNC_PROTO:
                refs += [p[1] for p in t.data]
            elif t.kind == DATASEC:
                refs = [v[0] for v in t.data]
            for r in refs:
                if r >= n:
                    raise BTFError("corrupt BTF: type %d refers to type %d, but only %d types exist" % (t.id, r, n - 1))
        for t in self.own:  # a chain longer than the number of types must contain a cycle
            steps, cur = 0, t
            while cur.kind in chain and cur.ref:
                steps += 1
                if steps > n:
                    raise BTFError("corrupt BTF: type %d is part of a reference cycle" % t.id)
                cur = self[cur.ref]

    def is_string_start(self, offset):
        if offset < self.str_start:
            return self.base.is_string_start(offset) if self.base is not None else False
        relative = offset - self.str_start
        if relative >= len(self.strings):
            return False
        return relative == 0 or self.strings[relative - 1] == 0

    def string(self, offset):
        if offset < self.str_start:
            if self.base is None:
                raise BTFError("string offset out of range")
            if offset:
                self._base_refs += 1
                if not self.base.is_string_start(offset):
                    self._base_misses += 1
            return self.base.string(offset)
        relative = offset - self.str_start
        if relative >= len(self.strings):
            raise BTFError("string offset out of range")
        return self.strings[relative:self.strings.index(b"\0", relative)].decode("utf-8", "replace")

    def _parse(self, data):
        end = self.endian
        pos, limit = 0, len(data)
        three = struct.Struct(end + "III")
        two = struct.Struct(end + "II")
        one = struct.Struct(end + "I")
        three_i = struct.Struct(end + "IIi")
        next_id = self.first_id
        while pos < limit:
            if pos + 12 > limit:
                raise BTFError("truncated BTF type")
            name_off, info, size_or_type = three.unpack_from(data, pos)
            pos += 12
            t = Type()
            t.id, t.name = next_id, self.string(name_off)
            t.vlen, t.kind, t.kflag = info & 0xFFFF, (info >> 24) & 0x1F, info >> 31
            t.size = t.ref = size_or_type
            t.data = None
            vlen = t.vlen
            if t.kind == INT:
                t.data = one.unpack_from(data, pos)[0]
                pos += 4
            elif t.kind == ARRAY:
                t.data = three.unpack_from(data, pos)  # element type, index type, nelems
                pos += 12
            elif t.kind in (STRUCT, UNION):
                members = []
                for _ in range(vlen):
                    m_name, m_type, m_off = three.unpack_from(data, pos)
                    pos += 12
                    members.append((self.string(m_name), m_type, m_off))
                t.data = members
            elif t.kind == ENUM:
                values = []
                for _ in range(vlen):
                    v_name, v_val = struct.unpack_from(end + "Ii", data, pos)
                    pos += 8
                    values.append((self.string(v_name), v_val))
                t.data = values
            elif t.kind == ENUM64:
                values = []
                for _ in range(vlen):
                    v_name, low, high = three.unpack_from(data, pos)
                    pos += 12
                    values.append((self.string(v_name), high << 32 | low))
                t.data = values
            elif t.kind == FUNC_PROTO:
                params = []
                for _ in range(vlen):
                    p_name, p_type = two.unpack_from(data, pos)
                    pos += 8
                    params.append((self.string(p_name), p_type))
                t.data = params
            elif t.kind == VAR:
                t.data = one.unpack_from(data, pos)[0]
                pos += 4
            elif t.kind == DATASEC:
                t.data = [three.unpack_from(data, pos + 12 * i) for i in range(vlen)]
                pos += 12 * vlen
            elif t.kind == DECL_TAG:
                t.data = one.unpack_from(data, pos)[0]
                pos += 4
            elif t.kind not in (PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG):
                raise BTFError("unknown BTF kind %d at id %d" % (t.kind, next_id))
            self.own.append(t)
            next_id += 1
        if pos != limit:
            raise BTFError("BTF type section has trailing bytes")

    def __getitem__(self, type_id):
        if type_id < self.first_id:
            if self.base is None:
                raise KeyError(type_id)
            return self.base[type_id]
        return self.own[type_id - self.first_id]

    def __iter__(self):
        if self.base is not None:
            yield from self.base
        yield from self.own

    @property
    def count(self):
        return self.next_id - 1


def elf_section(blob, wanted=b".BTF"):
    """The bytes of a named section of an ELF file, or None."""
    if blob[:4] != b"\x7fELF" or len(blob) < 64:
        return None
    wide = blob[4] == 2
    end = "<" if blob[5] == 1 else ">"
    if wide:
        shoff = struct.unpack_from(end + "Q", blob, 40)[0]
        entsize, num, strndx = struct.unpack_from(end + "HHH", blob, 58)
        fmt, name_at, off_at, size_at = "Q", 0, 24, 32
    else:
        shoff = struct.unpack_from(end + "I", blob, 32)[0]
        entsize, num, strndx = struct.unpack_from(end + "HHH", blob, 46)
        fmt, name_at, off_at, size_at = "I", 0, 16, 20
    if not shoff or not num or strndx >= num or shoff + num * entsize > len(blob):
        return None

    def field(index, at):
        return struct.unpack_from(end + fmt, blob, shoff + index * entsize + at)[0]

    strtab = field(strndx, off_at)
    for index in range(num):
        name = struct.unpack_from(end + "I", blob, shoff + index * entsize + name_at)[0]
        stop = blob.find(b"\0", strtab + name)
        if blob[strtab + name:stop] == wanted:
            offset, size = field(index, off_at), field(index, size_at)
            return blob[offset:offset + size]
    return None


# BPF programs carry BTF of their own (tens of types); a real kernel has tens of thousands.
MIN_KERNEL_TYPES = 1000


def carve(blob, base=None, little=True, min_types=None):
    """Find BTF by content in any bytes-like image. Returns the one with the most types, or None.

    Without a base we are looking for a kernel, so a loaded BPF program's small BTF does not count.
    """
    if min_types is None:
        min_types = 1 if base is not None else MIN_KERNEL_TYPES
    magics = (b"\x9f\xeb\x01", b"\xeb\x9f\x01") if little is None else ((b"\x9f\xeb\x01",) if little else (b"\xeb\x9f\x01",))
    best = None
    for magic in magics:
        at = blob.find(magic)
        while at != -1:
            try:
                candidate = BTF(blob, base=base, offset=at)
                if len(candidate.own) >= min_types and (best is None or len(candidate.own) > len(best.own)):
                    best = candidate
            except (BTFError, struct.error, IndexError, ValueError):
                pass  # includes NeedsBase: a memory image also holds module BTF, keep looking for vmlinux
            at = blob.find(magic, at + 1)
    return best


def is_kernel_module(blob):
    """True for an ELF relocatable object with a .gnu.linkonce.this_module section (a Linux kernel module).

    A section lookup, not a string search: vmlinux and the kernel's own module loader hold that string too.
    """
    if len(blob) < 64 or blob[:4] != b"\x7fELF" or blob[5] not in (1, 2):
        return False
    try:
        if struct.unpack_from("<H" if blob[5] == 1 else ">H", blob, 16)[0] != 1:  # ET_REL
            return False
        return elf_section(blob, b".gnu.linkonce.this_module") is not None
    except (struct.error, IndexError, ValueError):
        return False


def module_release(blob):
    """The kernel release a module was built for (first word of vermagic= in .modinfo), or None."""
    try:
        info = elf_section(blob, b".modinfo")
    except (struct.error, IndexError, ValueError):
        return None
    for entry in (info or b"").split(b"\0"):
        if entry.startswith(b"vermagic="):
            words = entry[len(b"vermagic="):].split()
            return words[0].decode("ascii", "replace") if words else None
    return None


def undefined_symbols(blob):
    """Names of the undefined symbols in an ELF file's .symtab (for a kernel module: what it takes from the kernel and
    other modules), ELF32 or ELF64, either byte order. Empty if there is no symbol table."""
    try:
        table, names = elf_section(blob, b".symtab"), elf_section(blob, b".strtab")
    except (struct.error, IndexError, ValueError):
        return set()
    if not table or not names:
        return set()
    end = "<" if blob[5] == 1 else ">"
    wide = blob[4] == 2
    size, layout = (24, end + "IBBHQQ") if wide else (16, end + "IIIBBH")
    out = set()
    for at in range(size, len(table) - size + 1, size):  # entry 0 is the null symbol
        fields = struct.unpack_from(layout, table, at)
        name, shndx = fields[0], fields[3] if wide else fields[5]
        if shndx == 0 and name:
            stop = names.find(b"\0", name)
            out.add(names[name:stop if stop != -1 else len(names)].decode("utf-8", "replace"))
    return out


BANNER = re.compile(rb"Linux version (\d[^\s\x00]*) \(")


def kernel_releases(blob):
    """Every release named by a 'Linux version <release> (' banner (empty for raw BTF).

    A vmlinux has one. A memory image can also hold copies in logs (dmesg, journald), possibly from an earlier boot,
    and in no fixed order, so the caller checks membership instead of trusting the first match.
    """
    return {found.group(1).decode("ascii", "replace") for found in BANNER.finditer(blob)}


# Payload formats of an x86 bzImage (arch/x86/boot/compressed): magic at the start of the payload.
BZIMAGE_FORMATS = ((b"\x1f\x8b", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"), (b"\x5d\x00\x00", "lzma"),
                   (b"\x28\xb5\x2f\xfd", "zstd"), (b"\x02\x21\x4c\x18", "lz4"), (b"\x89LZO", "lzo"))
UNPACKERS = {"gzip": lambda: zlib.decompressobj(31), "xz": lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ),
             "lzma": lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE), "bzip2": bz2.BZ2Decompressor}
UNPACK_TOOLS = {"zstd": "zstd (unzstd)", "lz4": "lz4", "lzo": "lzop"}


def bzimage_payload(blob):
    """(format, compressed kernel) of an x86 bzImage, or None if blob is not one.

    Boot protocol 2.08+: payload_offset (0x248) and payload_length (0x24c) locate the payload, counted from the start
    of the protected-mode code at (setup_sects + 1) * 512 (setup_sects 0 means 4).
    """
    if len(blob) < 0x250 or blob[0x202:0x206] != b"HdrS":
        return None
    if struct.unpack_from("<H", blob, 0x206)[0] < 0x208:
        return "unknown", b""
    offset, length = struct.unpack_from("<II", blob, 0x248)
    start = ((blob[0x1F1] or 4) + 1) * 512 + offset
    payload = blob[start:start + length]
    for magic, kind in BZIMAGE_FORMATS:
        if payload[:len(magic)] == magic:
            return kind, payload
    return "unknown", payload


def unpack_kernel_image(blob, path):
    """The kernel inside a compressed kernel file chosen as the vmlinux, else blob itself.

    An x86 bzImage packed with gzip, xz, lzma or bzip2 is unpacked here (Python's standard library); zstd, lz4 and lzo
    are not, and the error says what to install. A whole-file gzip (an arm64 Image.gz, as Ubuntu ships its arm64
    vmlinuz) is unpacked too.
    """
    if blob[:2] == b"\x1f\x8b":
        try:
            return zlib.decompressobj(31).decompress(bytes(blob))
        except zlib.error:
            return blob
    found = bzimage_payload(blob)
    if found is None:
        return blob
    kind, payload = found
    if kind in UNPACKERS:
        try:
            return UNPACKERS[kind]().decompress(bytes(payload))
        except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError) as error:
            raise BTFError("the chosen vmlinux (%s) is a compressed kernel image (bzImage, %s) that could not be "
                           "unpacked (%s): extract it with scripts/extract-vmlinux, or use a copy of "
                           "/sys/kernel/btf/vmlinux from the same kernel" % (path, kind, error))
    if kind in UNPACK_TOOLS:
        raise BTFError("the chosen vmlinux (%s) is a compressed kernel image (bzImage) packed with %s, which btf2ida "
                       "cannot unpack: install %s and run scripts/extract-vmlinux on it again (without it, "
                       "extract-vmlinux still exits 0 and writes the bzImage unchanged; `file vmlinux` must say ELF), "
                       "or use a copy of /sys/kernel/btf/vmlinux from the same kernel" % (path, kind, UNPACK_TOOLS[kind]))
    raise BTFError("the chosen vmlinux (%s) is a compressed kernel image (bzImage) in a format btf2ida does not know: "
                   "extract it with scripts/extract-vmlinux, or use a copy of /sys/kernel/btf/vmlinux from the same "
                   "kernel" % path)


def load_base(blob, path):
    """BTF of the vmlinux chosen as the base of a module's split BTF; a BTFError that says why if it has none."""
    try:
        return load(blob)
    except BTFError as error:
        if blob[0x202:0x206] == b"HdrS":
            hint = ("it is a compressed kernel image (bzImage): extract it first with scripts/extract-vmlinux, "
                    "or use a copy of /sys/kernel/btf/vmlinux from the same kernel")
        else:
            hint = "use the uncompressed vmlinux of the same kernel build, or a copy of its /sys/kernel/btf/vmlinux"
        raise BTFError("the chosen vmlinux (%s) has no BTF (%s): %s" % (path, error, hint))


def load(blob, base=None):
    """Raw BTF, an ELF with a .BTF section, or anything containing BTF."""
    if blob[:2] in (b"\x9f\xeb", b"\xeb\x9f"):
        try:
            return BTF(blob, base=base)
        except (NeedsBase, BaseMismatch):
            raise
        except BTFError:
            pass
    section = elf_section(blob)
    if section:
        distilled = elf_section(blob, b".BTF.base")
        if distilled:  # an external module (Linux 6.11+): its split BTF sits on this small base, not on vmlinux
            data = BTF(section, base=BTF(distilled))
            data.distilled = True
            return data
        return BTF(section, base=base)
    found = carve(blob, base=base, little=None)
    if found is None:
        raise BTFError("no BTF found")
    return found
