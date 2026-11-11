#!/usr/bin/env python3
"""Read Linux BTF from a raw blob, an ELF file or any memory image. Standard library only."""
import struct

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
    """True for an ELF relocatable object that is a Linux kernel module (it carries .gnu.linkonce.this_module)."""
    return (len(blob) >= 64 and blob[:4] == b"\x7fELF" and blob[16:18] in (b"\x01\x00", b"\x00\x01")
            and blob.find(b".gnu.linkonce.this_module") != -1)


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
        return BTF(section, base=base)
    found = carve(blob, base=base, little=None)
    if found is None:
        raise BTFError("no BTF found")
    return found
