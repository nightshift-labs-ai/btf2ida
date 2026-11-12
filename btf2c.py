#!/usr/bin/env python3
"""Turn Linux BTF into C declarations that IDA can parse, plus function prototypes.

Every struct is emitted packed with explicit padding, so its layout is exactly what BTF says.
Standard library only.
"""
import argparse
import re
import sys

import btf as B

IDENT = re.compile(r"[^0-9A-Za-z_]")

# Names a C compiler accepts but IDA's parser may not (same list as MemLens): C and C++ keywords
# (the kernel has members called private, new, class) and IDA's own type keywords.
RESERVED = set("""auto break case char const continue default do double else enum extern float for goto if inline int long
register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool __func__
__FUNCTION__ __PRETTY_FUNCTION__ alignas alignof and and_eq asm bitand bitor bool catch char8_t char16_t char32_t class compl
concept consteval constexpr constinit const_cast co_await co_return co_yield decltype delete dynamic_cast explicit export false
friend mutable namespace new noexcept not not_eq nullptr operator or or_eq private protected public reinterpret_cast requires
static_assert static_cast template this thread_local throw true try typeid typename using virtual wchar_t xor xor_eq
__int8 __int16 __int32 __int64 __int128 __cdecl __stdcall __fastcall __thiscall __pascal __usercall __userpurge __near __far
__huge __hidden __return_ptr __struct_ptr __array_ptr __unused __noreturn __pure __cppobj __unaligned __ptr32 __ptr64 __seg
__spoils __shifted __tuple __golang __swiftcall _BOOL1 _BOOL2 _BOOL4 _BYTE _WORD _DWORD _QWORD _OWORD _TBYTE _UNKNOWN __high
__bitmask __invbf __bin __oct __hex __dec __sbin __soct __shex __udec __float __char __segm __enum __off __offset __strlit
__stroff __custom __invsign __invbits __lzero __tabform
near far huge interrupt cdecl pascal stdcall fastcall thiscall flat large small""".split())
MODS = (B.CONST, B.VOLATILE, B.RESTRICT, B.TYPE_TAG)


def ident(name):
    clean = IDENT.sub("_", name)
    if clean[:1].isdigit():
        clean = "_" + clean
    return clean + "_" if clean in RESERVED else clean


class Generator:
    def __init__(self, data, pointer_size=8, bool_name="bool"):
        self.btf = data
        self.pointer_size = pointer_size
        self.tags = {}
        self.taken = set()
        self.done = set()
        self.active = set()
        self.anon_by_pointer = set()  # anonymous structs/unions only reached through a pointer
        self.body = []
        self.sizes = {}
        self.constants = set()
        self.stats = {"structs": 0, "unions": 0, "empty": 0, "base_only": 0, "opaque_members": 0, "enums": 0, "typedefs": 0, "bitfields_as_storage": 0, "dropped_members": 0}
        self.dropped = []
        self.scope = 0
        self._typedef_names = None
        self.bool_name = bool_name  # the plugin passes _BOOL1 when IDA's bool is not 1 byte
        for t in data:  # Struct, union, enum tags and typedefs share one namespace in IDA.
            if t.kind in (B.STRUCT, B.UNION, B.ENUM, B.ENUM64) or (t.kind == B.FWD and not t.name == ""):
                self.tag(t)
        for t in data:
            if t.kind == B.TYPEDEF:
                self.tag(t)

    def tag(self, t):
        name = self.tags.get(t.id)
        if name is None:
            base = ident(t.name) if t.name else "__anon_%d" % t.id
            name = base if base not in self.taken else "%s__%d" % (base, t.id)
            self.taken.add(name)
            self.tags[t.id] = name
        return name

    def strip(self, type_id):
        while type_id:
            t = self.btf[type_id]
            if t.kind not in MODS:
                return t
            type_id = t.ref
        return None

    def resolve(self, type_id):
        """Follow modifiers and typedefs."""
        while type_id:
            t = self.btf[type_id]
            if t.kind not in MODS and t.kind != B.TYPEDEF:
                return t
            type_id = t.ref
        return None

    def size_of(self, type_id):
        if type_id in self.sizes:
            return self.sizes[type_id]
        t = self.resolve(type_id)
        if t is None or t.kind in (B.FUNC_PROTO, B.FWD):
            size = 0
        elif t.kind == B.PTR:
            size = self.pointer_size
        elif t.kind == B.ARRAY:
            size = t.data[2] * self.size_of(t.data[0])
        else:
            size = t.size
        self.sizes[type_id] = size
        return size

    def typedef_alias(self, t):
        """A typedef emitted as its target: `typedef struct a a;` and names IDA reserves (bool)."""
        target = self.strip(t.ref)
        if ident(t.name) != t.name:
            return True
        return target is not None and target.kind in (B.STRUCT, B.UNION, B.ENUM, B.ENUM64) and target.name == t.name

    def base(self, t):
        """C spelling by size and sign, so it never depends on the parsing compiler's `long`."""
        if t.kind == B.FLOAT:
            return {4: "float", 8: "double"}.get(t.size) or "unsigned char /*float%d*/" % t.size
        if t.name == "char":  # the kernel builds with -funsigned-char, but this is still text
            return "char"
        encoding = t.data >> 24
        if encoding & B.INT_BOOL:  # IDA's own bool; the C header includes <stdbool.h> for gcc
            return self.bool_name if t.size == 1 else {2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}.get(t.size, "unsigned char")
        if t.size == 1 and encoding & B.INT_CHAR:
            return "char"
        signed = encoding & B.INT_SIGNED
        name = {1: "char", 2: "short", 4: "int", 8: "long long", 16: "__int128"}.get(t.size)
        if name is None:
            raise B.BTFError("integer of %d bytes" % t.size)
        return ("signed " if signed and t.size == 1 else "" if signed else "unsigned ") + name

    def spec(self, t):
        if t.kind in (B.INT, B.FLOAT):
            return self.base(t)
        if t.kind in (B.STRUCT, B.UNION):
            return ("union " if t.kind == B.UNION else "struct ") + self.tags[t.id]
        if t.kind == B.FWD:
            return ("union " if t.kflag else "struct ") + self.tags[t.id]
        if t.kind == B.ENUM:
            return "enum " + self.tags[t.id] if t.size == 4 and t.data else self.sized(t)
        if t.kind == B.ENUM64:
            return self.sized(t)
        if t.kind == B.TYPEDEF:
            return self.tags[t.id]
        raise B.BTFError("no specifier for kind %d" % t.kind)

    @staticmethod
    def sized(t):
        return {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}[t.size]

    def typedef_names(self):
        """Names of the typedefs the header declares (aliased ones are emitted as their target, so not included)."""
        if self._typedef_names is None:
            self._typedef_names = {self.tags[t.id] for t in self.btf if t.kind == B.TYPEDEF and not self.typedef_alias(t)}
        return self._typedef_names

    def params(self, t):
        if not t.data:
            return "void"
        out = []
        for index, (name, type_id) in enumerate(t.data):
            if type_id == 0 and not name:
                out.append("...")
                continue
            # a parameter named like a typedef (size_t code, where `code` is also a typedef) gets "_": a parser that
            # looks names up as types may read it as one. Tag names (struct page *page) are left as they are.
            param = ident(name) if name else "a%d" % (index + 1)
            out.append(self.decl(type_id, param + "_" if param in self.typedef_names() else param))
        return ", ".join(out)

    def decl(self, type_id, inner):
        """A C declaration of `inner` with this BTF type."""
        const = False
        while type_id:
            t = self.btf[type_id]
            if t.kind not in MODS:
                break
            const = const or t.kind == B.CONST
            type_id = t.ref
        if type_id == 0:
            return ("const void" if const else "void") + (" " + inner if inner else "")
        if t.kind == B.TYPEDEF and self.typedef_alias(t):
            return self.decl(t.ref, inner) if not const else self.decl_const(t.ref, inner)
        if t.kind == B.PTR:
            target = self.strip(t.ref)
            if target is not None and target.kind == B.ARRAY and target.data[2] == 0:
                return self.decl(target.data[0], "*" + inner)  # same layout; IDA's parser is unproven on (*x)[0]
            if target is not None and target.kind in (B.ARRAY, B.FUNC_PROTO):
                return self.decl(t.ref, "(*%s)" % inner)
            return self.decl(t.ref, "*" + inner)
        if t.kind == B.ARRAY:
            return self.decl(t.data[0], "%s[%d]" % (inner, t.data[2]))
        if t.kind == B.FUNC_PROTO:
            return self.decl(t.ref, "%s(%s)" % (inner, self.params(t)))
        text = self.spec(t)
        if const:
            text = "const " + text
        return text + (" " + inner if inner else "")

    def decl_const(self, type_id, inner):
        t = self.strip(type_id)
        if t is None or t.kind in (B.PTR, B.ARRAY, B.FUNC_PROTO):
            return self.decl(type_id, inner)
        return "const " + self.decl(type_id, inner)

    # Emission order. "name" = its name must be declared; "complete" = its size must be known.
    def need_name(self, type_id):
        while type_id:
            t = self.btf[type_id]
            if t.kind in MODS or t.kind == B.PTR:
                type_id = t.ref
            elif t.kind == B.ARRAY:
                self.need_complete(t.data[0])
                return
            elif t.kind == B.FUNC_PROTO:
                for _, param in t.data:
                    self.need_name(param)
                type_id = t.ref
            elif t.kind == B.TYPEDEF:
                self.emit_typedef(t) if not self.typedef_alias(t) else self.need_name(t.ref)
                return
            elif t.kind in (B.ENUM, B.ENUM64):
                self.emit_enum(t)
                return
            else:
                if t.kind in (B.STRUCT, B.UNION) and not t.name:
                    self.anon_by_pointer.add(t.id)
                return

    def need_complete(self, type_id):
        while type_id:
            t = self.btf[type_id]
            if t.kind in MODS:
                type_id = t.ref
            elif t.kind == B.ARRAY:
                type_id = t.data[0]
            elif t.kind == B.TYPEDEF:
                if self.typedef_alias(t):
                    type_id = t.ref
                else:
                    self.need_complete(t.ref)
                    self.emit_typedef(t)
                    return
            elif t.kind in (B.STRUCT, B.UNION):
                self.emit_struct(t)
                return
            else:
                self.need_name(type_id)
                return

    def emit_typedef(self, t):
        if t.id in self.done or t.id in self.active:
            return
        self.active.add(t.id)
        self.need_name(t.ref)
        self.active.discard(t.id)
        self.done.add(t.id)
        self.body.append("typedef %s;\n" % self.decl(t.ref, self.tags[t.id]))
        self.stats["typedefs"] += 1

    def emit_enum(self, t):
        if t.id in self.done:
            return
        self.done.add(t.id)
        if t.kind != B.ENUM or t.size != 4 or not t.data:
            return
        items = []
        for name, value in t.data:
            label = ident(name)
            if label in self.constants or label in self.taken:
                label = "%s__%s" % (self.tags[t.id], label)
            if label in self.constants:
                continue
            self.constants.add(label)
            items.append("  %s = %d," % (label, value if t.kflag or value >= 0 else value & 0xFFFFFFFF))
        if items:
            self.body.append("enum %s {\n%s\n};\n" % (self.tags[t.id], "\n".join(items)))
            self.stats["enums"] += 1

    def member_bits(self, parent, offset, type_id):
        """(bit offset, bitfield width or 0)."""
        if parent.kflag:
            return offset & 0xFFFFFF, offset >> 24
        t = self.resolve(type_id)
        if t is not None and t.kind == B.INT and (t.data & 0xFF) != t.size * 8:
            return offset + ((t.data >> 16) & 0xFF), t.data & 0xFF
        return offset, 0

    def deps(self, t):
        for _, m_type, _ in t.data:
            inner = self.strip(m_type)
            if self.nested(inner):
                self.deps(inner)  # declared inline by members(): no separate top-level __anon_N copy
            else:
                self.need_complete(m_type)

    def emit_struct(self, t):
        if t.id in self.done or t.id in self.active:
            return
        self.active.add(t.id)
        self.deps(t)
        self.active.discard(t.id)
        self.done.add(t.id)
        self.scope = 0
        keyword = "union" if t.kind == B.UNION else "struct"
        if t.size == 0:  # nothing to lay out: only its forward declaration is emitted
            self.stats["empty"] += 1
            return
        if self.base_only(t):
            # A distilled base names a kernel struct with its size only: a padding body would replace
            # the real definition, so only its forward declaration is emitted.
            self.stats["base_only"] += 1
            return
        self.stats["unions" if t.kind == B.UNION else "structs"] += 1
        lines = self.members(t, "  ")
        self.body.append("%s %s {\n%s\n};\n" % (keyword, self.tags[t.id], "\n".join(lines)))

    def nested(self, t):
        return t is not None and t.kind in (B.STRUCT, B.UNION) and not t.name

    def base_only(self, t):
        """A kernel struct/union that a module's distilled base BTF knows by name and size only."""
        return self.btf.distilled and t.kind in (B.STRUCT, B.UNION) and t.vlen == 0 and t.size and t.id < self.btf.first_id

    def opaque(self, type_id):
        """(bytes, C name) when a member holds base-only structs by value (directly or as an array), else None."""
        count = 1
        while type_id:
            t = self.btf[type_id]
            if t.kind in MODS or t.kind == B.TYPEDEF:  # any typedef: `typedef struct qrwlock arch_rwlock_t` too
                type_id = t.ref
            elif t.kind == B.ARRAY:
                count *= t.data[2]
                type_id = t.data[0]
            elif self.base_only(t):
                return count * t.size, self.spec(t)
            else:
                return None
        return None

    def member(self, name, m_type, indent):
        """Lines declaring one non-bitfield member."""
        opaque = self.opaque(m_type)
        if opaque:  # its layout is not in the BTF: keep the size, name the type in a comment
            self.stats["opaque_members"] += 1
            return ["%sunsigned char %s[%d]; /* %s, known only by name and size (distilled base BTF) */"
                    % (indent, ident(name) if name else "__anon", opaque[0], opaque[1])]
        t = self.strip(m_type)
        if self.nested(t):
            keyword = "union" if t.kind == B.UNION else "struct"
            label = ident(name) if name else ""
            return ["%s%s {" % (indent, keyword)] + self.members(t, indent + "  ") + ["%s}%s;" % (indent, " " + label if label else "")]
        return ["%s%s;" % (indent, self.decl(m_type, ident(name) if name else "__anon"))]

    def members(self, t, indent):
        out = []
        self.scope += 1
        tail = "_n%d" % self.scope if len(indent) > 2 else ""
        if t.kind == B.UNION:
            largest = 0
            for name, m_type, offset in t.data:
                _, width = self.member_bits(t, offset, m_type)
                size = self.size_of(m_type)
                if width or size == 0:
                    if width:
                        self.stats["bitfields_as_storage"] += 1
                    continue
                largest = max(largest, size)
                out.extend(self.member(name, m_type, indent))
            if largest < t.size or not out:
                out.append("%sunsigned char __raw%s[%d];" % (indent, tail, max(t.size, 1)))
            return out
        cursor = 0
        items = sorted(t.data, key=lambda m: self.member_bits(t, m[2], m[1])[0])
        index = 0
        while index < len(items):
            name, m_type, offset = items[index]
            bit, width = self.member_bits(t, offset, m_type)
            if width:
                start, end, labels = bit // 8, (bit + width + 7) // 8, []
                while index < len(items):
                    other = self.member_bits(t, items[index][2], items[index][1])
                    if not other[1] or other[0] // 8 > end:
                        break
                    end = max(end, (other[0] + other[1] + 7) // 8)
                    labels.append("%s:%d@%d" % (items[index][0] or "?", other[1], other[0] - start * 8))
                    index += 1
                self.stats["bitfields_as_storage"] += len(labels)
                if start >= cursor:
                    if start > cursor:
                        out.append("%sunsigned char __pad_%x%s[%d];" % (indent, cursor, tail, start - cursor))
                    out.append("%sunsigned char __bits_%x%s[%d]; /* %s */" % (indent, start, tail, end - start, ", ".join(labels)))
                    cursor = end
                else:
                    self.stats["dropped_members"] += len(labels)
                    self.dropped.append((t.name, labels))
                continue
            index += 1
            start = bit // 8
            size = self.size_of(m_type)
            if size == 0:
                out.append("%s/* +0x%x %s (no size) */" % (indent, start, name))
                continue
            if start < cursor:
                self.stats["dropped_members"] += 1
                self.dropped.append((t.name, name))
                continue
            if start > cursor:
                out.append("%sunsigned char __pad_%x%s[%d];" % (indent, cursor, tail, start - cursor))
            out.extend(self.member(name, m_type, indent))
            cursor = start + size
        if cursor < t.size:
            out.append("%sunsigned char __pad_%x%s[%d];" % (indent, cursor, tail, t.size - cursor))
        return out

    def declarations(self):
        """Every declaration in parse order: forward tags, then the bodies."""
        for t in self.btf:
            if t.kind in (B.STRUCT, B.UNION) and (t.name or False):
                self.emit_struct(t)
            elif t.kind == B.TYPEDEF and not self.typedef_alias(t):
                self.need_complete(t.id)  # also emits anonymous structs reached only through pointers
            elif t.kind in (B.ENUM, B.ENUM64):
                self.emit_enum(t)
            elif t.kind == B.FUNC:
                self.need_name(t.ref)
        # An anonymous struct or union reached only through a pointer (struct { ... } *parts) got a
        # __anon_N tag but no body; define it so its members are not lost. Repeat: a body can add more.
        while True:
            pending = sorted(self.anon_by_pointer - self.done)
            if not pending:
                break
            for type_id in pending:
                self.emit_struct(self.btf[type_id])
        forward = []
        for t in self.btf:
            if t.kind in (B.STRUCT, B.UNION) or t.kind == B.FWD:
                if t.id in self.tags and (t.name or t.id in self.done):
                    keyword = "union" if (t.kind == B.UNION or (t.kind == B.FWD and t.kflag)) else "struct"
                    forward.append("%s %s;" % (keyword, self.tags[t.id]))
        return forward + self.body

    def prototypes(self, types=None):
        """[(function name, C declaration)] for every named BTF function, or for those in `types` only
        (for a kernel module: data.own = its own functions, data.base = vmlinux's)."""
        out, seen = [], set()
        for t in self.btf if types is None else types:
            if t.kind != B.FUNC or t.name in seen or ident(t.name) != t.name:
                continue
            seen.add(t.name)
            proto = self.btf[t.ref]
            if proto.kind != B.FUNC_PROTO:
                continue
            out.append((t.name, self.decl(t.ref, t.name)))
        return out

    def expected(self):
        """{C tag: (size, {member: byte offset})} for emitted named structs (plain members only)."""
        out = {}
        for t in self.btf:
            if t.kind not in (B.STRUCT, B.UNION) or t.id not in self.done or not t.size or not t.name or self.base_only(t):
                continue  # base-only structs are forward declarations: sizeof() would not compile
            fields = {}
            if t.kind == B.STRUCT:
                for name, m_type, offset in t.data:
                    bit, width = self.member_bits(t, offset, m_type)
                    if name and not width and self.size_of(m_type):
                        fields[ident(name)] = bit // 8
            out[self.tags[t.id]] = (t.size, fields)
        return out


def header(generator):
    text = "/* Generated by btf2ida from Linux BTF. */\n#include <stdbool.h>\n#pragma pack(push, 1)\n\n"
    return text + "\n".join(generator.declarations()) + "\n#pragma pack(pop)\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="raw BTF, an ELF with .BTF, or any image containing BTF")
    parser.add_argument("output", help="C header to write")
    parser.add_argument("--base", help="vmlinux BTF, for split BTF of a kernel module")
    parser.add_argument("--pointer-size", type=int, default=8)
    parser.add_argument("--prototypes", help="also write one prototype per line here")
    parser.add_argument("--asserts", help="also write a C file of _Static_assert layout checks")
    args = parser.parse_args(argv)
    try:
        with open(args.input, "rb") as handle:
            blob = B.unpack_kernel_image(handle.read(), args.input)
        base = None
        if args.base:
            with open(args.base, "rb") as handle:
                base = B.load_base(B.unpack_kernel_image(handle.read(), args.base), args.base)
        data = B.load(blob, base=base)
        if data.distilled and base is not None:
            print("btf2c: %s carries its own distilled .BTF.base, which its BTF is built on; --base is not used "
                  "(kernel structs it names by size only become forward declarations)" % args.input, file=sys.stderr)
    except B.NeedsBase as error:
        sys.exit("btf2c: %s: %s (add --base /path/to/vmlinux or /sys/kernel/btf/vmlinux)" % (args.input, error))
    except (B.BTFError, OSError) as error:
        sys.exit("btf2c: %s" % error)
    generator = Generator(data, args.pointer_size)
    text = header(generator)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)
    if args.prototypes:
        # A function may not share its name with a typedef or an enum constant in the same C scope
        # (Debian 13: function and typedef dmi_callback), so those lines are written as comments.
        ordinary = set(generator.constants)
        ordinary.update(generator.tags[t.id] for t in generator.btf if t.kind == B.TYPEDEF and t.id in generator.tags)
        clashes = 0
        with open(args.prototypes, "w", encoding="utf-8") as handle:
            for name, prototype in generator.prototypes():
                if name in ordinary:
                    clashes += 1
                    handle.write("/* name also used by a typedef or enum constant in the header: %s; */\n" % prototype)
                else:
                    handle.write(prototype + ";\n")
        if clashes:
            print("btf2c: %d prototype(s) written as comments: the name clashes with a typedef or enum constant" % clashes, file=sys.stderr)
    if args.asserts:
        with open(args.asserts, "w", encoding="utf-8") as handle:
            handle.write('#include "%s"\n' % args.output.rsplit("/", 1)[-1])
            kinds = {}
            for t in generator.btf:
                if t.kind in (B.STRUCT, B.UNION) and t.name:
                    kinds[generator.tags[t.id]] = "union" if t.kind == B.UNION else "struct"
            for tag, (size, fields) in generator.expected().items():
                handle.write("_Static_assert(sizeof(%s %s) == %d, \"%s\");\n" % (kinds[tag], tag, size, tag))
                for member, offset in fields.items():
                    handle.write("_Static_assert(__builtin_offsetof(%s %s, %s) == %d, \"%s.%s\");\n" % (kinds[tag], tag, member, offset, tag, member))
    print(generator.stats, file=sys.stderr)


if __name__ == "__main__":
    main()
