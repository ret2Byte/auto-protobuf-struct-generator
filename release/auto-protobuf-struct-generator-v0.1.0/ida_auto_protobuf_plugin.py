import base64
import os
import re
import shutil
import struct
import subprocess
import zlib
from typing import Dict, List, Optional, Sequence, Tuple

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_segment
import idautils

try:
    from google.protobuf import descriptor_pb2
except ImportError:
    descriptor_pb2 = None


PROTO_SUFFIX_RE = re.compile(rb"([A-Za-z0-9_./\\+\-]{1,200}\.proto)")
RAW_PROTO_RE = re.compile(rb"\x0a[\x01-\x7f][A-Za-z0-9_./\\+\-]{1,200}\.proto")
MAX_DESCRIPTOR_SIZE = 0x10000
GZIP_MAGIC = b"\x1f\x8b\x08"
WELL_KNOWN_PROTOS = {
    "google/protobuf/descriptor.proto",
    "google/protobuf/any.proto",
    "google/protobuf/timestamp.proto",
    "google/protobuf/duration.proto",
    "google/protobuf/empty.proto",
    "google/protobuf/wrappers.proto",
    "google/protobuf/struct.proto",
    "google/protobuf/field_mask.proto",
    "google/protobuf/api.proto",
    "google/protobuf/source_context.proto",
    "google/protobuf/type.proto",
}

LABEL_TO_TYPE = {
    1: "optional",
    2: "required",
    3: "repeated",
}

TYPE_TO_NAME = {
    1: "double",
    2: "float",
    3: "int64",
    4: "uint64",
    5: "int32",
    6: "fixed64",
    7: "fixed32",
    8: "bool",
    9: "string",
    10: "group",
    11: "message",
    12: "bytes",
    13: "uint32",
    14: "enum",
    15: "sfixed32",
    16: "sfixed64",
    17: "sint32",
    18: "sint64",
}

PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC = 0x28AAEEF9
PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC = 0x114315AF

PROTOBUF_C_TYPE_TO_FIELD = {
    0: descriptor_pb2.FieldDescriptorProto.TYPE_INT32 if descriptor_pb2 else 5,
    1: descriptor_pb2.FieldDescriptorProto.TYPE_SINT32 if descriptor_pb2 else 17,
    2: descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32 if descriptor_pb2 else 15,
    3: descriptor_pb2.FieldDescriptorProto.TYPE_INT64 if descriptor_pb2 else 3,
    4: descriptor_pb2.FieldDescriptorProto.TYPE_SINT64 if descriptor_pb2 else 18,
    5: descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64 if descriptor_pb2 else 16,
    6: descriptor_pb2.FieldDescriptorProto.TYPE_UINT32 if descriptor_pb2 else 13,
    7: descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32 if descriptor_pb2 else 7,
    8: descriptor_pb2.FieldDescriptorProto.TYPE_UINT64 if descriptor_pb2 else 4,
    9: descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64 if descriptor_pb2 else 6,
    10: descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT if descriptor_pb2 else 2,
    11: descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE if descriptor_pb2 else 1,
    12: descriptor_pb2.FieldDescriptorProto.TYPE_BOOL if descriptor_pb2 else 8,
    13: descriptor_pb2.FieldDescriptorProto.TYPE_ENUM if descriptor_pb2 else 14,
    14: descriptor_pb2.FieldDescriptorProto.TYPE_STRING if descriptor_pb2 else 9,
    15: descriptor_pb2.FieldDescriptorProto.TYPE_BYTES if descriptor_pb2 else 12,
    16: descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE if descriptor_pb2 else 11,
}

PROTOBUF_C_LABEL_TO_FIELD = {
    0: descriptor_pb2.FieldDescriptorProto.LABEL_REQUIRED if descriptor_pb2 else 2,
    1: descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL if descriptor_pb2 else 1,
    2: descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED if descriptor_pb2 else 3,
    3: descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL if descriptor_pb2 else 1,
}


def _sanitize_ident(name: str) -> str:
    text = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not text:
        text = "protobuf_output"
    if text[0].isdigit():
        text = "_" + text
    return text


def _is_well_known(name: str) -> bool:
    return name in WELL_KNOWN_PROTOS


def _decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    for index in range(10):
        pos = offset + index
        if pos >= len(data):
            return 0, 0
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, index + 1
        shift += 7
    return 0, 0


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _walk_protobuf_message(data: bytes, max_size: int) -> Optional[int]:
    pos = 0
    limit = min(len(data), max_size)
    prev = 0
    while pos < limit:
        tag, consumed = _decode_varint(data, pos)
        if consumed == 0:
            break
        field_no = tag >> 3
        wire_type = tag & 0x07
        if field_no == 0 or field_no > 0x1FFFFFFF:
            break
        pos += consumed
        if wire_type == 0:
            _, consumed = _decode_varint(data, pos)
            if consumed == 0:
                break
            pos += consumed
        elif wire_type == 1:
            pos += 8
        elif wire_type == 2:
            length, consumed = _decode_varint(data, pos)
            if consumed == 0:
                break
            pos += consumed + length
        elif wire_type == 5:
            pos += 4
        else:
            break
        if pos > limit:
            break
        prev = pos
    return prev or None


def _iter_segment_data() -> Sequence[Tuple[str, int, bytes]]:
    out: List[Tuple[str, int, bytes]] = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if not seg:
            continue
        size = seg.end_ea - seg.start_ea
        if size <= 0:
            continue
        seg_bytes = ida_bytes.get_bytes(seg.start_ea, size)
        if seg_bytes:
            out.append((ida_segment.get_segm_name(seg), seg.start_ea, seg_bytes))
    return out


class IdaBinaryView:
    def __init__(self):
        self.ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        self.big_endian = bool(ida_ida.inf_is_be())

    def read_bytes_va(self, ea: int, size: int) -> bytes:
        data = ida_bytes.get_bytes(ea, size)
        return data or b""

    def read_u32(self, ea: int) -> int:
        data = self.read_bytes_va(ea, 4)
        if len(data) < 4:
            return 0
        return struct.unpack(">I" if self.big_endian else "<I", data)[0]

    def read_ptr(self, ea: int) -> int:
        data = self.read_bytes_va(ea, self.ptr_size)
        if len(data) < self.ptr_size:
            return 0
        fmt = ">Q" if self.big_endian and self.ptr_size == 8 else "<Q" if self.ptr_size == 8 else ">I" if self.big_endian else "<I"
        return struct.unpack(fmt, data)[0]

    def read_cstring_va(self, ea: int, max_len: int = 512) -> str:
        if not ea:
            return ""
        out = bytearray()
        for index in range(max_len):
            byte = self.read_bytes_va(ea + index, 1)
            if not byte or byte == b"\x00":
                break
            out.extend(byte)
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return out.decode("latin1")
            except Exception:
                return ""

    def valid_va(self, ea: int) -> bool:
        return ida_segment.getseg(ea) is not None


def _score_descriptor(proto: "descriptor_pb2.FileDescriptorProto") -> int:
    score = len(proto.message_type) * 4 + len(proto.enum_type) * 2
    if proto.name.endswith(".proto"):
        score += 5
    for message in proto.message_type:
        score += len(message.field) * 2
    return score


def _try_parse_descriptor(blob: bytes) -> Optional["descriptor_pb2.FileDescriptorProto"]:
    if descriptor_pb2 is None:
        return None
    proto = descriptor_pb2.FileDescriptorProto()
    try:
        proto.ParseFromString(blob)
    except Exception:
        return None
    if not proto.name or not proto.name.endswith(".proto"):
        return None
    if _is_well_known(proto.name):
        return None
    if not proto.message_type and not proto.enum_type and not proto.service:
        return None
    return proto


def _try_parse_descriptor_autosize(data: bytes, max_size: int = MAX_DESCRIPTOR_SIZE) -> Optional["descriptor_pb2.FileDescriptorProto"]:
    end_pos = _walk_protobuf_message(data, max_size)
    if end_pos and end_pos > 8:
        proto = _try_parse_descriptor(data[:end_pos])
        if proto:
            return proto
    for marker in (b"proto3", b"proto2"):
        idx = data.find(marker)
        if idx != -1 and idx < max_size:
            proto = _try_parse_descriptor(data[: idx + len(marker)])
            if proto:
                return proto
    return None


def _find_cpp_descriptors() -> List["descriptor_pb2.FileDescriptorProto"]:
    found: Dict[str, descriptor_pb2.FileDescriptorProto] = {}
    for _, _, seg_bytes in _iter_segment_data():
        for match in PROTO_SUFFIX_RE.finditer(seg_bytes):
            filename = match.group(1).decode("utf-8", errors="ignore")
            if _is_well_known(filename):
                continue
            encoded = b"\x0a" + _encode_varint(len(filename.encode("utf-8"))) + filename.encode("utf-8")
            start = 0
            while True:
                pos = seg_bytes.find(encoded, start)
                if pos == -1:
                    break
                proto = _try_parse_descriptor_autosize(seg_bytes[pos : pos + MAX_DESCRIPTOR_SIZE])
                if proto and proto.name == filename:
                    current = found.get(proto.name)
                    if current is None or _score_descriptor(proto) > _score_descriptor(current):
                        found[proto.name] = proto
                start = pos + 1
    return list(found.values())


def _find_raw_descriptors() -> List["descriptor_pb2.FileDescriptorProto"]:
    found: Dict[str, descriptor_pb2.FileDescriptorProto] = {}
    for _, _, seg_bytes in _iter_segment_data():
        for match in RAW_PROTO_RE.finditer(seg_bytes):
            start = match.start()
            proto = _try_parse_descriptor_autosize(seg_bytes[start : start + MAX_DESCRIPTOR_SIZE])
            if proto:
                current = found.get(proto.name)
                if current is None or _score_descriptor(proto) > _score_descriptor(current):
                    found[proto.name] = proto
    return list(found.values())


def _gunzip_maybe(data: bytes) -> bytes:
    if len(data) < 10 or not data.startswith(GZIP_MAGIC):
        return b""
    try:
        flags = data[3]
        pos = 10
        if flags & 0x04:
            if pos + 2 > len(data):
                return b""
            xlen = data[pos] | (data[pos + 1] << 8)
            pos += 2 + xlen
        if flags & 0x08:
            pos = data.find(b"\x00", pos) + 1
        if flags & 0x10:
            pos = data.find(b"\x00", pos) + 1
        if flags & 0x02:
            pos += 2
        if pos <= 0 or pos >= len(data):
            return b""
        return zlib.decompress(data[pos:], -zlib.MAX_WBITS)
    except Exception:
        return b""


def _find_go_descriptors() -> List["descriptor_pb2.FileDescriptorProto"]:
    found: Dict[str, descriptor_pb2.FileDescriptorProto] = {}
    lengths = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]
    for _, _, seg_bytes in _iter_segment_data():
        pos = 0
        while True:
            pos = seg_bytes.find(GZIP_MAGIC, pos)
            if pos == -1:
                break
            for size in lengths:
                chunk = seg_bytes[pos : pos + size]
                decompressed = _gunzip_maybe(chunk)
                if not decompressed:
                    continue
                proto = _try_parse_descriptor(decompressed)
                if proto:
                    current = found.get(proto.name)
                    if current is None or _score_descriptor(proto) > _score_descriptor(current):
                        found[proto.name] = proto
                    break
            pos += 1
    return list(found.values())


class ProtobufCEnumInfo:
    def __init__(self, view: IdaBinaryView, ea: int):
        self.view = view
        self.ea = ea
        self.name = ""
        self.short_name = ""
        self.package_name = ""
        self.values: List[Tuple[str, int]] = []
        self._parse()

    def _parse(self) -> None:
        p = self.view.ptr_size
        endian = ">" if self.view.big_endian else "<"
        if p == 8:
            fmt = f"{endian}I4xQQQQI4xQI4xQI4xQ"
        else:
            fmt = f"{endian}IIIIIIIIIII"
        size = struct.calcsize(fmt)
        data = self.view.read_bytes_va(self.ea, size)
        if len(data) < size:
            return
        vals = struct.unpack(fmt, data)
        if vals[0] != PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC:
            return
        self.name = self.view.read_cstring_va(vals[1])
        self.short_name = self.view.read_cstring_va(vals[2])
        self.package_name = self.view.read_cstring_va(vals[4] if p == 8 else vals[4])
        n_values = vals[5]
        values_ptr = vals[6]
        if not self.name or not values_ptr or n_values <= 0 or n_values > 10000:
            return
        if p == 8:
            entry_size = 24
            for i in range(n_values):
                off = values_ptr + i * entry_size
                entry = self.view.read_bytes_va(off, entry_size)
                if len(entry) < entry_size:
                    break
                name_ptr, _, value = struct.unpack(f"{endian}QQi", entry[:20])
                name = self.view.read_cstring_va(name_ptr)
                if name:
                    self.values.append((name, value))
        else:
            entry_size = 12
            for i in range(n_values):
                off = values_ptr + i * entry_size
                entry = self.view.read_bytes_va(off, entry_size)
                if len(entry) < entry_size:
                    break
                name_ptr, _, value = struct.unpack(f"{endian}IIi", entry)
                name = self.view.read_cstring_va(name_ptr)
                if name:
                    self.values.append((name, value))


class ProtobufCFieldInfo:
    def __init__(self, view: IdaBinaryView, ea: int):
        self.name = ""
        self.id = 0
        self.label = 0
        self.type = 0
        self.descriptor_ptr = 0
        self.flags = 0
        self._parse(view, ea)

    def _parse(self, view: IdaBinaryView, ea: int) -> None:
        p = view.ptr_size
        endian = ">" if view.big_endian else "<"
        if p == 8:
            fmt = f"{endian}QIIIII4xQQIIQQ"
        else:
            fmt = f"{endian}IIIIIIIIIIII"
        size = struct.calcsize(fmt)
        data = view.read_bytes_va(ea, size)
        if len(data) < size:
            return
        vals = struct.unpack(fmt, data)
        self.name = view.read_cstring_va(vals[0])
        self.id = vals[1]
        self.label = vals[2]
        self.type = vals[3]
        self.descriptor_ptr = vals[6]
        self.flags = vals[8]

    def valid(self) -> bool:
        return bool(self.name) and 0 < self.id < 0x20000000 and 0 <= self.type <= 16 and 0 <= self.label <= 3


class ProtobufCMessageInfo:
    def __init__(self, view: IdaBinaryView, ea: int):
        self.view = view
        self.ea = ea
        self.name = ""
        self.short_name = ""
        self.package_name = ""
        self.fields: List[ProtobufCFieldInfo] = []
        self._parse()

    def _parse(self) -> None:
        p = self.view.ptr_size
        endian = ">" if self.view.big_endian else "<"
        if p == 8:
            fmt = f"{endian}I4xQQQQQI4xQQI4xQQQQQ"
        else:
            fmt = f"{endian}IIIIIIIIIIIIIII"
        size = struct.calcsize(fmt)
        data = self.view.read_bytes_va(self.ea, size)
        if len(data) < size:
            return
        vals = struct.unpack(fmt, data)
        if vals[0] != PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC:
            return
        self.name = self.view.read_cstring_va(vals[1])
        self.short_name = self.view.read_cstring_va(vals[2])
        self.package_name = self.view.read_cstring_va(vals[4])
        n_fields = vals[6]
        fields_ptr = vals[7]
        if not self.name or not fields_ptr or n_fields <= 0 or n_fields > 10000:
            return
        field_size = struct.calcsize(f"{endian}QIIIII4xQQIIQQ") if p == 8 else struct.calcsize(f"{endian}IIIIIIIIIIII")
        for index in range(n_fields):
            field = ProtobufCFieldInfo(self.view, fields_ptr + index * field_size)
            if field.valid():
                self.fields.append(field)

    def valid(self) -> bool:
        return bool(self.name) and bool(self.fields)


def _scan_protobuf_c() -> List["descriptor_pb2.FileDescriptorProto"]:
    if descriptor_pb2 is None:
        return []
    view = IdaBinaryView()
    endian = ">" if view.big_endian else "<"
    msg_magic = struct.pack(f"{endian}I", PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC)
    enum_magic = struct.pack(f"{endian}I", PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC)
    enum_by_ea: Dict[int, ProtobufCEnumInfo] = {}
    message_infos: List[ProtobufCMessageInfo] = []

    for _, start_ea, seg_bytes in _iter_segment_data():
        base = 0
        while True:
            idx = seg_bytes.find(enum_magic, base)
            if idx == -1:
                break
            info = ProtobufCEnumInfo(view, start_ea + idx)
            if info.name and info.values:
                enum_by_ea[start_ea + idx] = info
            base = idx + 1
        base = 0
        while True:
            idx = seg_bytes.find(msg_magic, base)
            if idx == -1:
                break
            info = ProtobufCMessageInfo(view, start_ea + idx)
            if info.valid():
                message_infos.append(info)
            base = idx + 1

    if not message_infos:
        return []

    message_name_by_ea = {info.ea: info.short_name or info.name.split(".")[-1] for info in message_infos}
    results: Dict[str, descriptor_pb2.FileDescriptorProto] = {}

    for msg in message_infos:
        proto = descriptor_pb2.FileDescriptorProto()
        pkg = msg.package_name or ""
        message_name = msg.short_name or msg.name.split(".")[-1]
        proto.name = f"{_sanitize_ident(message_name).lower()}.proto"
        proto.package = pkg
        proto.syntax = "proto2"
        message = proto.message_type.add()
        message.name = message_name

        used_enums: Dict[str, ProtobufCEnumInfo] = {}
        for field_info in msg.fields:
            field = message.field.add()
            field.name = field_info.name
            field.number = field_info.id
            field.label = PROTOBUF_C_LABEL_TO_FIELD.get(field_info.label, descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL)
            field.type = PROTOBUF_C_TYPE_TO_FIELD.get(field_info.type, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)
            if field_info.type == 16 and field_info.descriptor_ptr:
                target_name = message_name_by_ea.get(field_info.descriptor_ptr)
                if target_name:
                    field.type_name = f".{pkg}.{target_name}" if pkg else f".{target_name}"
            elif field_info.type == 13 and field_info.descriptor_ptr:
                enum_info = enum_by_ea.get(field_info.descriptor_ptr)
                if enum_info:
                    enum_name = enum_info.short_name or enum_info.name.split(".")[-1]
                    field.type_name = f".{pkg}.{enum_name}" if pkg else f".{enum_name}"
                    used_enums[enum_name] = enum_info

        for enum_name, enum_info in used_enums.items():
            enum_proto = proto.enum_type.add()
            enum_proto.name = enum_name
            for name, value in enum_info.values:
                item = enum_proto.value.add()
                item.name = name
                item.number = value

        results[f"protobuf-c:{pkg}:{message_name}"] = proto
    return list(results.values())


def _field_type_name(field: "descriptor_pb2.FieldDescriptorProto", local_types: Dict[str, str], package: str) -> str:
    if field.type_name:
        type_name = field.type_name.lstrip(".")
        if package and type_name.startswith(package + "."):
            type_name = type_name[len(package) + 1 :]
        return local_types.get(type_name, type_name.split(".")[-1])
    return TYPE_TO_NAME.get(field.type, "bytes")


def _format_default_value(field: "descriptor_pb2.FieldDescriptorProto") -> Optional[str]:
    if not field.HasField("default_value"):
        return None
    if field.type == field.TYPE_STRING:
        return '"' + field.default_value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if field.type == field.TYPE_BYTES:
        escaped = field.default_value.encode("latin1", "backslashreplace").decode("ascii")
        return '"' + escaped.replace('"', '\\"') + '"'
    return field.default_value


def _field_option_strings(field: "descriptor_pb2.FieldDescriptorProto") -> List[str]:
    options: List[str] = []
    if field.HasField("options") and field.options.HasField("packed"):
        options.append(f"packed = {'true' if field.options.packed else 'false'}")
    default_value = _format_default_value(field)
    if default_value is not None:
        options.append(f"default = {default_value}")
    return options


def _render_enum(enum: "descriptor_pb2.EnumDescriptorProto", indent: int = 0) -> List[str]:
    pad = " " * indent
    lines = [f"{pad}enum {enum.name} {{"]
    for value in enum.value:
        lines.append(f"{pad}  {value.name} = {value.number};")
    lines.append(f"{pad}}}")
    return lines


def _render_message(message: "descriptor_pb2.DescriptorProto", local_types: Dict[str, str], package: str, indent: int = 0) -> List[str]:
    pad = " " * indent
    lines = [f"{pad}message {message.name} {{"]
    for enum in message.enum_type:
        lines.extend(_render_enum(enum, indent + 2))
        lines.append("")
    for nested in message.nested_type:
        if nested.options.map_entry:
            continue
        lines.extend(_render_message(nested, local_types, package, indent + 2))
        lines.append("")
    for field in message.field:
        label = LABEL_TO_TYPE.get(field.label, "optional")
        field_type = _field_type_name(field, local_types, package)
        line = f"{pad}  {label} {field_type} {field.name} = {field.number}"
        options = _field_option_strings(field)
        if options:
            line += " [" + ", ".join(options) + "]"
        line += ";"
        lines.append(line)
    lines.append(f"{pad}}}")
    return lines


def _build_type_index(proto: "descriptor_pb2.FileDescriptorProto") -> Dict[str, str]:
    index: Dict[str, str] = {}

    def visit_message(prefix: str, message: "descriptor_pb2.DescriptorProto") -> None:
        full = f"{prefix}.{message.name}" if prefix else message.name
        index[full] = message.name
        for enum in message.enum_type:
            index[f"{full}.{enum.name}"] = enum.name
        for nested in message.nested_type:
            if not nested.options.map_entry:
                visit_message(full, nested)

    for enum in proto.enum_type:
        name = f"{proto.package}.{enum.name}" if proto.package else enum.name
        index[name] = enum.name
    for message in proto.message_type:
        visit_message(proto.package, message)
    return index


def render_proto(proto: "descriptor_pb2.FileDescriptorProto") -> str:
    local_types = _build_type_index(proto)
    lines = [f'syntax = "{proto.syntax or "proto2"}";', ""]
    if proto.package:
        lines.append(f"package {proto.package};")
        lines.append("")
    for dependency in proto.dependency:
        lines.append(f'import "{dependency}";')
    if proto.dependency:
        lines.append("")
    for enum in proto.enum_type:
        lines.extend(_render_enum(enum))
        lines.append("")
    for message in proto.message_type:
        lines.extend(_render_message(message, local_types, proto.package))
        lines.append("")
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def render_python_module(proto: "descriptor_pb2.FileDescriptorProto", module_name: str) -> str:
    serialized = base64.b64encode(proto.SerializeToString()).decode("ascii")
    return f'''# Generated by IDA Auto Protobuf Struct Generator.
import base64 as _base64

from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    _base64.b64decode("{serialized}")
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "{module_name}", globals())
'''


def _compile_with_protoc(proto_path: str, output_dir: str) -> Tuple[bool, str]:
    protoc = shutil.which("protoc")
    if not protoc:
        return False, "protoc not found in PATH"
    command = [
        protoc,
        f"--proto_path={output_dir}",
        f"--python_out={output_dir}",
        os.path.basename(proto_path),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            cwd=output_dir,
        )
    except Exception as exc:
        return False, str(exc)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or f"protoc exited with {completed.returncode}").strip()
        return False, message
    return True, ""


def _write_output_files(
    proto: "descriptor_pb2.FileDescriptorProto",
    output_dir: str,
    binary_stem: str,
    ordinal: int,
) -> Tuple[str, str, str]:
    suffix = "" if ordinal == 0 else f"_{ordinal}"
    base = f"{binary_stem}{suffix}"
    proto_path = os.path.join(output_dir, f"{base}.proto")
    with open(proto_path, "w", encoding="utf-8", newline="\n") as proto_file:
        proto_file.write(render_proto(proto))

    pb2_path = os.path.join(output_dir, f"{base}_pb2.py")
    ok, reason = _compile_with_protoc(proto_path, output_dir)
    if ok and os.path.exists(pb2_path):
        return proto_path, pb2_path, "pb2"

    py_path = os.path.join(output_dir, f"{base}_pb.py")
    module_name = _sanitize_ident(f"{base}_pb")
    with open(py_path, "w", encoding="utf-8", newline="\n") as py_file:
        py_file.write(render_python_module(proto, module_name))
    return proto_path, py_path, f"fallback:{reason}"


def _collect_all_descriptors() -> Tuple[List["descriptor_pb2.FileDescriptorProto"], Dict[str, int]]:
    stats: Dict[str, int] = {}
    found: Dict[str, descriptor_pb2.FileDescriptorProto] = {}
    scanners = [
        ("cpp", _find_cpp_descriptors),
        ("go", _find_go_descriptors),
        ("raw", _find_raw_descriptors),
        ("protobuf-c", _scan_protobuf_c),
    ]
    for name, scanner in scanners:
        try:
            results = scanner()
        except Exception:
            results = []
        stats[name] = len(results)
        for proto in results:
            key = proto.name
            current = found.get(key)
            if current is None or _score_descriptor(proto) > _score_descriptor(current):
                found[key] = proto
    return sorted(found.values(), key=lambda item: item.name), stats


class AutoProtobufRunner:
    @staticmethod
    def run() -> bool:
        if descriptor_pb2 is None:
            ida_kernwin.warning("google.protobuf is not available in the current IDA Python environment.")
            return False
        input_path = ida_nalt.get_input_file_path()
        if not input_path:
            ida_kernwin.warning("Failed to resolve the input binary path.")
            return False

        output_dir = os.path.dirname(input_path)
        binary_stem = _sanitize_ident(os.path.splitext(os.path.basename(input_path))[0])
        descriptors, stats = _collect_all_descriptors()
        if not descriptors:
            ida_kernwin.warning(
                "No protobuf definitions were recovered.\n"
                "Scanners tried: cpp/raw/go/protobuf-c.\n"
                "This sample may strip descriptors and not use protobuf-c layouts."
            )
            return False

        generated: List[Tuple[str, str, str, str]] = []
        for index, proto in enumerate(descriptors):
            proto_path, py_path, mode = _write_output_files(proto, output_dir, binary_stem, index)
            generated.append((proto.name, proto_path, py_path, mode))

        lines = [f"Recovered {len(generated)} protobuf definition file(s)."]
        lines.append(f"cpp={stats.get('cpp', 0)}, go={stats.get('go', 0)}, raw={stats.get('raw', 0)}, protobuf-c={stats.get('protobuf-c', 0)}")
        for proto_name, proto_path, py_path, mode in generated[:10]:
            lines.append(proto_name)
            lines.append(f"  {proto_path}")
            lines.append(f"  {py_path}")
            lines.append(f"  mode={mode}")
        if len(generated) > 10:
            lines.append(f"... and {len(generated) - 10} more.")
        ida_kernwin.info("\n".join(lines))
        return True


class AutoProtobufPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        AutoProtobufRunner.run()


class AutoProtobufPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Recover protobuf message definitions from embedded descriptors and protobuf-c metadata."
    help = "Scan ELF/PE binaries for C++/Go/raw descriptors and protobuf-c structures."
    wanted_name = "Auto Protobuf Struct Generator"
    wanted_hotkey = "Ctrl-Alt-P"

    def init(self):
        return AutoProtobufPlugmod()


def PLUGIN_ENTRY():
    return AutoProtobufPlugin()
