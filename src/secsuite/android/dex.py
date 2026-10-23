"""Minimal reader for DEX (Dalvik Executable) files.

The reader understands the ``dex`` header and the identifier tables that
describe the constant pool: strings, type descriptors, prototypes, methods
and class definitions.  Bytecode is not decoded, which is all a static
triage pass over an APK needs in order to find suspicious strings, hooks and
class names.

Only the standard library is used.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass
from typing import NamedTuple

from .axml import AndroidParseError

__all__ = [
    "AndroidParseError",
    "DexInfo",
    "extract_strings",
    "parse_dex",
    "parse_proto_descriptors",
    "read_dex_from_zip",
]


DEX_MAGIC = b"dex\n"
"""Magic prefix of every DEX file."""

DEX_ENDIAN_CONSTANT = 0x12345678
"""Endian tag of a little endian DEX file."""

DEX_REVERSE_ENDIAN_CONSTANT = 0x78563412
"""Endian tag of a big endian DEX file, which this reader does not support."""

DEX_HEADER_SIZE = 0x70
"""Size of the fixed DEX header in bytes."""

STRING_ID_ITEM_SIZE = 4
TYPE_ID_ITEM_SIZE = 4
PROTO_ID_ITEM_SIZE = 12
METHOD_ID_ITEM_SIZE = 8
CLASS_DEF_ITEM_SIZE = 32

TYPE_LIST_ITEM_SIZE = 4
"""Size of the ``size`` field that heads a ``type_list``."""

MUTF8_NULL = b"\xc0\x80"
"""Two byte encoding of U+0000 used by modified UTF-8."""

PRIMITIVE_NAMES = {
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "V": "void",
}
"""Java names of the primitive type descriptors."""


@dataclass
class DexInfo:
    """The parts of a DEX file that are useful for static triage."""

    strings: list[str]
    types: list[str]
    methods: list[str]
    classes: list[str]

    def has_string(self, needle: str) -> bool:
        """True when any string of the pool contains the needle.

        The comparison is case insensitive, matching :meth:`find_strings`.
        """
        if not isinstance(needle, str):
            raise TypeError("needle must be a string")
        lowered = needle.lower()
        return any(lowered in candidate.lower() for candidate in self.strings)

    def find_strings(self, *needles: str) -> list[str]:
        """Strings containing ANY of the needles (case-insensitive)."""
        for needle in needles:
            if not isinstance(needle, str):
                raise TypeError("needles must be strings")
        lowered = [needle.lower() for needle in needles]
        if not lowered:
            return []
        found: list[str] = []
        for candidate in self.strings:
            lowered_candidate = candidate.lower()
            if any(needle in lowered_candidate for needle in lowered):
                found.append(candidate)
        return found

    def class_names(self) -> list[str]:
        """Class names of the DEX file in dotted Java notation.

        ``Lcom/example/Foo$Bar;`` is reported as ``com.example.Foo$Bar``.
        """
        return [_descriptor_to_java_name(descriptor) for descriptor in self.classes]


class _DexHeader(NamedTuple):
    """The fixed part of a DEX header."""

    version: int
    file_size: int
    header_size: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int


class _DexTables(NamedTuple):
    """Everything this reader extracts from a DEX file."""

    strings: list[str]
    types: list[str]
    protos: list[str]
    methods: list[str]
    classes: list[str]


def _descriptor_to_java_name(descriptor: str) -> str:
    """Convert a type descriptor into a dotted Java style name."""
    dimensions = 0
    while descriptor.startswith("["):
        dimensions += 1
        descriptor = descriptor[1:]
    if descriptor.startswith("L") and descriptor.endswith(";"):
        name = descriptor[1:-1].replace("/", ".")
    else:
        name = PRIMITIVE_NAMES.get(descriptor, descriptor)
    return name + "[]" * dimensions


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidParseError(message)


def _parse_header(data: bytes) -> _DexHeader:
    """Decode and validate the fixed DEX header."""
    _require(
        len(data) >= DEX_HEADER_SIZE,
        f"DEX file is truncated: {len(data)} bytes, the header needs {DEX_HEADER_SIZE}",
    )
    _require(
        data[:4] == DEX_MAGIC,
        f"not a DEX file: the magic must start with {DEX_MAGIC!r}",
    )
    version_bytes = data[4:7]
    _require(
        version_bytes.isdigit(),
        f"not a DEX file: '{version_bytes.decode('latin-1')}' is not a version number",
    )
    version = int(version_bytes)
    _require(
        data[7] == 0,
        "not a DEX file: the magic is not terminated by a zero byte",
    )

    endian_tag = struct.unpack_from("<I", data, 40)[0]
    if endian_tag == DEX_REVERSE_ENDIAN_CONSTANT:
        raise AndroidParseError(
            "big endian DEX files are not supported by this reader"
        )
    _require(
        endian_tag == DEX_ENDIAN_CONSTANT,
        f"invalid DEX endian tag 0x{endian_tag:08x}",
    )

    (
        file_size,
        header_size,
        _endian,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = struct.unpack_from("<20I", data, 32)

    return _DexHeader(
        version=version,
        file_size=file_size,
        header_size=header_size,
        link_size=link_size,
        link_off=link_off,
        map_off=map_off,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        proto_ids_size=proto_ids_size,
        proto_ids_off=proto_ids_off,
        field_ids_size=field_ids_size,
        field_ids_off=field_ids_off,
        method_ids_size=method_ids_size,
        method_ids_off=method_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
        data_size=data_size,
        data_off=data_off,
    )


def _read_uleb128(data: bytes, position: int, limit: int) -> tuple[int, int]:
    """Read an unsigned LEB128 value, returning the value and the new position."""
    result = 0
    shift = 0
    while True:
        _require(
            position < limit,
            "truncated DEX file: ULEB128 value runs past the end of the file",
        )
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        _require(shift <= 35, "truncated DEX file: ULEB128 value is too large")


def _read_string_data(data: bytes, position: int) -> tuple[str, int]:
    """Decode a ``string_data_item`` and return the text and the new position.

    The item starts with the number of UTF-16 code units of the string.  When
    that count carries the ``0x8000`` marker the real length sits in the low
    bits and a second ULEB128 gives the size of the payload; otherwise the
    first ULEB128 is the size of the payload itself.  The payload is followed
    by a zero byte.
    """
    limit = len(data)
    marker, position = _read_uleb128(data, position, limit)
    if marker & 0x8000:
        byte_length, position = _read_uleb128(data, position, limit)
    else:
        byte_length = marker
    end = position + byte_length
    if end > limit:
        raise AndroidParseError(
            f"truncated DEX file: string data needs {byte_length} byte(s) at "
            f"offset {position} but only {limit - position} remain"
        )
    payload = data[position:end]
    position = end

    if payload.endswith(b"\x00"):
        payload = payload[:-1]
    else:
        extension = _utf8_tail_extension(payload, data, position, limit)
        payload += extension
        position += len(extension)
        if position < limit:
            position += 1

    text = payload.replace(MUTF8_NULL, b"\x00").decode("utf-8", errors="replace")
    return text, position


def _utf8_sequence_length(lead: int) -> int:
    """Number of bytes in the UTF-8 sequence introduced by ``lead``.

    Returns zero for bytes that cannot start a sequence.
    """
    if lead < 0x80:
        return 1
    if lead < 0xC0:
        return 0
    if lead < 0xE0:
        return 2
    if lead < 0xF0:
        return 3
    if lead < 0xF8:
        return 4
    return 0


def _utf8_tail_is_truncated(payload: bytes) -> bool:
    """True when the payload ends in the middle of a multi byte sequence.

    The length prefix of a DEX string counts UTF-16 code units, so a string
    with characters outside ASCII is cut short when the payload size is
    derived from that count.
    """
    continuations = 0
    for byte in reversed(payload[-4:]):
        if 0x80 <= byte < 0xC0:
            continuations += 1
            continue
        total = _utf8_sequence_length(byte)
        return total != 0 and continuations + 1 < total
    return False


def _utf8_tail_extension(
    payload: bytes, data: bytes, position: int, limit: int
) -> bytes:
    """Return the bytes that complete a truncated UTF-8 sequence."""
    if not _utf8_tail_is_truncated(payload):
        return b""
    extra = bytearray()
    while len(extra) < 3 and position + len(extra) < limit:
        byte = data[position + len(extra)]
        if not 0x80 <= byte < 0xC0:
            break
        extra.append(byte)
    return bytes(extra)


def _parse_strings(data: bytes, header: _DexHeader) -> list[str]:
    """Decode the string pool of the DEX file."""
    count = header.string_ids_size
    if count == 0:
        return []
    offsets_base = header.string_ids_off
    _require(
        offsets_base + count * STRING_ID_ITEM_SIZE <= len(data),
        "truncated DEX file: the string id table is incomplete",
    )
    strings: list[str] = []
    for index in range(count):
        offset = struct.unpack_from("<I", data, offsets_base + index * STRING_ID_ITEM_SIZE)[0]
        _require(
            offset < len(data),
            f"truncated DEX file: string {index} points past the end of the file",
        )
        text, _ = _read_string_data(data, offset)
        strings.append(text)
    return strings


def _parse_types(data: bytes, header: _DexHeader, strings: list[str]) -> list[str]:
    """Decode the type id table into type descriptors."""
    count = header.type_ids_size
    if count == 0:
        return []
    base = header.type_ids_off
    _require(
        base + count * TYPE_ID_ITEM_SIZE <= len(data),
        "truncated DEX file: the type id table is incomplete",
    )
    types: list[str] = []
    for index in range(count):
        descriptor_index = struct.unpack_from("<I", data, base + index * TYPE_ID_ITEM_SIZE)[0]
        _require(
            descriptor_index < len(strings),
            f"truncated DEX file: type {index} refers to unknown string "
            f"{descriptor_index}",
        )
        types.append(strings[descriptor_index])
    return types


def _parse_type_list(data: bytes, offset: int, types: list[str]) -> list[str]:
    """Decode a ``type_list`` into the descriptors it holds."""
    if offset == 0:
        return []
    _require(
        offset + TYPE_LIST_ITEM_SIZE <= len(data),
        "truncated DEX file: a type list points past the end of the file",
    )
    size = struct.unpack_from("<I", data, offset)[0]
    _require(
        offset + TYPE_LIST_ITEM_SIZE + size * 2 <= len(data),
        "truncated DEX file: a type list is incomplete",
    )
    parameters: list[str] = []
    for index in range(size):
        type_index = struct.unpack_from("<H", data, offset + TYPE_LIST_ITEM_SIZE + index * 2)[0]
        _require(
            type_index < len(types),
            f"truncated DEX file: a type list refers to unknown type {type_index}",
        )
        parameters.append(types[type_index])
    return parameters


def _parse_protos(
    data: bytes, header: _DexHeader, strings: list[str], types: list[str]
) -> list[str]:
    """Decode the proto id table into readable signatures.

    A signature looks like ``(Ljava/lang/String;I)V``.
    """
    count = header.proto_ids_size
    if count == 0:
        return []
    base = header.proto_ids_off
    _require(
        base + count * PROTO_ID_ITEM_SIZE <= len(data),
        "truncated DEX file: the proto id table is incomplete",
    )
    protos: list[str] = []
    for index in range(count):
        shorty_index, return_type_index, parameters_off = struct.unpack_from(
            "<3I", data, base + index * PROTO_ID_ITEM_SIZE
        )
        _require(
            shorty_index < len(strings),
            f"truncated DEX file: proto {index} refers to unknown shorty index "
            f"{shorty_index}",
        )
        _require(
            return_type_index < len(types),
            f"truncated DEX file: proto {index} refers to unknown type "
            f"{return_type_index}",
        )
        parameters = _parse_type_list(data, parameters_off, types)
        signature = "(" + "".join(parameters) + ")" + types[return_type_index]
        protos.append(signature)
    return protos


def _parse_methods(
    data: bytes, header: _DexHeader, strings: list[str], types: list[str]
) -> list[str]:
    """Decode the method id table into ``descriptor->name`` strings."""
    count = header.method_ids_size
    if count == 0:
        return []
    base = header.method_ids_off
    _require(
        base + count * METHOD_ID_ITEM_SIZE <= len(data),
        "truncated DEX file: the method id table is incomplete",
    )
    methods: list[str] = []
    for index in range(count):
        class_index, _proto_index, name_index = struct.unpack_from(
            "<HHI", data, base + index * METHOD_ID_ITEM_SIZE
        )
        _require(
            class_index < len(types),
            f"truncated DEX file: method {index} refers to unknown type "
            f"{class_index}",
        )
        _require(
            name_index < len(strings),
            f"truncated DEX file: method {index} refers to unknown string "
            f"{name_index}",
        )
        methods.append(f"{types[class_index]}->{strings[name_index]}")
    return methods


def _parse_classes(data: bytes, header: _DexHeader, types: list[str]) -> list[str]:
    """Decode the class definitions into the descriptors of the classes."""
    count = header.class_defs_size
    if count == 0:
        return []
    base = header.class_defs_off
    _require(
        base + count * CLASS_DEF_ITEM_SIZE <= len(data),
        "truncated DEX file: the class definition table is incomplete",
    )
    classes: list[str] = []
    for index in range(count):
        class_index = struct.unpack_from("<I", data, base + index * CLASS_DEF_ITEM_SIZE)[0]
        _require(
            class_index < len(types),
            f"truncated DEX file: class {index} refers to unknown type "
            f"{class_index}",
        )
        classes.append(types[class_index])
    return classes


def _parse_dex(data: bytes) -> _DexTables:
    """Decode a DEX file into its identifier tables."""
    header = _parse_header(data)
    strings = _parse_strings(data, header)
    types = _parse_types(data, header, strings)
    protos = _parse_protos(data, header, strings, types)
    methods = _parse_methods(data, header, strings, types)
    classes = _parse_classes(data, header, types)
    return _DexTables(
        strings=strings, types=types, protos=protos, methods=methods, classes=classes
    )


def parse_dex(data: bytes) -> DexInfo:
    """Parse a DEX file and return its string, type, method and class tables.

    Raises AndroidParseError when the file is not a valid DEX image.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_dex expects a bytes-like object")
    tables = _parse_dex(bytes(data))
    return DexInfo(
        strings=tables.strings,
        types=tables.types,
        methods=tables.methods,
        classes=tables.classes,
    )


def parse_proto_descriptors(data: bytes) -> list[str]:
    """Return the prototype signatures of a DEX file, for example ``(I)V``."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_proto_descriptors expects a bytes-like object")
    return _parse_dex(bytes(data)).protos


def extract_strings(data: bytes) -> list[str]:
    """Return the string pool of a DEX file."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("extract_strings expects a bytes-like object")
    return _parse_dex(bytes(data)).strings


def read_dex_from_zip(zip_path: str) -> bytes:
    """Return the bytes of classes.dex from an APK zip, raising AndroidParseError if absent."""
    try:
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
            candidates = [name for name in names if name == "classes.dex"]
            if not candidates:
                candidates = [
                    name for name in names if name.endswith("/classes.dex")
                ]
            if not candidates:
                raise AndroidParseError(
                    f"{zip_path} does not contain a classes.dex entry"
                )
            return archive.read(candidates[0])
    except zipfile.BadZipFile as exc:
        raise AndroidParseError(f"{zip_path} is not a valid zip archive: {exc}") from exc
    except OSError as exc:
        raise AndroidParseError(f"cannot read {zip_path}: {exc}") from exc
