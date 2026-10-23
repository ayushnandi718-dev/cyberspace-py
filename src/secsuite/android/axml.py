"""Decoder for Android binary XML (AXML).

APKs ship ``AndroidManifest.xml`` and compiled layout resources in a binary
form that mirrors the AOSP ``ResourceTypes.h`` chunk layout.  The decoder
below walks that chunk tree, decodes the string pool and resolves attribute
values into their textual form.

Chunk types handled here::

    0x0001  RES_STRING_POOL_TYPE
    0x0003  RES_XML_TYPE                 (file header)
    0x0100  RES_XML_START_NAMESPACE_TYPE
    0x0101  RES_XML_END_NAMESPACE_TYPE
    0x0102  RES_XML_START_ELEMENT_TYPE
    0x0103  RES_XML_END_ELEMENT_TYPE
    0x0104  RES_XML_CDATA_TYPE
    0x0180  RES_XML_RESOURCE_MAP_TYPE

Only the standard library is used.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

__all__ = [
    "AndroidParseError",
    "XmlAttribute",
    "XmlNode",
    "parse_axml",
]


class AndroidParseError(Exception):
    """Raised when an Android binary resource cannot be decoded.

    Every parse failure in this package is reported with this exception so
    that callers can distinguish "this file is not a valid Android binary
    resource" from an arbitrary ``struct.error`` or ``UnicodeDecodeError``.
    """


# --- Chunk identifiers ---------------------------------------------------------

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

NO_ENTRY = 0xFFFFFFFF
"""Value used by ``ResStringPool_ref`` fields that carry no reference."""

ANDROID_NAMESPACE_URI = "http://schemas.android.com/apk/res/android"
"""URI of the framework resource namespace, i.e. the ``android:`` prefix."""

ANDROID_NAMESPACE_PREFIX = "android"

# --- Res_value data types ------------------------------------------------------

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1F
TYPE_INT_COLOR_ARGB4 = 0x1D
TYPE_INT_COLOR_RGB4 = 0x1E

TYPE_FIRST_INT = 0x10
TYPE_LAST_INT = 0x1F

# --- String pool flags ---------------------------------------------------------

SORTED_FLAG = 0x001
UTF8_FLAG = 0x100

RES_STRING_POOL_HEADER_SIZE = 28
"""Size of ``ResStringPool_header``: 8 byte chunk header plus five uint32."""

RES_XML_NODE_HEADER_SIZE = 16
"""Size of ``ResXMLTree_node``: chunk header plus line number and comment."""

RES_XML_ATTR_EXT_SIZE = 20
"""Size of ``ResXMLTree_attrExt``, i.e. the offset of the first attribute."""

RES_XML_ATTRIBUTE_SIZE = 20
"""Size of ``ResXMLTree_attribute`` including the embedded ``Res_value``."""


@dataclass(frozen=True)
class XmlAttribute:
    """A single attribute of an element with its value already resolved.

    ``name`` is the local name of the attribute, prefixed with ``android:``
    when the attribute lives in the framework namespace.  ``value`` is the
    textual form of the value: the decoded string for string attributes, and
    a type specific rendering (for example ``"@0x7f020000"``) otherwise.
    """

    name: str
    value: str
    resource_id: int | None = None
    raw_value: int | None = None
    value_type: int | None = None


@dataclass
class XmlNode:
    """An element of a decoded AXML document."""

    name: str
    attributes: list[XmlAttribute] = field(default_factory=list)
    children: list[XmlNode] = field(default_factory=list)

    def attr(self, name: str) -> str | None:
        """Value of the named attribute, or None if absent.

        The exact attribute name is matched first; when no attribute carries
        that exact name, attributes are matched on their local name so that
        ``"versionCode"`` finds ``"android:versionCode"``.
        """
        found = self.attr_node(name)
        return None if found is None else found.value

    def attr_node(self, name: str) -> XmlAttribute | None:
        """The named attribute, or None if the element does not carry it."""
        for attribute in self.attributes:
            if attribute.name == name:
                return attribute
        if ":" not in name:
            for attribute in self.attributes:
                if attribute.name.rsplit(":", 1)[-1] == name:
                    return attribute
        return None

    def find_all(self, name: str) -> list[XmlNode]:
        """All descendants with the given tag name, in document order."""
        matches: list[XmlNode] = []
        for child in self.children:
            if _tag_matches(child.name, name):
                matches.append(child)
            matches.extend(child.find_all(name))
        return matches

    def find(self, name: str) -> XmlNode | None:
        """First descendant with the given tag name, or None."""
        for child in self.children:
            if _tag_matches(child.name, name):
                return child
            found = child.find(name)
            if found is not None:
                return found
        return None

    def __iter__(self):
        """Iterate over the direct children of this node."""
        return iter(self.children)


def _tag_matches(candidate: str, query: str) -> bool:
    """True when ``candidate`` names the tag ``query``.

    A query without a prefix also matches a prefixed tag, so that looking for
    ``"activity"`` finds an ``"android:activity"`` element.
    """
    if candidate == query:
        return True
    if ":" in query:
        return False
    return candidate.rsplit(":", 1)[-1] == query


class _Reader:
    """Bounds checked little endian reader over a bytes buffer."""

    __slots__ = ("_data", "pos", "limit")

    def __init__(self, data: bytes, pos: int = 0, limit: int | None = None) -> None:
        self._data = data
        self.pos = pos
        self.limit = len(data) if limit is None else limit

    def remaining(self) -> int:
        """Number of bytes left before the reader limit."""
        return max(0, self.limit - self.pos)

    def _need(self, count: int, what: str) -> int:
        end = self.pos + count
        if count < 0 or end > self.limit:
            raise AndroidParseError(
                f"truncated AXML: {what} needs {count} byte(s) at offset "
                f"{self.pos} but only {self.remaining()} remain"
            )
        self.pos = end
        return end

    def u8(self, what: str = "byte") -> int:
        end = self._need(1, what)
        return self._data[end - 1]

    def u16(self, what: str = "uint16") -> int:
        end = self._need(2, what)
        return struct.unpack_from("<H", self._data, end - 2)[0]

    def u32(self, what: str = "uint32") -> int:
        end = self._need(4, what)
        return struct.unpack_from("<I", self._data, end - 4)[0]

    def take(self, count: int, what: str = "bytes") -> bytes:
        end = self._need(count, what)
        return self._data[end - count : end]

    def skip(self, count: int, what: str = "padding") -> None:
        self._need(count, what)


def _read_length8(reader: _Reader) -> int:
    """Read a one or two byte length with the high bit continuation scheme."""
    first = reader.u8("string length byte")
    if first & 0x80:
        second = reader.u8("string length continuation byte")
        return ((first & 0x7F) << 8) | second
    return first


def _read_length16(reader: _Reader) -> int:
    """Read a one or two unit UTF-16 length with the high bit extension."""
    value = reader.u16("utf-16 string length")
    if value & 0x8000:
        low = reader.u16("utf-16 string length extension")
        return ((value & 0x7FFF) << 16) | low
    return value


def _decode_utf16_string(reader: _Reader) -> str:
    """Decode one UTF-16 string of a string pool."""
    length = _read_length16(reader)
    raw = reader.take(length * 2, "utf-16 string data")
    if reader.remaining() >= 2:
        reader.skip(2, "utf-16 string terminator")
    return raw.decode("utf-16-le", errors="replace")


def _decode_utf8_string(reader: _Reader) -> str:
    """Decode one UTF-8 string of a string pool."""
    _read_length8(reader)
    byte_length = _read_length8(reader)
    raw = reader.take(byte_length, "utf-8 string data")
    if reader.remaining() >= 1:
        reader.skip(1, "utf-8 string terminator")
    return raw.decode("utf-8", errors="replace")


def _decode_string_pool(data: bytes, chunk_start: int, chunk_end: int) -> list[str]:
    """Decode a ``RES_STRING_POOL_TYPE`` chunk into a list of strings."""
    reader = _Reader(data, chunk_start, chunk_end)
    reader.u16("string pool chunk type")
    header_size = reader.u16("string pool header size")
    reader.u32("string pool chunk size")
    string_count = reader.u32("string count")
    reader.u32("style count")
    flags = reader.u32("string pool flags")
    strings_start = reader.u32("strings start")
    reader.u32("styles start")

    if string_count > chunk_end - chunk_start:
        raise AndroidParseError(
            f"string pool claims {string_count} strings but the chunk holds "
            f"only {chunk_end - chunk_start} bytes"
        )

    offsets_base = chunk_start + max(header_size, RES_STRING_POOL_HEADER_SIZE)
    if offsets_base + 4 * string_count > chunk_end:
        raise AndroidParseError("string pool offset table is truncated")

    data_base = chunk_start + strings_start
    if data_base > chunk_end:
        raise AndroidParseError("string pool data starts past the end of the chunk")

    is_utf8 = bool(flags & UTF8_FLAG)
    strings: list[str] = []
    for index in range(string_count):
        offset = struct.unpack_from("<I", data, offsets_base + 4 * index)[0]
        position = data_base + offset
        if position >= chunk_end:
            raise AndroidParseError(
                f"string {index} points to offset {position} past the end of the "
                "string pool"
            )
        string_reader = _Reader(data, position, chunk_end)
        if is_utf8:
            strings.append(_decode_utf8_string(string_reader))
        else:
            strings.append(_decode_utf16_string(string_reader))
    return strings


def _format_value(
    value_type: int, data: int, raw_value_index: int, pool: list[str]
) -> tuple[str, int | None]:
    """Render a ``Res_value`` as text.

    Returns the textual value and the raw typed integer, which is None for
    string values because those carry no meaningful numeric payload.
    """
    if value_type == TYPE_STRING:
        text: str | None = None
        if raw_value_index != NO_ENTRY and raw_value_index < len(pool):
            text = pool[raw_value_index]
        if text is None:
            text = _pool_string(pool, data)
        return text, None
    if value_type == TYPE_REFERENCE:
        return f"@0x{data:08x}", data
    if value_type == TYPE_ATTRIBUTE:
        return f"?0x{data:08x}", data
    if value_type == TYPE_INT_BOOLEAN:
        return ("true" if data != 0 else "false"), data
    if value_type == TYPE_INT_HEX:
        return f"0x{data:x}", data
    return str(data), data


def _pool_string(pool: list[str], index: int) -> str:
    """Return the string at ``index`` of the pool."""
    if index == NO_ENTRY:
        raise AndroidParseError("string reference is empty")
    if index >= len(pool):
        raise AndroidParseError(
            f"string index {index} is out of range, the pool holds {len(pool)} strings"
        )
    return pool[index]


class _AxmlParser:
    """Walks the chunk tree of an AXML document."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pool: list[str] = []
        self._resource_ids: list[int] = []
        self._prefix_to_uri: dict[str, str] = {}
        self._stack: list[XmlNode] = []
        self._root: XmlNode | None = None
        self._attribute_index = 0

    # -- namespace helpers ------------------------------------------------

    def _uri_for(self, uri_index: int) -> str | None:
        """Resolve a namespace reference to the URI it stands for.

        The reference is an index into the string pool.  Writers normally
        store the URI itself there, but some store the prefix instead, so a
        pool entry that matches a declared prefix is translated through the
        prefix to URI map.
        """
        if uri_index == NO_ENTRY:
            return None
        if uri_index >= len(self._pool):
            raise AndroidParseError(
                f"namespace index {uri_index} is out of range, the pool holds "
                f"{len(self._pool)} strings"
            )
        text = self._pool[uri_index]
        return self._prefix_to_uri.get(text, text)

    def _qualify(self, local: str, uri_index: int) -> str:
        """Prefix a local name with ``android:`` for the framework namespace.

        Names in any other namespace are reported with their local name
        only.
        """
        uri = self._uri_for(uri_index)
        if uri == ANDROID_NAMESPACE_URI:
            return f"{ANDROID_NAMESPACE_PREFIX}:{local}"
        return local

    # -- chunk handlers ---------------------------------------------------

    def _handle_namespace(self, position: int, end: int, closing: bool) -> None:
        reader = _Reader(self._data, position, end)
        reader.skip(RES_XML_NODE_HEADER_SIZE, "namespace node header")
        prefix_index = reader.u32("namespace prefix index")
        uri_index = reader.u32("namespace uri index")
        prefix = _pool_string(self._pool, prefix_index)
        uri = _pool_string(self._pool, uri_index)
        if closing:
            self._prefix_to_uri.pop(prefix, None)
        else:
            self._prefix_to_uri[prefix] = uri

    def _handle_start_element(self, position: int, end: int, header_size: int) -> None:
        reader = _Reader(self._data, position, end)
        reader.skip(RES_XML_NODE_HEADER_SIZE, "element node header")
        uri_index = reader.u32("element namespace index")
        name_index = reader.u32("element name index")
        attribute_start = reader.u16("attribute start offset")
        attribute_size = reader.u16("attribute size")
        attribute_count = reader.u16("attribute count")

        ext_base = position + max(header_size, RES_XML_NODE_HEADER_SIZE)
        if attribute_start:
            base = ext_base + attribute_start
        else:
            base = ext_base + RES_XML_ATTR_EXT_SIZE
        stride = (
            attribute_size
            if attribute_size >= RES_XML_ATTRIBUTE_SIZE
            else RES_XML_ATTRIBUTE_SIZE
        )

        attributes: list[XmlAttribute] = []
        for _ in range(attribute_count):
            attribute_reader = _Reader(self._data, base, end)
            attribute_uri = attribute_reader.u32("attribute namespace index")
            attribute_name = attribute_reader.u32("attribute name index")
            raw_value_index = attribute_reader.u32("attribute raw value index")
            attribute_reader.u16("attribute value size")
            attribute_reader.u8("attribute reserved byte")
            value_type = attribute_reader.u8("attribute value type")
            value_data = attribute_reader.u32("attribute value data")

            local = _pool_string(self._pool, attribute_name)
            value, raw_value = _format_value(
                value_type, value_data, raw_value_index, self._pool
            )
            resource_id: int | None = None
            if self._attribute_index < len(self._resource_ids):
                resource_id = self._resource_ids[self._attribute_index]
            self._attribute_index += 1

            attributes.append(
                XmlAttribute(
                    name=self._qualify(local, attribute_uri),
                    value=value,
                    resource_id=resource_id,
                    raw_value=raw_value,
                    value_type=value_type,
                )
            )
            base += stride

        node = XmlNode(name=self._qualify(_pool_string(self._pool, name_index), uri_index))
        node.attributes = attributes
        if self._stack:
            self._stack[-1].children.append(node)
        elif self._root is None:
            self._root = node
        self._stack.append(node)

    def _handle_end_element(self, position: int, end: int) -> None:
        reader = _Reader(self._data, position, end)
        reader.skip(RES_XML_NODE_HEADER_SIZE, "element node header")
        reader.u32("element namespace index")
        reader.u32("element name index")
        if len(self._stack) > 1:
            self._stack.pop()

    # -- driver ------------------------------------------------------------

    def parse(self) -> XmlNode:
        data = self._data
        if len(data) < 8:
            raise AndroidParseError("AXML file is too short to hold a header")
        file_type, file_header_size, file_chunk_size = struct.unpack_from("<HHI", data, 0)
        if file_type != RES_XML_TYPE:
            raise AndroidParseError(
                f"not an Android binary XML file, chunk type is 0x{file_type:04x}"
            )
        limit = len(data)
        if file_chunk_size >= 8:
            limit = min(file_chunk_size, len(data))

        position = max(file_header_size, 8)
        while position + 8 <= limit:
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, position)
            if chunk_size < 8:
                raise AndroidParseError(
                    f"invalid chunk size {chunk_size} at offset {position}"
                )
            chunk_end = position + chunk_size
            if chunk_end > limit:
                raise AndroidParseError(
                    f"chunk of type 0x{chunk_type:04x} at offset {position} extends "
                    "past the end of the file"
                )
            self._handle_chunk(chunk_type, position, chunk_end, header_size)
            position = (chunk_end + 3) & ~3

        if self._root is None:
            raise AndroidParseError("AXML document does not contain a root element")
        return self._root

    def _handle_chunk(
        self, chunk_type: int, position: int, chunk_end: int, header_size: int
    ) -> None:
        if chunk_type == RES_STRING_POOL_TYPE:
            if not self._pool:
                self._pool = _decode_string_pool(self._data, position, chunk_end)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            self._handle_resource_map(position, chunk_end, header_size)
        elif chunk_type == RES_XML_START_NAMESPACE_TYPE:
            self._handle_namespace(position, chunk_end, closing=False)
        elif chunk_type == RES_XML_END_NAMESPACE_TYPE:
            self._handle_namespace(position, chunk_end, closing=True)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            self._handle_start_element(position, chunk_end, header_size)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            self._handle_end_element(position, chunk_end)
        elif chunk_type == RES_XML_CDATA_TYPE:
            return

    def _handle_resource_map(
        self, position: int, chunk_end: int, header_size: int
    ) -> None:
        base = position + max(header_size, 8)
        count = max(0, (chunk_end - base) // 4)
        if count == 0:
            return
        self._resource_ids = list(
            struct.unpack_from(f"<{count}I", self._data, base)
        )


def parse_axml(data: bytes) -> XmlNode:
    """Parse an Android binary XML document and return its root element.

    Raises AndroidParseError on malformed input.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_axml expects a bytes-like object")
    return _AxmlParser(bytes(data)).parse()
