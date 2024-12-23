import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


class ECPointFormat(IntEnum):
    Uncompressed = 0


@register_extension
class ECPointFormatList(TLSExtension):
    type = ExtensionType.ec_point_formats
    formats: list[ECPointFormat]

    def __init__(self, formats: list[ECPointFormat]):
        self.formats = formats

    def build_content(self) -> bytes:
        result = struct.pack("!B", self.list_length)
        for fmt in self.formats:
            result += struct.pack("!B", fmt)
        return result

    @property
    def length(self):
        return 1 + self.list_length

    @property
    def list_length(self):
        return len(self.formats)

    @staticmethod
    def parse_content(raw: bytes):
        length, = struct.unpack_from("!B", raw)
        formats = []
        for pf, in struct.iter_unpack("!B", raw[1:1 + length]):
            formats.append(ECPointFormat(pf))
        return ECPointFormatList(formats)
