import struct

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


@register_extension
class ALPN(TLSExtension):
    type = ExtensionType.application_layer_protocol_negotiation
    protocols: list[str]

    def __init__(self, protocols: list[str] = None):
        if protocols is None:
            protocols = []
        self.protocols = protocols

    @property
    def length(self):
        return self.list_length + 2

    @property
    def list_length(self):
        return sum(1 + len(proto) for proto in self.protocols)

    def build_content(self) -> bytes:
        result = struct.pack("!H", self.list_length)
        for proto in self.protocols:
            string_length = len(proto)
            result += struct.pack(f"!B{string_length}s", string_length, proto.encode())
        return result

    @staticmethod
    def parse_content(raw: bytes):
        list_length, = struct.unpack_from("!H", raw)

        offset = 2
        protocols = []
        while offset - 2 < list_length:
            length, = struct.unpack_from("!B", raw, offset)
            protocols.append(raw[offset + 1:offset + 1 + length].decode())
            offset += length + 1
        return ALPN(protocols)
