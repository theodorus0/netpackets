import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


class NameType(IntEnum):
    Hostname = 0


class ServerName:
    name_type: NameType
    server_name: str

    def __init__(self, name: str, name_type: NameType = NameType.Hostname):
        self.server_name = name
        self.name_type = name_type

    @property
    def name_length(self):
        return len(self.server_name)

    @property
    def full_length(self):
        return 3 + self.name_length

    def build(self):
        return struct.pack("!BH", self.name_type, self.name_length) + self.server_name.encode()

    @staticmethod
    def parse(raw: bytes):
        name_type, name_length = struct.unpack_from("!BH", raw)
        return ServerName(raw[3:3 + name_length].decode(), NameType(name_type))

    def __repr__(self):
        return f"({self.name_type.name} {self.server_name})"


@register_extension
class ServerNameIndication(TLSExtension):
    type = ExtensionType.server_name
    names: list[ServerName]

    def __init__(self, names: list[ServerName] = None):
        if names is None:
            names = []
        self.names = names

    @property
    def length(self):
        return 2 + self.list_length

    @property
    def list_length(self):
        return sum(name.full_length for name in self.names)

    def build_content(self) -> bytes:
        result = struct.pack("!H", self.list_length)
        for name in self.names:
            result += name.build()
        return result

    @staticmethod
    def parse_content(raw: bytes):
        list_length, = struct.unpack_from("!H", raw)
        offset = 2
        names = []
        while offset < 2 + list_length:
            parse = ServerName.parse(raw[offset:])
            names.append(parse)
            offset += parse.full_length
        return ServerNameIndication(names)
