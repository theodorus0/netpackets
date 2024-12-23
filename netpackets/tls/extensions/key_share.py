import struct

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension
from netpackets.tls.extensions.supported_groups import EncryptionGroup

@register_extension
class KeyShareClientHello(TLSExtension):
    type = ExtensionType.key_share
    keys: dict[EncryptionGroup, bytes]

    def __init__(self, keys: dict[EncryptionGroup, bytes]):
        self.keys = keys

    @property
    def length(self):
        return 2 + self.list_length

    @property
    def list_length(self):
        return sum(2 + 2 + len(key) for group, key in self.keys.items())

    def build_content(self) -> bytes:
        result = struct.pack("!H", self.list_length)
        for group, key in self.keys.items():
            result += struct.pack("!HH", group, len(key)) + key
        return result

    @staticmethod
    def parse_content(raw: bytes):
        list_length, = struct.unpack_from("!H", raw)
        offset = 2
        keys = {}
        while offset - 2 < list_length:
            group, ke_len, = struct.unpack_from("!HH", raw, offset)
            key = raw[offset + 4:offset + 4 + ke_len]
            keys[group] = key
            offset += 4 + ke_len
        return KeyShareClientHello(keys)
