import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


class EncryptionGroup(IntEnum):
    secp256r1 = 0x17
    secp384r1 = 0x18
    secp521r1 = 0x19
    x25519 = 0x1d
    x448 = 0x1e

    ffdhe2048 = 0x100
    ffdhe3072 = 0x101
    ffdhe4096 = 0x102
    ffdhe6144 = 0x103
    ffdhe8192 = 0x104


@register_extension
class SupportedGroups(TLSExtension):
    type = ExtensionType.supported_groups
    groups: list[EncryptionGroup]

    def __init__(self, groups: list[EncryptionGroup]):
        self.groups = groups

    @property
    def length(self):
        return self.list_length + 2

    @property
    def list_length(self):
        return len(self.groups) * 2

    def build_content(self) -> bytes:
        result = struct.pack("!H", self.list_length)
        for gr in self.groups:
            result += struct.pack("!H", gr)
        return result

    @staticmethod
    def parse_content(raw: bytes) -> "SupportedGroups":
        list_len, = struct.unpack_from("!H", raw)
        groups = []
        for gr, in struct.iter_unpack("!H", raw[2:2 + list_len]):
            groups.append(EncryptionGroup(gr))
        return SupportedGroups(groups)
