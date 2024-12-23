import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


class PSKExchangeMode(IntEnum):
    psk_only = 0
    psk_dhe = 1


@register_extension
class PSKKeyExchangeModes(TLSExtension):
    type = ExtensionType.psk_key_exchange_modes
    modes: list[PSKExchangeMode]

    @property
    def length(self):
        return 1 + len(self.modes)

    def __init__(self, modes: list[PSKExchangeMode]):
        self.modes = modes

    def build_content(self) -> bytes:
        result = struct.pack("!B", len(self.modes))
        for mode in self.modes:
            result += struct.pack("!B", mode)
        return result

    @staticmethod
    def parse_content(raw: bytes):
        list_len = struct.unpack_from("!B", raw)
        modes = []
        for mode, in struct.iter_unpack("!B", raw[1:]):
            modes.append(PSKExchangeMode(mode))
        return PSKKeyExchangeModes(modes)
