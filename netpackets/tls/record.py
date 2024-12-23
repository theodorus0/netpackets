import struct
from enum import IntEnum
from typing import Any

from netpackets import Packet


class TLSContentType(IntEnum):
    ChangeCipherSpec = 0x14
    Alert = 0x15
    Handshake = 0x16
    Application = 0x17
    Heartbeat = 0x18


class TLSVersion(IntEnum):
    SSL3 = 0x0300
    TLS10 = 0x0301
    TLS11 = 0x0302
    TLS12 = 0x0303
    TLS13 = 0x0304


class TLSRecord(Packet):
    content_type: TLSContentType
    legacy_version: TLSVersion
    messages: bytes
    message_authentication_code: Any
    padding: bytes

    def __init__(self, content_type: TLSContentType, version: TLSVersion, messages: bytes = b""):
        self.content_type = content_type
        self.legacy_version = version
        self.messages = messages
        self.message_authentication_code = b""
        self.padding = b""

    @property
    def length(self):
        return len(self.messages) + len(self.message_authentication_code) + len(self.padding)

    def build(self) -> bytes:
        header = struct.pack("!BHH",
                             self.content_type,
                             self.legacy_version,
                             self.length)
        return header + self.messages + self.padding

    @staticmethod
    def parse(raw: bytes) -> "Packet":
        (content_type,
         legacy_version,
         length) = struct.unpack("!BHH", raw)
        return TLSRecord(content_type, legacy_version, raw[5:])
