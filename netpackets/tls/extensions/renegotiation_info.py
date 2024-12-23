import struct
from typing import Optional

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


@register_extension
class RenegotiationInfo(TLSExtension):
    type = ExtensionType.renegotiation_info

    client_verify_data: Optional[bytes]
    server_verify_data: Optional[bytes]

    def __init__(self, client_verify_data=b"", server_verify_data=b""):
        self.client_verify_data = client_verify_data
        self.server_verify_data = server_verify_data

    @property
    def length(self):
        return 1 + self.data_length

    @property
    def data_length(self):
        return len(self.client_verify_data) + len(self.server_verify_data)

    def build_content(self) -> bytes:
        result = struct.pack("!B", self.data_length)
        return result + self.client_verify_data + self.server_verify_data

    @staticmethod
    def parse_content(raw: bytes):
        data_len, = struct.unpack_from("!B", raw)
        if data_len > 30:
            # SSLv3
            key_len = 36
        else:
            # TSL
            key_len = 12
        if data_len > 0:
            client = raw[1:1 + key_len]
            server = raw[1 + key_len:1 + 2 * key_len]
            return RenegotiationInfo(client, server)
        return RenegotiationInfo()
