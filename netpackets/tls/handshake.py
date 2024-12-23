import struct

from netpackets.tls.client_hello import ClientHello
from netpackets.tls.handshake_message import TLSHandshakeMessage, HandshakeMessageType
from netpackets.tls.record import TLSRecord, TLSContentType, TLSVersion


def parse_message_by_type(type: HandshakeMessageType, data: bytes) -> TLSHandshakeMessage:
    if type == HandshakeMessageType.ClientHello:
        return ClientHello.parse_handshake_message(data)


class TLSHandshakeRecord(TLSRecord):
    handshake_messages: list[TLSHandshakeMessage]

    def __init__(self, version: TLSVersion, messages: list[TLSHandshakeMessage]):
        super().__init__(TLSContentType.Handshake, version)
        self.handshake_messages = messages

    @staticmethod
    def parse(raw: bytes) -> "TLSHandshakeRecord":
        (content_type,
         legacy_version,
         length) = struct.unpack_from("!BHH", raw)

        offset = 5
        handshake_messages = []
        while offset < 5 + length:
            message_type, message_length_bytes = struct.unpack_from("!B3s", raw, offset)
            message_length = int.from_bytes(message_length_bytes)
            handshake_messages.append(parse_message_by_type(message_type, raw[offset + 4:]))
            offset += message_length + 4
        return TLSHandshakeRecord(TLSVersion(legacy_version), handshake_messages)

    def __repr__(self):
        return f"<TLS {self.legacy_version.name}>"

    def build(self) -> bytes:
        result = struct.pack("!BHH",
                             self.content_type,
                             self.legacy_version,
                             self.length)
        for message in self.handshake_messages:
            result += message.build()
        return result
